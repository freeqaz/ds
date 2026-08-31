// SPDX-License-Identifier: Apache-2.0

// HMAC key lifecycle tests (doc 16 §6.3): per-host per-epoch key derivation,
// rotation at the golden-image cadence, re-key on host redeploy, and the LIVE
// re-key end-to-end — every live digest re-pushed under the new key, the new
// digests published + acked BEFORE the old key is retired (no mint-before-attach
// gap, no digest dropped). The truncation-length choice (OQ8 / RATIONALE.md) is
// asserted here. SYNTHETIC ONLY (D50): every key is a `ds-synth-*` root, never
// real HMAC material; every secret is a `ds-synth-*` plaintext.
package digest

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// synthRoot is the synthetic fleet root key the lifecycle derives per-host
// per-epoch keys from (D50 — never a real root). 32 bytes = the rootKeyMinLen
// floor.
var synthRoot = []byte("ds-synth-fleet-root-key-0000000000000000")

const synthHostA = "host-a"

// --- key derivation -------------------------------------------------------

func TestDeriveKeyIsDeterministicAndPerCoordinate(t *testing.T) {
	e0 := KeyEpoch{HostID: synthHostA, Epoch: 0, Generation: 0}
	k0a := DeriveKey(synthRoot, e0)
	k0b := DeriveKey(synthRoot, e0)
	if !bytes.Equal(k0a, k0b) {
		t.Fatal("DeriveKey not deterministic for the same coordinate")
	}
	if len(k0a) != hmacSHA256LenBytes {
		t.Fatalf("derived key len %d, want %d (full HMAC-SHA-256 width)", len(k0a), hmacSHA256LenBytes)
	}

	// Every coordinate axis changes the key: host, epoch, generation.
	cases := []KeyEpoch{
		{HostID: "host-b", Epoch: 0, Generation: 0},   // different host
		{HostID: synthHostA, Epoch: 1, Generation: 0}, // next epoch (rotation)
		{HostID: synthHostA, Epoch: 0, Generation: 1}, // re-key generation
	}
	for _, c := range cases {
		if bytes.Equal(k0a, DeriveKey(synthRoot, c)) {
			t.Errorf("coordinate %+v derived the same key as the base epoch", c)
		}
	}

	// A different root yields different material for the same coordinate.
	otherRoot := []byte("ds-synth-OTHER-fleet-root-000000000000000")
	if bytes.Equal(k0a, DeriveKey(otherRoot, e0)) {
		t.Error("different root derived the same key (root not mixed in)")
	}
}

func TestKeyIDCollisionFree(t *testing.T) {
	// Length-delimited coordinate fields must make two distinct coordinates yield
	// distinct ids — including adversarial host ids that try to forge a delimiter.
	ids := map[string]KeyEpoch{}
	coords := []KeyEpoch{
		{HostID: "host-a", Epoch: 1, Generation: 0},
		{HostID: "host-a", Epoch: 10, Generation: 0},      // 1|0 vs 10 must not alias
		{HostID: "host-a1", Epoch: 0, Generation: 0},      // host eats the epoch digit?
		{HostID: "host-a-e1-g0", Epoch: 0, Generation: 0}, // host forges the whole suffix
		{HostID: "host-b", Epoch: 1, Generation: 0},
		{HostID: "host-a", Epoch: 1, Generation: 1},
	}
	for _, c := range coords {
		id := c.KeyID()
		if prev, ok := ids[id]; ok {
			t.Fatalf("key id %q collides: %+v and %+v", id, prev, c)
		}
		ids[id] = c
	}
}

// --- rotation (golden-image cadence) --------------------------------------

func TestRotateAdvancesEpochAndRetiresOld(t *testing.T) {
	m, err := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	e0 := m.Current()
	id0 := m.ActiveKeyID()
	if e0.Epoch != 0 || e0.Generation != 0 {
		t.Fatalf("fresh manager at epoch %d gen %d, want 0/0", e0.Epoch, e0.Generation)
	}

	e1 := m.Rotate()
	if e1.Epoch != 1 || e1.Generation != 0 {
		t.Errorf("after Rotate: epoch %d gen %d, want 1/0", e1.Epoch, e1.Generation)
	}
	if m.ActiveKeyID() == id0 {
		t.Error("active key id did not change after Rotate")
	}
	// The old key is retiring (its live digests are still matchable until torn
	// down or re-pushed) — not silently dropped.
	if !containsStr(m.RetiringKeyIDs(), id0) {
		t.Errorf("rotated-out key %q not in retiring set %v", id0, m.RetiringKeyIDs())
	}
	// A rotated-out producer stamps the OLD id; the active producer stamps the new.
	actProd, _ := m.Producer()
	if actProd.KeyID() != e1.KeyID() {
		t.Errorf("active producer key id %q, want %q", actProd.KeyID(), e1.KeyID())
	}
}

// --- re-key (host redeploy) -----------------------------------------------

func TestRekeyAdvancesGenerationSoRedeployNeverReusesAKey(t *testing.T) {
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	e0 := m.Current()
	k0 := DeriveKey(synthRoot, e0)
	id0 := e0.KeyID()

	e1 := m.Rekey()
	if e1.Generation != 1 {
		t.Errorf("after Rekey: generation %d, want 1 (a redeploy gets a fresh generation)", e1.Generation)
	}
	if e1.KeyID() == id0 {
		t.Error("re-key produced the same key id as the pre-redeploy key")
	}
	if bytes.Equal(DeriveKey(synthRoot, e1), k0) {
		t.Error("re-key derived the SAME key material as before the redeploy")
	}
	if !containsStr(m.RetiringKeyIDs(), id0) {
		t.Errorf("pre-redeploy key %q not retiring after Rekey", id0)
	}
}

// --- LIVE re-key end-to-end (the no-gap, no-loss guarantee) ----------------

// rekeyConsumer records every published batch BY KEY ID so a test can assert
// which key each session's digests were pushed under, and can be told to fail
// the Nth publish (to exercise the fail-closed leg). It is the in-process
// stand-in for the D109 host-agent ack-er (no live boundary — the wave rule).
type rekeyConsumer struct {
	identityv1.UnimplementedDigestFeedServiceServer
	// byKeyID accumulates the entries acked under each key id (the boundary's
	// loaded set per key). A live re-key MUST populate the new key id for every
	// session before the old key id is dropped.
	byKeyID map[string][]*identityv1.DigestEntry
	// failOnPublishN, if >0, makes the Nth (1-based) DigestPublish fail with an
	// uncommitted ack — to prove a partial re-key leaves the old key live.
	publishCount   int
	failOnPublishN int
}

func newRekeyConsumer() *rekeyConsumer {
	return &rekeyConsumer{byKeyID: map[string][]*identityv1.DigestEntry{}}
}

func (c *rekeyConsumer) DigestPublish(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	c.publishCount++
	committed := true
	if c.failOnPublishN > 0 && c.publishCount == c.failOnPublishN {
		committed = false // uncommitted ack ⇒ PublishSession fails closed
	} else {
		for _, e := range req.GetEntries() {
			c.byKeyID[e.GetKeyId()] = append(c.byKeyID[e.GetKeyId()], e)
		}
	}
	return &identityv1.DigestPublishResponse{
		BatchId:    req.GetBatchId(),
		Session:    req.GetSession(),
		ConsumerId: "synth-host-agent",
		Committed:  committed,
	}, nil
}

func (c *rekeyConsumer) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	for _, kid := range req.GetKeyIds() {
		delete(c.byKeyID, kid)
	}
	return &identityv1.DigestRevokeResponse{Session: req.GetSession(), ConsumerId: "synth-host-agent", Committed: true}, nil
}

func liveSessions() []LiveSession {
	exp := time.Now().Add(15 * time.Minute)
	return []LiveSession{
		{SessionUUID: "00000000-0000-4000-8000-00000000aa01", Creds: []Credential{
			{Plaintext: []byte("ds-synth-sessA-github-pat"), CredClass: Issued("github"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: exp},
			{Plaintext: []byte("ds-synth-sessA-canary"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: exp},
		}},
		{SessionUUID: "00000000-0000-4000-8000-00000000aa02", Creds: []Credential{
			{Plaintext: []byte("ds-synth-sessB-aws-key"), CredClass: Issued("aws"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: exp},
		}},
	}
}

func batchIDFor(s string) string { return "rekey-batch-" + s }

// TestLiveRekeyRePushesEveryDigestBeforeRetiringOld is the core acceptance
// proof: a host redeploy (Rekey) re-pushes every live session's digests under
// the NEW key, the new digests are acked, and only THEN is the old key retired
// — with no instant at which a session is unshadowed by both keys.
func TestLiveRekeyRePushesEveryDigestBeforeRetiringOld(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)

	m, err := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sessions := liveSessions()

	// Pre-state: every session is shadowed under the OLD key (the original
	// mint-before-attach publish at session create).
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		pr, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID)
		if err != nil || !pr.Routable {
			t.Fatalf("initial publish for %q: err=%v routable=%v", s.SessionUUID, err, pr.Routable)
		}
	}
	if _, ok := consumer.byKeyID[oldID]; !ok {
		t.Fatalf("old key %q has no loaded digests after initial publish", oldID)
	}

	// Redeploy: advance the lifecycle, then live re-key.
	newE := m.Rekey()
	newID := newE.KeyID()
	if newID == oldID {
		t.Fatal("re-key did not change the active key id")
	}

	res, err := m.LiveRekey(context.Background(), client, oldID, sessions, batchIDFor)
	if err != nil {
		t.Fatalf("LiveRekey: %v", err)
	}
	if !res.OldKeyRetired {
		t.Fatal("LiveRekey reported old key NOT retired on the happy path")
	}
	if res.NewKeyID != newID {
		t.Errorf("re-key NewKeyID %q, want %q", res.NewKeyID, newID)
	}
	if len(res.Republished) != len(sessions) {
		t.Errorf("re-pushed %d sessions, want %d", len(res.Republished), len(sessions))
	}
	for i, pr := range res.Republished {
		if !pr.Routable {
			t.Errorf("re-push %d not routable", i)
		}
	}

	// NO DIGEST DROPPED: every session's every credential, every variant, is now
	// matchable under the NEW key. We build the matcher the boundary would hold
	// post-flip from the consumer's accumulated new-key entries.
	newProd, _ := m.Producer()
	newMatcher, _ := MatcherFromProducer(newProd)
	newMatcher.Load(consumer.byKeyID[newID])
	wantDigests := 0
	for _, s := range sessions {
		for _, c := range s.Creds {
			wantDigests += len(AllVariants)
			if r := newMatcher.Match(c.Plaintext); !r.Matched {
				t.Errorf("after live re-key, credential not matchable under new key: %q", c.Plaintext)
			}
		}
	}
	if got := len(consumer.byKeyID[newID]); got != wantDigests {
		t.Errorf("new key loaded %d digests, want %d (one per cred per variant — no digest dropped)", got, wantDigests)
	}

	// The old key is no longer SELECTED by the lifecycle (retired) — but note the
	// boundary still held its digests through the whole re-push, so no gap ever
	// existed. The lifecycle no longer lists it as retiring.
	if containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old key %q still retiring after a successful LiveRekey", oldID)
	}
}

// TestLiveRekeyHasNoGap_OldDigestsStayLiveUntilNewAcked proves the ordering
// invariant directly: at the moment the new-key digests become matchable, the
// OLD-key digests are STILL loaded at the boundary — so a session is shadowed by
// at least one key at every instant (no mint-before-attach gap).
func TestLiveRekeyHasNoGap_OldDigestsStayLiveUntilNewAcked(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	sessions := liveSessions()

	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial publish: %v", err)
		}
	}

	m.Rekey()
	res, err := m.LiveRekey(context.Background(), client, oldID, sessions, batchIDFor)
	if err != nil {
		t.Fatalf("LiveRekey: %v", err)
	}

	// LiveRekey only retires the old key AFTER the new acks — and it never asked
	// the consumer to drop the old key (no DigestRevoke was issued by LiveRekey),
	// so the boundary STILL holds the old-key digests post-re-key. The matchable
	// window under the old key was therefore continuous up to and through the new
	// digests landing.
	if _, ok := consumer.byKeyID[oldID]; !ok {
		t.Fatal("old-key digests were dropped at the boundary during LiveRekey — a gap")
	}
	oldMatcher, _ := NewMatcher(oldID, DeriveKey(synthRoot, KeyEpoch{HostID: synthHostA, Epoch: 0, Generation: 0}))
	oldMatcher.Load(consumer.byKeyID[oldID])
	for _, s := range sessions {
		for _, c := range s.Creds {
			if r := oldMatcher.Match(c.Plaintext); !r.Matched {
				t.Errorf("old-key shadow lost during re-key for %q (a gap)", c.Plaintext)
			}
		}
	}
	if !res.OldKeyRetired {
		t.Error("old key should be retired (lifecycle-side) after the new digests acked")
	}

	// Optional flush AFTER the re-push: now (and only now) the old digests may be
	// revoked — bounding the §6.3 oracle window without ever opening a gap.
	if err := m.RetireOldKeyViaRevoke(context.Background(), client, oldID, sessions); err != nil {
		t.Fatalf("RetireOldKeyViaRevoke after LiveRekey: %v", err)
	}
	if _, ok := consumer.byKeyID[oldID]; ok {
		t.Error("old-key digests not flushed by RetireOldKeyViaRevoke")
	}
}

// TestLiveRekeyFailClosed_PartialRePushLeavesOldKeyLive proves a failed re-push
// does NOT retire the old key — every session stays shadowed by the old digests
// (no gap), and the caller can retry the redeploy.
func TestLiveRekeyFailClosed_PartialRePushLeavesOldKeyLive(t *testing.T) {
	consumer := newRekeyConsumer()
	consumer.failOnPublishN = 2 // fail the SECOND session's re-push
	client := dialConsumer(t, consumer)
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	sessions := liveSessions()
	if len(sessions) < 2 {
		t.Fatal("need >=2 sessions to exercise a partial re-push")
	}

	oldID := m.ActiveKeyID()
	m.Rekey()
	res, err := m.LiveRekey(context.Background(), client, oldID, sessions, batchIDFor)
	if err == nil {
		t.Fatal("partial re-push: want error (fail-closed)")
	}
	if res.OldKeyRetired {
		t.Fatal("partial re-push must NOT retire the old key (would open a gap)")
	}
	// The old key is STILL retiring (still live at the boundary) — the caller can
	// retry. It was never dropped.
	if !containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old key %q dropped from retiring on a failed re-key — gap risk", oldID)
	}
}

// TestLiveRekeyGuards covers the fail-closed construction/ordering guards.
func TestLiveRekeyGuards(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	sessions := liveSessions()
	ctx := context.Background()

	// nil client.
	if _, err := m.LiveRekey(ctx, nil, "x", sessions, batchIDFor); err == nil {
		t.Error("nil client: want error")
	}
	// old key id equals the active id (manager not advanced).
	if _, err := m.LiveRekey(ctx, client, m.ActiveKeyID(), sessions, batchIDFor); err == nil {
		t.Error("old==active key id: want error (advance the manager first)")
	}
	// old key not in the retiring set (never rotated).
	if _, err := m.LiveRekey(ctx, client, "ds-dk-host-a-e9-g9", sessions, batchIDFor); err == nil {
		t.Error("non-retiring old key: want error")
	}
	// nil batchIDFor after a real advance.
	old := m.ActiveKeyID()
	m.Rekey()
	if _, err := m.LiveRekey(ctx, client, old, sessions, nil); err == nil {
		t.Error("nil batchIDFor: want error")
	}
	// RetireOldKeyViaRevoke refuses while the key is still retiring (LiveRekey not
	// run) — so it can never flush the only shadow.
	if err := m.RetireOldKeyViaRevoke(ctx, client, old, sessions); err == nil {
		t.Error("revoke while still retiring: want error (no gap)")
	}
}

// --- KeyManager construction + truncation choice (OQ8) --------------------

func TestNewKeyManagerFailClosed(t *testing.T) {
	if _, err := NewKeyManager(synthHostA, nil, 0); err != ErrNoRootKey {
		t.Errorf("nil root: err=%v, want ErrNoRootKey", err)
	}
	if _, err := NewKeyManager(synthHostA, []byte("too-short"), 0); err == nil {
		t.Error("short root: want error (below 32-byte floor)")
	}
	if _, err := NewKeyManager("", synthRoot, 0); err != ErrNoHostID {
		t.Errorf("empty host: err=%v, want ErrNoHostID", err)
	}
	if _, err := NewKeyManager(synthHostA, synthRoot, 4); err != ErrTruncTooShort {
		t.Errorf("trunc=4: err=%v, want ErrTruncTooShort", err)
	}
	if _, err := NewKeyManager(synthHostA, synthRoot, 33); err != ErrTruncTooLong {
		t.Errorf("trunc=33: err=%v, want ErrTruncTooLong", err)
	}
}

// TestChosenTruncationLength pins the OQ8 truncation choice recorded in
// RATIONALE.md: 16 bytes / 128 bits. This is the assertion the wave acceptance
// names — if the chosen length ever moves, this test and RATIONALE.md must move
// together (and, per doc 16 §6.3 / OQ8, the docs/16 record the report proposes).
func TestChosenTruncationLength(t *testing.T) {
	const chosen = 16
	if DefaultTruncationLenBytes != chosen {
		t.Fatalf("DefaultTruncationLenBytes = %d, want %d (the OQ8 choice; see RATIONALE.md)",
			DefaultTruncationLenBytes, chosen)
	}
	if DefaultTruncationLenBytes*8 != 128 {
		t.Fatalf("chosen truncation is %d bits, want 128 (the FP≈0-at-fleet-counts choice)", DefaultTruncationLenBytes*8)
	}
	// A manager defaults to the chosen length, and its minted producer stamps it.
	m, _ := NewKeyManager(synthHostA, synthRoot, 0)
	prod, _ := m.Producer()
	if prod.TruncationLenBytes() != chosen {
		t.Errorf("default producer trunc %d, want %d", prod.TruncationLenBytes(), chosen)
	}
}

// TestProducerForEpochThreadsKeyAndID proves the lifecycle-aware constructor
// derives the epoch key and stamps the epoch's key id, matching the manager.
func TestProducerForEpochThreadsKeyAndID(t *testing.T) {
	e := KeyEpoch{HostID: synthHostA, Epoch: 3, Generation: 1}
	prod, err := NewProducerForEpoch(synthRoot, e, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewProducerForEpoch: %v", err)
	}
	if prod.KeyID() != e.KeyID() {
		t.Errorf("producer key id %q, want %q", prod.KeyID(), e.KeyID())
	}
	// It matches a manager advanced to the same coordinate.
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	m.Rotate() // e1
	m.Rotate() // e2
	m.Rekey()  // e3 g1
	mProd, _ := m.Producer()
	if mProd.KeyID() != e.KeyID() {
		t.Fatalf("manager key id %q, want %q (epoch/gen threading)", mProd.KeyID(), e.KeyID())
	}
	// Same coordinate ⇒ same digests (the boundary selects one key for both).
	secret := []byte("ds-synth-thread-check")
	cred := Credential{Plaintext: secret, CredClass: Issued("svc"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION}
	a, _ := prod.Entries(cred)
	b, _ := mProd.Entries(cred)
	for i := range a {
		if !bytes.Equal(a[i].GetDigest(), b[i].GetDigest()) {
			t.Fatal("NewProducerForEpoch and KeyManager.Producer disagree on a digest at the same coordinate")
		}
	}
}

// TestPublishSessionWithManagerThreadsActiveKey proves the lifecycle-aware
// publish rides the manager's active key id.
func TestPublishSessionWithManagerThreadsActiveKey(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	m.Rotate() // move off epoch 0 so we are sure the ACTIVE key is threaded
	activeID := m.ActiveKeyID()

	s := liveSessions()[0]
	pr, err := PublishSessionWithManager(context.Background(), client, m, s.SessionUUID, s.Creds, "wm-batch")
	if err != nil || !pr.Routable {
		t.Fatalf("PublishSessionWithManager: err=%v routable=%v", err, pr.Routable)
	}
	if _, ok := consumer.byKeyID[activeID]; !ok {
		t.Errorf("published under %v, want active key %q", keysOf(consumer.byKeyID), activeID)
	}
	// nil manager fails closed.
	if _, err := PublishSessionWithManager(context.Background(), client, nil, s.SessionUUID, s.Creds, "b"); err == nil {
		t.Error("nil manager: want error (fail-closed)")
	}
}

// --- helpers --------------------------------------------------------------

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func keysOf(m map[string][]*identityv1.DigestEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
