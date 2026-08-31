package policylog

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nftbridge"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"

	"google.golang.org/protobuf/proto"
)

// TestComposeLayers_DenyWins proves the frozen invariant (doc 13 §1 rule 2): an
// allow at a NARROWER scope can never re-admit what a BROADER layer denies — and,
// symmetrically, a deny anywhere wins over an allow anywhere. The composed Allow
// set excludes every denied key; the composed Deny set is the union of denies.
func TestComposeLayers_DenyWins(t *testing.T) {
	layers := []Layer{
		{Scope: LayerSystemBaseline, Deny: []string{"evil.example"}},
		{Scope: LayerOrg, Allow: []string{"github.com", "evil.example"}}, // org tries to allow a baseline-denied key
		{Scope: LayerRepoSession, Allow: []string{"pypi.org"}, Deny: []string{"github.com"}},
	}
	got := ComposeLayers(layers)

	// evil.example: denied by baseline → never allowed even though org allows it.
	// github.com: allowed by org but denied by repo/session → deny wins.
	// pypi.org: allowed by repo/session, denied nowhere → survives.
	wantAllow := []string{"pypi.org"}
	wantDeny := []string{"evil.example", "github.com"}
	assertStrings(t, "Allow", got.Allow, wantAllow)
	assertStrings(t, "Deny", got.Deny, wantDeny)
}

// TestComposeLayers_OrderIndependentResult proves composition is deterministic
// and order-independent for the RESULT (deny is a union; an allow survives iff
// denied nowhere) — so the snapshot identity does not depend on the order rows
// were appended.
func TestComposeLayers_OrderIndependentResult(t *testing.T) {
	a := []Layer{
		{Scope: LayerOrg, Allow: []string{"a", "b"}, Deny: []string{"c"}},
		{Scope: LayerSystemBaseline, Allow: []string{"c"}, Deny: []string{"d"}},
	}
	b := []Layer{
		{Scope: LayerSystemBaseline, Deny: []string{"d"}, Allow: []string{"c"}},
		{Scope: LayerOrg, Deny: []string{"c"}, Allow: []string{"b", "a"}},
	}
	ca, cb := ComposeLayers(a), ComposeLayers(b)
	assertStrings(t, "Allow(a)", ca.Allow, cb.Allow)
	assertStrings(t, "Deny(a)", ca.Deny, cb.Deny)
	assertStrings(t, "Allow", ca.Allow, []string{"a", "b"})
	assertStrings(t, "Deny", ca.Deny, []string{"c", "d"})
}

// TestComposeSnapshot_IdentityIsStable proves the §5 snapshot identity (seq,
// content_hash, document) is a pure function of the composed inputs: the same
// shared material + sections yields byte-identical document and content_hash, and
// the hash is exactly SHA-256 over the produce-once document bytes (doc 13 §5.1).
func TestComposeSnapshot_IdentityIsStable(t *testing.T) {
	shared := ComposedPolicy{Allow: []string{"github.com"}, Deny: []string{"evil.example"}}
	sessions := []SessionComposite{
		{SessionID: "sess-b", Composed: ComposedPolicy{Allow: []string{"pypi.org"}}},
		{SessionID: "sess-a", Composed: ComposedPolicy{Deny: []string{"npm.evil"}}},
	}
	s1 := ComposeSnapshot(7, shared, sessions)
	s2 := ComposeSnapshot(7, shared, sessions)

	if string(s1.Document) != string(s2.Document) {
		t.Fatalf("document bytes are not deterministic:\n %q\n %q", s1.Document, s2.Document)
	}
	if s1.ContentHash != s2.ContentHash {
		t.Fatalf("content_hash is not deterministic: %x vs %x", s1.ContentHash, s2.ContentHash)
	}
	// The hash IS SHA-256 over exactly the produce-once document bytes (§5.1).
	if want := nftbridge.HashPayload(s1.Document); s1.ContentHash != want {
		t.Errorf("content_hash %x != HashPayload(document) %x", s1.ContentHash, want)
	}
	if s1.Seq != 7 {
		t.Errorf("Seq = %d, want 7", s1.Seq)
	}
	// Sub-hashes are ordered by session_id (doc 13 §5.1) regardless of input order.
	if len(s1.Sections) != 2 || s1.Sections[0].SessionID != "sess-a" || s1.Sections[1].SessionID != "sess-b" {
		t.Errorf("sections not ordered by session_id: %+v", s1.Sections)
	}
}

// TestComposeSnapshot_OneSessionChangeRehashesOneSection proves the composite
// rollup (doc 13 §5.1, D120): changing ONE session's policy re-hashes that
// session's section but leaves the other section's sub-hash unchanged.
func TestComposeSnapshot_OneSessionChangeRehashesOneSection(t *testing.T) {
	shared := ComposedPolicy{Allow: []string{"github.com"}}
	base := []SessionComposite{
		{SessionID: "sess-a", Composed: ComposedPolicy{Allow: []string{"a1"}}},
		{SessionID: "sess-b", Composed: ComposedPolicy{Allow: []string{"b1"}}},
	}
	changed := []SessionComposite{
		{SessionID: "sess-a", Composed: ComposedPolicy{Allow: []string{"a1"}}},
		{SessionID: "sess-b", Composed: ComposedPolicy{Allow: []string{"b1", "b2"}}}, // sess-b changed
	}
	s1 := ComposeSnapshot(1, shared, base)
	s2 := ComposeSnapshot(2, shared, changed)

	if s1.Sections[0].Hash != s2.Sections[0].Hash {
		t.Error("sess-a sub-hash changed when only sess-b changed")
	}
	if s1.Sections[1].Hash == s2.Sections[1].Hash {
		t.Error("sess-b sub-hash unchanged after its policy changed")
	}
	if s1.ContentHash == s2.ContentHash {
		t.Error("host content_hash unchanged after a session policy changed")
	}
}

// TestSessionComposite_GrantDeniedDoesNotReadmit proves deny-overrides applies to
// ask-grants too (doc 13 §1 rule 2 / §8): a live grant whose rule is denied by
// the composed policy is dropped from the section — a grant never re-admits what
// a layer denies.
func TestSessionComposite_GrantDeniedDoesNotReadmit(t *testing.T) {
	a := SessionComposite{
		SessionID: "sess-x",
		Composed:  ComposedPolicy{Deny: []string{"blocked.example"}},
		Grants:    []LiveGrant{{Rule: "blocked.example", ExpiresUnix: 9_999_999_999}},
	}
	b := SessionComposite{
		SessionID: "sess-x",
		Composed:  ComposedPolicy{Deny: []string{"blocked.example"}},
		// no grant for the denied rule
	}
	// The denied-grant section must hash identically to the no-grant section: the
	// grant contributed nothing because deny won.
	sa := ComposeSnapshot(1, ComposedPolicy{}, []SessionComposite{a})
	sb := ComposeSnapshot(1, ComposedPolicy{}, []SessionComposite{b})
	if sa.ContentHash != sb.ContentHash {
		t.Errorf("a denied grant changed the snapshot — deny did not win over the grant")
	}
}

// TestLiveGrantsFrom_DropsExpired proves the §8 liveness gate: a grant whose
// non-zero expiry is at or before now is dropped (it gates no new flow); a
// zero-expiry grant (no recorded TTL) and a future-expiry grant survive.
func TestLiveGrantsFrom_DropsExpired(t *testing.T) {
	now := time.Unix(1_000, 0)
	grants := []LiveGrant{
		{Rule: "expired", ExpiresUnix: 999},  // before now → dropped
		{Rule: "at-now", ExpiresUnix: 1_000}, // == now → dropped (not After)
		{Rule: "future", ExpiresUnix: 1_001}, // after now → live
		{Rule: "no-ttl", ExpiresUnix: 0},     // no recorded TTL → live
	}
	got := liveGrantsFrom(grants, now)
	gotRules := make([]string, len(got))
	for i, g := range got {
		gotRules[i] = g.Rule
	}
	assertStrings(t, "live", sortedCopy(gotRules), []string{"future", "no-ttl"})
}

// assertStrings fails the test if got != want (order-sensitive; the composition
// outputs are pre-sorted so this also pins ordering).
func assertStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length = %d %v, want %d %v", label, len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q (got %v, want %v)", label, i, got[i], want[i], got, want)
		}
	}
}

// --- POL-4 fleet-digest revocation sweep --------------------------------------

// fleetSweepEntry builds a synthetic DIGEST_SCOPE_FLEET DigestEntry whose digest
// bytes encode the given seed (and embed a '\n' to exercise the length-framed parse),
// so distinct seeds yield distinct content ids. It reuses the package's existing
// fleetEntry helper (fleetdigestsink_test.go).
func fleetSweepEntry(keyID string, seed byte) *identityv1.DigestEntry {
	return fleetEntry(keyID, seed, seed^0x5a, 0x00, '\n')
}

// fleetRow builds a FleetDigestKind policy_log row from a synthetic artifact using
// the SAME producer path the landed FleetDigestSink writes (marshalFleetArtifact),
// so the sweep is exercised against the real envelope, not a hand-faked body.
func fleetRow(t *testing.T, seq int64, keyID, batch string, entries ...*identityv1.DigestEntry) store.PolicyLogRow {
	t.Helper()
	payload, err := marshalFleetArtifact(FleetDigestArtifact{KeyID: keyID, Entries: entries, BatchID: batch})
	if err != nil {
		t.Fatalf("marshalFleetArtifact(seq=%d key=%q): %v", seq, keyID, err)
	}
	return store.PolicyLogRow{Seq: seq, Kind: FleetDigestKind, Actor: "fleet-digest-producer", Payload: payload}
}

// entryHex is the canonical (deterministic) content-id identity the sweep emits for
// an entry — the same encoding marshalFleetArtifact frames.
func entryHex(t *testing.T, e *identityv1.DigestEntry) string {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return hex.EncodeToString(b)
}

func forbiddenHexes(fs FleetSweep) []string {
	out := make([]string, len(fs.Forbidden))
	for i, f := range fs.Forbidden {
		out[i] = f.EntryHex
	}
	return out
}

// TestSweepFleetDigests_UnionAcrossKeys proves the sweep folds the live forbidden
// digests across distinct key ids into the deterministic union, ignoring every
// non-fleet-digest row (an ordinary append + an ask-grant must contribute nothing).
func TestSweepFleetDigests_UnionAcrossKeys(t *testing.T) {
	e1 := fleetSweepEntry("key-a", 0x11)
	e2 := fleetSweepEntry("key-b", 0x22)
	rows := []store.PolicyLogRow{
		{Seq: 1, Kind: store.PolicyKindAppend, Payload: []byte("system_baseline||allow=github.com|deny=")},
		fleetRow(t, 2, "key-a", "batch-a", e1),
		{Seq: 3, Kind: store.PolicyKindAskGrant, SessionUUID: "s1", Payload: []byte("grant")},
		fleetRow(t, 4, "key-b", "batch-b", e2),
	}
	got := SweepFleetDigests(rows)

	if got.HighSeq != 4 {
		t.Errorf("HighSeq = %d, want 4", got.HighSeq)
	}
	if len(got.Revoked) != 0 {
		t.Errorf("Revoked = %v, want none", got.Revoked)
	}
	assertStrings(t, "forbidden", forbiddenHexes(got), sortedCopy([]string{entryHex(t, e1), entryHex(t, e2)}))
	// Each forbidden digest carries the key id it was derived under.
	for _, f := range got.Forbidden {
		if f.KeyID != "key-a" && f.KeyID != "key-b" {
			t.Errorf("unexpected forbidden key id %q", f.KeyID)
		}
	}
}

// TestSweepFleetDigests_EmptyArtifactRevokes proves an empty-entries artifact under
// a key id is the REVOKE shape (doc 16 §6.2): it retires that key's fleet digests
// and is recorded in Revoked, while other keys' digests survive.
func TestSweepFleetDigests_EmptyArtifactRevokes(t *testing.T) {
	live := fleetSweepEntry("key-keep", 0x33)
	rows := []store.PolicyLogRow{
		fleetRow(t, 1, "key-gone", "b1", fleetSweepEntry("key-gone", 0x44)),
		fleetRow(t, 2, "key-keep", "b2", live),
		fleetRow(t, 3, "key-gone", "b3"), // empty entries == revoke key-gone
	}
	got := SweepFleetDigests(rows)

	assertStrings(t, "revoked", got.Revoked, []string{"key-gone"})
	assertStrings(t, "forbidden", forbiddenHexes(got), []string{entryHex(t, live)})
	if got.HighSeq != 3 {
		t.Errorf("HighSeq = %d, want 3", got.HighSeq)
	}
}

// TestSweepFleetDigests_LatestPerKeyWins proves last-write-wins per key id: a later
// artifact under the same key id supersedes the earlier one (a re-push under a key),
// and the fold is order-independent (the sweep sorts by seq before folding).
func TestSweepFleetDigests_LatestPerKeyWins(t *testing.T) {
	old := fleetSweepEntry("key-x", 0x01)
	cur := fleetSweepEntry("key-x", 0x02)
	inOrder := []store.PolicyLogRow{
		fleetRow(t, 5, "key-x", "old", old),
		fleetRow(t, 9, "key-x", "new", cur),
	}
	reversed := []store.PolicyLogRow{
		fleetRow(t, 9, "key-x", "new", cur),
		fleetRow(t, 5, "key-x", "old", old),
	}
	g1 := SweepFleetDigests(inOrder)
	g2 := SweepFleetDigests(reversed)

	want := []string{entryHex(t, cur)}
	assertStrings(t, "forbidden(in-order)", forbiddenHexes(g1), want)
	assertStrings(t, "forbidden(reversed-input)", forbiddenHexes(g2), want)
	if g1.HighSeq != 9 || g2.HighSeq != 9 {
		t.Errorf("HighSeq = %d/%d, want 9/9", g1.HighSeq, g2.HighSeq)
	}
}

// TestSweepFleetDigests_MultiEntryRoundTrip proves the length-framed envelope parse
// survives entries whose marshaled bytes contain a newline (the parse reads by hex
// length, never by line), and that the swept set is deterministic regardless of the
// producer's entry iteration order (the writer sorts; the reader hex-encodes).
func TestSweepFleetDigests_MultiEntryRoundTrip(t *testing.T) {
	a := fleetSweepEntry("key-m", 0x0a) // digest carries '\n'
	b := fleetSweepEntry("key-m", 0x0b)
	c := fleetSweepEntry("key-m", 0x0c)
	got := SweepFleetDigests([]store.PolicyLogRow{fleetRow(t, 1, "key-m", "batch", a, b, c)})

	assertStrings(t, "forbidden", forbiddenHexes(got),
		sortedCopy([]string{entryHex(t, a), entryHex(t, b), entryHex(t, c)}))
	if len(got.Revoked) != 0 {
		t.Errorf("Revoked = %v, want none", got.Revoked)
	}
}

// TestSweepFleetDigests_UnreadableRowFailsClosed proves fail-closed parsing: a
// FleetDigestKind row with a malformed body advances no key state — it yields no
// forbidden digest and no spurious revoke (it is simply skipped).
func TestSweepFleetDigests_UnreadableRowFailsClosed(t *testing.T) {
	good := fleetSweepEntry("key-ok", 0x77)
	rows := []store.PolicyLogRow{
		{Seq: 1, Kind: FleetDigestKind, Payload: []byte("not-a-fleet-envelope\n")},
		fleetRow(t, 2, "key-ok", "b", good),
		{Seq: 3, Kind: FleetDigestKind, Payload: nil}, // empty body: not the revoke shape, just malformed
	}
	got := SweepFleetDigests(rows)

	if len(got.Revoked) != 0 {
		t.Errorf("Revoked = %v, want none (malformed != revoke)", got.Revoked)
	}
	assertStrings(t, "forbidden", forbiddenHexes(got), []string{entryHex(t, good)})
	if got.HighSeq != 3 {
		t.Errorf("HighSeq = %d, want 3 (high seq tracks every fleet-digest row, even unparsable)", got.HighSeq)
	}
}

// TestParseFleetEnvelope_RevokeShape proves the explicit revoke shape parses ok with
// an EMPTY entry set (distinct from a parse failure): entries=0 is a legitimate body.
func TestParseFleetEnvelope_RevokeShape(t *testing.T) {
	payload, err := marshalFleetArtifact(FleetDigestArtifact{KeyID: "key-r", BatchID: "b"})
	if err != nil {
		t.Fatalf("marshal revoke artifact: %v", err)
	}
	keyID, entries, ok := parseFleetEnvelope(payload)
	if !ok {
		t.Fatal("revoke envelope did not parse ok")
	}
	if keyID != "key-r" {
		t.Errorf("keyID = %q, want key-r", keyID)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want empty (revoke)", entries)
	}
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
