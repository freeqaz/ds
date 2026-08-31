// SPDX-License-Identifier: Apache-2.0

package hostredeployconverge

import (
	"errors"
	"testing"
)

// convergence_test.go — the OFFLINE half of the re-key-on-host-redeploy
// conformance suite. It drives the PURE verdict core (Evaluate) against SYNTHETIC
// re-key observations — no live host, no KVM, no boundary, zero network — so it
// runs green in ordinary CI and is the in-wave proof of the doc 16 §6.3 claim.
// The env-gated live half (live_test.go) reuses this SAME Evaluate, so the wire
// pass and the offline spec can never disagree on a converged/violated verdict.

// digest is a terse helper for building synthetic Digest entries.
func digest(session, secret string) Digest { return Digest{SessionID: session, SecretID: secret} }

// twoLiveSessions is a synthetic two-session live population (three secrets) the
// happy-path and drop cases build on. It is clearly synthetic (D50): no
// plaintext, no real session ids, constructed in-test.
func twoLiveSessions() []Digest {
	return []Digest{
		digest("sess-A", "anthropic-key"),
		digest("sess-A", "github-token"),
		digest("sess-B", "npm-token"),
	}
}

// TestEvaluate_CleanRekeyConverges is the happy path: a genuine epoch rotation
// re-pushes EVERY live digest under the new key and acks the new set BEFORE
// revoking the old — mint-before-attach honored. The verdict must converge with
// zero violations and the full live set carried forward.
func TestEvaluate_CleanRekeyConverges(t *testing.T) {
	live := twoLiveSessions()
	obs := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-8",
		LiveOldKeyDigests:            live,
		NewKeyDigests:                append([]Digest(nil), live...), // every live digest re-pushed
		NewHostAckedBeforeOldRevoked: true,
	}
	v := Evaluate(obs)
	if !v.Converged {
		t.Fatalf("clean re-key should converge, got violations: %v", v.Violations)
	}
	if len(v.Violations) != 0 {
		t.Errorf("clean re-key should have no violations, got %v", v.Violations)
	}
	if v.CarriedForward != len(live) {
		t.Errorf("CarriedForward = %d, want %d (every live digest re-pushed)", v.CarriedForward, len(live))
	}
	if v.LiveCount != len(live) {
		t.Errorf("LiveCount = %d, want %d", v.LiveCount, len(live))
	}
}

// TestEvaluate_DroppedDigestFailsOpen asserts that dropping a live digest from
// the new-key set fires ErrDigestDropped — the §6.3 "re-pushes EVERY live digest"
// clause. The dropped secret would be absent from the keyed plane: a fail-open
// gap.
func TestEvaluate_DroppedDigestFailsOpen(t *testing.T) {
	live := twoLiveSessions()
	// New host re-pushes all BUT sess-B/npm-token.
	obs := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-8",
		LiveOldKeyDigests:            live,
		NewKeyDigests:                []Digest{digest("sess-A", "anthropic-key"), digest("sess-A", "github-token")},
		NewHostAckedBeforeOldRevoked: true,
	}
	v := Evaluate(obs)
	if v.Converged {
		t.Fatal("a dropped live digest must NOT converge")
	}
	if !hasSentinel(v.Violations, ErrDigestDropped) {
		t.Errorf("want ErrDigestDropped among violations, got %v", v.Violations)
	}
	if v.CarriedForward != 2 {
		t.Errorf("CarriedForward = %d, want 2 (the two re-pushed digests)", v.CarriedForward)
	}
}

// TestEvaluate_RevokeBeforeAckViolatesMintBeforeAttach asserts that revoking the
// old key BEFORE the new-key set is acked (NewHostAckedBeforeOldRevoked=false)
// fires ErrAttachBeforeMint — even when every digest is otherwise re-pushed and
// the key genuinely rotated. The ordering is the load-bearing invariant.
func TestEvaluate_RevokeBeforeAckViolatesMintBeforeAttach(t *testing.T) {
	live := twoLiveSessions()
	obs := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-8",
		LiveOldKeyDigests:            live,
		NewKeyDigests:                append([]Digest(nil), live...),
		NewHostAckedBeforeOldRevoked: false, // old key revoked before new set acked
	}
	v := Evaluate(obs)
	if v.Converged {
		t.Fatal("revoke-before-ack must NOT converge (mint-before-attach inverted)")
	}
	if !hasSentinel(v.Violations, ErrAttachBeforeMint) {
		t.Errorf("want ErrAttachBeforeMint among violations, got %v", v.Violations)
	}
}

// TestEvaluate_NoRotationIsNotARekey asserts that reusing the old key id
// (NewKeyID == OldKeyID) fires ErrKeyNotRotated — a non-rotation is not a re-key
// (per-host per-epoch keys).
func TestEvaluate_NoRotationIsNotARekey(t *testing.T) {
	live := twoLiveSessions()
	obs := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-7", // reused, not rotated
		LiveOldKeyDigests:            live,
		NewKeyDigests:                append([]Digest(nil), live...),
		NewHostAckedBeforeOldRevoked: true,
	}
	v := Evaluate(obs)
	if v.Converged {
		t.Fatal("a re-key that reuses the old key id must NOT converge")
	}
	if !hasSentinel(v.Violations, ErrKeyNotRotated) {
		t.Errorf("want ErrKeyNotRotated among violations, got %v", v.Violations)
	}
}

// TestEvaluate_StaleKeyedNewEntry asserts that a new-host entry observed loaded
// under the OLD key id (flagged via StaleKeyedSecretIDs) fires
// ErrStaleKeyOnNewSet — the entry is present but does not converge under the new
// epoch.
func TestEvaluate_StaleKeyedNewEntry(t *testing.T) {
	live := twoLiveSessions()
	obs := Observation{
		OldKeyID:          "epoch-7",
		NewKeyID:          "epoch-8",
		LiveOldKeyDigests: live,
		NewKeyDigests:     append([]Digest(nil), live...),
		// The npm-token entry was loaded under the OLD key id.
		StaleKeyedSecretIDs:          []digestKey{StaleKey("sess-B", "npm-token")},
		NewHostAckedBeforeOldRevoked: true,
	}
	v := Evaluate(obs)
	if v.Converged {
		t.Fatal("a stale-keyed new entry must NOT converge")
	}
	if !hasSentinel(v.Violations, ErrStaleKeyOnNewSet) {
		t.Errorf("want ErrStaleKeyOnNewSet among violations, got %v", v.Violations)
	}
	// The secret is still PRESENT (matched by session+secret), so it counts as
	// carried-forward — the fault is the key id, not a drop.
	if v.CarriedForward != len(live) {
		t.Errorf("CarriedForward = %d, want %d (stale-keyed entry is present, just mis-keyed)", v.CarriedForward, len(live))
	}
}

// TestEvaluate_MultipleViolationsAllSurface asserts a re-key that breaks SEVERAL
// invariants at once surfaces ALL of them — Evaluate never short-circuits, so an
// operator sees every way the re-key failed.
func TestEvaluate_MultipleViolationsAllSurface(t *testing.T) {
	live := twoLiveSessions()
	obs := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-7",                                   // not rotated
		LiveOldKeyDigests:            live,                                        //
		NewKeyDigests:                []Digest{digest("sess-A", "anthropic-key")}, // two digests dropped
		NewHostAckedBeforeOldRevoked: false,                                       // revoke-before-ack
	}
	v := Evaluate(obs)
	if v.Converged {
		t.Fatal("a multiply-broken re-key must NOT converge")
	}
	for _, want := range []error{ErrKeyNotRotated, ErrDigestDropped, ErrAttachBeforeMint} {
		if !hasSentinel(v.Violations, want) {
			t.Errorf("want %v among violations, got %v", want, v.Violations)
		}
	}
}

// TestEvaluate_EmptyLiveSetStillRequiresOrdering asserts the vacuous case: with
// NO live digests, a re-key still must ROTATE the key AND ack-before-revoke. An
// empty live set with a clean rotation + correct ordering converges; the same
// empty set with revoke-before-ack does NOT (the ordering invariant binds even
// when there is nothing to carry).
func TestEvaluate_EmptyLiveSetStillRequiresOrdering(t *testing.T) {
	clean := Observation{
		OldKeyID:                     "epoch-7",
		NewKeyID:                     "epoch-8",
		NewHostAckedBeforeOldRevoked: true,
	}
	if v := Evaluate(clean); !v.Converged {
		t.Errorf("empty live set with clean rotation+ordering should converge, got %v", v.Violations)
	}
	badOrder := clean
	badOrder.NewHostAckedBeforeOldRevoked = false
	if v := Evaluate(badOrder); v.Converged || !hasSentinel(v.Violations, ErrAttachBeforeMint) {
		t.Errorf("empty live set with revoke-before-ack must NOT converge with ErrAttachBeforeMint, got converged=%v violations=%v", v.Converged, v.Violations)
	}
}

// TestSentinelsDistinct guards that the named violation sentinels are distinct
// values — a copy-paste that collapsed two onto the same error would make
// errors.Is matching ambiguous.
func TestSentinelsDistinct(t *testing.T) {
	all := []error{ErrDigestDropped, ErrAttachBeforeMint, ErrKeyNotRotated, ErrStaleKeyOnNewSet, ErrLiveDriverNotWired}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if errors.Is(all[i], all[j]) {
				t.Errorf("sentinels %d and %d are not distinct", i, j)
			}
		}
	}
}

// hasSentinel reports whether any violation wraps the target sentinel.
func hasSentinel(violations []error, target error) bool {
	for _, v := range violations {
		if errors.Is(v, target) {
			return true
		}
	}
	return false
}
