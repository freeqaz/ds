// SPDX-License-Identifier: Apache-2.0

// The producer-side SecretMatcher reference (doc 14 §6/§7; D73).
//
// The authoritative SecretMatcher trait + verdict semantics
// ({Pass, Hold, Block, Flag, Redact-reserved}, hold-back, confirm-before-verdict)
// are BOUNDARY's — they live in dataplane/'s policy-core and are consumed across
// the frozen digest-feed seam (docs 11–14). This is NOT that enforcement plane.
//
// What lives here is the producer's MATCHABILITY PROOF: a minimal, decode-free
// matcher that loads the exact DigestEntry set the producer pushed and answers
// "would the boundary block this candidate byte span?" by computing
//
//	trunc( HMAC-SHA-256(key, candidate_bytes) )
//
// and testing set membership — the same predicate the boundary applies, with the
// SAME key the producer used. It exists so the producer can assert, in-process
// and over synthetic secrets, that every variant it pushes is matchable BEFORE
// the session's first egress byte (the round2/08 test-6 anchor, doc 16 §6.1).
// It deliberately does not decode candidates: the producer pushed one digest per
// ENCODING, so the matcher hashes raw wire bytes and the encoded forms line up
// by construction (variant.go).
package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// MatchResult is what the producer-side matcher returns for a candidate span.
// Matched is the only load-bearing field for the matchability proof; CredClass,
// Scope, and VariantTag carry the matched entry's provenance so a test can
// assert WHICH registered form fired (the boundary's verdict provenance — plane
// + which variant — derives from the same entry).
type MatchResult struct {
	// Matched is true iff the candidate's keyed-truncated hash is in the set.
	Matched bool
	// CredClass of the matched entry (ISSUED{service_id} | FORBIDDEN), nil on no
	// match. A FORBIDDEN match is the canary-never-egresses block; an ISSUED
	// match to the wrong service is the wrong-destination event (doc 14 §7).
	CredClass *identityv1.DigestCredClass
	// Scope of the matched entry, or UNSPECIFIED on no match.
	Scope identityv1.DigestScope
	// VariantTag of the matched entry — which encoding fired (RAW/BASE64/…),
	// UNSPECIFIED on no match.
	VariantTag identityv1.DigestVariantTag
}

// Matcher is the producer-side reference matcher. It is keyed by the same
// per-host per-epoch HMAC key the producer used; only entries sharing this
// matcher's key id are considered (a digest under a rotated-out key never
// matches here, mirroring the boundary's per-key-id selection, doc 16 §6.3).
//
// Entries are indexed by hex(truncLen | digest) so lookup is O(1) per candidate
// and a one-byte truncation-length difference can never alias two digests.
type Matcher struct {
	keyID string
	key   []byte
	set   map[string]*identityv1.DigestEntry
}

// NewMatcher builds a matcher for one key epoch. It mirrors a boundary that has
// loaded the HMAC key id keyID with material key. Fail-closed on missing
// material: a matcher with no key can match nothing and would silently pass
// every secret.
func NewMatcher(keyID string, key []byte) (*Matcher, error) {
	if len(key) == 0 {
		return nil, ErrNoKey
	}
	if keyID == "" {
		return nil, ErrNoKeyID
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Matcher{keyID: keyID, key: k, set: make(map[string]*identityv1.DigestEntry)}, nil
}

// MatcherFromProducer builds a matcher loaded with the SAME key id + material a
// Producer holds — the producer/consumer pair sharing one boundary key. This is
// the matchability-proof constructor: a test mints with the Producer and matches
// with the Matcher from this call, exactly as the real producer (trust zone) and
// boundary (host) share a key out of band.
func MatcherFromProducer(p *Producer) (*Matcher, error) {
	return NewMatcher(p.keyID, p.key)
}

// Load registers a batch of pushed DigestEntry values (the bytes the boundary
// received over DigestPublish). Entries under a different key id than this
// matcher holds are skipped (per-key-id selection); entries with no digest bytes
// are skipped (nothing to match). Returns the number of entries indexed.
func (m *Matcher) Load(entries []*identityv1.DigestEntry) int {
	n := 0
	for _, e := range entries {
		if e.GetKeyId() != m.keyID {
			continue
		}
		if len(e.GetDigest()) == 0 {
			continue
		}
		m.set[indexKey(e.GetAlgo().GetTruncationLenBytes(), e.GetDigest())] = e
		n++
	}
	return n
}

// Len reports how many digests are loaded.
func (m *Matcher) Len() int { return len(m.set) }

// Match answers whether the candidate raw wire bytes match any loaded digest.
// It computes the truncated keyed hash of the candidate at EACH truncation
// length present in the loaded set and tests membership — so a matcher loaded
// with mixed truncation lengths (e.g. across a re-key) still matches correctly.
// Decode-free by design (see the file header).
func (m *Matcher) Match(candidate []byte) MatchResult {
	for _, trunc := range m.truncLens() {
		sum := m.hashTrunc(candidate, trunc)
		if e, ok := m.set[indexKey(trunc, sum)]; ok {
			return MatchResult{
				Matched:    true,
				CredClass:  e.GetCredClass(),
				Scope:      e.GetScope(),
				VariantTag: e.GetVariantTag(),
			}
		}
	}
	return MatchResult{Matched: false}
}

// hashTrunc computes trunc( HMAC-SHA-256(key, candidate) ) — the exact predicate
// the producer used on the encoded plaintext, applied here to the raw candidate.
func (m *Matcher) hashTrunc(candidate []byte, trunc uint32) []byte {
	mac := hmac.New(sha256.New, m.key)
	mac.Write(candidate)
	full := mac.Sum(nil)
	if int(trunc) > len(full) {
		trunc = uint32(len(full))
	}
	out := make([]byte, trunc)
	copy(out, full[:trunc])
	return out
}

// truncLens returns the distinct truncation lengths across the loaded set. Small
// (one or two values in practice) so a linear scan to collect them is cheap; it
// avoids assuming a single global truncation length.
func (m *Matcher) truncLens() []uint32 {
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, e := range m.set {
		t := e.GetAlgo().GetTruncationLenBytes()
		if t == 0 {
			t = uint32(len(e.GetDigest()))
		}
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// indexKey is the set key: the truncation length (so a 16-byte and a would-be
// 8-byte digest of the same prefix never alias) joined to the hex digest.
func indexKey(trunc uint32, digest []byte) string {
	return itoa(int(trunc)) + ":" + hex.EncodeToString(digest)
}
