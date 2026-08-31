// SPDX-License-Identifier: Apache-2.0

// content_hash — SHA-256 over the produce-once canonical payload (doc 13 §5.1,
// D120) and the composite host-document rollup (doc 13 §5 snapshot-identity row,
// D120 / open question 11).
//
// THE FROZEN ANTI-DRIFT RULE (doc 13 §5.1 "Produce-once / verify-only"): the Go
// host agent serializes the composed document EXACTLY ONCE (Canonicalize, in
// canonical.go) and hashes those exact bytes (HashPayload). The Rust consumers
// hash the TRANSPORTED bytes, compare, NACK host-wide on mismatch, then parse —
// they never re-serialize or re-canonicalize. content_hash is the full 32 bytes
// of SHA-256, no truncation (§5.1 "Hash + truncation").
//
// COMPOSITE (doc 13 §5 snapshot-identity composite reading, D120): "full
// composed policy document" is a composite host document — shared system/org
// material plus a repeated per-session section keyed by session_id. Per-section
// sub-hashes are rolled into the host content_hash so a one-session change
// re-hashes one section, not the whole composite. The rollup below is the Go
// producer of that structure; ds-contracts verifies the transported bytes.
package nftbridge

import (
	"crypto/sha256"
	"sort"
)

// ContentHash is the full 32-byte SHA-256 digest that the §5 snapshot-identity
// tuple (seq, content_hash, document) carries. No truncation (§5.1).
type ContentHash [sha256.Size]byte

// HashPayload computes the content_hash of an already-formed canonical payload:
// SHA-256 over the exact transported bytes. This is the one hashing primitive —
// the Go side calls it on bytes from Canonicalize, and the golden fixtures pin
// (payload, content_hash) so the Rust side can verify the same bytes.
func HashPayload(payload []byte) ContentHash {
	return sha256.Sum256(payload)
}

// CanonicalHash is the produce-once convenience: canonicalize v exactly once and
// hash the result. It returns BOTH the payload and its hash because the caller
// (the host agent) must transport the payload bytes verbatim alongside the hash
// — the Rust consumer hashes the payload, not a re-encoding (§5.1 verify-only).
func CanonicalHash(v Value) (payload []byte, hash ContentHash) {
	payload = Canonicalize(v)
	return payload, HashPayload(payload)
}

// SessionSection is one entry of the composite per-session repeated section: a
// session_id and the deny-wins COMPOSED session policy for it (rule §1.2 — the
// composed output, never raw layers). The caller composes Policy into a Value
// tree; the rollup orders sections by SessionID and folds a per-section
// sub-hash into the host content_hash.
type SessionSection struct {
	SessionID string
	Policy    Value
}

// SectionHash is the sub-hash recorded for one per-session section so a
// one-session change re-hashes only that section (§5.1 composite-interaction).
type SectionHash struct {
	SessionID string
	// Payload is the canonical bytes of this section's {session_id, policy}
	// envelope — what HostDocument transports and the Rust side verifies.
	Payload []byte
	// Hash is SHA-256 over Payload, the rolled-up sub-hash.
	Hash ContentHash
}

// HostDocument is the composite snapshot the host transports: the shared
// (system/org) composed material, the ordered per-session sections, the
// per-section sub-hashes, the full canonical payload, and the host content_hash
// computed over that payload. The singular §5 identity tuple is unchanged — one
// seq, one content_hash — and "singular" governs identity, not internal
// cardinality.
type HostDocument struct {
	// Payload is the produce-once canonical bytes of the WHOLE composite
	// document. The host transports these verbatim; the Rust consumer hashes
	// them and compares to ContentHash before parsing.
	Payload []byte
	// ContentHash is SHA-256 over Payload — the §5 identity tuple's hash.
	ContentHash ContentHash
	// Sections are the per-session sub-hashes, ordered by session_id, for
	// incremental re-hashing (§5.1 composite-interaction).
	Sections []SectionHash
}

// session-section envelope field keys. Fixed by this spec, not a per-library
// proto-JSON default (§5.1): a section is the two-member object {session_id,
// policy}; the host document is {sections, shared}.
const (
	keySessionID = "session_id"
	keyPolicy    = "policy"
	keySections  = "sections"
	keyShared    = "shared"
)

// ComposeHostDocument builds the composite host document from the shared
// material and the per-session sections, applying the §5.1 ordering and the
// per-section sub-hash rollup deterministically:
//
//   - sections are ordered by session_id (lexicographic UTF-16, the JCS key
//     rule — for session-id strings this is byte order);
//   - each section is canonicalized as {policy, session_id} and sub-hashed;
//   - the host document is canonicalized as {sections, shared} and hashed.
//
// The host content_hash is taken over the WHOLE document payload (a single
// SHA-256 over the produce-once bytes); the per-section sub-hashes ride
// alongside so a one-session change re-hashes one section, not the whole
// composite. The shared block is omitted from the envelope when nil (absent ==
// omitted, §5.1) — pass a non-nil shared Value when the snapshot carries shared
// material, which the host document always does in practice.
func ComposeHostDocument(shared Value, sections []SessionSection) HostDocument {
	// Order sections by session_id (JCS key order). Copy first so the caller's
	// slice is not mutated.
	ordered := make([]SessionSection, len(sections))
	copy(ordered, sections)
	sort.SliceStable(ordered, func(i, j int) bool {
		return lessUTF16(ordered[i].SessionID, ordered[j].SessionID)
	})

	sectionArr := NewArray()
	subHashes := make([]SectionHash, 0, len(ordered))
	for _, s := range ordered {
		env := NewObject().
			Set(keySessionID, Str(s.SessionID)).
			Set(keyPolicy, s.Policy)
		payload := Canonicalize(env)
		h := HashPayload(payload)
		subHashes = append(subHashes, SectionHash{
			SessionID: s.SessionID,
			Payload:   payload,
			Hash:      h,
		})
		sectionArr.Append(env)
	}

	doc := NewObject().Set(keySections, sectionArr)
	if shared != nil {
		doc.Set(keyShared, shared)
	}
	payload := Canonicalize(doc)
	return HostDocument{
		Payload:     payload,
		ContentHash: HashPayload(payload),
		Sections:    subHashes,
	}
}
