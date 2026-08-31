// SPDX-License-Identifier: Apache-2.0

// The production secret-digest producer (doc 16 §6; D39/D73/D84).
//
// Replaces the Stage-0 fake (identity/fakes/digest-publisher): given a
// credential's PLAINTEXT — touched only here, inside the D39 secret-store trust
// zone — it computes the keyed HMAC-SHA-256 digest of every encoding variant and
// emits the frozen doc 14 §7 DigestEntry set. The plaintext is consumed,
// digested, and never retained, logged, or returned: only the truncated digest
// bytes leave this process (the "digests, never secrets" contract).
//
// HMAC key lifecycle is Identity's (doc 16 §6.3, the doc 14 OQ7 erratum):
// per-host per-epoch keys, the key id carried so the boundary selects the
// matching key and a live re-key re-pushes every live digest under the new id.
// This file owns the per-credential digest computation; the key/epoch are
// supplied to the Producer by its caller (the host-side key custody is §6.3, not
// this file's concern beyond holding the bytes in the trust zone).
package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultTruncationLenBytes is the Stage-0 truncation applied to the 32-byte
// HMAC-SHA-256 output before it crosses the seam (doc 16 §6.3: chosen to keep
// the false-positive rate ≈ 0 at fleet digest counts). 16 bytes / 128 bits is
// the fake's value (identity/fakes/digest-publisher) — kept identical so the
// production producer and the fake are byte-compatible against one boundary key.
//
// KEY-LIFECYCLE RECONCILIATION (do not relitigate here). 16 is a KEPT-IDENTICAL-
// TO-THE-FAKE default bounded by NewProducer's floor/ceiling (8 ≤ truncLen ≤ 32),
// NOT a value pinned by the doc 16 §6.3 false-positive-vs-fleet-digest-count
// analysis. That analysis — does 128 bits hold ≈0 FP at the real fleet digest
// count, or must the default move — is OPEN under taskdb task
// 01KTWJ4NR0A76YW7SY2CV528AH; this line links it, never duplicates its math. The
// KEY SOURCE (who mints keyID+key per host/epoch and hands it to NewProducer) is
// the KeyManager (keys.go, custody in the D39 trust zone), and the epoch-roll
// re-push rides KeyManager.LiveRekey (rotation.go, RevokeSession-then-republish) —
// see publish.go's PublishSessionWithManager reconciliation note for the
// composition point the orchestrator create-spine now drives.
const DefaultTruncationLenBytes = 16

// minTruncationLenBytes guards against a caller asking for a dangerously short
// digest (a 1-byte digest would collide constantly). 8 bytes / 64 bits is the
// floor; the default is 16.
const minTruncationLenBytes = 8

// hmacSHA256LenBytes is the full HMAC-SHA-256 output width. Truncation can never
// exceed it: a request to truncate to more bytes than the hash produces is a
// misconfiguration, not a longer digest — and slicing full[:truncLen] beyond the
// 32-byte output would panic at digest time. NewProducer rejects it up front
// (fail-closed) rather than constructing a producer that panics on first use.
const hmacSHA256LenBytes = 32

var (
	// ErrNoKey is returned when a Producer is constructed without HMAC key
	// material — fail-closed, never silently produce an unkeyed digest.
	ErrNoKey = errors.New("digest: empty HMAC key (fail-closed)")
	// ErrNoKeyID is returned when a Producer is constructed without a key id —
	// the boundary cannot select the matching key without it (doc 16 §6.3).
	ErrNoKeyID = errors.New("digest: empty key id (fail-closed)")
	// ErrTruncTooShort is returned when the requested truncation is below the
	// floor — too-short digests collide and defeat the ≈0 FP-rate goal.
	ErrTruncTooShort = errors.New("digest: truncation length below the 8-byte floor")
	// ErrTruncTooLong is returned when the requested truncation exceeds the
	// 32-byte HMAC-SHA-256 output — there is no digest material past it, and
	// emitting it would panic at digest time. Fail-closed at construction.
	ErrTruncTooLong = errors.New("digest: truncation length above the 32-byte HMAC-SHA-256 width")
)

// Producer computes keyed HMAC digests for credentials inside the D39 trust
// zone. It holds the per-host per-epoch HMAC key + its id and the truncation
// length, all agreed with the boundary (doc 16 §6.3). It is stateless beyond
// that material and safe for concurrent use: every method derives a fresh
// hmac.Hash per call.
//
// The key bytes live here ONLY because this process runs in the secret-store
// trust zone; a Producer must never be constructed on the virtual-metal host.
type Producer struct {
	keyID    string
	key      []byte
	truncLen uint32
}

// NewProducer builds a Producer for one key epoch. keyID is the per-host
// per-epoch id the boundary uses to select the key; key is the HMAC secret;
// truncLen is the truncated digest length in bytes (0 ⇒ DefaultTruncationLenBytes).
// Fail-closed on missing material so a misconfigured producer never emits an
// unkeyed or unselectable digest.
func NewProducer(keyID string, key []byte, truncLen uint32) (*Producer, error) {
	if len(key) == 0 {
		return nil, ErrNoKey
	}
	if keyID == "" {
		return nil, ErrNoKeyID
	}
	if truncLen == 0 {
		truncLen = DefaultTruncationLenBytes
	}
	if truncLen < minTruncationLenBytes {
		return nil, ErrTruncTooShort
	}
	if truncLen > hmacSHA256LenBytes {
		return nil, ErrTruncTooLong
	}
	// Copy the key so the caller cannot mutate the Producer's material after
	// construction (and so a caller that zeroes its buffer post-mint does not
	// blank our key).
	k := make([]byte, len(key))
	copy(k, key)
	return &Producer{keyID: keyID, key: k, truncLen: truncLen}, nil
}

// NewProducerForEpoch threads a per-host per-epoch KEY through digest production
// (doc 16 §6.3): it derives the epoch's HMAC key from the root and the KeyEpoch
// coordinate (keys.go) and stamps the coordinate's key id on every entry, so the
// boundary selects the matching key. It is the lifecycle-aware constructor — the
// active-key path goes through KeyManager.Producer, which calls this — kept here
// (not a rewrite of NewProducer) so the key/epoch threading lives beside the
// digest computation it parameterizes. The root key never escapes: DeriveKey
// returns fresh material and NewProducer copies it.
func NewProducerForEpoch(rootKey []byte, e KeyEpoch, truncLen uint32) (*Producer, error) {
	if len(rootKey) == 0 {
		return nil, ErrNoRootKey
	}
	if e.HostID == "" {
		return nil, ErrNoHostID
	}
	return NewProducer(e.KeyID(), DeriveKey(rootKey, e), truncLen)
}

// KeyID returns the key id this producer stamps on every entry.
func (p *Producer) KeyID() string { return p.keyID }

// TruncationLenBytes returns the truncation length this producer applies.
func (p *Producer) TruncationLenBytes() uint32 { return p.truncLen }

// digestVariant computes trunc( HMAC-SHA-256(key, ENCODE_variant(plaintext)) ).
// ok is false only for an unproducible variant tag (UNSPECIFIED/unknown).
func (p *Producer) digestVariant(plaintext []byte, variant identityv1.DigestVariantTag) (sum []byte, ok bool) {
	encoded, ok := encodeVariant(plaintext, variant)
	if !ok {
		return nil, false
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write(encoded)
	full := mac.Sum(nil)
	out := make([]byte, p.truncLen)
	copy(out, full[:p.truncLen])
	return out, true
}

// Credential is the per-secret input to digest production. The Plaintext is the
// only credential material in this struct and is consumed (HMACed) but never
// retained by the Producer. CredClass is the doc 14 §7 class (ISSUED{service_id}
// derived from the grant record, or FORBIDDEN for a guarded canary); Scope is
// SESSION (this seam) or FLEET (classification only — fleet rides the policy
// stream, §6.2); Expiry tracks the credential TTL so the boundary ages the
// entry out in lockstep (teardown-flush invariant).
type Credential struct {
	// Plaintext is the secret bytes. Touched only to digest; never stored.
	Plaintext []byte
	// CredClass is ISSUED{service_id} | FORBIDDEN (doc 14 §7).
	CredClass *identityv1.DigestCredClass
	// Scope is SESSION | FLEET (doc 14 §7 / §6.2).
	Scope identityv1.DigestScope
	// Expiry is the absolute entry expiry (tracks the credential TTL).
	Expiry time.Time
}

// Issued builds the ISSUED{service_id} class oneof (a credential Identity minted,
// tagged with its intended service — the tag is DERIVED from the grant record,
// doc 16 §5.1/§6).
func Issued(serviceID string) *identityv1.DigestCredClass {
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Issued_{
			Issued: &identityv1.DigestCredClass_Issued{ServiceId: serviceID},
		},
	}
}

// Forbidden builds the FORBIDDEN class oneof (a credential Identity guards — the
// canary-never-egresses assurance anchor, D73).
func Forbidden() *identityv1.DigestCredClass {
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Forbidden_{
			Forbidden: &identityv1.DigestCredClass_Forbidden{},
		},
	}
}

// Entries computes the full RAW|BASE64|URLENC|HEX DigestEntry set for one
// credential (doc 14 §7: a credential pushed in N encodings yields N entries
// sharing key_id/algo/cred_class/scope/expiry and differing only in
// digest + variant_tag). The credential's plaintext is digested and dropped; the
// returned entries carry NO plaintext (the "plaintext never crosses" invariant
// holds by construction — no field on a DigestEntry carries it).
//
// Fail-closed: an empty plaintext or a missing cred class returns an error and
// NO entries — a session must not be marked routable on a digest set that does
// not actually shadow its credential.
func (p *Producer) Entries(cred Credential) ([]*identityv1.DigestEntry, error) {
	if len(cred.Plaintext) == 0 {
		return nil, errors.New("digest: empty credential plaintext (fail-closed)")
	}
	if cred.CredClass == nil || cred.CredClass.GetClass() == nil {
		return nil, errors.New("digest: missing cred class (fail-closed)")
	}
	algo := &identityv1.DigestAlgo{
		Family:             identityv1.DigestAlgo_FAMILY_HMAC_SHA256,
		TruncationLenBytes: p.truncLen,
	}
	var expiry *timestamppb.Timestamp
	if !cred.Expiry.IsZero() {
		expiry = timestamppb.New(cred.Expiry)
	}
	entries := make([]*identityv1.DigestEntry, 0, len(AllVariants))
	for _, variant := range AllVariants {
		sum, ok := p.digestVariant(cred.Plaintext, variant)
		if !ok {
			// AllVariants holds only producible tags, so this is unreachable;
			// kept fail-closed rather than emitting a bogus entry.
			return nil, errors.New("digest: unproducible variant in AllVariants")
		}
		entries = append(entries, &identityv1.DigestEntry{
			KeyId:      p.keyID,
			Algo:       algo,
			Digest:     sum,
			CredClass:  cred.CredClass,
			Scope:      cred.Scope,
			Expiry:     expiry,
			VariantTag: variant,
		})
	}
	return entries, nil
}

// BatchEntries computes the entry sets for several credentials and concatenates
// them — the shape a session's full digest set takes in one mint-before-attach
// publish (doc 16 §6.1). Fail-closed: any one credential's failure fails the
// whole batch (a partially-shadowed session must not go routable).
func (p *Producer) BatchEntries(creds []Credential) ([]*identityv1.DigestEntry, error) {
	out := make([]*identityv1.DigestEntry, 0, len(creds)*len(AllVariants))
	for i, c := range creds {
		es, err := p.Entries(c)
		if err != nil {
			return nil, errIndexed(i, err)
		}
		out = append(out, es...)
	}
	return out, nil
}

// FleetBatchEntries computes the entry set for a fleet-scope credential set —
// the forbidden-class digests that ride the POLICY stream, not the session
// DigestFeedService (doc 16 §6.2, "two cadences, no third channel", D72). It is
// BatchEntries with one extra guard: every credential MUST already carry
// Scope == DIGEST_SCOPE_FLEET. The guard is here so a fleet re-key can never
// silently emit a session-scope entry onto the policy stream (which would cross
// the two cadences). Fail-closed: a non-fleet (or unspecified) scope, or any
// per-credential digest failure, fails the whole batch and emits NO entries.
//
// It does NOT itself choose a delivery path — the caller (publish.go's
// PublishFleetPolicy) routes the returned entries over the policy-stream sink.
// This keeps the digest computation identical to the session path (reusing
// Entries) and isolates only the scope assertion.
func (p *Producer) FleetBatchEntries(creds []Credential) ([]*identityv1.DigestEntry, error) {
	for i, c := range creds {
		if c.Scope != identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			return nil, errIndexed(i, errors.New("digest: non-fleet scope on the policy-stream path (fail-closed: fleet digests ride policy_log, D72)"))
		}
	}
	return p.BatchEntries(creds)
}

func errIndexed(i int, err error) error {
	return errors.Join(errors.New("digest: credential["+itoa(i)+"]"), err)
}

// itoa avoids pulling strconv for a single small-int format.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
