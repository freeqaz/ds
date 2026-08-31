// SPDX-License-Identifier: Apache-2.0

// Producer correctness: the keyed HMAC digest of every encoding variant is the
// value an INDEPENDENT computation (recomputed here from the documented formula,
// not from the producer's own code path) yields. SYNTHETIC ONLY (D50): every
// secret is a `ds-synth-*` value under a synthetic key.
package digest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// synthKeyID / synthKey are the synthetic per-host per-epoch material used
// throughout the tests (D50 — never a real HMAC key).
const synthKeyID = "ds-synth-key-epoch-0001"

var synthKey = []byte("ds-synth-hmac-key-0000000000000000")

// refDigest independently recomputes trunc( HMAC-SHA-256(key, encoded) ) using
// the documented encoding for each variant, with NO call into producer/variant
// code — so a bug in encodeVariant cannot make the producer agree with itself.
func refDigest(t *testing.T, key, plaintext []byte, variant identityv1.DigestVariantTag, trunc int) []byte {
	t.Helper()
	var encoded []byte
	switch variant {
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW:
		encoded = plaintext
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64:
		encoded = []byte(base64.StdEncoding.EncodeToString(plaintext))
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC:
		encoded = []byte(refURLEncodeAll(plaintext))
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX:
		encoded = []byte(hex.EncodeToString(plaintext))
	default:
		t.Fatalf("ref: unproducible variant %v", variant)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(encoded)
	return mac.Sum(nil)[:trunc]
}

// refURLEncodeAll is an independent percent-encoder (encode every non-unreserved
// byte) used by the reference path, written separately from urlEncodeAll.
func refURLEncodeAll(b []byte) string {
	const hexdig = "0123456789ABCDEF"
	var sb bytes.Buffer
	for _, c := range b {
		isUnreserved := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
		if isUnreserved {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hexdig[c>>4])
		sb.WriteByte(hexdig[c&0x0f])
	}
	return sb.String()
}

func TestProducerComputesAllFourEncodings(t *testing.T) {
	const trunc = DefaultTruncationLenBytes
	prod, err := NewProducer(synthKeyID, synthKey, trunc)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	// A secret with bytes that exercise every encoder: letters, digits, and
	// reserved bytes (/, +, =, space) that url-encoding must escape.
	secret := []byte("ds-synth-pat_AB+cd/=ef 12")
	cred := Credential{
		Plaintext: secret,
		CredClass: Issued("github"),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		Expiry:    time.Now().Add(15 * time.Minute),
	}
	entries, err := prod.Entries(cred)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4 (RAW/BASE64/URLENC/HEX)", len(entries))
	}

	seen := map[identityv1.DigestVariantTag]bool{}
	for _, e := range entries {
		// Shared fields identical across variants.
		if e.GetKeyId() != synthKeyID {
			t.Errorf("key id %q, want %q", e.GetKeyId(), synthKeyID)
		}
		if e.GetAlgo().GetFamily() != identityv1.DigestAlgo_FAMILY_HMAC_SHA256 {
			t.Errorf("family %v, want HMAC_SHA256", e.GetAlgo().GetFamily())
		}
		if e.GetAlgo().GetTruncationLenBytes() != trunc {
			t.Errorf("trunc %d, want %d", e.GetAlgo().GetTruncationLenBytes(), trunc)
		}
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Errorf("scope %v, want SESSION", e.GetScope())
		}
		if e.GetCredClass().GetIssued().GetServiceId() != "github" {
			t.Errorf("service id %q, want github", e.GetCredClass().GetIssued().GetServiceId())
		}
		// Digest matches the independent recomputation.
		want := refDigest(t, synthKey, secret, e.GetVariantTag(), trunc)
		if !bytes.Equal(e.GetDigest(), want) {
			t.Errorf("variant %v: digest %x, want %x", e.GetVariantTag(), e.GetDigest(), want)
		}
		if len(e.GetDigest()) != trunc {
			t.Errorf("variant %v: digest len %d, want %d", e.GetVariantTag(), len(e.GetDigest()), trunc)
		}
		seen[e.GetVariantTag()] = true
	}
	for _, v := range AllVariants {
		if !seen[v] {
			t.Errorf("missing variant %v", v)
		}
	}
	// PLAINTEXT NEVER CROSSES: no entry's bytes contain the raw secret.
	for _, e := range entries {
		if bytes.Contains(e.GetDigest(), secret) {
			t.Fatalf("variant %v: plaintext leaked into digest", e.GetVariantTag())
		}
	}
}

func TestVariantDigestsAreDistinct(t *testing.T) {
	prod, err := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	// A secret containing RESERVED bytes (/, +, =, space) so its RAW, BASE64,
	// URLENC, and HEX forms are all genuinely different byte strings — and thus
	// all four digests differ. (A secret of only unreserved chars would have
	// RAW == URLENC by construction; that aliasing is correct producer behavior,
	// covered by TestUnreservedSecretRawEqualsUrlenc.)
	entries, err := prod.Entries(Credential{
		Plaintext: []byte("ds/synth+distinct=secret 42"),
		CredClass: Forbidden(),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	digests := map[string]identityv1.DigestVariantTag{}
	for _, e := range entries {
		k := hex.EncodeToString(e.GetDigest())
		if prev, ok := digests[k]; ok {
			t.Fatalf("variants %v and %v produced the same digest", prev, e.GetVariantTag())
		}
		digests[k] = e.GetVariantTag()
	}
}

// TestUnreservedSecretRawEqualsUrlenc documents the (correct) aliasing: a secret
// whose bytes are all RFC 3986 unreserved characters has an identical RAW and
// URLENC on-the-wire form, so their digests coincide. The matcher still matches
// such a secret (one digest serves both forms); this is not a bug, it is the
// definition of url-encoding.
func TestUnreservedSecretRawEqualsUrlenc(t *testing.T) {
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	secret := []byte("ds-synth-unreserved-only-42") // no reserved bytes
	entries, err := prod.Entries(Credential{
		Plaintext: secret,
		CredClass: Forbidden(),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	var raw, urlenc []byte
	for _, e := range entries {
		switch e.GetVariantTag() {
		case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW:
			raw = e.GetDigest()
		case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC:
			urlenc = e.GetDigest()
		}
	}
	if !bytes.Equal(raw, urlenc) {
		t.Errorf("unreserved-only secret: RAW digest %x != URLENC digest %x (expected equal)", raw, urlenc)
	}
}

func TestProducerFailClosed(t *testing.T) {
	if _, err := NewProducer(synthKeyID, nil, 16); err != ErrNoKey {
		t.Errorf("empty key: err=%v, want ErrNoKey", err)
	}
	if _, err := NewProducer("", synthKey, 16); err != ErrNoKeyID {
		t.Errorf("empty key id: err=%v, want ErrNoKeyID", err)
	}
	if _, err := NewProducer(synthKeyID, synthKey, 4); err != ErrTruncTooShort {
		t.Errorf("trunc=4: err=%v, want ErrTruncTooShort", err)
	}
	// Above the 32-byte HMAC-SHA-256 width is rejected at construction — never
	// allowed to construct a producer that panics (full[:truncLen] out of range)
	// the first time it digests. The full width (32) is the boundary and legal.
	if _, err := NewProducer(synthKeyID, synthKey, 33); err != ErrTruncTooLong {
		t.Errorf("trunc=33: err=%v, want ErrTruncTooLong", err)
	}
	if p32, err := NewProducer(synthKeyID, synthKey, 32); err != nil {
		t.Errorf("trunc=32 (full width): err=%v, want nil", err)
	} else if _, err := p32.Entries(Credential{Plaintext: []byte("ds-synth-x"), CredClass: Issued("svc")}); err != nil {
		t.Errorf("trunc=32 Entries: unexpected err=%v (must not panic/error at full width)", err)
	}
	prod, err := NewProducer(synthKeyID, synthKey, 0) // 0 ⇒ default
	if err != nil {
		t.Fatalf("trunc=0 (default): %v", err)
	}
	if prod.TruncationLenBytes() != DefaultTruncationLenBytes {
		t.Errorf("default trunc = %d, want %d", prod.TruncationLenBytes(), DefaultTruncationLenBytes)
	}
	// Empty plaintext and missing class fail closed with no entries.
	if _, err := prod.Entries(Credential{Plaintext: nil, CredClass: Issued("svc")}); err == nil {
		t.Error("empty plaintext: want error")
	}
	if _, err := prod.Entries(Credential{Plaintext: []byte("x"), CredClass: nil}); err == nil {
		t.Error("nil cred class: want error")
	}
}

func TestBatchEntriesConcatenatesAndFailsClosed(t *testing.T) {
	prod, err := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	creds := []Credential{
		{Plaintext: []byte("ds-synth-a"), CredClass: Issued("github"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION},
		{Plaintext: []byte("ds-synth-b"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION},
	}
	es, err := prod.BatchEntries(creds)
	if err != nil {
		t.Fatalf("BatchEntries: %v", err)
	}
	if len(es) != 2*len(AllVariants) {
		t.Fatalf("batch entries %d, want %d", len(es), 2*len(AllVariants))
	}
	// One bad credential fails the whole batch (no partially-shadowed session).
	bad := append([]Credential(nil), creds...)
	bad = append(bad, Credential{Plaintext: nil, CredClass: Issued("x")})
	if _, err := prod.BatchEntries(bad); err == nil {
		t.Error("batch with a bad credential: want error (fail-closed)")
	}
}
