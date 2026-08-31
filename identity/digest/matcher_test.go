// SPDX-License-Identifier: Apache-2.0

// The matchability proof (round2/08 test 6, doc 16 §6.1): every variant the
// producer pushes is matchable, pre-egress, against its on-the-wire encoded
// form — and ONLY against that form. SYNTHETIC ONLY (D50).
package digest

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// wireForms returns, for a secret, the exact bytes it takes on the wire under
// each variant — produced by an INDEPENDENT encoder (so a matcher built on
// variant.go is proven against forms not derived from variant.go).
func wireForms(secret []byte) map[identityv1.DigestVariantTag][]byte {
	return map[identityv1.DigestVariantTag][]byte{
		identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW:    append([]byte(nil), secret...),
		identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64: []byte(base64.StdEncoding.EncodeToString(secret)),
		identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC: []byte(refURLEncodeAll(secret)),
		identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX:    []byte(hex.EncodeToString(secret)),
	}
}

// TestEveryVariantIsMatchablePreEgress is the core acceptance proof: mint with
// the Producer, load the pushed entries into the Matcher (the boundary's view),
// and confirm each variant's wire form matches — with the correct class +
// variant provenance — before any byte egresses.
func TestEveryVariantIsMatchablePreEgress(t *testing.T) {
	prod, err := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	// A FORBIDDEN canary (the canary-never-egresses anchor, D73) with bytes that
	// exercise base64 padding, url-reserved chars, and hex.
	secret := []byte("ds-synth-canary/AB+cd= 99")
	entries, err := prod.Entries(Credential{
		Plaintext: secret,
		CredClass: Forbidden(),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		Expiry:    time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	matcher, err := MatcherFromProducer(prod)
	if err != nil {
		t.Fatalf("MatcherFromProducer: %v", err)
	}
	if n := matcher.Load(entries); n != 4 {
		t.Fatalf("loaded %d digests, want 4", n)
	}

	forms := wireForms(secret)
	for variant, wire := range forms {
		res := matcher.Match(wire)
		if !res.Matched {
			t.Errorf("variant %v: wire form NOT matched pre-egress (%q)", variant, wire)
			continue
		}
		if res.VariantTag != variant {
			t.Errorf("variant %v: matched as variant %v", variant, res.VariantTag)
		}
		if res.CredClass.GetForbidden() == nil {
			t.Errorf("variant %v: matched class is not FORBIDDEN", variant)
		}
		if res.Scope != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Errorf("variant %v: matched scope %v, want SESSION", variant, res.Scope)
		}
	}
}

func TestNonSecretBytesDoNotMatch(t *testing.T) {
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	entries, _ := prod.Entries(Credential{
		Plaintext: []byte("ds-synth-real-secret"),
		CredClass: Issued("github"),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	m, _ := MatcherFromProducer(prod)
	m.Load(entries)
	for _, benign := range [][]byte{
		[]byte("GET /healthz HTTP/1.1"),
		[]byte("ds-synth-real-secre"),   // one byte short
		[]byte("ds-synth-real-secrets"), // one byte long
		[]byte(""),
		[]byte("Authorization: Bearer not-the-secret"),
	} {
		if res := m.Match(benign); res.Matched {
			t.Errorf("benign candidate matched: %q (variant %v)", benign, res.VariantTag)
		}
	}
}

func TestWrongKeyNeverMatches(t *testing.T) {
	prodA, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	secret := []byte("ds-synth-session-A-secret")
	entries, _ := prodA.Entries(Credential{
		Plaintext: secret,
		CredClass: Issued("github"),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})

	// A matcher under a DIFFERENT key id never indexes producer-A's entries
	// (per-key-id selection, doc 16 §6.3) — proves a rotated-out / cross-session
	// key cannot match (the "session A's material is useless against B" property).
	other, _ := NewMatcher("ds-synth-key-epoch-0002", []byte("ds-synth-other-key-99999999999999"))
	if n := other.Load(entries); n != 0 {
		t.Fatalf("foreign-key matcher indexed %d entries, want 0", n)
	}
	if res := other.Match(secret); res.Matched {
		t.Error("secret matched under a different key id")
	}

	// Same key id but different MATERIAL also never matches (the digest bytes
	// were computed under producer-A's key).
	sameIDdiffKey, _ := NewMatcher(synthKeyID, []byte("ds-synth-WRONG-material-000000000"))
	sameIDdiffKey.Load(entries)
	if res := sameIDdiffKey.Match(secret); res.Matched {
		t.Error("secret matched under same key id but wrong material")
	}
}

func TestMatcherFailClosedConstruction(t *testing.T) {
	if _, err := NewMatcher(synthKeyID, nil); err != ErrNoKey {
		t.Errorf("empty key: err=%v, want ErrNoKey", err)
	}
	if _, err := NewMatcher("", synthKey); err != ErrNoKeyID {
		t.Errorf("empty key id: err=%v, want ErrNoKeyID", err)
	}
}

// TestIssuedWrongDestinationProvenance proves the ISSUED class + service id are
// reported on a match — the input the boundary's wrong-destination decision
// (block+log) is made from (doc 14 §7).
func TestIssuedWrongDestinationProvenance(t *testing.T) {
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	secret := []byte("ds-synth-github-pat-0001")
	entries, _ := prod.Entries(Credential{
		Plaintext: secret,
		CredClass: Issued("github"),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	m, _ := MatcherFromProducer(prod)
	m.Load(entries)
	res := m.Match(secret) // RAW form
	if !res.Matched {
		t.Fatal("issued secret not matched")
	}
	if got := res.CredClass.GetIssued().GetServiceId(); got != "github" {
		t.Errorf("matched service id %q, want github", got)
	}
}

// TestMixedTruncationLengths proves the matcher still works when entries carry
// different truncation lengths (a re-key window where old 16-byte and new
// 12-byte digests coexist).
func TestMixedTruncationLengths(t *testing.T) {
	prod16, _ := NewProducer(synthKeyID, synthKey, 16)
	prod12, _ := NewProducer(synthKeyID, synthKey, 12)
	secret := []byte("ds-synth-mixed-trunc")
	e16, _ := prod16.Entries(Credential{Plaintext: secret, CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION})
	e12, _ := prod12.Entries(Credential{Plaintext: secret, CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION})

	m, _ := NewMatcher(synthKeyID, synthKey)
	m.Load(e16)
	m.Load(e12)
	if res := m.Match(secret); !res.Matched {
		t.Error("RAW secret not matched across mixed truncation lengths")
	}
}
