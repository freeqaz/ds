// SPDX-License-Identifier: Apache-2.0
//
// attach_digest.go — the ATTACH-SEAM keyed-secret-digest matcher consumer
// wiring (D73 residual; doc 20 §4 canary row; doc 12 §10).
//
// THE RESIDUAL THIS LANE COVERS. The keyed secret-egress plane catches a
// planted or known credential at first egress on INSPECTED paths through
// ds-tlsproxy (doc 12 §5.3, the "canary never egresses" (c) assertion). But a
// user-PASTED token entering via the client wrapper → CC stdin NEVER traverses
// the proxy — the wrapper's Driver writes it straight onto the session's stdin.
// Doc 20 §4's canary row names exactly this gap: "the attach-seam matcher
// consumer (user-pasted tokens entering via client wrapper → CC stdin, which
// never traverses ds-tlsproxy) is a tracked follow-on owned by Attach & client."
//
// This file is the canary-side WIRING of that consumer. It builds a keyed digest
// feed in the SAME frozen shape ds-tlsproxy consumes (identity.v1.DigestEntry —
// HMAC-SHA-256-truncated digests over each encoded variant, tagged
// ISSUED{service_id} | FORBIDDEN, doc 14 §7) from a planted synthetic canary,
// hands it to the wrapper's AttachDigestMatcher, and exposes a helper the
// canary's planted-canary stdin-entry test variant drives. It does NOT invent a
// new feed contract — it reuses the one the proxy plane already consumes (the
// doc-20 acceptance pin).
//
// NEVER-LOG-THE-SECRET (D73). The producer side computes digests inside the D39
// trust zone; here, for the SYNTHETIC fixture (D50), this lane plays the
// producer with a made-up canary and a made-up HMAC key — but the matcher
// itself never receives the plaintext digest of anything: it is handed the
// feed's digest BYTES and computes the candidate's keyed hash itself. The match
// event the matcher returns is fingerprint-class only. The test asserts the
// planted canary substring appears in zero bytes of any emitted log/event/spool.

package canary

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// AttachDigestFeed is a synthetic, fully-built keyed digest feed plus the HMAC
// key parameters needed to drive the wrapper's AttachDigestMatcher — the
// canary-side analogue of the digest set the producer pushes to the boundary
// host (doc 14 §7). It is the matcher-consumer wiring fixture: a planted-canary
// stdin-entry test constructs one of these and asserts the matcher events the
// pasted canary without leaking it.
//
// SYNTHETIC ONLY (D50): KeyID/HMACKey/Canary are made-up markers, never real
// provider token shapes — the canary lane plays the off-host producer in-process
// so no real credential or network is involved.
type AttachDigestFeed struct {
	// KeyID is the id of the (synthetic) HMAC key the entries were minted under.
	KeyID string
	// HMACKey is the (synthetic) per-host per-epoch HMAC key (doc 16 §6.3).
	HMACKey []byte
	// TruncLen is the truncation length (bytes) applied to the keyed hash —
	// producer and matcher agree on it (DigestAlgo.truncation_len_bytes).
	TruncLen int
	// DigestSetVersion is the non-policy digest-set version stamped for
	// attribution (doc 14 §7).
	DigestSetVersion string
	// Entries is the frozen identity.v1.DigestEntry set — one entry per
	// (credential × encoding variant), exactly the shape ds-tlsproxy consumes.
	Entries []*identityv1.DigestEntry
}

// attachCanaryTruncLen is the Stage-0 truncation length for the synthetic canary
// feed. 16 bytes keeps the false-positive rate ≈ 0 at fixture scale while
// exercising the truncation-agreement contract (doc 16 §6.3).
const attachCanaryTruncLen = 16

// allAttachVariants is the encoding set the producer mints one entry per — the
// same variants the proxy plane carries so a base64'd / url-encoded / hex'd
// paste matches as readily as the raw bytes (doc 14 §7).
var allAttachVariants = []identityv1.DigestVariantTag{
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX,
}

// BuildAttachCanaryFeed plays the off-host producer for the SYNTHETIC canary
// `secret`: it computes the keyed-hash digest of the secret under EVERY encoding
// variant and emits one frozen identity.v1.DigestEntry per variant, all under
// the same key id / class / scope / expiry — the exact entry-set shape doc 14 §7
// freezes and the proxy plane consumes. `serviceID` non-empty mints the ISSUED
// class (tagged with that service); empty mints the FORBIDDEN class (a guarded
// credential — the doc 06 (c) "canary never egresses" anchor).
//
// This is the matcher-consumer WIRING: feed these Entries to
// claudecode.NewAttachDigestMatcher and the matcher will recognize a paste of
// `secret` (in any of these encodings) on the attach/stdin path. The plaintext
// `secret` is used ONLY to compute the digests here (the producer's job); it is
// not stored on the returned feed.
func BuildAttachCanaryFeed(keyID string, hmacKey []byte, secret []byte, serviceID, digestSetVersion string) AttachDigestFeed {
	var entries []*identityv1.DigestEntry
	for _, variant := range allAttachVariants {
		encoded := encodeAttachVariant(secret, variant)
		entries = append(entries, &identityv1.DigestEntry{
			KeyId: keyID,
			Algo: &identityv1.DigestAlgo{
				Family:             identityv1.DigestAlgo_FAMILY_HMAC_SHA256,
				TruncationLenBytes: attachCanaryTruncLen,
			},
			Digest:    keyedTruncatedDigest(hmacKey, encoded, attachCanaryTruncLen),
			CredClass: attachCredClass(serviceID),
			Scope:     identityv1.DigestScope_DIGEST_SCOPE_SESSION,
			// Expiry left nil: the matcher loads entries by key/algo/variant and
			// does not gate on expiry (the boundary host ages entries out via the
			// teardown-flush invariant, doc 14 §7 — not the matcher's concern).
			VariantTag: variant,
		})
	}
	return AttachDigestFeed{
		KeyID:            keyID,
		HMACKey:          append([]byte(nil), hmacKey...),
		TruncLen:         attachCanaryTruncLen,
		DigestSetVersion: digestSetVersion,
		Entries:          entries,
	}
}

// attachCredClass mints the ISSUED{service_id} class when serviceID is non-empty,
// else the FORBIDDEN class (no payload — its presence is the signal, doc 14 §7).
func attachCredClass(serviceID string) *identityv1.DigestCredClass {
	if serviceID != "" {
		return &identityv1.DigestCredClass{
			Class: &identityv1.DigestCredClass_Issued_{
				Issued: &identityv1.DigestCredClass_Issued{ServiceId: serviceID},
			},
		}
	}
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Forbidden_{
			Forbidden: &identityv1.DigestCredClass_Forbidden{},
		},
	}
}

// encodeAttachVariant re-encodes `b` under one variant tag — the PRODUCER-side
// encoding. The producer pre-encodes, minting one digest per variant; the
// matcher then tests a candidate token AS-IS (it does NOT re-encode), so a
// secret pasted in this encoding hashes to the entry minted here (doc 14 §7).
func encodeAttachVariant(b []byte, variant identityv1.DigestVariantTag) []byte {
	switch variant {
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64:
		return []byte(base64.StdEncoding.EncodeToString(b))
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC:
		return []byte(url.QueryEscape(string(b)))
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX:
		return []byte(hex.EncodeToString(b))
	default: // RAW (and any unspecified, defensively): the bytes as-is.
		return b
	}
}

// keyedTruncatedDigest is the producer's keyed-hash derivation: HMAC-SHA-256 of
// `b` under `key`, truncated to `truncLen` bytes (doc 14 §7). It MUST match the
// matcher's candidate-side derivation for membership to test true.
func keyedTruncatedDigest(key, b []byte, truncLen int) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	sum := mac.Sum(nil)
	out := make([]byte, truncLen)
	copy(out, sum[:truncLen])
	return out
}
