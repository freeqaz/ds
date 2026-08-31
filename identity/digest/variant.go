// SPDX-License-Identifier: Apache-2.0

// Encoding variants (doc 14 §7: variant_tag RAW | BASE64 | URLENC | HEX).
//
// The producer pushes ONE digest per encoding the credential could appear as on
// the wire, so the boundary SecretMatcher blocks a base64'd or url-encoded
// secret as readily as the raw bytes WITHOUT decoding candidate spans. The
// design is symmetric and decode-free on the consumer side:
//
//	producer digest(variant) = trunc( HMAC-SHA-256(key, ENCODE_variant(plaintext)) )
//	matcher candidate-hash    = trunc( HMAC-SHA-256(key, RAW_WIRE_BYTES) )
//
// A secret that hits the wire base64-encoded IS exactly ENCODE_BASE64(plaintext)
// as bytes, so the matcher's hash of those raw wire bytes equals the producer's
// BASE64-variant digest. The matcher therefore never decodes — it only hashes
// the bytes it sees and tests set membership. This file owns the ENCODE side;
// the matcher (matcher.go) owns the candidate-hash side; they meet at the byte
// representation each variant defines.
package digest

import (
	"encoding/base64"
	"encoding/hex"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// AllVariants is the canonical RAW|BASE64|URLENC|HEX set the producer emits for
// every credential (doc 14 §7). UNSPECIFIED is never produced — it is the
// proto-3 zero value and a producer that emitted it would push an
// un-disambiguated digest, so it is excluded by construction.
var AllVariants = []identityv1.DigestVariantTag{
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC,
	identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX,
}

// encodeVariant returns the byte representation a credential takes on the wire
// under the given variant — the exact bytes the producer HMACs and the exact
// bytes the matcher would see and HMAC. ok is false for UNSPECIFIED (and any
// unknown tag): a producer must never emit a digest for an undisambiguated
// encoding.
//
// Encoding choices, each the form the secret most plausibly appears as on the
// wire:
//   - RAW:    the plaintext bytes verbatim (Authorization: token <raw>, query
//     params, JSON string bodies).
//   - BASE64: STANDARD base64 (RFC 4648, with `+` `/` and `=` padding) — the
//     HTTP Basic-auth form and the common config/secret-blob encoding.
//   - URLENC: percent-encoding of every byte that is not an RFC 3986 unreserved
//     character (form-encoded bodies / query strings). Encoding EVERY reserved
//     byte (rather than the minimal set) is the conservative producer choice:
//     it matches the most aggressive url-encoder a client might use, and a
//     client that under-encodes leaves more RAW-matchable bytes, not fewer.
//   - HEX:    lowercase hex (token blobs, hex-encoded keys). Lowercase is the
//     produced form; an upper-case hex secret is its own distinct plaintext and
//     would be registered separately if it were a real credential.
func encodeVariant(plaintext []byte, variant identityv1.DigestVariantTag) (encoded []byte, ok bool) {
	switch variant {
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW:
		return plaintext, true
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(plaintext)))
		base64.StdEncoding.Encode(out, plaintext)
		return out, true
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC:
		return urlEncodeAll(plaintext), true
	case identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX:
		out := make([]byte, hex.EncodedLen(len(plaintext)))
		hex.Encode(out, plaintext)
		return out, true
	default:
		return nil, false
	}
}

// urlEncodeAll percent-encodes every byte that is not an RFC 3986 *unreserved*
// character (ALPHA / DIGIT / "-" / "." / "_" / "~"). We deliberately do NOT use
// net/url, whose QueryEscape leaves several sub-delims and `+`-for-space
// substitution in place — those forms vary by client and would split one
// on-the-wire encoding into several. Encoding maximally yields one canonical
// URLENC form per secret; the matcher hashes the wire bytes as-is, so the
// canonical form is what must match.
func urlEncodeAll(plaintext []byte) []byte {
	const upperhex = "0123456789ABCDEF"
	out := make([]byte, 0, len(plaintext)*3)
	for _, c := range plaintext {
		if unreserved(c) {
			out = append(out, c)
			continue
		}
		out = append(out, '%', upperhex[c>>4], upperhex[c&0x0f])
	}
	return out
}

// unreserved reports whether c is an RFC 3986 unreserved character (never
// percent-encoded).
func unreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}
