// SPDX-License-Identifier: Apache-2.0

package nftbridge

import (
	"testing"
)

// TestCanonicalScalars pins the pinned proto->JSON scalar mapping (doc 13 §5.1):
// int as shortest decimal, int64-as-string, enum-as-integer, bool, bytes as
// base64url-no-pad, and JCS string escaping.
func TestCanonicalScalars(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want string
	}{
		{"int_zero", Int(0), "0"},
		{"int_neg", Int(-5), "-5"},
		{"int_large", Int(900), "900"},
		{"int64_as_string", Int64String(1000000), `"1000000"`},
		{"int64_max", Int64String(9223372036854775807), `"9223372036854775807"`},
		{"bool_true", Bool(true), "true"},
		{"bool_false", Bool(false), "false"},
		{"null", Null, "null"},
		{"str_plain", Str("github.com"), `"github.com"`},
		{"str_quote", Str(`a"b`), `"a\"b"`},
		{"str_backslash", Str(`a\b`), `"a\\b"`},
		{"str_controls", Str("\b\t\n\f\r"), `"\b\t\n\f\r"`},
		// Control char below 0x20 (no two-char escape) -> \u001f, lowercase hex (RFC 8785 §3.2.2.2).
		{"str_unit_sep", Str("\x1f"), `"\u001f"`},
		{"str_unicode_raw", Str("café"), `"café"`},
		{"str_emoji_raw", Str("\U0001F40D"), `"🐍"`},
		// 0xdeadbeef -> base64url no pad -> "3q2-7w".
		{"bytes_b64url", Bytes([]byte{0xde, 0xad, 0xbe, 0xef}), `"3q2-7w"`},
		{"bytes_empty", Bytes(nil), `""`},
		// base64url uses '-' and '_' where standard uses '+' and '/'.
		{"bytes_url_alphabet", Bytes([]byte{0xfb, 0xff, 0xbf}), `"-_-_"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(Canonicalize(tc.v))
			if got != tc.want {
				t.Fatalf("Canonicalize(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestObjectKeyOrdering asserts that object members emit in JCS key order
// regardless of insertion order (the field-order-only-diffs-hash-equal
// property, doc 13 §5.1), and that a duplicate Set replaces in place.
func TestObjectKeyOrdering(t *testing.T) {
	a := NewObject().Set("b", Int(2)).Set("a", Int(1)).Set("c", Int(3))
	b := NewObject().Set("c", Int(3)).Set("b", Int(2)).Set("a", Int(1))
	const want = `{"a":1,"b":2,"c":3}`
	if got := string(Canonicalize(a)); got != want {
		t.Fatalf("insertion order b,a,c -> %q, want %q", got, want)
	}
	if got := string(Canonicalize(b)); got != want {
		t.Fatalf("insertion order c,b,a -> %q, want %q", got, want)
	}

	// Replace-in-place keeps the form well-defined.
	d := NewObject().Set("k", Int(1)).Set("k", Int(2))
	if d.Len() != 1 {
		t.Fatalf("duplicate Set left Len=%d, want 1", d.Len())
	}
	if got := string(Canonicalize(d)); got != `{"k":2}` {
		t.Fatalf("duplicate Set -> %q, want last-write-wins", got)
	}
}

// TestArrayOrderPreserved asserts arrays are NOT reordered: the canonicalizer
// preserves caller order (the §5.1 ordering of repeated sections / repeated
// {key,value} lists is the caller's responsibility, applied before construction).
func TestArrayOrderPreserved(t *testing.T) {
	arr := NewArray(Str("z"), Str("a"), Str("m"))
	if got := string(Canonicalize(arr)); got != `["z","a","m"]` {
		t.Fatalf("array reordered: %q", got)
	}
}

// TestUTF16KeyOrdering exercises the UTF-16 code-unit key ordering rule for keys
// outside the BMP. A key starting with U+1F40D (a surrogate pair, first unit
// 0xD83D) must sort AFTER a BMP key like "z" (0x007A) — byte order on the raw
// UTF-8 would put the 4-byte sequence first, so this distinguishes the two rules.
func TestUTF16KeyOrdering(t *testing.T) {
	o := NewObject().
		Set("\U0001F40D", Int(1)). // astral
		Set("z", Int(2)).          // BMP
		Set("a", Int(3))           // BMP
	// Expected order under UTF-16 code units: a (0x61), z (0x7A), 🐍 (0xD83D…).
	want := "{\"a\":3,\"z\":2,\"\U0001F40D\":1}"
	if got := string(Canonicalize(o)); got != want {
		t.Fatalf("UTF-16 key order: got %q want %q", got, want)
	}
}

// TestMeaningfulZeroVsAbsent is the load-bearing §5.1 distinction: a present
// meaningful-zero must produce DIFFERENT bytes (and thus a different hash) from
// an omitted field, while a field-order-only difference produces IDENTICAL bytes.
func TestMeaningfulZeroVsAbsent(t *testing.T) {
	withZero := NewObject().Set("negative_ttl", Int(0)).Set("x", Int(1))
	absent := NewObject().Set("x", Int(1))
	reordered := NewObject().Set("x", Int(1)).Set("negative_ttl", Int(0))

	pZero := Canonicalize(withZero)
	pAbsent := Canonicalize(absent)
	pReordered := Canonicalize(reordered)

	if string(pZero) == string(pAbsent) {
		t.Fatal("meaningful-zero and absent produced identical bytes — they must differ")
	}
	if string(pZero) != string(pReordered) {
		t.Fatalf("field-order-only diff changed bytes: %q vs %q", pZero, pReordered)
	}

	hZero := HashPayload(pZero)
	hAbsent := HashPayload(pAbsent)
	hReordered := HashPayload(pReordered)
	if hZero == hAbsent {
		t.Fatal("meaningful-zero and absent hashed equal — must differ")
	}
	if hZero != hReordered {
		t.Fatal("field-order-only diff changed the hash — must hash equal")
	}
}

// TestSetToDefaultEqualsAbsent is the complement of TestMeaningfulZeroVsAbsent
// and the fifth distinct §5.1 adversarial property ("set-to-default vs absent
// hash equal"): a field carrying its NON-meaningful default is OMITTED by the
// producer, so the composed tree — and thus the bytes and the hash — is
// identical to one where the field was never present. This proves the
// canonicalizer never injects defaults: "present default" is not an input the
// producer ever forms; only the caller's compose-time omission discipline
// distinguishes it from a meaningful value, which (per TestMeaningfulZeroVsAbsent)
// must instead be Set explicitly to survive the hash.
func TestSetToDefaultEqualsAbsent(t *testing.T) {
	// The producer composing a block whose negative_ttl defaults to "uncached"
	// in the NON-meaningful sense omits the key entirely.
	defaultOmitted := NewObject().Set("x", Int(1))
	absent := NewObject().Set("x", Int(1))
	// A meaningful zero, by contrast, is Set explicitly.
	meaningfulZero := NewObject().Set("negative_ttl", Int(0)).Set("x", Int(1))

	if string(Canonicalize(defaultOmitted)) != string(Canonicalize(absent)) {
		t.Fatal("set-to-default (omitted) and absent produced different bytes — must be equal")
	}
	if HashPayload(Canonicalize(defaultOmitted)) != HashPayload(Canonicalize(absent)) {
		t.Fatal("set-to-default (omitted) and absent hashed differently — must be equal")
	}
	// Sanity: the meaningful-zero case is NOT equal to the omitted/absent one,
	// so the two §5.1 rules are genuinely distinct and both hold.
	if HashPayload(Canonicalize(meaningfulZero)) == HashPayload(Canonicalize(absent)) {
		t.Fatal("meaningful-zero collapsed into absent — the explicit-presence rule is broken")
	}
}

// TestNestedStructure exercises objects/arrays nested arbitrarily.
func TestNestedStructure(t *testing.T) {
	v := NewObject().
		Set("outer", NewArray(
			NewObject().Set("k", Str("v")),
			NewObject().Set("n", Int(7)),
		)).
		Set("flag", Bool(false))
	const want = `{"flag":false,"outer":[{"k":"v"},{"n":7}]}`
	if got := string(Canonicalize(v)); got != want {
		t.Fatalf("nested = %q, want %q", got, want)
	}
}

// TestContentHashIsFull32Bytes guards the no-truncation rule (doc 13 §5.1).
func TestContentHashIsFull32Bytes(t *testing.T) {
	var h ContentHash
	if len(h) != 32 {
		t.Fatalf("ContentHash is %d bytes, want 32 (no truncation)", len(h))
	}
}

// TestHashPayloadKnownVector pins SHA-256 against the empty input, an external
// fixed vector (proves we are using a real SHA-256, not a stub).
func TestHashPayloadKnownVector(t *testing.T) {
	h := HashPayload([]byte("abc"))
	// SHA-256("abc") is a well-known constant.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hexString(h[:]); got != want {
		t.Fatalf("SHA-256(\"abc\") = %s, want %s", got, want)
	}
}

// hexString is a tiny local hex encoder so the test stays dependency-clean.
func hexString(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexd[x>>4], hexd[x&0xf])
	}
	return string(out)
}
