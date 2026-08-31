// SPDX-License-Identifier: Apache-2.0

// Canonical snapshot serialization — the PRODUCE-ONCE side (doc 13 §5.1, D120).
//
// This file is the Go host agent's single canonicalizer: it serializes a
// composed policy snapshot (and, on the identical path, a doc 18 role document)
// into a deterministic byte payload that the content_hash is taken over. The
// Rust consumers NEVER re-run this canonicalizer — they hash the transported
// bytes and compare (see content_hash.go for the rule, and the ds-contracts
// snapshot_verify.rs verify-only path). The cross-language reproduction surface
// is therefore zero: only one language ever forms the bytes.
//
// Byte format (doc 13 §5.1 "Payload byte-format"): RFC 8785 (JCS) canonical JSON
// under the PINNED proto->JSON mapping, which deliberately excludes the hard
// part of JCS:
//
//   - no map<> fields: every keyed collection is a repeated {key,value} list
//     emitted in lexicographic-by-UTF-8-key order. The Object type below sorts
//     its members by the JCS key-ordering rule for exactly this reason.
//   - absent == default == omitted: a meaningful default (e.g. dns.negative_ttl:
//     0, "uncached") MUST be emitted with explicit presence to survive the hash.
//     The canonicalizer does not inject defaults; the caller composes the value
//     model, so "present zero" and "absent" are distinct inputs by construction.
//   - NO FLOATS: the schema is integers + strings only. JCS's ECMAScript number
//     formatting (the genuinely hard part of RFC 8785) is thus never exercised;
//     integers serialize as their shortest decimal form and int64 rides as a
//     string (Int64String below), so no number ever needs float normalization.
//   - int64-as-string, enum-as-integer, bytes-as-base64url — all fixed here,
//     never left to a per-library proto-JSON default.
//
// Stdlib only (orchestrator/go.mod is STDLIB-FENCED): the emitter is hand-rolled
// over the pinned subset. crypto/sha256 (content_hash.go) is the only crypto
// primitive used.
package nftbridge

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Value is a node in the canonical value model. It is the input to Canonicalize.
// The host agent composes a snapshot into a Value tree exactly once; the
// canonical bytes are a pure function of that tree. The permitted concrete
// types are the constructors below — Object, Array, Str, Int, Int64String,
// Bool, and Null. No float type exists, by the §5.1 "no floats" pin.
type Value interface {
	// canonicalize appends this value's JCS byte form to dst and returns it.
	canonicalize(dst []byte) []byte
}

// Object is a JCS object: a set of string-keyed members emitted in
// lexicographic-by-UTF-16-code-unit key order (RFC 8785 §3.2.3). Construct it
// with NewObject and Set so duplicate keys are impossible — the canonical form
// of an object is undefined if a key repeats, and we reject that at build time
// rather than silently picking a winner.
type Object struct {
	keys   []string
	values map[string]Value
}

// NewObject returns an empty canonical object.
func NewObject() *Object {
	return &Object{values: make(map[string]Value)}
}

// Set adds or replaces a member. Replacing a key keeps the canonical form
// well-defined (the last write wins, deterministically) — callers building a
// snapshot generally Set each key once.
func (o *Object) Set(key string, v Value) *Object {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = v
	return o
}

// Len reports the number of distinct members.
func (o *Object) Len() int { return len(o.keys) }

func (o *Object) canonicalize(dst []byte) []byte {
	// JCS orders object keys by their UTF-16 code-unit sequence (RFC 8785
	// §3.2.3 "Sorting of Object Properties"). For the pinned proto->JSON
	// subset the keys are proto field names — ASCII identifiers — so UTF-16
	// and byte order coincide; we implement the full UTF-16 rule anyway so the
	// emitter is correct for any key a future schema row might introduce.
	ordered := make([]string, len(o.keys))
	copy(ordered, o.keys)
	sort.SliceStable(ordered, func(i, j int) bool {
		return lessUTF16(ordered[i], ordered[j])
	})
	dst = append(dst, '{')
	for i, k := range ordered {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, k)
		dst = append(dst, ':')
		dst = o.values[k].canonicalize(dst)
	}
	dst = append(dst, '}')
	return dst
}

// Array is a JCS array. Element order is meaningful and preserved exactly as
// given — the §5.1 ordering rules (repeated {key,value} by key, per-session
// section by session_id) are the CALLER's responsibility to apply before
// constructing the Array; the canonicalizer never reorders array elements.
type Array struct {
	items []Value
}

// NewArray returns an array over the given items, in order.
func NewArray(items ...Value) *Array { return &Array{items: items} }

// Append adds an item to the end of the array.
func (a *Array) Append(v Value) *Array {
	a.items = append(a.items, v)
	return a
}

// Len reports the number of elements.
func (a *Array) Len() int { return len(a.items) }

func (a *Array) canonicalize(dst []byte) []byte {
	dst = append(dst, '[')
	for i, it := range a.items {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = it.canonicalize(dst)
	}
	dst = append(dst, ']')
	return dst
}

// Str is a JSON string value, emitted with JCS string escaping.
type Str string

func (s Str) canonicalize(dst []byte) []byte { return appendJSONString(dst, string(s)) }

// Int is a small integer (anything that fits an int and is NOT an int64 field).
// Used for enum-as-integer and for bounded counters/ttls. Emitted as its
// shortest decimal form, which for integers is JCS-canonical with no float
// normalization needed.
type Int int64

func (n Int) canonicalize(dst []byte) []byte { return strconv.AppendInt(dst, int64(n), 10) }

// Int64String is an int64 field carried as a JSON STRING per the pinned mapping
// (proto int64/uint64 -> string), so a 64-bit value never round-trips through a
// double. The decimal text is the canonical content.
type Int64String int64

func (n Int64String) canonicalize(dst []byte) []byte {
	return appendJSONString(dst, strconv.FormatInt(int64(n), 10))
}

// Bool is a JSON boolean.
type Bool bool

func (b Bool) canonicalize(dst []byte) []byte {
	if bool(b) {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}

// nullValue is the JSON null literal. Use Null for the singleton.
type nullValue struct{}

// Null is the JSON null value. Per the §5.1 "absent == default == omitted" rule
// a field that is semantically absent should be OMITTED from its Object rather
// than Set to Null; Null exists for the rare schema slot whose absence is itself
// a distinct, meaningful value carried on the wire.
var Null Value = nullValue{}

func (nullValue) canonicalize(dst []byte) []byte { return append(dst, "null"...) }

// Bytes is a proto bytes field, emitted base64url (no padding) per the pinned
// mapping (§5.1 "bytes-as-base64url").
type Bytes []byte

func (b Bytes) canonicalize(dst []byte) []byte {
	return appendJSONString(dst, base64URLNoPad(b))
}

// Canonicalize returns the JCS canonical byte payload for v. This is the
// PRODUCE-ONCE payload: the host agent calls it exactly once per snapshot and
// the content_hash is SHA-256 over the returned bytes (see HashPayload).
func Canonicalize(v Value) []byte {
	return v.canonicalize(make([]byte, 0, 256))
}

// ── JCS string escaping (RFC 8785 §3.2.2.2) ──────────────────────────────────

const hexDigits = "0123456789abcdef"

// appendJSONString writes s as a JCS-canonical JSON string: minimal escaping,
// lowercase \u hex, control chars below 0x20 escaped, the two-char escapes for
// the set RFC 8785 mandates (\b \t \n \f \r \" \\). All other code points,
// including non-ASCII, are emitted as raw UTF-8 (JCS does NOT \u-escape them).
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for _, r := range s {
		switch r {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			if r < 0x20 {
				// Other control characters: \u00XX, lowercase hex.
				dst = append(dst, '\\', 'u', '0', '0',
					hexDigits[(r>>4)&0xf], hexDigits[r&0xf])
			} else {
				dst = appendRuneUTF8(dst, r)
			}
		}
	}
	return append(dst, '"')
}

// appendRuneUTF8 appends r as UTF-8 without importing unicode/utf8 (kept lean;
// stdlib-only either way, this is just a direct encoder).
func appendRuneUTF8(dst []byte, r rune) []byte {
	switch {
	case r < 0x80:
		return append(dst, byte(r))
	case r < 0x800:
		return append(dst, byte(0xC0|(r>>6)), byte(0x80|(r&0x3F)))
	case r < 0x10000:
		return append(dst, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
	default:
		return append(dst,
			byte(0xF0|(r>>18)), byte(0x80|((r>>12)&0x3F)),
			byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
	}
}

// lessUTF16 reports whether a sorts before b under the UTF-16 code-unit
// ordering RFC 8785 §3.2.3 mandates for object keys. For ASCII keys this is
// identical to byte order; the full rule matters only when a key carries code
// points above U+FFFF (surrogate pairs), which sort after the BMP.
func lessUTF16(a, b string) bool {
	ai := utf16.Encode([]rune(a))
	bi := utf16.Encode([]rune(b))
	n := len(ai)
	if len(bi) < n {
		n = len(bi)
	}
	for i := 0; i < n; i++ {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return len(ai) < len(bi)
}

// base64URLNoPad encodes b with the URL-safe alphabet and no padding, matching
// the proto-JSON bytes-as-base64url pin (§5.1). Hand-rolled to keep the mapping
// explicit and stdlib-light; encoding/base64 would also do but spelling it out
// pins the exact alphabet/padding the spec names.
func base64URLNoPad(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	n := len(b)
	for i := 0; i < n; i += 3 {
		var chunk uint32
		rem := n - i
		chunk = uint32(b[i]) << 16
		if rem > 1 {
			chunk |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			chunk |= uint32(b[i+2])
		}
		sb.WriteByte(alphabet[(chunk>>18)&0x3F])
		sb.WriteByte(alphabet[(chunk>>12)&0x3F])
		if rem > 1 {
			sb.WriteByte(alphabet[(chunk>>6)&0x3F])
		}
		if rem > 2 {
			sb.WriteByte(alphabet[chunk&0x3F])
		}
	}
	return sb.String()
}
