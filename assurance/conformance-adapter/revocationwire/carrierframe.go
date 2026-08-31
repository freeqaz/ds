// SPDX-License-Identifier: Apache-2.0

package revocationwire

// carrierframe.go promotes two MORE hand-rolled cross-process contracts — both
// currently kept in lock-step across two trees ONLY by byte-identical hand-copied
// literals — into this single conformance fixture, exactly as RungToWireByte already
// single-sources the D53 revocation-delta rung→wire-byte table (doc 11 §5.3, doc 12
// §8.1, D40/D67):
//
//  1. THE WatchPolicies(from_seq) CARRIER FRAME. The host agent's live host-local
//     `WatchPolicies(from_seq)` carrier (Go producer
//     orchestrator/internal/hostagent/dnsfeed_carrier.go `encodeWatchVersion`) serves a
//     length-prefixed version stream the ds-dnsgate consumer (Rust
//     dataplane/services/ds-dnsgate/src/server.rs `WatchPoliciesFrame`) reads. The two
//     halves share NO crate — there is no gRPC/tonic in the dataplane workspace, no FFI,
//     no shared type. A frame-shape divergence (a byte-order flip, a field reorder, a
//     content_hash-width change) surfaces ONLY at live integration. Before this fixture the
//     golden hex lived as a HAND-COPIED literal in BOTH the Go test (dnsfeed_carrier_test.go
//     `carrierGoldenFrameHex`) and the Rust test (server.rs `CARRIER_GOLDEN_FRAME_HEX`);
//     a drift in one tree's copy never broke the other tree's self-consistent suite. This
//     fixture is the ONE artifact both trees pin: it carries the canonical
//     `(seq, content_hash, document)` tuple, the authoritative version-frame BODY bytes the
//     carrier wire contract serialises it to, AND the 8-byte from_seq handshake — each
//     RE-DERIVED here by an INDEPENDENT encoder over the canonical tuple, so a one-byte
//     drift of the golden (in this single source, or copied wrong into a tree) turns this
//     conformance suite RED.
//
//  2. THE caRef-LEAF cross-reader DOMAIN. The orchestrator producer drops a session's
//     interception CA at `ca_<uuid>.pem` (+ the proxy-bound `ca_<uuid>.key.pem`); THREE
//     readers must land on that one leaf — the producer write
//     (controlplane/liveedges.go `ProducerCARefLeaf`), the host-agent cert consumer, and
//     the ds-tlsproxy key/cert consumer (Rust main.rs `session_ca_leaf_stem`). A drift
//     between the producer's `trustpath.Sanitize(caRefFor(uuid))` and the consumer's
//     `sanitize_ca_ref("ca:" + uuid)` is the EXACT bug that fail-closed-panicked the live
//     posture-(b) cred-swap e2e (the producer wrote a file the consumer never found). The
//     golden `(uuid → ca_<uuid>)` rows lived as hand-copied tables in BOTH trees
//     (`CrossReaderCARefVectors` in Go, `CROSS_READER_CAREF_VECTORS` in Rust). This fixture
//     pins those rows once, re-deriving each leaf stem from the canonical uuid by an
//     INDEPENDENT sanitizer that is a byte-for-byte port of both sides' transform, so a
//     `trustpath.Sanitize` / `sanitize_ca_ref` change that drifts EITHER tree turns this
//     conformance suite RED before it can re-introduce the live MISS.
//
// WHY A FIXTURE, NOT A RUNTIME IMPORT (the round-D constraint). Neither tree can import
// this package at runtime: the orchestrator module may import ONLY proto/gen/go cross-tree
// (D80), and the Rust dataplane cannot import a Go package at all. So the single-source
// property is the SAME one RungToWireByte uses: this fixture is the AUTHORITATIVE artifact,
// every value is RE-COMPUTED here from the canonical inputs by an independent codec, and the
// per-tree literal copies are each pinned by their own suite against their own independent
// re-derivation (Go `encodeWatchVersion`, Rust `encode_version`; Go `trustpath.Sanitize`,
// Rust `sanitize_ca_ref`). A real wire/leaf drift can never pass all three because all three
// must reproduce the SAME bytes this fixture freezes.
//
// STDLIB-ONLY, ZERO DEPENDENCIES (the FROZEN-discipline posture the dataplane shares): this
// package mirrors the wire contract, it does not import the Rust crate (it can't), any proto,
// or the orchestrator trustpath package. NEVER-LOG-THE-SECRET (D73): every fixture value is a
// SYNTHETIC conformance string (a distinct-byte seq, a fixed ASCII document, ULID-shaped test
// uuids), never a real policy/secret/PEM byte.

import (
	"crypto/sha256"
	"encoding/binary"
)

// ─── The WatchPolicies carrier-frame golden (the single source both trees pin) ───

// CarrierContentHashLen is the wire content_hash width: a full SHA-256 (32 bytes). A frame
// whose content_hash_len field is a DIFFERENT width is a torn frame both decoders reject
// (Go decodeCarrierVersion, Rust WatchPoliciesFrame::decode_version). It is named (not a bare
// 32) so the width is a single named constant the conformance suite keys on.
const CarrierContentHashLen = sha256.Size

// CarrierGoldenSeq is the fixed u64 seq of the cross-language fixture tuple. The distinct
// bytes (01 02 .. 08) make a byte-order divergence in the 8-byte big-endian seq field visible
// (a little-endian encode would render 08 07 .. 01). IDENTICAL to the Go test's
// carrierGoldenSeq and the Rust test's CARRIER_GOLDEN_SEQ.
const CarrierGoldenSeq uint64 = 0x0102030405060708

// CarrierGoldenDoc is the fixed produce-once transported document (the §5.1 identity tuple's
// document leg). CarrierGoldenContentHash is SHA-256 over EXACTLY these bytes. IDENTICAL to
// both trees' fixtures.
const CarrierGoldenDoc = "ds-watchpolicies-frame-conformance\n"

// CarrierGoldenContentHashHex is the full 32-byte SHA-256 content_hash over CarrierGoldenDoc,
// as 64 lowercase hex chars — the §5.1 content_hash leg. It is the AUTHORITATIVE hash the
// conformance suite re-derives (sha256(CarrierGoldenDoc)) and pins both trees against; the Go
// fixture's carrierGoldenContentHashHex and the Rust fixture's CARRIER_GOLDEN_CONTENT_HASH_HEX
// are byte-identical to this.
const CarrierGoldenContentHashHex = "d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5"

// CarrierGoldenFrameHex is the canonical version-frame BODY bytes the carrier wire contract
// serialises (CarrierGoldenSeq, content_hash, CarrierGoldenDoc) to, as hex:
//
//	seq(8B BE) || content_hash_len=32(4B BE) || content_hash(32) || doc_len(4B BE) || document.
//
// This is the byte-for-byte handshake-free version frame BOTH languages agree on; the
// conformance suite re-derives it with EncodeCarrierVersion below and asserts equality, so the
// golden is never an unchecked literal. IDENTICAL to the Go fixture's carrierGoldenFrameHex and
// the Rust fixture's CARRIER_GOLDEN_FRAME_HEX.
const CarrierGoldenFrameHex = "010203040506070800000020" +
	"d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5" +
	"0000002364732d7761746368706f6c69636965732d6672616d652d636f6e666f726d616e63650a"

// CarrierGoldenHandshakeHex is the 8-byte big-endian from_seq handshake body a dialing
// consumer sends a producer to open a WatchPolicies(from_seq) stream — the resume cursor (D36).
// The fixture pins it for the canonical seq so the handshake leg is single-sourced too (a
// consumer that flips the handshake byte order replays the wrong history). It is exactly the
// 8 big-endian bytes of CarrierGoldenSeq; the conformance suite re-derives it. Both the Go
// carrier (writeWatchFrame of fromSeq[:]) and the Rust producer
// (WatchPoliciesFrame::encode_handshake) emit these bytes.
const CarrierGoldenHandshakeHex = "0102030405060708"

// EncodeCarrierVersion is the INDEPENDENT reference encoder for one carrier version-frame
// body — a byte-for-byte port of the Go producer's encodeWatchVersion (dnsfeed_carrier.go) and
// the Rust consumer's WatchPoliciesFrame::encode_version (server.rs):
//
//	seq(8B BE) || content_hash_len(4B BE) || content_hash || document_len(4B BE) || document.
//
// The conformance suite encodes the canonical tuple with THIS and asserts it equals the pinned
// CarrierGoldenFrameHex, so the golden is the authoritative produce-once wire form derived from
// the canonical inputs, not an unverified literal. A frame shape drift in this single source
// turns the suite RED.
func EncodeCarrierVersion(seq uint64, contentHash, document []byte) []byte {
	out := make([]byte, 0, 8+4+len(contentHash)+4+len(document))
	out = binary.BigEndian.AppendUint64(out, seq)
	out = binary.BigEndian.AppendUint32(out, uint32(len(contentHash)))
	out = append(out, contentHash...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(document)))
	out = append(out, document...)
	return out
}

// EncodeCarrierHandshake is the INDEPENDENT reference encoder for the 8-byte big-endian
// from_seq handshake — a port of the Go carrier handshake write and the Rust
// WatchPoliciesFrame::encode_handshake. The conformance suite pins it against
// CarrierGoldenHandshakeHex.
func EncodeCarrierHandshake(fromSeq uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, fromSeq)
	return out
}

// DecodeCarrierVersion is the INDEPENDENT reference decoder — the byte-for-byte mirror of the
// Go consumer-mirror decodeCarrierVersion (dnsfeed_carrier_test.go) and the Rust
// WatchPoliciesFrame::decode_version (server.rs). It returns ok=false FAIL-CLOSED for a
// malformed frame, with the SAME rejection set both decoders pin:
//
//   - a truncated field (the body ends before the seq / a length prefix / a declared field);
//   - a content_hash_len that is not the 32-byte SHA-256 width (a torn frame);
//   - trailing bytes AFTER the document (an over-long frame — the body did not consume exactly).
//
// It never fabricates a version from a malformed frame (the carrier drops the stream
// fail-closed, the host stays on its current version). This is the cross-language
// malformed-frame leg: the conformance suite drives truncated AND over-long inputs through it
// and asserts they are rejected identically to both sides.
func DecodeCarrierVersion(body []byte) (seq uint64, contentHash, document []byte, ok bool) {
	// seq (8B) + content_hash_len (4B) is the minimum a well-formed frame carries.
	if len(body) < 8+4 {
		return 0, nil, nil, false
	}
	seq = binary.BigEndian.Uint64(body[0:8])
	hashLen := binary.BigEndian.Uint32(body[8:12])
	off := 12
	// The wire content_hash is a full SHA-256 (32 bytes) — a different width is a torn frame.
	if int(hashLen) != CarrierContentHashLen {
		return 0, nil, nil, false
	}
	if off+int(hashLen) > len(body) {
		return 0, nil, nil, false
	}
	hash := body[off : off+int(hashLen)]
	off += int(hashLen)
	if off+4 > len(body) {
		return 0, nil, nil, false
	}
	docLen := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	// The document field must consume the frame EXACTLY: a short body is truncated, a long one
	// is over-long (trailing bytes) — both are malformed.
	if off+int(docLen) != len(body) {
		return 0, nil, nil, false
	}
	return seq, hash, body[off : off+int(docLen)], true
}

// ─── The caRef-leaf cross-reader vectors (the single source both trees pin) ───

// CARefPrefix is the canonical caRef prefix the orchestrator producer derives a session's CA
// reference from: `caRef = "ca:" + session_uuid` (controlplane/liveedges.go caRefFor; Rust
// main.rs CA_REF_PREFIX). It is the head of the leaf-name domain all three readers key on.
const CARefPrefix = "ca:"

// CARefEmptySentinel is the literal an EMPTY sanitized ref collapses to — the SAME
// `"session"` fallback both SanitizeCARef and the Rust sanitize_ca_ref use (an empty leaf is
// never a valid single-component filename). Named so the empty-input row is a single source.
const CARefEmptySentinel = "session"

// SanitizeCARef reduces an opaque ref to a safe single-component filename drawn only from
// [A-Za-z0-9._-], replacing every other byte with '_'; an empty result collapses to
// CARefEmptySentinel. It is a BYTE-FOR-BYTE port of the orchestrator's trustpath.Sanitize
// (controlplane producer side) and the Rust ds-tlsproxy sanitize_ca_ref (consumer side) — both
// of which this fixture single-sources. It is ALSO the defense-in-depth path-traversal guard:
// '/', '\\', '..' all map to '_', so a crafted ref can never escape the .ds-ca-bundles subdir.
//
// The conformance suite uses THIS to re-derive every CrossReaderCARefVectors leaf stem from its
// canonical uuid, so a drift in either tree's sanitizer (against this single source) turns the
// suite RED.
func SanitizeCARef(ref string) string {
	out := make([]byte, 0, len(ref))
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return CARefEmptySentinel
	}
	return string(out)
}

// CARefLeafStem re-derives the on-disk leaf STEM (no extension) the producer/host-agent/proxy
// agree on for a session uuid: SanitizeCARef("ca:" + uuid) = "ca_<uuid>". The cert lands at
// `<stem>.pem` and the proxy-bound PKCS#8 key at the sibling `<stem>.key.pem`. This is the ONE
// transform the cross-reader conformance pins against the producer's Go
// trustpath.Sanitize(caRefFor(uuid)) and the consumer's Rust session_ca_leaf_stem(uuid).
func CARefLeafStem(sessionUUID string) string {
	return SanitizeCARef(CARefPrefix + sessionUUID)
}

// CARefLeafCert / CARefLeafKey render the full on-disk leaf NAMES (with extensions) the
// producer drops and the consumers read for a session uuid — `ca_<uuid>.pem` (the trust-anchor
// cert injected into the guest) and `ca_<uuid>.key.pem` (the proxy-bound PKCS#8 key read
// host-side only, NEVER injected, D8/D39). They are the byte-identical analogs of the
// orchestrator's trustpath.BundleFilename / keyFilename for caRefFor(uuid).
func CARefLeafCert(sessionUUID string) string { return CARefLeafStem(sessionUUID) + ".pem" }
func CARefLeafKey(sessionUUID string) string  { return CARefLeafStem(sessionUUID) + ".key.pem" }

// CARefLeafVector is one golden row of the cross-reader leaf-name conformance fixture: for
// SessionUUID, the producer drops Stem (=> Stem.pem cert + Stem.key.pem proxy-bound key) and the
// ds-tlsproxy / host-agent consumers MUST read EXACTLY that stem. The conformance suite asserts
// CARefLeafStem(SessionUUID) == Stem for every row, so the golden is re-derived, not an
// unchecked literal.
type CARefLeafVector struct {
	// SessionUUID is the create's stable session key the caRef is derived from.
	SessionUUID string
	// Stem is the FROZEN on-disk leaf stem (no extension) all three readers agree on:
	// SanitizeCARef("ca:" + SessionUUID). The cert is Stem+".pem", the key Stem+".key.pem".
	Stem string
}

// CrossReaderCARefVectors is the golden cross-reader leaf-name table — the SINGLE SOURCE of the
// shared leaf-name domain BOTH trees pin (Go CrossReaderCARefVectors, Rust
// CROSS_READER_CAREF_VECTORS). Keep these rows byte-identical with both. Each row's Stem is the
// authoritative `ca_<uuid>` leaf the conformance suite re-derives from SessionUUID via the
// independent SanitizeCARef, so a sanitize drift in EITHER tree turns the suite RED before it
// can re-introduce the producer↔consumer MISS that fail-closed-panicked the live e2e.
var CrossReaderCARefVectors = []CARefLeafVector{
	// A ULID-shaped session uuid (the common case): only [A-Za-z0-9], so the "ca:" prefix's ':'
	// is the only byte sanitize touches (':' → '_').
	{SessionUUID: "01HZX9K6Q2VN7T4M8B0CWRD5EF", Stem: "ca_01HZX9K6Q2VN7T4M8B0CWRD5EF"},
	// The producer's own test session id (caproducer_test.go uses "sess-prod-1"): a hyphen
	// survives sanitize, the ':' from the "ca:" prefix becomes '_'.
	{SessionUUID: "sess-prod-1", Stem: "ca_sess-prod-1"},
	// A uuid carrying a sanitize-illegal byte ('/'): both trees must map it to '_' identically
	// (defense-in-depth — the leaf can never escape the .ds-ca-bundles subdir).
	{SessionUUID: "a/b", Stem: "ca_a_b"},
}
