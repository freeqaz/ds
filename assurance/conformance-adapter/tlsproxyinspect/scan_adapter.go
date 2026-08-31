// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// scan_adapter.go — the conformance adapter for the TLS-7 in-process
// secret-scanning gate (D73; doc 09 §5 TLS-7; doc 12 §5 / §13.5), wiring a
// REAL keyed-digest matcher + hold-back buffer + verdict→Finding bridge behind
// the boundary/tlsproxy EXPORTED SecretScanner / SecretHook / Finding seams. It
// is the TLS-7 sibling of tlsproxyinspect.go's TLS-3 adapter: the boundary
// NewSecretScanner is a RED stub returning ErrNotImplemented at the spec layer,
// so the real ScanInbound verdict the seam promises is implemented HERE, as the
// Go mirror of dataplane/services/ds-tlsproxy/src/scan.rs (the SecretMatcher /
// Verdict / HoldBackBuffer / DigestSetMatcher model), satisfying
// tlsproxy.SecretScanner.
//
// # Why this MIRRORS the boundary seam shapes (it cannot import the TLS-7 tests)
//
// The boundary TLS-7 tests live in boundary/tlsproxy/tlsproxy_scan_test.go as
// PACKAGE-INTERNAL test funcs (TestSecretScan_SeededLongLivedTokenInbound_Hook-
// Fires, TestSecretScan_NearMissContent_NoFalseTrigger, TestSecretScan_Pass-
// ThroughNotScanned_GuaranteeBoundaryDocumented) and ALL their helpers
// (newInspectHarness, recordingUpstream, recordingHook, recordingScanner) live in
// boundary/tlsproxy/tlsproxy_fakes_test.go — a _test.go file, not importable.
// Only the EXPORTED seams in boundary/tlsproxy/tlsproxy.go are reachable
// (SecretScanner, SecretHook, Finding, ResponseMeta, SessionRef, Config, …). So
// this adapter MIRRORS the seam shapes: it IMPLEMENTS the exported SecretScanner
// interface with a real keyed-matcher-backed adapter type (KeyedSecretScanner)
// and re-expresses the three TLS-7 assertions in scan_adapter_test.go against
// that real-plane-backed seam (the doc.go MIRROR guarantee).
//
// # The TLS-7 model mirrored from scan.rs (the in-process gate)
//
// D73 ratified TLS-7 as an IN-PROCESS module on the INSPECTED (TLS-3-terminated)
// path, invoked from the body-filter chain so a planted canary credential is
// caught AT FIRST EGRESS / never egresses (doc 09 §5 TLS-7 done-when). The pieces
// mirrored here, faithful to scan.rs:
//
//   - SecretMatcher — the frozen matcher seam: scan(chunk, endOfStream, ctx) ->
//     (verdict, error). The keyed plane (KeyedDigestMatcher) is an EXACT match on
//     a fake keyed digest feed (the canary registered as a forbidden-class digest),
//     near-zero false-positive rate. The matcher OWNS its carryover; the proxy owns
//     the hold-back invariant (HoldBackBuffer).
//   - Verdict — { Pass(releaseN), Hold, Block(prov), Flag(prov), Redact(prov) }.
//     A keyed forbidden-class hit defaults to Block; the configured alert-mode rung
//     is Flag (pass + finding). Every non-Pass verdict carries fingerprint-free
//     POL-3 provenance — never a matched byte (never-log-the-secret).
//   - HoldBackBuffer — the proxy-owned hold-back: no byte is forwarded upstream
//     until the matcher releases it (retain up to maxSecretLen−1 trailing bytes) so
//     a secret spanning a chunk/TLS-record boundary is never detected only after
//     its prefix already egressed. ScanGate drives the matcher over the buffer.
//
// # The boundary Finding bridge — fingerprint, NEVER the token
//
// The boundary SecretScanner.ScanInbound returns []Finding{Kind, Fingerprint,
// Where}. A keyed hit yields ONE Finding whose Kind is the token CLASS (e.g.
// "github-token"), Where is the LOCATION ("body" | "header:<name>" | "query"),
// and Fingerprint is a SHA-256-derived, truncated fingerprint of the MATCHED
// DIGEST id — never the token value. findingFromVerdict is the single bridge
// point; it is unit-asserted (scan_adapter_test.go) to carry zero token bytes in
// any field. This realizes the boundary LOG-5 / never-log-the-secret clause as a
// type-and-construction property of the adapter.
//
// # Pass-through is OUTSIDE the scan promise (the boundary guarantee)
//
// TLS-7 scanning is on the INSPECTED path ONLY (doc 12 §5.3 stated non-claim, D17
// /D74). The TLS-4 opaque pass-through tunnel NEVER reaches a scanner — the
// PassThroughDispatcher (tlsproxyinspect.go) routes a listed domain to DialRaw and
// NEVER calls ScanInbound. scan_adapter_test.go drives that dispatcher with the
// SAME canary in the opaque body and asserts the scanner's call count stays 0 —
// the living documentation of the guarantee's boundary.
//
// # forbid(unsafe) / D40 pingora confinement
//
// This adapter is stdlib-only (crypto/hmac + crypto/sha256 for the fake keyed
// digest feed; no unsafe, no pingora — it CANNOT import pingora). The confinement
// holds trivially across the seam, exactly as the TLS-3 adapter.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// Unexported sentinels.
//
// NOTE: the package's exportedSentinelUniverse reconciliation tests
// (TestExportedSentinelUniverseComplete / TestExportedErrorVarsCoveredByUniverse
// in tlsproxyinspect_test.go) scan EVERY non-_test.go file for EXPORTED
// `Err* = errors.New(...)` / `Err* = fmt.Errorf(...)` package-level vars and
// reconcile them against that immutable universe map. To avoid breaking those
// tests from this additive file, every sentinel here is UNEXPORTED (lower-case
// err*) — they are package-internal causes the adapter wraps at the return site,
// never part of the exported reject-cause universe.
// ───────────────────────────────────────────────────────────────────────────

var (
	// errKeyedMatcherFailed is the keyed-plane engine failure cause. Under the
	// fail-closed-when-keyed contract (D73, doc 12 §13.5) a keyed-plane error
	// collapses the gate to Hold (no byte released) — it never silently passes.
	errKeyedMatcherFailed = errors.New("tlsproxyinspect: keyed secret-matcher failed (fail-closed: no byte released)")

	// errKeyedNotSealed is the mint-before-attach barrier cause: the keyed plane
	// is loaded but the session was not sealed (digests not acked). scan fails
	// closed rather than matching against a half-attached set (doc 16 §6.1, D109).
	errKeyedNotSealed = errors.New("tlsproxyinspect: keyed plane loaded but session not sealed (mint-before-attach unsatisfied)")
)

// ───────────────────────────────────────────────────────────────────────────
// Verdict — the direction-symmetric TLS-7 verdict (mirrors scan.rs Verdict).
// Every payload is a small count or fingerprint-free provenance; no matched
// byte ever rides the verdict (never-log-the-secret).
// ───────────────────────────────────────────────────────────────────────────

// VerdictKind discriminates a Verdict. The zero value is VerdictUnset so a
// never-decided flow can never satisfy a release/block assertion.
type VerdictKind int

const (
	// VerdictUnset is the zero value — no scan decision has been made.
	VerdictUnset VerdictKind = iota
	// VerdictPass releases the first ReleaseN held bytes upstream — they are clean.
	VerdictPass
	// VerdictHold releases nothing and awaits more input (a candidate may straddle
	// the chunk/record boundary at the tail). The fail-closed default collapses here.
	VerdictHold
	// VerdictBlock aborts: the matched bytes must never egress; the agent sees an
	// in-band refusal. Carries fingerprint-free provenance.
	VerdictBlock
	// VerdictFlag passes the bytes but raises a finding (alert mode). Carries
	// provenance; the bytes are NOT held.
	VerdictFlag
	// VerdictRedact is reserved (D73): the schema slot is frozen, the redaction
	// implementation deferred. Carries provenance so the shape is complete.
	VerdictRedact
)

// String makes scan failures readable.
func (k VerdictKind) String() string {
	switch k {
	case VerdictPass:
		return "Pass"
	case VerdictHold:
		return "Hold"
	case VerdictBlock:
		return "Block"
	case VerdictFlag:
		return "Flag"
	case VerdictRedact:
		return "Redact"
	default:
		return "Unset"
	}
}

// ScanProvenance is the POL-3 provenance a non-Pass verdict carries (mirrors
// scan.rs ScanProvenance) plus the keyed/generic plane discriminator D73 adds.
// It carries NO matched bytes and NO fingerprint — never-log-the-secret is a
// type-level property here (the only data is rule metadata + plane).
type ScanProvenance struct {
	// RuleID is the matched rule / digest id (POL-3 rule_id).
	RuleID string
	// RulesetVersion is the digest-set/ruleset version in force (the PolicyVersion
	// slot).
	RulesetVersion string
	// PolicyLayer is the composing policy layer.
	PolicyLayer string
	// Plane names which plane produced the match (keyed | generic).
	Plane Plane
	// Kind is the token CLASS the matched digest belongs to (e.g. "github-token"),
	// carried for the boundary Finding.Kind — it is a class label, never a token byte.
	Kind string
}

// Plane is the D73 two-plane discriminator (doc 12 §5.2). The keyed plane is an
// exact match on Identity-minted/guarded digests (near-zero FP, the only plane
// inline-block verdicts trust); the generic plane is pattern rules capped at
// block+log.
type Plane int

const (
	// PlaneUnset is the zero value.
	PlaneUnset Plane = iota
	// PlaneKeyed is the exact-match-against-the-keyed-digest-feed plane.
	PlaneKeyed
	// PlaneGeneric is the pattern-rule plane (capped at block+log).
	PlaneGeneric
)

// String renders the plane.
func (p Plane) String() string {
	switch p {
	case PlaneKeyed:
		return "keyed"
	case PlaneGeneric:
		return "generic"
	default:
		return "unset"
	}
}

// ───────────────────────────────────────────────────────────────────────────
// VariantTag — the encoding a single keyed digest was computed over (mirrors
// scan.rs VariantTag / digest_feed.proto DigestVariantTag, doc 14 §7). The
// producer pushes ONE digest per encoding a credential could appear in on the
// wire (raw + base64 + url-percent + lower-hex), each computed over the ENCODED
// form. The matcher hashes a wire window AS-IS (the wire already carries the
// encoded bytes) — it does NOT re-encode at match time, so a base64'd or
// url-encoded secret matches the corresponding per-variant digest as readily as
// the raw bytes matches the Raw digest. encodeVariant is the single source of
// the encoding both producer and (candidate-derivation) consumer agree on, so
// the four encodings can never skew between the two sides.
// ───────────────────────────────────────────────────────────────────────────

// VariantTag is the encoding a keyed digest covers (mirrors scan.rs VariantTag).
type VariantTag int

const (
	// VariantRaw is the credential's raw bytes.
	VariantRaw VariantTag = iota
	// VariantBase64 is standard base64 (RFC 4648, `=`-padded) of the credential.
	VariantBase64
	// VariantUrlEnc is RFC 3986 url-percent-encoding of the credential.
	VariantUrlEnc
	// VariantHex is lowercase hex of the credential.
	VariantHex
)

// String renders the variant tag (used in test names / diagnostics, never a
// secret byte).
func (v VariantTag) String() string {
	switch v {
	case VariantBase64:
		return "base64"
	case VariantUrlEnc:
		return "urlenc"
	case VariantHex:
		return "hex"
	default:
		return "raw"
	}
}

// allVariants is the Stage-0 variant set the producer pushes one digest each for
// (doc 14 §7). Centralized so a feed registers every variant uniformly and the
// conformance test table walks the same closed set.
var allVariants = []VariantTag{VariantRaw, VariantBase64, VariantUrlEnc, VariantHex}

// encodeVariant applies a VariantTag's encoding to raw — the canonical, single-
// source implementation of the variant invariant producer and consumer MUST
// agree on (mirrors scan.rs encode_variant). The producer pushes one digest per
// encoding, computed over THIS function's output; a candidate appearing in that
// encoding on the wire is exactly these bytes. Stdlib-only (encoding/base64,
// net/url, encoding/hex) — no new dependency, no unsafe.
func encodeVariant(tag VariantTag, raw []byte) []byte {
	switch tag {
	case VariantBase64:
		return []byte(base64.StdEncoding.EncodeToString(raw))
	case VariantUrlEnc:
		// url.QueryEscape encodes space as '+'; the wire form of a percent-encoded
		// credential in a path/query uses %XX for non-unreserved bytes. For the
		// alphanumeric+symbol credential shapes in scope QueryEscape and PathEscape
		// agree on the credential bytes; PathEscape mirrors the RFC 3986 unreserved
		// set scan.rs url_percent_encode uses (alnum + -_.~ pass through).
		return []byte(url.PathEscape(string(raw)))
	case VariantHex:
		return []byte(hex.EncodeToString(raw))
	default:
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
}

// Verdict is the result the matcher returns for a scanned span (mirrors scan.rs
// Verdict). ReleaseN is meaningful only for VerdictPass; Prov is set for the
// Block/Flag/Redact verdicts.
type Verdict struct {
	Kind VerdictKind
	// ReleaseN is the count of leading hold-back bytes cleared for egress (Pass).
	ReleaseN int
	// Prov is the fingerprint-free POL-3 provenance (Block/Flag/Redact only).
	Prov ScanProvenance
}

// ReleasesNothing reports whether the verdict forwards ZERO new bytes this call
// (Hold and Block). The fail-closed default collapses to one of these.
func (v Verdict) ReleasesNothing() bool {
	return v.Kind == VerdictHold || v.Kind == VerdictBlock
}

// ───────────────────────────────────────────────────────────────────────────
// SecretMatcher — the frozen matcher seam (mirrors scan.rs SecretMatcher).
// scan(chunk, endOfStream, ctx) -> (Verdict, error). The matcher owns its
// carryover; the gate owns the byte hold-back.
// ───────────────────────────────────────────────────────────────────────────

// ScanCtx is the thin per-stream scan context (mirrors scan.rs ScanCtx): it
// names the direction so the matcher can scope carryover; it carries no secret.
type ScanCtx struct {
	// Direction is the scan direction; v0 enables Egress (request) and the
	// boundary's ScanInbound is the ingress (response) direction the same shape
	// serves — enabling the second direction is policy, not a shape change.
	Direction Direction
}

// Direction is the scan direction (mirrors scan.rs Direction).
type Direction int

const (
	// DirectionEgress is the request direction (bytes the agent sends upstream).
	DirectionEgress Direction = iota
	// DirectionIngress is the response direction (bytes entering the VM) — the
	// direction the boundary SecretScanner.ScanInbound seam names.
	DirectionIngress
)

// SecretMatcher is the frozen TLS-7 matcher seam (mirrors scan.rs SecretMatcher).
// The engine choice (exact-set vs aho-corasick vs Vectorscan) is §9-Free behind
// this trait; the keyed plane shipped here is the exact-set fake digest feed the
// offline conformance row drives.
type SecretMatcher interface {
	// Scan the full scannable span (the hold-back tail joined to the new chunk),
	// with endOfStream set on the final chunk so a tail candidate resolves, in ctx.
	// Returns the Verdict or an error the fail-closed gate acts on.
	Scan(span []byte, endOfStream bool, ctx ScanCtx) (Verdict, error)
}

// ───────────────────────────────────────────────────────────────────────────
// Fake keyed digest feed — the keyed plane (mirrors scan.rs KeyedDigest /
// DigestSetMatcher). plaintext-never-crosses-the-seam: a digest is the truncated
// HMAC of the token; NO field holds a plaintext. The matcher confirms by hashing
// a candidate window and comparing — it never stores the candidate, and a verdict
// carries only fingerprint-free provenance.
// ───────────────────────────────────────────────────────────────────────────

// keyedDigest is one keyed-plane entry: the truncated HMAC of a registered token,
// plus the metadata to hash a candidate comparably and build provenance. The only
// token-derived value is Digest (a one-way keyed hash); there is NO plaintext slot
// (plaintext-never-crosses-the-seam, doc 14 §7).
type keyedDigest struct {
	// keyID selects the HMAC key the digest was computed under.
	keyID string
	// truncLen is the truncation length applied to the keyed hash before comparison.
	truncLen int
	// digest is the truncated HMAC — the one token-derived value.
	digest []byte
	// ruleID is the producer-assigned digest id surfaced in provenance (POL-3
	// rule_id) — it names the matched digest, never a token byte.
	ruleID string
	// kind is the token CLASS (e.g. "github-token") surfaced as Finding.Kind — a
	// class label, never a token byte.
	kind string
	// variant is which encoding this entry's digest was computed over (descriptive
	// metadata; the matcher hashes the wire window AS-IS and never re-encodes, so
	// this is NOT consulted at match time — it documents which on-wire encoding the
	// digest covers, mirroring scan.rs KeyedEntry not retaining variant_tag).
	variant VariantTag
}

// DigestHasher is the §9-Free keyed-hash seam (mirrors scan.rs DigestHasher):
// given a candidate's bytes it produces the SAME truncated HMAC the producer
// computed in the trust zone, so a candidate digest is byte-comparable to a loaded
// digest. It is handed only candidate bytes + the keyID + truncation length; it
// returns digest bytes, never the input — so it cannot become a plaintext sink.
type DigestHasher interface {
	// Hash returns the truncated keyed hash of candidate under keyID, truncated to
	// truncLen bytes, or (nil, false) when keyID is unknown to this hasher.
	Hash(keyID string, candidate []byte, truncLen int) ([]byte, bool)
}

// hmacDigestHasher is the fake keyed-hash engine the offline conformance row
// drives: HMAC-SHA-256 keyed on per-keyID material, truncated. It mirrors a real
// ring::hmac producer; the SAME function the fake digest feed registers with, so
// the producer and matcher computations can never skew.
type hmacDigestHasher struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// newHMACDigestHasher builds an empty fake keyed-hash engine.
func newHMACDigestHasher() *hmacDigestHasher {
	return &hmacDigestHasher{keys: map[string][]byte{}}
}

// addKey registers HMAC key material under keyID (the producer/consumer share it
// in the fake feed; in production the producer holds it inside the trust zone and
// only digests cross).
func (h *hmacDigestHasher) addKey(keyID string, key []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := make([]byte, len(key))
	copy(cp, key)
	h.keys[keyID] = cp
}

// Hash implements DigestHasher: truncated HMAC-SHA-256 of candidate under keyID.
func (h *hmacDigestHasher) Hash(keyID string, candidate []byte, truncLen int) ([]byte, bool) {
	h.mu.RLock()
	key, ok := h.keys[keyID]
	h.mu.RUnlock()
	if !ok {
		return nil, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(candidate)
	sum := mac.Sum(nil)
	if truncLen <= 0 || truncLen > len(sum) {
		truncLen = len(sum)
	}
	out := make([]byte, truncLen)
	copy(out, sum[:truncLen])
	return out, true
}

// compile-time proof the fake hasher satisfies the seam.
var _ DigestHasher = (*hmacDigestHasher)(nil)

// KeyedDigestMatcher is the keyed-plane SecretMatcher (mirrors scan.rs
// DigestSetMatcher): it ingests a fake keyed digest feed (the canary registered
// as a digest) and matches a scannable span by hashing candidate windows AS-IS
// through the DigestHasher and comparing to the loaded digests. It carries ONLY
// fingerprints (digest bytes + rule metadata); never a plaintext.
//
// Match precedence (egress/ingress, v0): the keyed plane is exact-match (the only
// plane inline-block verdicts trust); a keyed hit returns the configured hit
// verdict (default Block) carrying plane=keyed. No match → Pass up to the
// hold-back floor (the trailing window is held for the next chunk so a boundary-
// straddling secret is never released early — the gate enforces the byte hold-back).
type KeyedDigestMatcher struct {
	mu sync.Mutex

	hasher  DigestHasher
	digests []keyedDigest
	// setVersion is the digest-set version stamped into keyed provenance.
	setVersion string
	// policyLayer is the composing policy layer for keyed provenance.
	policyLayer string
	// present is true once a digest set has been ingested (the keyed plane loaded).
	present bool
	// sealed is the mint-before-attach barrier: false until seal() records the
	// ack-landed edge. While present-but-unsealed, Scan fails closed.
	sealed bool
	// retain is the hold-back release window: retain maxCandidateLen−1 trailing
	// bytes so a boundary-straddling candidate is held for the next chunk.
	retain int
	// hitVerdict is the verdict a keyed hit produces (default VerdictBlock; the
	// alert-mode rung is VerdictFlag).
	hitVerdict VerdictKind
	// generic is the loaded POL-4 generic plane (pattern rules capped at block+log).
	// Checked AFTER the keyed plane; a generic hit always Blocks (the cap), carrying
	// plane=generic. Empty until ingestGeneric loads a pack.
	generic GenericPack
}

// NewKeyedDigestMatcher builds an empty keyed matcher over hasher with a hold-back
// release window of maxCandidateLen−1 trailing bytes (the same floor the
// HoldBackBuffer retains). No plane is loaded yet — Scan Passes everything (the
// gate's hold-back still applies) until a digest set is ingested.
func NewKeyedDigestMatcher(hasher DigestHasher, maxCandidateLen int) *KeyedDigestMatcher {
	retain := maxCandidateLen - 1
	if retain < 0 {
		retain = 0
	}
	return &KeyedDigestMatcher{
		hasher:      hasher,
		policyLayer: "identity-keyed",
		retain:      retain,
		hitVerdict:  VerdictBlock,
	}
}

// withHitVerdict sets the keyed-hit verdict (default VerdictBlock). The alert-mode
// configured rung is VerdictFlag — pass + finding (the boundary "alert mode
// delivers" default the seeded-token row asserts).
func (m *KeyedDigestMatcher) withHitVerdict(v VerdictKind) *KeyedDigestMatcher {
	m.hitVerdict = v
	return m
}

// ingest registers a keyed digest set (the fake digest-feed publish). It marks the
// keyed plane PRESENT but NOT yet sealed — per mint-before-attach the matcher must
// not match until seal() records the ack-landed edge.
func (m *KeyedDigestMatcher) ingest(setVersion string, ds []keyedDigest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.digests = append(m.digests, ds...)
	if setVersion != "" {
		m.setVersion = setVersion
	}
	m.present = true
	m.sealed = false
}

// seal records the mint-before-attach ack-landed edge (the in-process twin of
// DigestPublishResponse.committed → session routable). Until called, Scan fails
// closed on a loaded keyed plane. Idempotent / no-op when no plane is present.
func (m *KeyedDigestMatcher) seal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.present {
		m.sealed = true
	}
}

// keyedLoaded reports whether the keyed plane is PRESENT (regardless of seal). The
// caller wires this into the gate for the fail-closed-when-keyed bit (D73), sourced
// from the SAME state that decides matching so the two can never skew.
func (m *KeyedDigestMatcher) keyedLoaded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.present
}

// maxCandidateLen is the longest candidate the loaded plane could match — the
// basis for the gate's hold-back window. Keyed entries carry only digests (the
// plaintext length is not on the wire), so this reflects the configured retain+1.
func (m *KeyedDigestMatcher) maxCandidateLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retain + 1
}

// Scan implements SecretMatcher: keyed plane exact-match over the scannable span,
// else Pass up to the hold-back floor (or everything at end-of-stream).
//
// Fail-closed (D73, doc 12 §13.5): a present-but-unsealed keyed plane returns an
// error so the gate Holds (no byte released) — never a silent miss against a
// half-attached set.
func (m *KeyedDigestMatcher) Scan(span []byte, endOfStream bool, _ ScanCtx) (Verdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.present && !m.sealed {
		return Verdict{}, errKeyedNotSealed
	}

	if m.present && m.sealed {
		if v, ok := m.matchKeyed(span); ok {
			return v, nil
		}
	}

	// Generic plane next (capped at block+log). The generic plane is a policy
	// artifact, not gated by the keyed mint-before-attach seal — it matches whenever
	// a pack is loaded, mirroring scan.rs's keyed-then-generic precedence.
	if len(m.generic.Rules) > 0 {
		if prov, ok := matchGenericPack(m.generic, span); ok {
			return Verdict{Kind: VerdictBlock, Prov: prov}, nil
		}
	}

	// Clean: release up to the hold-back floor (hold the trailing window for the
	// next chunk so a boundary-straddling candidate is never released early), or
	// everything at end-of-stream.
	return Verdict{Kind: VerdictPass, ReleaseN: m.cleanReleaseN(len(span), endOfStream)}, nil
}

// ingestGeneric loads the POL-4 generic pack (the generic plane), replacing any
// prior pack wholesale (a snapshot is a full document). The generic plane is a
// policy artifact — it does not participate in the keyed mint-before-attach seal.
func (m *KeyedDigestMatcher) ingestGeneric(pack GenericPack) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generic = pack
}

// matchKeyed checks the keyed plane against span. It hashes every candidate window
// (bounded by maxCandidateLen) AS-IS through the hasher and compares to each loaded
// digest; on the first hit it returns the configured hit verdict carrying
// fingerprint-free provenance (plane=keyed). Caller holds m.mu.
func (m *KeyedDigestMatcher) matchKeyed(span []byte) (Verdict, bool) {
	spanLen := len(span)
	if spanLen == 0 {
		return Verdict{}, false
	}
	maxW := m.retain + 1
	if maxW > spanLen {
		maxW = spanLen
	}
	for _, entry := range m.digests {
		for wlen := 1; wlen <= maxW; wlen++ {
			for start := 0; start+wlen <= spanLen; start++ {
				window := span[start : start+wlen]
				cand, ok := m.hasher.Hash(entry.keyID, window, entry.truncLen)
				if !ok {
					continue
				}
				if hmac.Equal(cand, entry.digest) {
					prov := ScanProvenance{
						RuleID:         entry.ruleID,
						RulesetVersion: m.setVersion,
						PolicyLayer:    m.policyLayer,
						Plane:          PlaneKeyed,
						Kind:           entry.kind,
					}
					return Verdict{Kind: m.hitVerdict, Prov: prov}, true
				}
			}
		}
	}
	return Verdict{}, false
}

// cleanReleaseN is how many leading bytes are safe to release on a clean span:
// everything except the trailing hold-back window, or all of it at end-of-stream.
// Caller holds m.mu.
func (m *KeyedDigestMatcher) cleanReleaseN(spanLen int, endOfStream bool) int {
	if endOfStream {
		return spanLen
	}
	n := spanLen - m.retain
	if n < 0 {
		return 0
	}
	return n
}

// compile-time proof the keyed matcher satisfies the matcher seam.
var _ SecretMatcher = (*KeyedDigestMatcher)(nil)

// ───────────────────────────────────────────────────────────────────────────
// Generic plane — POL-4 generic-pack content-class rules (mirrors scan.rs
// GenericRule / GenericPack / match_generic_pack, doc 14 §9). The generic plane
// is pattern rules at 25–75% precision and is CAPPED at block+log: a generic rule
// can never drive a suspend/kill rung (doc 14 §8). v0 confirms a rule by literal
// substring (the real RegexSet/Vectorscan engine is §9-Free behind the seam); the
// SHAPE — keyword prefilter → literal confirm → allowlist suppression — is what is
// frozen here. A generic match carries plane=generic provenance, NEVER a matched
// byte (the never-log-the-secret type property holds across both planes).
// ───────────────────────────────────────────────────────────────────────────

// GenericRule is one generic-plane content-class rule (the gitleaks-compatible
// field set, mirrors scan.rs GenericRule).
type GenericRule struct {
	// ID is the rule id (gitleaks `id`) surfaced as rule_id in provenance.
	ID string
	// Regex is the detection pattern (gitleaks `regex`). v0 confirms by literal
	// substring; the §9-Free regex engine swaps in behind the seam.
	Regex string
	// Keywords is the keyword prefilter (gitleaks `keywords`): a span containing
	// NONE of them skips this rule entirely. Empty = no prefilter (always confirmed).
	Keywords []string
	// Kind is the content class surfaced as Finding.Kind (e.g. "aws-access-key") —
	// a class label, never a secret byte.
	Kind string
	// Allowlists is the per-rule allowlist (gitleaks `allowlists`): a confirm whose
	// span sits inside an allowlisted substring is suppressed (a known false positive).
	Allowlists []string
}

// GenericPack is the POL-4 generic pack — a versioned set of GenericRules on the
// policy-snapshot subscription (mirrors scan.rs GenericPack, doc 14 §9).
type GenericPack struct {
	// Rules in force.
	Rules []GenericRule
	// PackVersion is the ruleset version stamped into generic-plane provenance.
	PackVersion string
	// PolicyLayer is the composing policy layer for generic matches.
	PolicyLayer string
}

// matchGenericPack matches span against a GenericPack (keyword prefilter → literal
// confirm → allowlist suppression) and, on the first non-suppressed hit, returns
// the fingerprint-free provenance (plane=generic, the pack version/layer, the rule
// id + class). Mirrors scan.rs match_generic_pack — the SINGLE generic-plane match
// implementation. Carries no matched byte.
func matchGenericPack(pack GenericPack, span []byte) (ScanProvenance, bool) {
	for _, rule := range pack.Rules {
		// Keyword prefilter: a span with NONE of the rule's keywords skips the confirm.
		if len(rule.Keywords) > 0 {
			any := false
			for _, k := range rule.Keywords {
				if strings.Contains(string(span), k) {
					any = true
					break
				}
			}
			if !any {
				continue
			}
		}
		// Confirm (v0 literal substring; §9-Free engine swaps in here).
		if rule.Regex == "" || !strings.Contains(string(span), rule.Regex) {
			continue
		}
		// Allowlist suppression: a matched span inside an allowlisted substring is a
		// known false positive.
		suppressed := false
		for _, a := range rule.Allowlists {
			if a != "" && strings.Contains(string(span), a) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}
		return ScanProvenance{
			RuleID:         rule.ID,
			RulesetVersion: pack.PackVersion,
			PolicyLayer:    pack.PolicyLayer,
			Plane:          PlaneGeneric,
			Kind:           rule.Kind,
		}, true
	}
	return ScanProvenance{}, false
}

// ───────────────────────────────────────────────────────────────────────────
// HoldBackBuffer — the proxy-owned hold-back invariant (mirrors scan.rs
// HoldBackBuffer). A byte enters and leaves it ONLY when the matcher releases it;
// it holds cleartext transiently only and is never serialized.
// ───────────────────────────────────────────────────────────────────────────

// HoldBackBuffer retains up to maxSecretLen−1 trailing bytes so a secret
// straddling a chunk/TLS-record boundary is held until the matcher has seen its
// whole span — never detected only after its prefix already egressed.
type HoldBackBuffer struct {
	bytes []byte
	// retain is the hold-back window: maxSecretLen−1 trailing bytes.
	retain int
}

// NewHoldBackBuffer builds a buffer whose hold-back window is maxSecretLen−1
// trailing bytes. maxSecretLen of 0 or 1 means a zero-width window.
func NewHoldBackBuffer(maxSecretLen int) *HoldBackBuffer {
	retain := maxSecretLen - 1
	if retain < 0 {
		retain = 0
	}
	return &HoldBackBuffer{retain: retain}
}

// RetainWindow is the hold-back window size (maxSecretLen−1).
func (b *HoldBackBuffer) RetainWindow() int { return b.retain }

// Append adds the next cleartext chunk (the new bytes join the retained tail so
// the matcher sees one contiguous span across the boundary).
func (b *HoldBackBuffer) Append(chunk []byte) { b.bytes = append(b.bytes, chunk...) }

// Scannable is the full buffered span the matcher scans (retained tail + new chunk).
func (b *HoldBackBuffer) Scannable() []byte { return b.bytes }

// Len is how many bytes are currently buffered.
func (b *HoldBackBuffer) Len() int { return len(b.bytes) }

// ReleasableFloor is how many leading bytes are safe to release WITHOUT a matcher
// verdict — everything except the trailing hold-back window. The matcher's Pass
// ReleaseN may release MORE (it cleared the tail too); this is the no-verdict
// floor, never an upper bound.
func (b *HoldBackBuffer) ReleasableFloor() int {
	n := len(b.bytes) - b.retain
	if n < 0 {
		return 0
	}
	return n
}

// DrainFront drains (releases) the first n bytes from the front, returning them for
// egress. n is clamped to the buffered length; the retained tail stays held.
func (b *HoldBackBuffer) DrainFront(n int) []byte {
	if n > len(b.bytes) {
		n = len(b.bytes)
	}
	if n < 0 {
		n = 0
	}
	out := make([]byte, n)
	copy(out, b.bytes[:n])
	b.bytes = b.bytes[n:]
	return out
}

// DrainAll drains the entire buffer (end-of-stream, after the final clearing
// verdict): the hold-back window no longer matters once the stream is complete.
func (b *HoldBackBuffer) DrainAll() []byte {
	out := b.bytes
	b.bytes = nil
	return out
}

// ───────────────────────────────────────────────────────────────────────────
// ScanGate — the proxy-owned gate driving a SecretMatcher across a stream over
// the HoldBackBuffer (mirrors scan.rs ScanGate). It owns the hold-back invariant
// and the fail-closed-when-keyed decision.
// ───────────────────────────────────────────────────────────────────────────

// ScanGate drives matcher over buffer chunk by chunk. Invariant: a byte enters
// the buffer and leaves it ONLY when the matcher returns a Pass releasing it (or
// end-of-stream drains the cleared remainder). On a matcher error under
// fail-closed, NO held byte is released.
type ScanGate struct {
	matcher     SecretMatcher
	buffer      *HoldBackBuffer
	keyedLoaded bool
	// egressed accumulates every byte the gate RELEASED upstream — the recording
	// upstream the chunk-boundary test inspects to prove zero matched bytes egress.
	egressed []byte
}

// NewScanGate builds a gate over matcher with a hold-back window sized to
// maxSecretLen. keyedLoaded records whether the keyed plane is loaded (forces
// fail-closed regardless of any fail-open posture — D73, doc 12 §13.5).
func NewScanGate(matcher SecretMatcher, maxSecretLen int, keyedLoaded bool) *ScanGate {
	return &ScanGate{
		matcher:     matcher,
		buffer:      NewHoldBackBuffer(maxSecretLen),
		keyedLoaded: keyedLoaded,
	}
}

// ScanChunk feeds the next cleartext chunk (with endOfStream on the final chunk)
// and returns the Verdict. The chunk is appended to the hold-back buffer first, so
// the matcher always sees the buffered tail joined to the new bytes — a secret
// spanning the chunk boundary is one contiguous view, never two halves scanned in
// isolation.
//
// Fail-closed (D73): a matcher error while the keyed plane is loaded collapses to
// VerdictHold — NO held byte is released. The gate then APPLIES a Pass verdict's
// ReleaseN by draining exactly that many bytes from the front into egressed; a
// Block/Hold drains nothing (the matched bytes never egress).
func (g *ScanGate) ScanChunk(chunk []byte, endOfStream bool, ctx ScanCtx) Verdict {
	g.buffer.Append(chunk)
	v, err := g.matcher.Scan(g.buffer.Scannable(), endOfStream, ctx)
	if err != nil {
		if g.keyedLoaded {
			// Fail-closed: release nothing, hold every buffered byte.
			return Verdict{Kind: VerdictHold}
		}
		// Fail-open (generic-flag-only, explicit policy bit): pass the remainder.
		v = Verdict{Kind: VerdictPass, ReleaseN: g.buffer.Len()}
	}
	switch v.Kind {
	case VerdictPass, VerdictFlag:
		n := v.ReleaseN
		if v.Kind == VerdictFlag {
			// Flag is pass-and-alert: the bytes are not held. Release the whole
			// buffered span (or up to ReleaseN if the matcher narrowed it).
			if n <= 0 {
				n = g.buffer.Len()
			}
		}
		g.egressed = append(g.egressed, g.buffer.DrainFront(n)...)
	default:
		// Hold / Block / Redact / Unset release nothing this call.
	}
	return v
}

// Egressed returns every byte the gate has RELEASED upstream so far — the
// recording-upstream surface the chunk-boundary test greps for matched bytes
// (zero hits is the invariant).
func (g *ScanGate) Egressed() []byte { return g.egressed }

// Buffer borrows the hold-back buffer (its Len / Scannable view) for the proxy's
// release bookkeeping and for tests asserting no byte egressed prematurely.
func (g *ScanGate) Buffer() *HoldBackBuffer { return g.buffer }

// ───────────────────────────────────────────────────────────────────────────
// KeyedSecretScanner — the boundary SecretScanner seam over the keyed matcher.
//
// This is the real-plane adapter the boundary TLS-7 tests' configured scanner
// would delegate to (boundary recordingScanner.delegate). ScanInbound runs the
// matcher over the full body via a ScanGate and bridges the verdict into the
// boundary Finding shape — fingerprint, class, location — NEVER the token.
// ───────────────────────────────────────────────────────────────────────────

// KeyedSecretScanner satisfies the boundary SecretScanner seam (ScanInbound). It
// runs the keyed matcher over the response body and returns one Finding per
// non-Pass verdict, each carrying a fingerprint (NOT the token), the token class
// (Kind), and the location (Where).
type KeyedSecretScanner struct {
	matcher *KeyedDigestMatcher
	// maxSecretLen sizes the hold-back window the per-call gate uses.
	maxSecretLen int
}

// NewKeyedSecretScanner builds the scanner over matcher. maxSecretLen sizes the
// hold-back window (typically matcher.maxCandidateLen()).
func NewKeyedSecretScanner(matcher *KeyedDigestMatcher) *KeyedSecretScanner {
	return &KeyedSecretScanner{matcher: matcher, maxSecretLen: matcher.maxCandidateLen()}
}

// ScanInbound implements the boundary SecretScanner seam: it scans body (the
// inspected-path cleartext) for registered keyed digests and returns a Finding for
// each hit. The location (Where) is "body" — the body-direction scan; a real
// integration also scans header:<name> / query (the boundary Finding.Where shape).
//
// The matcher is consulted as ONE end-of-stream chunk (ScanInbound receives the
// full materialized body); the streaming chunk-boundary hold-back is exercised by
// the gate directly in the chunk-boundary test. A keyed hit yields a Block-or-Flag
// verdict carrying fingerprint-free provenance, which findingFromVerdict bridges
// into a token-free Finding.
func (s *KeyedSecretScanner) ScanInbound(_ context.Context, _ tlsproxy.SessionRef, _ tlsproxy.ResponseMeta, body []byte) ([]tlsproxy.Finding, error) {
	maxLen := s.maxSecretLen
	if maxLen < 1 {
		maxLen = 1
	}
	gate := NewScanGate(s.matcher, maxLen, s.matcher.keyedLoaded())
	v := gate.ScanChunk(body, true, ScanCtx{Direction: DirectionIngress})
	switch v.Kind {
	case VerdictBlock, VerdictFlag, VerdictRedact:
		return []tlsproxy.Finding{findingFromVerdict(v, "body")}, nil
	case VerdictHold:
		// A Hold at end-of-stream while the keyed plane is loaded is the
		// fail-closed posture (matcher error). Surface it as an error so the caller
		// never silently delivers an unscanned body (never a vacuous clean result).
		if s.matcher.keyedLoaded() {
			return nil, fmt.Errorf("tlsproxyinspect: scan held at end-of-stream: %w", errKeyedMatcherFailed)
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// findingFromVerdict is the SINGLE bridge from a matcher Verdict to a boundary
// Finding. It populates:
//
//   - Kind: the token CLASS from provenance (e.g. "github-token") — a class label.
//   - Where: the location ("body" | "header:<name>" | "query").
//   - Fingerprint: a stable, truncated SHA-256-derived fingerprint of the matched
//     DIGEST id (RuleID) + plane + ruleset version — NEVER the token value, NEVER a
//     matched byte. The verdict carries no token bytes (never-log-the-secret is a
//     type property of ScanProvenance), so the fingerprint is computed from rule
//     metadata only and is reproducible across runs.
//
// This is the load-bearing never-log-the-secret construction point; scan_adapter_-
// test.go asserts NO field of the returned Finding contains the seeded token.
func findingFromVerdict(v Verdict, where string) tlsproxy.Finding {
	prov := v.Prov
	kind := prov.Kind
	if kind == "" {
		kind = "secret"
	}
	return tlsproxy.Finding{
		Kind:        kind,
		Fingerprint: fingerprintFor(prov),
		Where:       where,
	}
}

// fingerprintFor derives a stable, token-free fingerprint from rule metadata
// (RuleID + plane + ruleset version) — never the token. It is a truncated hex
// SHA-256 so it is loggable and stable but reveals nothing about the matched bytes.
func fingerprintFor(prov ScanProvenance) string {
	sum := sha256.Sum256([]byte(prov.RuleID + "|" + prov.Plane.String() + "|" + prov.RulesetVersion))
	return "fp_" + hex.EncodeToString(sum[:8])
}

// compile-time proof the scanner satisfies the boundary SecretScanner seam.
var _ tlsproxy.SecretScanner = (*KeyedSecretScanner)(nil)

// ───────────────────────────────────────────────────────────────────────────
// Configured hook + canary feed helpers — the fake digest feed the conformance
// row plants the canary into, and the configured response hook the boundary
// SecretHook seam mirrors.
// ───────────────────────────────────────────────────────────────────────────

// RecordingHook satisfies the boundary SecretHook seam, capturing every Finding
// for assertion (the conformance mirror of boundary recordingHook). The configured
// hook fires per Finding the scanner returns.
type RecordingHook struct {
	mu       sync.Mutex
	findings []tlsproxy.Finding
}

// NewRecordingHook builds an empty capturing hook.
func NewRecordingHook() *RecordingHook { return &RecordingHook{} }

// OnFinding records the finding (the boundary SecretHook seam).
func (h *RecordingHook) OnFinding(_ context.Context, _ tlsproxy.SessionRef, f tlsproxy.Finding) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.findings = append(h.findings, f)
	return nil
}

// Findings returns a copy of every captured finding.
func (h *RecordingHook) Findings() []tlsproxy.Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]tlsproxy.Finding(nil), h.findings...)
}

// compile-time proof the hook satisfies the boundary SecretHook seam.
var _ tlsproxy.SecretHook = (*RecordingHook)(nil)

// CanaryFeed is the fake keyed digest feed the conformance row plants a canary
// into: it registers a token's per-class digest (the keyed plane) so the matcher
// can detect that exact token — without ever holding the token plaintext past
// registration (only the HMAC digest is retained). It bundles the shared fake
// hasher so producer and matcher computations cannot skew.
type CanaryFeed struct {
	hasher     *hmacDigestHasher
	keyID      string
	truncLen   int
	setVersion string
	digests    []keyedDigest
	// maxLen tracks the longest registered token (the hold-back window basis).
	maxLen int
}

// NewCanaryFeed builds a fake keyed digest feed under one HMAC key id. truncLen is
// the digest truncation length (16 bytes mirrors the proto Stage-0 default range).
func NewCanaryFeed(keyID, setVersion string, truncLen int) *CanaryFeed {
	h := newHMACDigestHasher()
	h.addKey(keyID, []byte("ds-fake-keyed-hmac-key:"+keyID))
	return &CanaryFeed{hasher: h, keyID: keyID, truncLen: truncLen, setVersion: setVersion}
}

// Register plants a canary token of class kind under ruleID: it computes the
// token's truncated HMAC and retains ONLY the digest (never the plaintext). This is
// the producer-side computation inside the (fake) trust zone — after this call the
// token plaintext is not held anywhere in the feed.
//
// It registers the RAW variant only — the historical default the keyed-plane rows
// drive. Use RegisterAllVariants to plant the full per-encoding digest set (the
// variant invariant: one digest per encoding a credential could appear in).
func (f *CanaryFeed) Register(ruleID, kind, token string) {
	f.registerVariant(ruleID, kind, token, VariantRaw)
}

// RegisterAllVariants plants a canary token under ruleID with ONE digest per
// Stage-0 encoding (raw + base64 + url-percent + lower-hex), mirroring the
// producer pushing every variant a credential could appear in on the wire (doc 14
// §7). The per-variant ruleID is suffixed with the variant tag so an overlapping
// match reports WHICH encoding fired. Each variant's digest is computed over the
// ENCODED form, so the matcher — which hashes wire windows AS-IS — catches the
// secret in any of these encodings. Only the HMAC digests are retained; the token
// plaintext is never held past this call.
func (f *CanaryFeed) RegisterAllVariants(ruleID, kind, token string) {
	for _, vt := range allVariants {
		f.registerVariant(ruleID+":"+vt.String(), kind, token, vt)
	}
}

// registerVariant computes one variant's digest over the ENCODED token bytes and
// retains it (the shared body of Register / RegisterAllVariants). maxLen tracks
// the longest ENCODED form across all registered variants — the on-wire candidate
// bound the matcher window scan and the gate hold-back window are sized to (an
// encoded form is longer than the raw secret, so the bound must cover it).
func (f *CanaryFeed) registerVariant(ruleID, kind, token string, vt VariantTag) {
	encoded := encodeVariant(vt, []byte(token))
	digest, ok := f.hasher.Hash(f.keyID, encoded, f.truncLen)
	if !ok {
		// keyID always known (we registered it in NewCanaryFeed); defensive only.
		return
	}
	f.digests = append(f.digests, keyedDigest{
		keyID:    f.keyID,
		truncLen: f.truncLen,
		digest:   digest,
		ruleID:   ruleID,
		kind:     kind,
		variant:  vt,
	})
	if len(encoded) > f.maxLen {
		// The hold-back / window bound must cover the longest ON-WIRE (encoded) form.
		f.maxLen = len(encoded)
	}
}

// Matcher builds a sealed KeyedDigestMatcher over the registered digests with the
// given hit verdict (VerdictBlock default semantics, VerdictFlag for alert mode).
// The matcher is the keyed plane the scanner/gate drive; it is sealed (mint-
// before-attach satisfied) so it matches live.
func (f *CanaryFeed) Matcher(hit VerdictKind) *KeyedDigestMatcher {
	maxCand := f.maxLen
	if maxCand < 1 {
		maxCand = 1
	}
	m := NewKeyedDigestMatcher(f.hasher, maxCand).withHitVerdict(hit)
	m.ingest(f.setVersion, f.copyDigests())
	m.seal()
	return m
}

// UnsealedMatcher builds an UNSEALED matcher (keyed plane present but not acked) —
// the mint-before-attach fail-closed posture the gate must Hold on.
func (f *CanaryFeed) UnsealedMatcher(hit VerdictKind) *KeyedDigestMatcher {
	maxCand := f.maxLen
	if maxCand < 1 {
		maxCand = 1
	}
	m := NewKeyedDigestMatcher(f.hasher, maxCand).withHitVerdict(hit)
	m.ingest(f.setVersion, f.copyDigests())
	// deliberately NOT sealed.
	return m
}

// MatcherWithGeneric builds a sealed keyed matcher (as Matcher) and additionally
// ingests a generic pack, so the conformance row can drive a two-plane matcher
// (keyed-then-generic precedence). maxCand is widened to cover the longest generic
// regex span so a generic candidate straddling a chunk boundary is held too.
func (f *CanaryFeed) MatcherWithGeneric(hit VerdictKind, pack GenericPack) *KeyedDigestMatcher {
	maxCand := f.maxLen
	for _, r := range pack.Rules {
		if len(r.Regex) > maxCand {
			maxCand = len(r.Regex)
		}
	}
	if maxCand < 1 {
		maxCand = 1
	}
	m := NewKeyedDigestMatcher(f.hasher, maxCand).withHitVerdict(hit)
	// Only load (and seal) the keyed plane when the feed actually has digests — a
	// generic-only pack must NOT mark the keyed plane present (the keyed mint-before-
	// attach gate is irrelevant to a pure generic-plane matcher).
	if digests := f.copyDigests(); len(digests) > 0 {
		m.ingest(f.setVersion, digests)
		m.seal()
	}
	m.ingestGeneric(pack)
	return m
}

// copyDigests returns a defensive copy of the registered digests (sorted by ruleID
// for deterministic match order across runs).
func (f *CanaryFeed) copyDigests() []keyedDigest {
	out := append([]keyedDigest(nil), f.digests...)
	sort.Slice(out, func(i, j int) bool { return out[i].ruleID < out[j].ruleID })
	return out
}

// MaxTokenLen is the longest registered ON-WIRE form (the hold-back window basis
// the chunk-boundary test sizes its split on: maxSecretLen−1). With only the raw
// variant registered (Register) it equals the raw token length; once encoded
// variants are registered (RegisterAllVariants) it is the longest encoded form —
// the on-wire bound the matcher window scan and gate hold-back must cover.
func (f *CanaryFeed) MaxTokenLen() int { return f.maxLen }

// scrubbed reports whether s appears anywhere in any field of f — the never-log-
// the-secret assertion helper the test reuses (kept here beside the bridge it
// guards so the construction and its guarantee live together).
func findingContains(f tlsproxy.Finding, needle string) bool {
	return strings.Contains(f.Kind, needle) ||
		strings.Contains(f.Fingerprint, needle) ||
		strings.Contains(f.Where, needle)
}
