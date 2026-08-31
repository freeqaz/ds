// SPDX-License-Identifier: Apache-2.0

package fleetreg

// revocation.go — the EMERGENCY fleet-wide token-revocation PRODUCER (D102 /
// P-R6, doc 19 §7; the "fleet-revocation-clock" assurance row, doc 19 §13).
//
// When a per-session bearer token is stolen, killing it on the issuing host is
// not enough: it must be invalidated on EVERY host fast (the POL-4 seconds-scale
// push-to-enforced bar, doc 13 §5). This file is the control-plane half of that
// path: it turns an operator's "revoke this token fleet-wide" into ONE versioned
// token-revocation policy artifact appended onto the EXISTING `policy_log` seq —
// the same one-subscriber-per-host distribution channel the digest feed already
// rides (D72, "two cadences, no third channel"). It introduces NO new proto and
// NO new RPC: the revocation entry rides INSIDE the composed policy document the
// orchestrator's policy-log adapter already appends (PolicySnapshot.document is
// contractually opaque), modelled here behind a [RevocationSink] Go seam so this
// module stays buildable in-process against a fake (the synthetic-fixture rule,
// D50) without owning the control-plane RPC.
//
// SECRET DISCIPLINE (the whole reason this file is careful): a revocation entry
// carries ONLY a chain FINGERPRINT (a hex SHA-256 reduction of the token's
// revocation id, D124) or a unique BLOCK IDENTIFIER — NEVER the token bytes.
// Nothing secret ever touches the log. The entry constructors enforce this
// structurally: they accept only hex-encoded identifiers of a bounded shape, so
// a caller cannot smuggle raw token bytes into the artifact even by mistake.
//
// The Rust ENFORCEMENT half (the consumer that recognizes these entries and
// severs established flows rung-conditionally per D53/D77 via the shared
// `flush_session` primitive, D68) lives in the data plane
// (`ds-policy-snapshot` recognition + `ds-nft` apply-path flush call-site); this
// file is producer-only and orders nothing downstream of the append.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// RevocationSchemaVersion is the versioned schema tag every fleet
	// token-revocation artifact carries (doc 19 §7). A bump is a new artifact
	// shape the consumer negotiates; the value is stamped on every append so a
	// consumer can reject an artifact it does not understand fail-closed.
	RevocationSchemaVersion = "fleet-revocation/v1"

	// fingerprintHexLen is the hex-string length of a SHA-256 chain fingerprint
	// (D124, SHA-256 only): 32 bytes → 64 lower-hex characters. The entry
	// constructor pins this length so a raw token (arbitrary length / alphabet)
	// cannot pass as a fingerprint.
	fingerprintHexLen = sha256.Size * 2

	// blockIDHexMaxLen bounds a unique block identifier's hex length. Biscuit
	// per-block revocation ids are 32-byte signatures (64 hex); the bound is
	// generous but finite so an over-long blob (a possible token smuggle) is
	// rejected.
	blockIDHexMaxLen = 128
)

// FleetRevocationEntry names ONE revoked token in a fleet-revocation artifact —
// by a chain fingerprint OR a unique block identifier, never by its bytes (doc
// 19 §7/§9). Exactly one of the two fields is set; both are lower-hex encoded.
//
// Construct entries through [RevocationEntryFromFingerprint] /
// [RevocationEntryFromBlockID] (or [FingerprintToken] for the one-way reduction)
// — never by populating the fields directly with untrusted input, so the
// no-token-bytes invariant is checked at the boundary.
type FleetRevocationEntry struct {
	// Fingerprint is the hex-lowercase SHA-256 chain fingerprint of the revoked
	// token's revocation id (the identity/mint TokenLineage per-block fingerprint,
	// doc 19 §9). Empty when the entry is keyed by BlockID instead.
	Fingerprint string
	// BlockID is a hex-lowercase unique block/revocation identifier (e.g.
	// Biscuit's native per-block revocation id, §7 OQ6). Empty when the entry is
	// keyed by Fingerprint instead.
	BlockID string
}

// FingerprintToken computes the chain fingerprint of a token's revocation id —
// the one-way SHA-256 reduction (D124) that turns a secret-adjacent revocation
// id into the hex identity safe to publish. The input bytes are hashed and
// dropped; only the returned hex digest ever reaches a [FleetRevocationEntry].
// This is the producer-side helper an operator/tool calls to derive the
// fingerprint it revokes by; the raw id never crosses into the artifact.
func FingerprintToken(revocationID []byte) string {
	sum := sha256.Sum256(revocationID)
	return hex.EncodeToString(sum[:])
}

// RevocationEntryFromFingerprint builds an entry keyed by a hex SHA-256 chain
// fingerprint. Fail-closed: the input must be exactly [fingerprintHexLen]
// lower-hex characters — a raw token, an upper-hex string, or a wrong-length
// blob is rejected, so token bytes can never masquerade as a fingerprint.
func RevocationEntryFromFingerprint(hexFingerprint string) (FleetRevocationEntry, error) {
	if err := validateHexID("fingerprint", hexFingerprint, fingerprintHexLen, fingerprintHexLen); err != nil {
		return FleetRevocationEntry{}, err
	}
	return FleetRevocationEntry{Fingerprint: hexFingerprint}, nil
}

// RevocationEntryFromBlockID builds an entry keyed by a hex unique block
// identifier. Fail-closed: the input must be an even-length lower-hex string of
// at most [blockIDHexMaxLen] characters — same anti-smuggle bound as the
// fingerprint path.
func RevocationEntryFromBlockID(hexBlockID string) (FleetRevocationEntry, error) {
	if err := validateHexID("block id", hexBlockID, 2, blockIDHexMaxLen); err != nil {
		return FleetRevocationEntry{}, err
	}
	return FleetRevocationEntry{BlockID: hexBlockID}, nil
}

// id returns the entry's non-empty identifier (fingerprint or block id) — for
// dedup and log provenance. Never any token bytes.
func (e FleetRevocationEntry) id() string {
	if e.Fingerprint != "" {
		return e.Fingerprint
	}
	return e.BlockID
}

// validate re-checks the no-token-bytes invariant on an entry before it is
// appended — defense in depth against a directly-populated struct that bypassed
// the constructors. EXACTLY one identifier must be set, and it must be a bounded
// lower-hex string.
func (e FleetRevocationEntry) validate() error {
	switch {
	case e.Fingerprint == "" && e.BlockID == "":
		return errors.New("fleetreg: revocation entry has neither a fingerprint nor a block id (fail-closed)")
	case e.Fingerprint != "" && e.BlockID != "":
		return errors.New("fleetreg: revocation entry sets BOTH fingerprint and block id (ambiguous; set exactly one)")
	case e.Fingerprint != "":
		return validateHexID("fingerprint", e.Fingerprint, fingerprintHexLen, fingerprintHexLen)
	default:
		return validateHexID("block id", e.BlockID, 2, blockIDHexMaxLen)
	}
}

// validateHexID enforces that id is a lower-hex string of even length in
// [minLen,maxLen]. Lower-hex + even-length + bounded is the structural fence
// that keeps a raw token (which is neither fixed-length nor hex) out of a
// revocation artifact.
func validateHexID(kind, id string, minLen, maxLen int) error {
	if len(id) < minLen || len(id) > maxLen {
		return fmt.Errorf("fleetreg: %s %q has length %d, want in [%d,%d] (fail-closed: not a hex identifier)",
			kind, redact(id), len(id), minLen, maxLen)
	}
	if len(id)%2 != 0 {
		return fmt.Errorf("fleetreg: %s has odd hex length %d (fail-closed)", kind, len(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("fleetreg: %s is not lower-hex at byte %d (fail-closed: not a hex identifier)", kind, i)
		}
	}
	return nil
}

// redact bounds an invalid identifier in an error to its length prefix so a
// rejected value (which might be a mistakenly-passed secret) is never echoed
// whole into a log.
func redact(id string) string {
	const keep = 6
	if len(id) <= keep {
		return "…"
	}
	return id[:keep] + "…"
}

// FleetRevocationArtifact is one versioned token-revocation policy artifact as it
// is appended onto the `policy_log` seq (doc 19 §7; D72). It carries the schema
// version, the set of revoked-token entries (fingerprint/block-id only), and a
// producer-chosen BatchID for ack provenance — the revocation analogue of the
// digest feed's FleetPolicyArtifact. It is host-wide (no session ref): a fleet
// revocation reaches every host's one-per-host policy subscriber.
type FleetRevocationArtifact struct {
	// SchemaVersion is [RevocationSchemaVersion] — stamped so a consumer can
	// fail-closed on an artifact shape it does not understand.
	SchemaVersion string
	// Entries is the set of revoked tokens (fingerprint/block-id only; NEVER
	// token bytes).
	Entries []FleetRevocationEntry
	// BatchID correlates the append with its ack (provenance, doc 16 §6.5).
	BatchID string
}

// RevocationResult reports the outcome of one fleet-revocation append. Seq is the
// assigned `policy_log` seq (the single policy version namespace, D72); Committed
// is true iff the two-phase apply barrier confirmed the artifact is live on the
// subscriber. Count echoes how many entries were published.
type RevocationResult struct {
	Seq       uint64
	Committed bool
	BatchID   string
	Count     int
}

// RevocationSink is the producer-side seam onto the `policy_log` append path for
// token-revocation artifacts (doc 19 §7; D72). It is a Go interface, NOT a new
// proto/RPC: the wire surface already exists (the orchestrator's policy-log
// append → the per-host WatchPolicies fan-out), and the revocation entry rides
// INSIDE the composed document that path already carries. Inventing a second
// stream would be the "third channel" D72 forbids.
//
// PRODUCTION SATISFIER (the real adapter, landed 2026-07-10):
// orchestrator/internal/policylog.FleetRevocationSink — it appends a
// `fleet-revocation/v1` artifact as a FleetRevocationKind row on the
// orchestrator's AppendPolicy path and returns the committed two-phase ack, so
// the existing one-per-host WatchPolicies fan-out delivers it under the POL-4
// bar. That adapter mirrors this seam's value types field-for-field because the
// D80 import-boundary bars the orchestrator tree from importing identity/fleetreg
// (cross-tree is proto/gen/go only); the one-line forwarding shim that binds
// *FleetRevocationSink to this named interface lives in a tree allowed to import
// both (fleetreg's cmd / an assurance bridge), exactly as the fleet-digest
// PolicySink seam is wired. The in-process fake (spyRevSink) that satisfies this
// interface is TEST-ONLY (revocation_test.go) — it never ships in the production
// path; production always resolves to the FleetRevocationSink adapter above
// (D50, no live boundary in-tree).
type RevocationSink interface {
	// AppendRevocation appends one fleet-revocation artifact and returns its
	// assigned seq + commit state. Fail-closed: an error OR an uncommitted result
	// means the revocation is NOT applied, exactly as an uncommitted digest ack
	// blocks the session path.
	AppendRevocation(ctx context.Context, art FleetRevocationArtifact) (RevocationResult, error)
}

// RevocationPublisher is the emergency fleet-revocation control-plane verb (doc
// 19 §7). It owns nothing but the append seam: an operator calls RevokeTokens
// with the fingerprints/block-ids of the stolen tokens, and it publishes ONE
// versioned artifact onto the policy stream. It holds no key and reads no
// plaintext — a revocation names an already-derived fingerprint, so unlike the
// digest producer it never touches a secret at all.
type RevocationPublisher struct {
	sink RevocationSink
}

// NewRevocationPublisher builds a publisher over the policy_log append seam.
// Fail-closed: a nil sink is rejected — a nil sink would silently no-op an
// emergency revocation the security team believes landed fleet-wide.
func NewRevocationPublisher(sink RevocationSink) (*RevocationPublisher, error) {
	if sink == nil {
		return nil, errors.New("fleetreg: nil revocation sink (fail-closed: a revocation must reach policy_log)")
	}
	return &RevocationPublisher{sink: sink}, nil
}

// RevokeTokens publishes an emergency fleet-wide token revocation as ONE
// versioned policy artifact onto the `policy_log` seq (doc 19 §7). Every entry is
// re-validated (no-token-bytes, exactly-one-identifier) BEFORE the append, and
// duplicate identifiers are collapsed so one revoked token is named once.
//
// Fail-closed end to end: an empty entry set, an invalid entry, a sink error, or
// an uncommitted apply all return a non-nil error and a non-committed result —
// the operator learns the revocation did NOT land fleet-wide rather than
// believing a stolen token is dead when it is still live.
func (p *RevocationPublisher) RevokeTokens(ctx context.Context, entries []FleetRevocationEntry, batchID string) (RevocationResult, error) {
	if len(entries) == 0 {
		return RevocationResult{}, errors.New("fleetreg: no revocation entries (fail-closed: refusing to append an empty revocation)")
	}
	seen := make(map[string]struct{}, len(entries))
	deduped := make([]FleetRevocationEntry, 0, len(entries))
	for i, e := range entries {
		if err := e.validate(); err != nil {
			return RevocationResult{}, fmt.Errorf("fleetreg: revocation entry %d: %w", i, err)
		}
		if _, dup := seen[e.id()]; dup {
			continue
		}
		seen[e.id()] = struct{}{}
		deduped = append(deduped, e)
	}
	art := FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries:       deduped,
		BatchID:       batchID,
	}
	res, err := p.sink.AppendRevocation(ctx, art)
	if err != nil {
		return RevocationResult{}, fmt.Errorf("fleetreg: AppendRevocation: %w (fail-closed: revocation not applied)", err)
	}
	if res.BatchID == "" {
		res.BatchID = batchID
	}
	if res.Count == 0 {
		res.Count = len(deduped)
	}
	if !res.Committed {
		return res, fmt.Errorf("fleetreg: fleet revocation not committed (batch=%q seq=%d, %d entries): fail-closed, revocation not enforced fleet-wide",
			res.BatchID, res.Seq, res.Count)
	}
	return res, nil
}
