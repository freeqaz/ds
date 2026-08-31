package policylog

// This file is the orchestrator-side PRODUCTION satisfier for the identity
// fleet-revocation publish seam (doc 19 §7; D102/P-R6, D72/D68). The identity
// tree (identity/fleetreg) defines a `RevocationSink` Go interface
//
//	AppendRevocation(ctx context.Context, art FleetRevocationArtifact) (RevocationResult, error)
//
// that an operator's emergency fleet-wide kill-switch rides — NOT a new proto,
// NOT a new RPC ("two cadences, no third channel", D72). identity/fleetreg drives
// that interface through fleetreg.RevocationPublisher.RevokeTokens; in tests an
// in-process fake (spyRevSink) satisfies it. In PRODUCTION the satisfier is THIS
// adapter: a fleet-revocation/v1 artifact is appended to the policy_log under the
// single bigserial seq namespace (D72), and the existing one-per-host
// WatchPolicies fan-out (service.go) delivers it inside the prepare/commit
// barrier + revocation sweep — it inherits the POL-4 seconds-scale
// push-to-enforced bar exactly as every other policy artifact does (doc 19 §7,
// §13 fleet-revocation-clock row). The rung-conditional sever of established
// flows is the Rust consumer's job (ds-policy-snapshot::sweep_fleet_revocations
// + ds-nft's frozen flush_session call-site) — this file is producer-only and
// orders nothing downstream of the append.
//
// SECRET DISCIPLINE (the whole reason this file is careful, doc 19 §7/§9): a
// revocation entry carries ONLY a hex chain fingerprint or a unique hex block
// identifier — NEVER token bytes. This adapter re-checks that structural fence on
// every entry before it serializes the payload (belt-and-suspenders over the
// identity-side constructors), so token bytes can never enter the policy_log even
// if a mis-populated mirror struct reaches this seam.
//
// IMPORT-BOUNDARY NOTE (the one-shared-module rule, ci.yml import-boundary gate;
// D80): the orchestrator tree may import ONLY proto/gen/go across a seam, so it
// must NOT import identity/fleetreg. The seam's value types — FleetRevocation
// Artifact / RevocationResult / FleetRevocationEntry — are therefore MIRRORED
// here field-for-field (FleetRevocationArtifact / FleetRevocationResult /
// FleetRevocationEntry), all built from stdlib string values, so the mirror is
// byte-for-byte the same payload. The wiring point that hands a
// *FleetRevocationSink to a fleetreg.RevocationSink lives in a tree allowed to
// import both (fleetreg's cmd / an assurance bridge); a one-line forwarding shim
// there closes the named-type gap. The local `revocationSink` interface below is
// the compile-time statement of that contract: AppendRevocation's signature here
// matches the fleetreg seam's exactly (modulo the mirrored, identically-shaped
// value types).
//
// Governing decisions: D102/P-R6 (emergency fleet revocation as a policy
// artifact), D72 (fleet = policy artifact under policy_log, no third channel),
// D68 (shared flush_session sever primitive, cited not restated), D50 (synthetic
// fixtures, no live host), D80 (cross-tree only via proto/gen/go). Primary doc:
// docs/19-scoped-agent-credentials-design.md §7, §13.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// RevocationSchemaVersion is the versioned schema tag every appended
// fleet-revocation artifact carries (doc 19 §7). It MUST match
// fleetreg.RevocationSchemaVersion — the identity producer stamps it and this
// adapter re-asserts it — so a consumer that negotiates on the tag sees the same
// value regardless of which side built the artifact.
const RevocationSchemaVersion = "fleet-revocation/v1"

// FleetRevocationKind tags the policy_log rows this adapter appends: a fleet-scope
// token-revocation artifact (doc 19 §7). It is a distinct PolicyKind so the
// composer / sweep can classify the row as a fleet-revocation artifact (vs an
// ordinary composed append, an ask-grant, or a fleet-digest) without parsing the
// payload — the same tag-not-body classification the FleetDigestKind rows use. It
// is defined here (not in store.records) because this adapter — not the store —
// owns the fleet-revocation artifact shape; the store stays a generic append
// surface.
const FleetRevocationKind store.PolicyKind = "fleet_revocation"

// fingerprintHexLen is the hex-string length of a SHA-256 chain fingerprint
// (D124, SHA-256 only): 32 bytes → 64 lower-hex characters. Mirrors
// fleetreg.fingerprintHexLen; pinned so a raw token cannot pass as a fingerprint.
const fingerprintHexLen = sha256.Size * 2

// blockIDHexMaxLen bounds a unique block identifier's hex length. Biscuit native
// per-block revocation ids are 64-byte Ed25519 block signatures (128 hex, doc 19
// §7 OQ6 resolution); the bound is exactly that so a native id keys BlockID
// directly while an over-long blob (a possible token smuggle) is rejected.
// Mirrors fleetreg.blockIDHexMaxLen.
const blockIDHexMaxLen = 128

// FleetRevocationEntry is the orchestrator-side MIRROR of
// fleetreg.FleetRevocationEntry (doc 19 §7/§9): ONE revoked token, named by a hex
// chain fingerprint OR a unique hex block identifier — never by its bytes.
// Exactly one field is set; both are lower-hex encoded. The fields match the
// fleetreg seam's struct one-for-one so the produced policy_log payload is
// identical regardless of which side builds it.
type FleetRevocationEntry struct {
	// Fingerprint is the hex-lowercase SHA-256 chain fingerprint of the revoked
	// token's revocation id. Empty when the entry is keyed by BlockID instead.
	Fingerprint string
	// BlockID is a hex-lowercase unique block/revocation identifier (e.g.
	// Biscuit's native per-block revocation id, §7 OQ6). Empty when the entry is
	// keyed by Fingerprint instead.
	BlockID string
}

// id returns the entry's non-empty identifier (fingerprint or block id) — for
// dedup and log provenance. Never any token bytes.
func (e FleetRevocationEntry) id() string {
	if e.Fingerprint != "" {
		return e.Fingerprint
	}
	return e.BlockID
}

// FleetRevocationArtifact is the orchestrator-side MIRROR of
// fleetreg.FleetRevocationArtifact (doc 19 §7): one versioned token-revocation
// artifact as it is appended to the policy_log. SchemaVersion is
// [RevocationSchemaVersion]; Entries is the revoked-token set (fingerprint/
// block-id only, NEVER token bytes); BatchID correlates the append with its ack
// (provenance, doc 16 §6.5). An empty Entries set is rejected fail-closed — a
// revocation names at least one token. The fields match the fleetreg seam's
// struct one-for-one so the produced payload is identical regardless of producer.
type FleetRevocationArtifact struct {
	SchemaVersion string
	Entries       []FleetRevocationEntry
	BatchID       string
}

// FleetRevocationResult is the orchestrator-side MIRROR of
// fleetreg.RevocationResult: the outcome of one fleet-revocation append. Seq is
// the assigned policy_log bigserial (THE single policy version namespace, D72);
// Committed is true iff the append landed (fail-closed: an uncommitted artifact
// is NOT enforced fleet-wide, exactly as an uncommitted digest ack blocks the
// session path). BatchID echoes the request; Count echoes how many entries were
// published.
type FleetRevocationResult struct {
	Seq       uint64
	Committed bool
	BatchID   string
	Count     int
}

// revocationSink restates fleetreg.RevocationSink's method set in orchestrator
// terms (over the mirrored value types). It is the compile-time CONTRACT
// statement: *FleetRevocationSink must satisfy this, and this signature matches
// the fleetreg seam's AppendRevocation one-for-one (the named value types differ
// only because the import-boundary gate forbids importing identity/fleetreg here
// — their fields and wire payload are identical). The production wiring shim that
// bridges the two named interfaces lives in a tree that may import both.
type revocationSink interface {
	AppendRevocation(ctx context.Context, art FleetRevocationArtifact) (FleetRevocationResult, error)
}

// ErrEmptyRevocation is returned when an artifact carries no entries: a
// fleet-revocation names at least one revoked token, so an empty artifact is
// never valid (it would append a meaningless row and burn a seq for nothing).
var ErrEmptyRevocation = errors.New("policylog: fleet revocation artifact requires at least one entry (fail-closed)")

// ErrRevocationSchema is returned when an artifact's schema tag is not
// [RevocationSchemaVersion]: the adapter refuses to append an artifact shape a
// consumer would not recognize (fail-closed on a version skew).
var ErrRevocationSchema = errors.New("policylog: fleet revocation artifact carries an unrecognized schema version (fail-closed)")

// FleetRevocationSink is the production fleetreg.RevocationSink satisfier: it
// appends an emergency fleet-revocation artifact as a policy_log row on the
// orchestrator's AppendPolicy path, so the existing one-per-host WatchPolicies
// fan-out delivers it (doc 19 §7; D72). A zero FleetRevocationSink is not usable;
// construct with NewFleetRevocationSink.
type FleetRevocationSink struct {
	appender policyAppender
	actor    string // recorded on every appended row (D36 audit trail)
}

// NewFleetRevocationSink builds the adapter over an AppendPolicy seam and the
// actor recorded on every fleet-revocation row. The log IS the audit trail (D36),
// so a revocation artifact carries WHO published it; the actor defaults to a
// stable system identity when empty (an emergency kill-switch is driven by a
// platform/operator surface, but it is still attributed).
func NewFleetRevocationSink(appender policyAppender, actor string) *FleetRevocationSink {
	if actor == "" {
		actor = "fleet-revocation-producer"
	}
	return &FleetRevocationSink{appender: appender, actor: actor}
}

// AppendRevocation appends ONE fleet-revocation artifact to the policy_log and
// returns its assigned seq + commit state — the production realization of the
// identity-side RevocationSink seam (doc 19 §7). It re-validates the schema
// version and every entry (no-token-bytes, exactly-one-identifier), serializes
// the artifact into a canonical, order-stable payload (so an equal entry set
// always hashes equal), stamps a content hash, and appends a FleetRevocationKind
// row through the AppendPolicy leg; the store assigns the bigserial seq (D72).
//
// Fail-closed: an empty entry set, a bad schema tag, an entry that is not a
// bounded lower-hex identifier, a serialization failure, or a store append error
// returns a non-nil error and a non-committed result — exactly as an uncommitted
// revocation ack must not let an operator believe a stolen token is dead. On a
// clean append Committed is true and Seq is the store-assigned policy version.
func (s *FleetRevocationSink) AppendRevocation(ctx context.Context, art FleetRevocationArtifact) (FleetRevocationResult, error) {
	if s == nil || s.appender == nil {
		return FleetRevocationResult{}, errors.New("policylog: nil fleet revocation sink (fail-closed)")
	}
	if art.SchemaVersion != RevocationSchemaVersion {
		return FleetRevocationResult{BatchID: art.BatchID}, fmt.Errorf(
			"%w: got %q, want %q", ErrRevocationSchema, art.SchemaVersion, RevocationSchemaVersion)
	}
	if len(art.Entries) == 0 {
		return FleetRevocationResult{BatchID: art.BatchID}, ErrEmptyRevocation
	}
	payload, err := marshalRevocationArtifact(art)
	if err != nil {
		return FleetRevocationResult{BatchID: art.BatchID}, fmt.Errorf(
			"policylog: marshal fleet revocation artifact (batch=%q): %w (fail-closed)", art.BatchID, err)
	}
	sum := sha256.Sum256(payload)
	row := store.PolicyLogRow{
		Kind:        FleetRevocationKind,
		Actor:       s.actor,
		ContentHash: hex.EncodeToString(sum[:]),
		Payload:     payload,
	}
	appended, err := s.appender.AppendPolicy(ctx, row)
	if err != nil {
		// Fail-closed: the artifact did NOT land, so the revocation is not enforced.
		return FleetRevocationResult{BatchID: art.BatchID, Count: len(art.Entries)}, fmt.Errorf(
			"policylog: append fleet revocation artifact (batch=%q): %w (fail-closed: revocation not applied)",
			art.BatchID, err)
	}
	if appended.Seq < 0 {
		return FleetRevocationResult{BatchID: art.BatchID, Count: len(art.Entries)}, fmt.Errorf(
			"policylog: store returned non-positive seq %d for fleet revocation (batch=%q): fail-closed", appended.Seq, art.BatchID)
	}
	return FleetRevocationResult{
		Seq:       uint64(appended.Seq),
		Committed: true,
		BatchID:   art.BatchID,
		Count:     len(art.Entries),
	}, nil
}

// ---------------------------------------------------------------------------
// ds.fleet_revocation.v1 envelope codec — the SINGLE framing source.
//
// This is the one encode/decode pair for the versioned, line-framed
// ds.fleet_revocation.v1 policy_log payload: a self-describing header
// (`ds.fleet_revocation.v1`), the schema tag, the batch id, an entry count, then
// one line per entry (`e=<f|b>:<hexid>\n`, `f` = fingerprint, `b` = block id).
// Because every id is bounded lower-hex, a line boundary is an unambiguous
// delimiter (unlike the fleet-digest codec, whose raw proto entries may contain
// '\n' and so need a length prefix). Both a writer and any future in-tree reader
// route through this pair, so a format change is a single edit both pick up in
// lockstep.

const (
	revEnvelopeHeader  = "ds.fleet_revocation.v1"
	revEnvelopeSchema  = "schema="
	revEnvelopeBatch   = "batch="
	revEnvelopeCount   = "entries="
	revEnvelopeEntry   = "e=" // followed by "<f|b>:" then the lower-hex identifier
	revKindFingerprint = "f"
	revKindBlockID     = "b"
)

// validateRevHexID enforces that id is a lower-hex string of even length in
// [minLen,maxLen]. Lower-hex + even-length + bounded is the structural fence that
// keeps a raw token (which is neither fixed-length nor hex) out of a revocation
// artifact — the orchestrator-side belt-and-suspenders over the identity
// constructors. It never echoes the whole value on failure (a rejected value
// might be a mis-passed secret).
func validateRevHexID(kind, id string, minLen, maxLen int) error {
	if len(id) < minLen || len(id) > maxLen {
		return fmt.Errorf("policylog: %s has length %d, want in [%d,%d] (fail-closed: not a hex identifier)",
			kind, len(id), minLen, maxLen)
	}
	if len(id)%2 != 0 {
		return fmt.Errorf("policylog: %s has odd hex length %d (fail-closed)", kind, len(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("policylog: %s is not lower-hex at byte %d (fail-closed: not a hex identifier)", kind, i)
		}
	}
	return nil
}

// validateRevEntry re-checks the no-token-bytes invariant on a mirror entry:
// EXACTLY one identifier set, and it a bounded lower-hex string. Defense in depth
// against a directly-populated struct that bypassed the identity constructors.
func validateRevEntry(e FleetRevocationEntry) error {
	switch {
	case e.Fingerprint == "" && e.BlockID == "":
		return errors.New("policylog: revocation entry has neither a fingerprint nor a block id (fail-closed)")
	case e.Fingerprint != "" && e.BlockID != "":
		return errors.New("policylog: revocation entry sets BOTH fingerprint and block id (ambiguous; set exactly one)")
	case e.Fingerprint != "":
		return validateRevHexID("fingerprint", e.Fingerprint, fingerprintHexLen, fingerprintHexLen)
	default:
		return validateRevHexID("block id", e.BlockID, 2, blockIDHexMaxLen)
	}
}

// encodeRevEntry frames one validated entry into its canonical line form
// (`<f|b>:<hexid>`), NOT including the "e=" prefix or trailing newline (the
// caller owns those). The kind byte disambiguates a fingerprint from a block id
// so the reader reconstructs the exact FleetRevocationEntry field.
func encodeRevEntry(e FleetRevocationEntry) string {
	if e.Fingerprint != "" {
		return revKindFingerprint + ":" + e.Fingerprint
	}
	return revKindBlockID + ":" + e.BlockID
}

// marshalRevocationArtifact validates every entry, dedups by identifier, sorts
// the encoded entry lines (so entry ORDER never changes the payload bytes — two
// artifacts with the same entry SET hash equal), and frames the canonical
// ds.fleet_revocation.v1 payload. A nil/invalid entry fails the whole marshal
// closed (no half-formed artifact reaches the log).
func marshalRevocationArtifact(art FleetRevocationArtifact) ([]byte, error) {
	seen := make(map[string]struct{}, len(art.Entries))
	encoded := make([]string, 0, len(art.Entries))
	for i, e := range art.Entries {
		if err := validateRevEntry(e); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if _, dup := seen[e.id()]; dup {
			continue
		}
		seen[e.id()] = struct{}{}
		encoded = append(encoded, encodeRevEntry(e))
	}
	sort.Strings(encoded)

	var b strings.Builder
	b.WriteString(revEnvelopeHeader)
	b.WriteByte('\n')
	b.WriteString(revEnvelopeSchema)
	b.WriteString(art.SchemaVersion)
	b.WriteByte('\n')
	b.WriteString(revEnvelopeBatch)
	b.WriteString(art.BatchID)
	b.WriteByte('\n')
	b.WriteString(revEnvelopeCount)
	b.WriteString(strconv.Itoa(len(encoded)))
	b.WriteByte('\n')
	for _, enc := range encoded {
		b.WriteString(revEnvelopeEntry)
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// decodeRevocationArtifact is the inverse of marshalRevocationArtifact: it reads
// a ds.fleet_revocation.v1 payload back into its schema tag, batch id, and entry
// set, returning ok=false on ANY framing violation (fail-closed: a malformed
// artifact revokes nothing). Provided so an in-tree consumer (and the round-trip
// test) shares the single framing source with the writer; the live Rust sweep has
// its own recognizer against the same wire shape.
func decodeRevocationArtifact(payload []byte) (art FleetRevocationArtifact, ok bool) {
	rest := payload

	line, rest, found := revNextLine(rest)
	if !found || line != revEnvelopeHeader {
		return FleetRevocationArtifact{}, false
	}
	line, rest, found = revNextLine(rest)
	if !found || !strings.HasPrefix(line, revEnvelopeSchema) {
		return FleetRevocationArtifact{}, false
	}
	art.SchemaVersion = strings.TrimPrefix(line, revEnvelopeSchema)
	line, rest, found = revNextLine(rest)
	if !found || !strings.HasPrefix(line, revEnvelopeBatch) {
		return FleetRevocationArtifact{}, false
	}
	art.BatchID = strings.TrimPrefix(line, revEnvelopeBatch)
	line, rest, found = revNextLine(rest)
	if !found || !strings.HasPrefix(line, revEnvelopeCount) {
		return FleetRevocationArtifact{}, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, revEnvelopeCount))
	if err != nil || n < 0 {
		return FleetRevocationArtifact{}, false
	}

	entries := make([]FleetRevocationEntry, 0, n)
	for i := 0; i < n; i++ {
		line, rest, found = revNextLine(rest)
		if !found || !strings.HasPrefix(line, revEnvelopeEntry) {
			return FleetRevocationArtifact{}, false
		}
		body := strings.TrimPrefix(line, revEnvelopeEntry)
		kind, id, cut := strings.Cut(body, ":")
		if !cut {
			return FleetRevocationArtifact{}, false
		}
		var e FleetRevocationEntry
		switch kind {
		case revKindFingerprint:
			e = FleetRevocationEntry{Fingerprint: id}
		case revKindBlockID:
			e = FleetRevocationEntry{BlockID: id}
		default:
			return FleetRevocationArtifact{}, false
		}
		if err := validateRevEntry(e); err != nil {
			return FleetRevocationArtifact{}, false
		}
		entries = append(entries, e)
	}
	if len(rest) != 0 {
		return FleetRevocationArtifact{}, false
	}
	art.Entries = entries
	return art, true
}

// revNextLine splits off the bytes up to (not including) the next '\n', returning
// the line as a string, the remainder after the '\n', and whether a terminated
// line was found. A trailing unterminated segment returns found=false.
func revNextLine(b []byte) (line string, rest []byte, found bool) {
	for i := range b {
		if b[i] == '\n' {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", b, false
}

// Compile-time assertions:
//   - *FleetRevocationSink satisfies the local revocationSink mirror (which
//     restates fleetreg.RevocationSink's method set over the mirrored value
//     types). This is the in-tree, import-boundary-legal statement that the
//     adapter implements the fleet-revocation contract; the production shim that
//     binds it to the actual fleetreg.RevocationSink named interface lives in a
//     both-importing tree.
//   - *Service satisfies policyAppender, so the live PolicyService append path is
//     a drop-in for the adapter (the production fan-out).
var (
	_ revocationSink = (*FleetRevocationSink)(nil)
	_ policyAppender = (*Service)(nil)
)
