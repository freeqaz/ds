package policylog

// This file is the orchestrator-side PRODUCTION satisfier for the identity
// fleet-digest publish/revoke seam (doc 16 §6.2; D84/D72/D73). The identity tree
// (identity/digest) defines a `PolicySink` Go interface
//
//	AppendFleetDigest(ctx context.Context, art FleetPolicyArtifact) (FleetPolicyResult, error)
//
// that fleet-scope register/revoke rides — NOT a new proto, NOT a new RPC ("two
// cadences, no third channel", D72). identity/fleetreg drives that interface
// through digest.PublishFleetPolicy / digest.RevokeFleetPolicy; in tests an
// in-process fake satisfies it. In PRODUCTION the satisfier is THIS adapter: a
// fleet-scope digest artifact is appended to the policy_log under the single
// bigserial seq namespace (D72), and the existing one-per-host WatchPolicies
// fan-out (service.go) delivers it inside the prepare/commit barrier +
// revocation sweep — it inherits the POL-4 push-to-enforced bar exactly as every
// other policy artifact does (doc 16 §6.2).
//
// IMPORT-BOUNDARY NOTE (the one-shared-module rule, ci.yml import-boundary gate):
// the orchestrator tree may import ONLY proto/gen/go across a seam, so it must
// NOT import identity/digest. The seam's two value types — FleetPolicyArtifact
// and FleetPolicyResult — are therefore MIRRORED here field-for-field
// (FleetDigestArtifact / FleetDigestResult), and the seam's Entries element type
// (identityv1.DigestEntry) is the proto/gen/go type both sides share, so the
// mirror is byte-for-byte the same wire payload. The wiring point that hands a
// *FleetDigestSink to a digest.PolicySink lives in a tree allowed to import both
// (fleetreg's cmd / an assurance bridge); a one-line forwarding shim there closes
// the named-type gap. The local `policySink` interface below is the compile-time
// statement of that contract: AppendFleetDigest's signature here matches the
// digest seam's exactly (modulo the mirrored, identically-shaped value types).
//
// Governing decisions: D84 (fleet-digest registration surface), D72 (fleet =
// policy artifact under policy_log, no third channel), D73 (digest-set version is
// a content id, never a second namespace), D50 (synthetic fixtures, no live
// host). Primary doc: docs/16-identity-and-credentials-design.md §6.2, §9.

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
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"

	"google.golang.org/protobuf/proto"
)

// FleetDigestKind tags the policy_log rows this adapter appends: a fleet-scope
// digest artifact (doc 16 §6.2). It is a distinct PolicyKind so the composer /
// sweep can classify the row as a fleet-digest artifact (vs an ordinary composed
// append or a session-scoped ask-grant) without parsing the payload. It is
// defined here (not in store.records) because this adapter — not the store — owns
// the fleet-digest artifact shape; the store stays a generic append surface.
const FleetDigestKind store.PolicyKind = "fleet_digest"

// FleetDigestArtifact is the orchestrator-side MIRROR of
// identity/digest.FleetPolicyArtifact (doc 16 §6.2): one fleet-scope digest
// registration as it is appended to the policy_log. KeyID is the HMAC key id
// every entry was derived under (a re-key appends the new-key artifact before
// retiring the old one); Entries is the DIGEST_SCOPE_FLEET entry set
// (forbidden-class fleet digests); BatchID correlates the append with its ack
// (provenance, doc 16 §6.5). An EMPTY Entries set under a KeyID is a REVOKE — the
// retire of that key's fleet digests (digest.RevokeFleetPolicy appends exactly
// that), which the policy-log revocation sweep treats as "no entries under this
// key id" (doc 16 §6.2). The fields match the digest seam's struct one-for-one so
// the produced policy_log payload is identical regardless of which side builds it.
type FleetDigestArtifact struct {
	KeyID   string
	Entries []*identityv1.DigestEntry
	BatchID string
}

// FleetDigestResult is the orchestrator-side MIRROR of
// identity/digest.FleetPolicyResult: the outcome of one fleet-scope append. Seq
// is the assigned policy_log bigserial (THE single policy version namespace, D72)
// the store returned; Committed is true iff the append landed (the policy-stream
// analogue of DigestPublishResponse.committed) — fail-closed semantics mean an
// uncommitted artifact is NOT live. KeyID and BatchID echo the request for
// traceability (which artifact, under which key).
type FleetDigestResult struct {
	Seq       uint64
	Committed bool
	KeyID     string
	BatchID   string
}

// policySink restates identity/digest.PolicySink's method set in orchestrator
// terms (over the mirrored value types). It is the compile-time CONTRACT
// statement: *FleetDigestSink must satisfy this, and this signature matches the
// digest seam's AppendFleetDigest one-for-one (the named value types differ only
// because the import-boundary gate forbids importing identity/digest here — their
// fields and wire payload are identical). The production wiring shim that bridges
// the two named interfaces lives in a tree that may import both.
type policySink interface {
	AppendFleetDigest(ctx context.Context, art FleetDigestArtifact) (FleetDigestResult, error)
}

// FleetDigestSink consumes the package's existing narrow append seam
// (policyAppender in askapproval.go: just store.AppendPolicy). *Service satisfies
// it directly; a test fake satisfies it too (D50). The adapter depends only on the
// one method it uses, never the whole Service — so it composes onto the live
// PolicyService append path AND onto a synthetic store fan-out identically.

// ErrEmptyKeyID is returned when an artifact carries no key id: every fleet
// digest artifact — publish OR revoke — names the key its entries were derived
// under (or, for a revoke, the key being retired), so an empty key id is never a
// valid artifact (it would make the revocation sweep's "entries under this key
// id" classification meaningless).
var ErrEmptyKeyID = errors.New("policylog: fleet digest artifact requires a non-empty key id")

// FleetDigestSink is the production digest.PolicySink satisfier: it appends
// fleet-scope digest publish/revoke as policy_log artifacts on the orchestrator's
// AppendPolicy path, so the existing one-per-host WatchPolicies fan-out delivers
// them (doc 16 §6.2; D72). A zero FleetDigestSink is not usable; construct with
// NewFleetDigestSink.
type FleetDigestSink struct {
	appender policyAppender
	actor    string // recorded on every appended row (D36 audit trail)
}

// NewFleetDigestSink builds the adapter over an AppendPolicy seam and the actor
// recorded on every fleet-digest row. The log IS the audit trail (D36), so a
// fleet-digest artifact carries WHO published/revoked it; the actor defaults to a
// stable system identity when empty (the fleet-digest producer is a platform
// service, not an interactive principal — but it is still attributed).
func NewFleetDigestSink(appender policyAppender, actor string) *FleetDigestSink {
	if actor == "" {
		actor = "fleet-digest-producer"
	}
	return &FleetDigestSink{appender: appender, actor: actor}
}

// AppendFleetDigest appends ONE fleet-scope digest artifact to the policy_log and
// returns its assigned seq + commit state — the production realization of the
// identity-side PolicySink seam (doc 16 §6.2). It serializes the artifact into a
// canonical, order-stable payload (so an equal entry set always hashes equal,
// D73's content-id property), stamps a content hash, and appends a FleetDigestKind
// row through the AppendPolicy leg; the store assigns the bigserial seq (D72).
//
// REVOKE: an empty Entries set is the retire of KeyID's fleet digests
// (digest.RevokeFleetPolicy's shape) — it still appends a row (the revocation
// rides the SAME policy_log seq + the POL-4 sweep, doc 16 §6.2), carrying the
// retired key id and no entries, which the sweep treats as "no entries under this
// key id".
//
// Fail-closed: a missing key id, a serialization failure, or a store append error
// returns a non-nil error and a non-committed result — exactly as an uncommitted
// DigestPublish ack blocks the session path. On a clean append Committed is true
// and Seq is the store-assigned policy version.
func (s *FleetDigestSink) AppendFleetDigest(ctx context.Context, art FleetDigestArtifact) (FleetDigestResult, error) {
	if s == nil || s.appender == nil {
		return FleetDigestResult{}, errors.New("policylog: nil fleet digest sink (fail-closed)")
	}
	if art.KeyID == "" {
		return FleetDigestResult{}, ErrEmptyKeyID
	}
	payload, err := marshalFleetArtifact(art)
	if err != nil {
		return FleetDigestResult{}, fmt.Errorf("policylog: marshal fleet digest artifact (key=%q batch=%q): %w (fail-closed)", art.KeyID, art.BatchID, err)
	}
	sum := sha256.Sum256(payload)
	row := store.PolicyLogRow{
		Kind:        FleetDigestKind,
		Actor:       s.actor,
		ContentHash: hex.EncodeToString(sum[:]),
		Payload:     payload,
	}
	appended, err := s.appender.AppendPolicy(ctx, row)
	if err != nil {
		// Fail-closed: the artifact did NOT land, so it is not live. The caller's
		// error log names which artifact (key + batch) failed to apply.
		return FleetDigestResult{KeyID: art.KeyID, BatchID: art.BatchID}, fmt.Errorf(
			"policylog: append fleet digest artifact (key=%q batch=%q): %w (fail-closed: artifact not applied)",
			art.KeyID, art.BatchID, err)
	}
	if appended.Seq < 0 {
		return FleetDigestResult{KeyID: art.KeyID, BatchID: art.BatchID}, fmt.Errorf(
			"policylog: store returned non-positive seq %d for fleet digest (key=%q): fail-closed", appended.Seq, art.KeyID)
	}
	return FleetDigestResult{
		Seq:       uint64(appended.Seq),
		Committed: true,
		KeyID:     art.KeyID,
		BatchID:   art.BatchID,
	}, nil
}

// ---------------------------------------------------------------------------
// ds.fleet_digest.v1 envelope codec — the SINGLE framing source.
//
// This is the one encode/decode pair for the versioned, line-framed
// ds.fleet_digest.v1 policy_log payload: a self-describing header
// (`ds.fleet_digest.v1`), the key id, the batch id, an entry count, then one
// length-framed frame per raw entry (`e=<hexlen>:<rawbytes>\n`). The hex length
// prefix — never a line boundary — delimits each entry because a marshaled
// DigestEntry may itself contain a '\n' byte.
//
// BOTH sides route through this pair: the writer marshalFleetArtifact
// (encodeFleetEnvelope) and the POL-4 sweep's reader parseFleetEnvelope
// (decodeFleetEnvelope, compose.go). Single-sourcing the framing here makes a
// format change a single edit that both producer and consumer pick up in
// lockstep — the writer can never drift from the reader. The codec operates on
// RAW entry bytes (the lowest common denominator): the writer hands it the
// deterministically-marshaled, sorted entry encodings; the reader hex-encodes the
// raw frames it returns into the sweep's sortable content-id identity (D73).
//
// fleetEnvelope field keys — the single framing vocabulary both sides share.
const (
	fleetEnvelopeHeader = "ds.fleet_digest.v1"
	fleetEnvelopeKey    = "key="
	fleetEnvelopeBatch  = "batch="
	fleetEnvelopeCount  = "entries="
	fleetEnvelopeEntry  = "e=" // followed by "<hexlen>:" then raw entry bytes
)

// encodeFleetEnvelope frames a fleet-digest artifact's key id, batch id, and
// already-encoded (raw) entry bytes into the canonical ds.fleet_digest.v1 payload.
// The caller is responsible for the entry encoding + sort (the content-id
// stability, D73); this routine owns only the framing, so the bytes it emits are
// the single source the reader parses back. An empty entries slice yields the
// REVOKE shape (`entries=0`, no entry frames) — distinct from a parse failure.
func encodeFleetEnvelope(keyID, batchID string, encodedEntries [][]byte) []byte {
	var b strings.Builder
	// Versioned, line-framed header so the body is self-describing and stable.
	b.WriteString(fleetEnvelopeHeader)
	b.WriteByte('\n')
	b.WriteString(fleetEnvelopeKey)
	b.WriteString(keyID)
	b.WriteByte('\n')
	b.WriteString(fleetEnvelopeBatch)
	b.WriteString(batchID)
	b.WriteByte('\n')
	b.WriteString(fleetEnvelopeCount)
	b.WriteString(strconv.Itoa(len(encodedEntries)))
	b.WriteByte('\n')
	out := []byte(b.String())
	for _, enc := range encodedEntries {
		// length-prefixed entry framing (hex length + raw bytes) so the boundary
		// between entries is unambiguous and the whole body is order-stable.
		out = append(out, fleetEnvelopeEntry...)
		out = append(out, []byte(strconv.FormatInt(int64(len(enc)), 16))...)
		out = append(out, ':')
		out = append(out, enc...)
		out = append(out, '\n')
	}
	return out
}

// decodeFleetEnvelope is the inverse of encodeFleetEnvelope: it reads a
// ds.fleet_digest.v1 payload back into its key id and the RAW entry byte frames,
// returning ok=false on ANY framing violation (fail-closed: a malformed artifact
// advances no key's state). Entry bodies are read by their hex length prefix —
// never by line boundary — because a marshaled DigestEntry may itself contain a
// '\n'. An `entries=0` envelope decodes ok with an EMPTY entry set: the legitimate
// REVOKE shape, distinct from a parse failure. The batch id is required framing but
// not returned (no consumer needs it).
func decodeFleetEnvelope(payload []byte) (keyID string, entries [][]byte, ok bool) {
	rest := payload

	// Header line.
	line, rest, found := fleetNextLine(rest)
	if !found || line != fleetEnvelopeHeader {
		return "", nil, false
	}
	// key= line.
	line, rest, found = fleetNextLine(rest)
	if !found || !strings.HasPrefix(line, fleetEnvelopeKey) {
		return "", nil, false
	}
	keyID = strings.TrimPrefix(line, fleetEnvelopeKey)
	// batch= line (value not needed by any consumer, but the framing is required).
	line, rest, found = fleetNextLine(rest)
	if !found || !strings.HasPrefix(line, fleetEnvelopeBatch) {
		return "", nil, false
	}
	// entries=<n> line.
	line, rest, found = fleetNextLine(rest)
	if !found || !strings.HasPrefix(line, fleetEnvelopeCount) {
		return "", nil, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, fleetEnvelopeCount))
	if err != nil || n < 0 {
		return "", nil, false
	}

	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		// Each entry frame is: "e=" <hexlen> ":" <rawbytes> "\n". Read the length
		// prefix up to ':' then consume exactly that many raw bytes (which may
		// contain '\n'), then the trailing '\n'.
		if !strings.HasPrefix(string(rest), fleetEnvelopeEntry) {
			return "", nil, false
		}
		rest = rest[len(fleetEnvelopeEntry):]
		colon := fleetIndexByte(rest, ':')
		if colon < 0 {
			return "", nil, false
		}
		length, err := strconv.ParseInt(string(rest[:colon]), 16, 64)
		if err != nil || length < 0 {
			return "", nil, false
		}
		rest = rest[colon+1:]
		if int64(len(rest)) < length {
			return "", nil, false
		}
		raw := rest[:length]
		rest = rest[length:]
		// Trailing newline after the raw entry bytes.
		if len(rest) == 0 || rest[0] != '\n' {
			return "", nil, false
		}
		rest = rest[1:]
		// Copy so the returned slice does not alias the caller's payload backing array.
		frame := make([]byte, length)
		copy(frame, raw)
		out = append(out, frame)
	}
	// Nothing legitimate follows the declared entry count.
	if len(rest) != 0 {
		return "", nil, false
	}
	return keyID, out, true
}

// fleetNextLine splits off the bytes up to (not including) the next '\n', returning
// the line as a string, the remainder after the '\n', and whether a terminated line
// was found. A trailing unterminated segment returns found=false (the framing always
// newline-terminates its header lines).
func fleetNextLine(b []byte) (line string, rest []byte, found bool) {
	i := fleetIndexByte(b, '\n')
	if i < 0 {
		return "", b, false
	}
	return string(b[:i]), b[i+1:], true
}

// fleetIndexByte returns the index of the first occurrence of c in b, or -1.
func fleetIndexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// fleetArtifactEnvelope is the canonical, deterministically-serialized policy_log
// payload of a fleet-digest artifact. It carries the key id, batch id, and the
// DIGEST_SCOPE_FLEET entry set; the entries are proto-marshaled deterministically
// and sorted so an equal artifact always produces equal bytes (the content-id
// property, D73). It is a proto.Message wrapper-free, hand-rolled framing because
// the orchestrator owns the policy_log payload format (doc 13 §3: the layer parse
// is ds-contracts'; this is a fleet-digest artifact body, opaque to the composer
// beyond its FleetDigestKind tag). The framing itself is the shared
// encodeFleetEnvelope codec — the SINGLE source both this writer and the sweep's
// reader (parseFleetEnvelope) route through.
func marshalFleetArtifact(art FleetDigestArtifact) ([]byte, error) {
	// Deterministic per-entry marshal, then sort the encoded entries so entry
	// ORDER never changes the payload bytes (two artifacts with the same entry
	// SET hash equal regardless of producer iteration order).
	encoded := make([][]byte, 0, len(art.Entries))
	for i, e := range art.Entries {
		if e == nil {
			return nil, fmt.Errorf("nil entry at index %d", i)
		}
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			return nil, fmt.Errorf("entry at index %d is scope %v, not DIGEST_SCOPE_FLEET (doc 16 §6.2)", i, e.GetScope())
		}
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("marshal entry %d: %w", i, err)
		}
		encoded = append(encoded, b)
	}
	sort.Slice(encoded, func(i, j int) bool { return string(encoded[i]) < string(encoded[j]) })

	// Single-source the framing through the shared codec (the reader's inverse).
	return encodeFleetEnvelope(art.KeyID, art.BatchID, encoded), nil
}

// Compile-time assertions:
//   - *FleetDigestSink satisfies the local policySink mirror (which restates
//     identity/digest.PolicySink's method set over the mirrored value types). This
//     is the in-tree, import-boundary-legal statement that the adapter implements
//     the fleet-digest publish/revoke contract; the production shim that binds it
//     to the actual digest.PolicySink named interface lives in a both-importing
//     tree.
//   - *Service satisfies policyAppender, so the live PolicyService append path is
//     a drop-in for the adapter (the production fan-out).
var (
	_ policySink     = (*FleetDigestSink)(nil)
	_ policyAppender = (*Service)(nil)
)
