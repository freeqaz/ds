// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// schema_audit.go — REAL implementations of the LOG-1 wire schema + LOG-5
// credential-audit seams of boundary/flowlog (the boundary ships RED stubs).
//
// Three contracts live here:
//
//   - LOG-1 event schema (doc 09 §7 LOG-1): a stable, lossless, byte-stable wire
//     codec (MarshalEvent / UnmarshalEvent) over the sealed Event union, plus
//     Validate over each message — SessionRef required, POL-3 provenance required,
//     and the CredentialFingerprint FULL format (FingerprintPrefix + exactly 64
//     lowercase hex) enforced so a raw credential cannot be smuggled into the
//     fingerprint field.
//
//   - LOG-5 fingerprint (doc 09 §7 LOG-5 / D8): FingerprintCredential is the single
//     sanctioned secret→event path — SHA-256 over the secret, rendered as
//     FingerprintPrefix + 64 lowercase hex. Stable (joinable), avalanche (one bit
//     flips ~half the digest, so no offset/truncated slice of the secret survives),
//     non-reversible, fixed-length, and rejecting the empty secret with
//     ErrEmptySecret.
//
//   - LOG-5 audit query (doc 09 §7 LOG-5 Done-when): AuditQuerier answers "which
//     session used the <Service> key, when, for what request" over a window from
//     the shipped off-box store.
//
// These satisfy the boundary/flowlog seams FROM HERE (the tlsproxyinspect/
// netflowadapter precedent); boundary/flowlog is never edited.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
)

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 fingerprint — the single sanctioned secret→event path.
// ───────────────────────────────────────────────────────────────────────────

// FingerprintCredential is the real LOG-5 fingerprint: a SHA-256 digest of the
// secret rendered in the frozen FingerprintPrefix + 64-lowercase-hex format. It
// is the assurance twin of the boundary flowlog.FingerprintCredential stub. The
// empty secret is rejected (a missing secret is never silently fingerprinted).
//
// SHA-256 gives all four LOG-5 properties for free: stable (deterministic →
// joinable across sessions/time), avalanche (one input-bit flip changes ~half
// the output bits, so NO offset/truncated window of the secret survives in any
// encoding — the boundary windowed-leak scan passes), non-reversible (preimage
// resistance), and fixed-length (64 hex chars for any input size).
func FingerprintCredential(secret []byte) (flowlog.CredentialFingerprint, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("netflowadapter: %w", flowlog.ErrEmptySecret)
	}
	sum := sha256.Sum256(secret)
	return flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + hex.EncodeToString(sum[:])), nil
}

// validFingerprint enforces the FULL CredentialFingerprint format (LOG-1.e /
// LOG-5.c): the exact prefix plus EXACTLY FingerprintHexLen LOWERCASE hex
// digits. A bare HasPrefix check would accept a raw token smuggled behind the
// prefix — this rejects anything that is not the precise digest shape.
func validFingerprint(fp flowlog.CredentialFingerprint) bool {
	s := string(fp)
	if !strings.HasPrefix(s, flowlog.FingerprintPrefix) {
		return false
	}
	hexPart := s[len(flowlog.FingerprintPrefix):]
	if len(hexPart) != flowlog.FingerprintHexLen {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-1 Validate — SessionRef required, POL-3 provenance required, fingerprint
// FULL format enforced. These are the real validators the boundary stubs return
// ErrNotImplemented for.
// ───────────────────────────────────────────────────────────────────────────

// validateSessionRef rejects a zero SessionID or Iface — no event exists without
// session attribution (LOG-1). The returned error NAMES the missing field so a CI
// failure points at the exact gap.
func validateSessionRef(ref flowlog.SessionRef) error {
	if ref.SessionID == "" {
		return fmt.Errorf("netflowadapter: event missing required SessionRef.SessionID")
	}
	if ref.Iface == "" {
		return fmt.Errorf("netflowadapter: event missing required SessionRef.Iface")
	}
	return nil
}

// validateProvenance enforces POL-3: a PolicyDecision missing RuleID, PolicyLayer
// or PolicyVersion fails — "why was this blocked?" must always have a one-line
// answer (doc 09 §6 POL-3 Done-when).
func validateProvenance(d flowlog.PolicyDecision) error {
	if d.RuleID == "" {
		return fmt.Errorf("netflowadapter: PolicyDecision missing required provenance field RuleID")
	}
	if d.PolicyLayer == "" {
		return fmt.Errorf("netflowadapter: PolicyDecision missing required provenance field PolicyLayer")
	}
	if d.PolicyVersion == "" {
		return fmt.Errorf("netflowadapter: PolicyDecision missing required provenance field PolicyVersion")
	}
	return nil
}

// ValidateEvent is the real Validate for every LOG-1 message. It mirrors what the
// boundary flowlog Event.Validate() seams must do; it is exposed so the adapter's
// conformance tests assert the documented outcome against the real validator
// (the boundary stubs return ErrNotImplemented).
func ValidateEvent(ev flowlog.Event) error {
	if err := validateSessionRef(ev.Ref()); err != nil {
		return err
	}
	switch e := ev.(type) {
	case flowlog.PolicyDecision:
		return validateProvenance(e)
	case flowlog.DnsEvent:
		return validateProvenance(e.Decision)
	case flowlog.HttpEvent:
		return validateProvenance(e.Decision)
	case flowlog.CredentialUseEvent:
		if !validFingerprint(e.Fingerprint) {
			// A raw credential smuggled into the fingerprint field fails the FULL
			// format — the error names "fingerprint" (LOG-5).
			return fmt.Errorf("netflowadapter: CredentialUseEvent has an invalid credential fingerprint (must be %q + %d lowercase hex)", flowlog.FingerprintPrefix, flowlog.FingerprintHexLen)
		}
		return nil
	case flowlog.FlowRecord:
		return nil
	case flowlog.SpoolOverflow:
		return nil
	default:
		return fmt.Errorf("netflowadapter: unknown event type %T", ev)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-1 wire codec — a stable, lossless, byte-stable envelope over the sealed
// Event union. JSON with a discriminator tag is the Go-harness stand-in for the
// frozen protobuf wire contract: it round-trips losslessly and re-encodes
// byte-for-byte (deterministic field order). The codec carries ONLY the metadata
// fields the schema already exposes — no payload channel is introduced.
// ───────────────────────────────────────────────────────────────────────────

type eventKind string

const (
	kindFlow      eventKind = "FlowRecord"
	kindDns       eventKind = "DnsEvent"
	kindHTTP      eventKind = "HttpEvent"
	kindPolicy    eventKind = "PolicyDecision"
	kindCredUse   eventKind = "CredentialUseEvent"
	kindOverflow  eventKind = "SpoolOverflow"
	wireSeparator           = "|"
)

// MarshalEvent encodes an event as KIND|json(body). The discriminator preserves
// the concrete type across UnmarshalEvent so the round-trip is lossless, and
// encoding/json with struct field order is deterministic so re-encoding is
// byte-for-byte stable (LOG-1 Stage-0 freeze property).
func MarshalEvent(ev flowlog.Event) ([]byte, error) {
	var kind eventKind
	switch ev.(type) {
	case flowlog.FlowRecord:
		kind = kindFlow
	case flowlog.DnsEvent:
		kind = kindDns
	case flowlog.HttpEvent:
		kind = kindHTTP
	case flowlog.PolicyDecision:
		kind = kindPolicy
	case flowlog.CredentialUseEvent:
		kind = kindCredUse
	case flowlog.SpoolOverflow:
		kind = kindOverflow
	default:
		return nil, fmt.Errorf("netflowadapter: MarshalEvent: unknown event type %T", ev)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("netflowadapter: MarshalEvent(%T): %w", ev, err)
	}
	out := append([]byte(string(kind)+wireSeparator), body...)
	return out, nil
}

// UnmarshalEvent decodes a KIND|json(body) envelope back into the concrete event
// type named by the discriminator.
func UnmarshalEvent(data []byte) (flowlog.Event, error) {
	sep := -1
	for i := 0; i < len(data); i++ {
		if data[i] == wireSeparator[0] {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, fmt.Errorf("netflowadapter: UnmarshalEvent: missing discriminator separator")
	}
	kind := eventKind(data[:sep])
	body := data[sep+1:]
	switch kind {
	case kindFlow:
		var e flowlog.FlowRecord
		return e, json.Unmarshal(body, &e)
	case kindDns:
		var e flowlog.DnsEvent
		return e, json.Unmarshal(body, &e)
	case kindHTTP:
		var e flowlog.HttpEvent
		return e, json.Unmarshal(body, &e)
	case kindPolicy:
		var e flowlog.PolicyDecision
		return e, json.Unmarshal(body, &e)
	case kindCredUse:
		var e flowlog.CredentialUseEvent
		return e, json.Unmarshal(body, &e)
	case kindOverflow:
		var e flowlog.SpoolOverflow
		return e, json.Unmarshal(body, &e)
	default:
		return nil, fmt.Errorf("netflowadapter: UnmarshalEvent: unknown discriminator %q", kind)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 audit query — "which session used the <Service> key, when, for what
// request" over a window, from the shipped off-box store.
// ───────────────────────────────────────────────────────────────────────────

type auditQuerier struct{ store flowlog.Sink }

// NewAuditQuerier returns a real LOG-5 audit querier over the shipped store. It
// satisfies the boundary flowlog.AuditQuerier seam.
func NewAuditQuerier(store flowlog.Sink) flowlog.AuditQuerier { return &auditQuerier{store: store} }

// CredentialUses returns the CredentialUseEvents matching the query's Service and
// (optional) SessionID within the window. It reads the queryable off-box store —
// the audit answer is reconstructed from shipped telemetry, never from a side
// channel. A blank Service matches every service (the negative-space case: a
// pass-through window legitimately has zero credential uses).
func (a *auditQuerier) CredentialUses(ctx context.Context, q flowlog.CredentialUseQuery) ([]flowlog.CredentialUseEvent, error) {
	// Query the store for the session's story (or all stories when SessionID is
	// blank), then filter to CredentialUseEvents matching service + window.
	story, err := a.store.Query(ctx, flowlog.StoryQuery{SessionID: q.SessionID, Window: q.Window})
	if err != nil {
		return nil, fmt.Errorf("netflowadapter: CredentialUses: %w", err)
	}
	var out []flowlog.CredentialUseEvent
	for _, ev := range story {
		cu, ok := ev.(flowlog.CredentialUseEvent)
		if !ok {
			continue
		}
		if q.Service != "" && cu.Service != q.Service {
			continue
		}
		out = append(out, cu)
	}
	return out, nil
}

// compile-time proof these satisfy the boundary flowlog seams.
var (
	_ flowlog.AuditQuerier = (*auditQuerier)(nil)
)
