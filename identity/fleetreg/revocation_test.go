// SPDX-License-Identifier: Apache-2.0

package fleetreg

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ----- test doubles --------------------------------------------------------

// spyRevSink records every appended revocation artifact — the assurance anchor
// for "a fleet revocation rides the policy_log artifact shape, fingerprint-only".
// It assigns monotonic seqs and commits unless failNext / errNext is set.
type spyRevSink struct {
	appends  []FleetRevocationArtifact
	seq      uint64
	failNext bool // return committed:false (fail-closed apply leg)
	errNext  bool // return a transport error (fail-closed transport leg)
}

func (s *spyRevSink) AppendRevocation(_ context.Context, art FleetRevocationArtifact) (RevocationResult, error) {
	s.appends = append(s.appends, art)
	if s.errNext {
		s.errNext = false
		return RevocationResult{}, errors.New("spyRevSink: synthetic transport error")
	}
	if s.failNext {
		s.failNext = false
		return RevocationResult{BatchID: art.BatchID, Committed: false, Count: len(art.Entries)}, nil
	}
	s.seq++
	return RevocationResult{Seq: s.seq, Committed: true, BatchID: art.BatchID, Count: len(art.Entries)}, nil
}

// ----- tests ---------------------------------------------------------------

// TestNewRevocationPublisherFailClosed: a nil sink is rejected — a nil sink would
// silently no-op an emergency revocation.
func TestNewRevocationPublisherFailClosed(t *testing.T) {
	if _, err := NewRevocationPublisher(nil); err == nil {
		t.Fatal("expected fail-closed error for nil sink")
	}
	if _, err := NewRevocationPublisher(&spyRevSink{}); err != nil {
		t.Fatalf("unexpected error for valid sink: %v", err)
	}
}

// TestRevokeTokensRidesPolicyLog: a revocation publishes ONE versioned artifact
// onto the policy_log carrying the schema version, the fingerprint entries, and a
// committed seq (the §7 artifact shape, D72).
func TestRevokeTokensRidesPolicyLog(t *testing.T) {
	sink := &spyRevSink{}
	p, err := NewRevocationPublisher(sink)
	if err != nil {
		t.Fatalf("NewRevocationPublisher: %v", err)
	}
	fp1 := FingerprintToken([]byte("ds-synth-revocation-id-1"))
	fp2 := FingerprintToken([]byte("ds-synth-revocation-id-2"))
	e1, err := RevocationEntryFromFingerprint(fp1)
	if err != nil {
		t.Fatalf("entry 1: %v", err)
	}
	e2, err := RevocationEntryFromFingerprint(fp2)
	if err != nil {
		t.Fatalf("entry 2: %v", err)
	}

	res, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{e1, e2}, "batch-42")
	if err != nil {
		t.Fatalf("RevokeTokens: %v", err)
	}
	if !res.Committed {
		t.Fatal("expected committed result")
	}
	if res.Seq != 1 {
		t.Fatalf("seq = %d, want 1", res.Seq)
	}
	if res.Count != 2 {
		t.Fatalf("count = %d, want 2", res.Count)
	}
	if len(sink.appends) != 1 {
		t.Fatalf("appended %d artifacts, want 1", len(sink.appends))
	}
	art := sink.appends[0]
	if art.SchemaVersion != RevocationSchemaVersion {
		t.Fatalf("schema = %q, want %q", art.SchemaVersion, RevocationSchemaVersion)
	}
	if art.BatchID != "batch-42" {
		t.Fatalf("batch id = %q, want batch-42", art.BatchID)
	}
	if len(art.Entries) != 2 {
		t.Fatalf("artifact has %d entries, want 2", len(art.Entries))
	}
	if art.Entries[0].Fingerprint != fp1 || art.Entries[1].Fingerprint != fp2 {
		t.Fatalf("artifact fingerprints mismatch: %+v", art.Entries)
	}
}

// TestRevokeTokensDedups: the same revoked token named twice collapses to one
// entry (an operator listing a fingerprint twice does not double-append it).
func TestRevokeTokensDedups(t *testing.T) {
	sink := &spyRevSink{}
	p, _ := NewRevocationPublisher(sink)
	fp := FingerprintToken([]byte("dup"))
	e, _ := RevocationEntryFromFingerprint(fp)

	res, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{e, e, e}, "b")
	if err != nil {
		t.Fatalf("RevokeTokens: %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("count = %d, want 1 after dedup", res.Count)
	}
	if len(sink.appends[0].Entries) != 1 {
		t.Fatalf("artifact has %d entries, want 1 after dedup", len(sink.appends[0].Entries))
	}
}

// TestRevokeTokensEmptyRejected: an empty entry set is fail-closed — never append
// a meaningless revocation.
func TestRevokeTokensEmptyRejected(t *testing.T) {
	sink := &spyRevSink{}
	p, _ := NewRevocationPublisher(sink)
	if _, err := p.RevokeTokens(context.Background(), nil, "b"); err == nil {
		t.Fatal("expected fail-closed error for empty entry set")
	}
	if len(sink.appends) != 0 {
		t.Fatal("no artifact should be appended for an empty revocation")
	}
}

// TestRevokeTokensFailClosedOnUncommitted: an uncommitted apply surfaces as an
// error — the operator must not believe a still-live token is dead.
func TestRevokeTokensFailClosedOnUncommitted(t *testing.T) {
	sink := &spyRevSink{failNext: true}
	p, _ := NewRevocationPublisher(sink)
	e, _ := RevocationEntryFromFingerprint(FingerprintToken([]byte("x")))
	res, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{e}, "b")
	if err == nil {
		t.Fatal("expected fail-closed error on uncommitted apply")
	}
	if res.Committed {
		t.Fatal("result must not be committed")
	}
}

// TestRevokeTokensFailClosedOnTransportError: a sink transport error surfaces
// fail-closed.
func TestRevokeTokensFailClosedOnTransportError(t *testing.T) {
	sink := &spyRevSink{errNext: true}
	p, _ := NewRevocationPublisher(sink)
	e, _ := RevocationEntryFromBlockID("dead0beef0")
	if _, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{e}, "b"); err == nil {
		t.Fatal("expected fail-closed error on transport error")
	}
}

// TestRevocationEntryValidation: the entry constructors and validate() reject
// everything that is not a bounded lower-hex identifier — the structural fence
// that keeps raw token bytes out of a revocation artifact.
func TestRevocationEntryValidation(t *testing.T) {
	goodFP := FingerprintToken([]byte("ok"))

	// Constructor accepts a well-formed fingerprint.
	if _, err := RevocationEntryFromFingerprint(goodFP); err != nil {
		t.Fatalf("valid fingerprint rejected: %v", err)
	}
	// Wrong length (a raw token is not 64 hex chars).
	if _, err := RevocationEntryFromFingerprint("abcd"); err == nil {
		t.Fatal("short fingerprint should be rejected")
	}
	// Upper-hex is rejected (only lower-hex is a canonical fingerprint).
	if _, err := RevocationEntryFromFingerprint(strings.ToUpper(goodFP)); err == nil {
		t.Fatal("upper-hex fingerprint should be rejected")
	}
	// Non-hex alphabet (a base64 token) is rejected even at the right length.
	nonHex := strings.Repeat("g", fingerprintHexLen)
	if _, err := RevocationEntryFromFingerprint(nonHex); err == nil {
		t.Fatal("non-hex fingerprint should be rejected")
	}
	// Block id: even-length lower-hex accepted; odd length rejected.
	if _, err := RevocationEntryFromBlockID("00ff"); err != nil {
		t.Fatalf("valid block id rejected: %v", err)
	}
	if _, err := RevocationEntryFromBlockID("abc"); err == nil {
		t.Fatal("odd-length block id should be rejected")
	}

	// validate() catches a directly-populated ambiguous / empty entry.
	if err := (FleetRevocationEntry{}).validate(); err == nil {
		t.Fatal("empty entry should fail validate()")
	}
	if err := (FleetRevocationEntry{Fingerprint: goodFP, BlockID: "00ff"}).validate(); err == nil {
		t.Fatal("entry with BOTH identifiers should fail validate()")
	}

	// A directly-populated entry carrying raw token bytes is caught at append.
	sink := &spyRevSink{}
	p, _ := NewRevocationPublisher(sink)
	raw := FleetRevocationEntry{Fingerprint: "this-is-a-raw-token-not-a-hex-fingerprint"}
	if _, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{raw}, "b"); err == nil {
		t.Fatal("append must reject an entry that is not a hex identifier")
	}
	if len(sink.appends) != 0 {
		t.Fatal("no artifact should be appended when an entry is invalid")
	}
}

// TestRevocation_NoTokenBytes is the load-bearing security guard (doc 19 §7/§9,
// "fingerprint-only: zero token bytes in any log/spool"): given a synthetic token
// and its revocation id, the published artifact carries ONLY the SHA-256
// fingerprint — never the token bytes and never the raw revocation id. Proven by
// serializing the recorded artifact and asserting the secrets do not appear
// while the fingerprint does.
func TestRevocation_NoTokenBytes(t *testing.T) {
	// A synthetic bearer token and its (secret-adjacent) revocation id (D50).
	token := []byte("ds-synth-BEARER-TOKEN-eyJhbGciOiJFZERTQSJ9.super.secret.bytes")
	revocationID := []byte("ds-synth-revocation-block-id-CONFIDENTIAL")

	fp := FingerprintToken(revocationID)
	entry, err := RevocationEntryFromFingerprint(fp)
	if err != nil {
		t.Fatalf("RevocationEntryFromFingerprint: %v", err)
	}

	sink := &spyRevSink{}
	p, _ := NewRevocationPublisher(sink)
	if _, err := p.RevokeTokens(context.Background(), []FleetRevocationEntry{entry}, "kill-switch"); err != nil {
		t.Fatalf("RevokeTokens: %v", err)
	}

	// Serialize the entire recorded artifact — the exact bytes that rode the
	// policy_log seam — and scan it.
	if len(sink.appends) != 1 {
		t.Fatalf("appended %d artifacts, want 1", len(sink.appends))
	}
	serialized := []byte(fmt.Sprintf("%#v", sink.appends[0]))

	if bytes.Contains(serialized, token) {
		t.Fatal("SECURITY: token bytes appear in the serialized revocation artifact")
	}
	if bytes.Contains(serialized, revocationID) {
		t.Fatal("SECURITY: raw revocation id appears in the serialized revocation artifact")
	}
	// Also reject the hex encodings of the secrets — a serializer must not leak
	// them in an encoded form either.
	if bytes.Contains(serialized, []byte(hex.EncodeToString(token))) {
		t.Fatal("SECURITY: hex-encoded token bytes appear in the serialized artifact")
	}
	// The fingerprint (the one thing that SHOULD be there) is present.
	if !bytes.Contains(serialized, []byte(fp)) {
		t.Fatal("expected the fingerprint to be present in the artifact")
	}
	// And the fingerprint is not itself the token (sanity on the one-way reduction).
	if fp == string(token) || fp == string(revocationID) {
		t.Fatal("fingerprint must be a reduction, not the secret itself")
	}
}
