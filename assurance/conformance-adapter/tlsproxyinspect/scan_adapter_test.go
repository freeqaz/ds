// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// scan_adapter_test.go — the OFFLINE TLS-7 conformance (D73; doc 09 §5 TLS-7;
// doc 12 §5 / §13.5). Always runs, no live kernel/network, no DS_TLS3_LIVE gate.
// It re-expresses the three boundary TLS-7 assertions (boundary/tlsproxy/
// tlsproxy_scan_test.go: TestSecretScan_SeededLongLivedTokenInbound_HookFires,
// TestSecretScan_NearMissContent_NoFalseTrigger, TestSecretScan_PassThroughNot-
// Scanned_GuaranteeBoundaryDocumented) against the REAL keyed-matcher-backed
// adapter (KeyedSecretScanner / KeyedDigestMatcher / ScanGate / HoldBackBuffer in
// scan_adapter.go), since the boundary NewSecretScanner is a RED stub and the
// package-internal harness is not importable (the doc.go MIRROR guarantee).
//
// Three properties:
//
//  1. SEEDED-TOKEN: the canary planted in the fake keyed digest feed → a body
//     carrying the token → the configured hook fires with a Finding whose Kind
//     (token class), Fingerprint, and Where (location) are populated, and NO field
//     carries the token value (never-log-the-secret).
//  2. NEAR-MISS: README-format / base64 / UUID / truncated-prefix bodies → ZERO
//     findings (the gate is not noise — OQ8 rules quality).
//  3. CHUNK-BOUNDARY: the canary split at the maxSecretLen−1 boundary across two
//     chunks → held in the buffer, released only after the matcher's verdict, ZERO
//     matched bytes observed by the recording upstream (ScanGate.Egressed).
//  4. PASS-THROUGH: the SAME canary in an opaque TLS-4 pass-through body via the
//     real PassThroughDispatcher → the scanner's ScanInbound is NEVER called
//     (callCount==0); scanning is on the inspected path ONLY.

import (
	"context"
	"strings"
	"testing"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// seededToken mirrors the boundary scan test's planted long-lived credential
// (boundary/tlsproxy/tlsproxy_scan_test.go const seededToken). Reproduced here
// because that const lives in a _test.go file that is not importable.
const seededToken = "ghp_0123456789abcdef0123456789abcdef0123"

// tokenClass is the class label the canary feed tags the seeded token with — the
// Finding.Kind the boundary row asserts is populated (e.g. github-token).
const tokenClass = "github-token"

// newCanaryFeedWithSeed builds a fake keyed digest feed with the seeded token
// planted (registered as a keyed digest of class tokenClass). The feed retains
// ONLY the HMAC digest after Register — never the token plaintext.
func newCanaryFeedWithSeed(t *testing.T) *CanaryFeed {
	t.Helper()
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16)
	feed.Register("ghp-canary", tokenClass, seededToken)
	return feed
}

// scanningScanner wraps a real KeyedSecretScanner and counts ScanInbound calls —
// the conformance mirror of boundary recordingScanner, so the pass-through row can
// assert the scanner was NEVER invoked on the opaque path.
type scanningScanner struct {
	delegate *KeyedSecretScanner
	calls    int
}

func (s *scanningScanner) ScanInbound(ctx context.Context, sess tlsproxy.SessionRef, meta tlsproxy.ResponseMeta, body []byte) ([]tlsproxy.Finding, error) {
	s.calls++
	return s.delegate.ScanInbound(ctx, sess, meta, body)
}

func (s *scanningScanner) callCount() int { return s.calls }

var _ tlsproxy.SecretScanner = (*scanningScanner)(nil)

// ───────────────────────────────────────────────────────────────────────────
// (1) SEEDED-TOKEN — the configured hook fires with a token-free Finding.
// Mirrors boundary TestSecretScan_SeededLongLivedTokenInbound_HookFires.
// ───────────────────────────────────────────────────────────────────────────

func TestScan_SeededLongLivedTokenInbound_HookFires(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	// Default configured mode is alert-on-finding (Flag): delivery proceeds, the
	// hook still fires (the boundary "alert mode delivers" posture).
	scanner := NewKeyedSecretScanner(feed.Matcher(VerdictFlag))
	hook := NewRecordingHook()
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	body := []byte("here is the token you asked me to paste: " + seededToken + "\n")
	findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/plain"},
	}, body)
	if err != nil {
		t.Fatalf("ScanInbound: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("the configured scanner must fire a finding for a seeded long-lived token on the inspected path")
	}
	// Drive the configured hook exactly as the body-filter chain would.
	for _, f := range findings {
		if err := hook.OnFinding(ctx(), sess, f); err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
	}
	if len(hook.Findings()) == 0 {
		t.Fatal("the configured hook must fire for a seeded long-lived token entering the VM")
	}

	f := findings[0]
	if f.Kind == "" {
		t.Error("Finding.Kind must classify the secret (e.g. github-token)")
	}
	if f.Kind != tokenClass {
		t.Errorf("Finding.Kind = %q, want token class %q", f.Kind, tokenClass)
	}
	if f.Fingerprint == "" {
		t.Error("Finding.Fingerprint must be set")
	}
	if f.Where == "" {
		t.Error("Finding.Where must locate the secret (e.g. body)")
	}
	if f.Where != "body" {
		t.Errorf("Finding.Where = %q, want %q (body-direction scan)", f.Where, "body")
	}

	// never-log-the-secret: NO field of ANY finding (or any hook-captured finding)
	// may carry the token value.
	for _, f := range append(findings, hook.Findings()...) {
		if findingContains(f, seededToken) {
			t.Errorf("a Finding must carry a fingerprint, NEVER the token value: %+v", f)
		}
		// also reject any non-trivial token substring leaking into the fingerprint.
		if strings.Contains(f.Fingerprint, seededToken[:12]) {
			t.Errorf("Finding.Fingerprint leaked a token prefix: %q", f.Fingerprint)
		}
	}
}

// blockModeDelivers proves the keyed-hit default verdict is Block (matched bytes
// never egress) while alert mode is Flag (delivers + flags). Both fire a finding.
func TestScan_SeededToken_BlockMode_MatchedBytesNeverEgress(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	matcher := feed.Matcher(VerdictBlock)
	scanner := NewKeyedSecretScanner(matcher)
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	body := []byte("paste: " + seededToken)
	findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, body)
	if err != nil {
		t.Fatalf("ScanInbound: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("block-mode keyed hit must yield exactly one finding, got %d", len(findings))
	}
	if findings[0].Fingerprint == "" || findings[0].Kind != tokenClass {
		t.Errorf("block-mode finding malformed: %+v", findings[0])
	}
	if findingContains(findings[0], seededToken) {
		t.Errorf("block-mode finding leaked the token: %+v", findings[0])
	}
}

// ───────────────────────────────────────────────────────────────────────────
// (2) NEAR-MISS — README/base64/UUID/truncated-prefix bodies fire ZERO findings.
// Mirrors boundary TestSecretScan_NearMissContent_NoFalseTrigger.
// ───────────────────────────────────────────────────────────────────────────

func TestScan_NearMissContent_NoFalseTrigger(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	scanner := NewKeyedSecretScanner(feed.Matcher(VerdictBlock))
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	rows := []struct {
		name string
		body string
	}{
		{"README documenting the token FORMAT", "GitHub tokens look like ghp_ followed by 36 alphanumerics, e.g. ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
		{"random base64 blob", "payload=QmFzZTY0IGJsb2JzIGFyZSBub3Qgc2VjcmV0cyBidXQgbG9vayBlbnRyb3BpYyE9PQ=="},
		{"UUIDs", "request-id: 1f2e3d4c-5b6a-7980-1122-334455667788, trace: 99887766-5544-3322-1100-aabbccddeeff"},
		{"truncated token prefix", "the prefix ghp_abc alone is not a credential"},
		{"token with one byte flipped", "almost: ghp_0123456789abcdef0123456789abcdef012X"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{
				Status:  200,
				Headers: map[string]string{"Content-Type": "text/plain"},
			}, []byte(row.body))
			if err != nil {
				t.Fatalf("ScanInbound must scan near-miss content cleanly: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("near-miss content fired %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// (3) CHUNK-BOUNDARY hold-back — the canary split at maxSecretLen−1 is held in
// the buffer, released only after the matcher's verdict, and ZERO matched bytes
// reach the recording upstream (ScanGate.Egressed).
// ───────────────────────────────────────────────────────────────────────────

func TestScan_ChunkBoundary_CanaryHeldBack_ZeroMatchedBytesEgress(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	matcher := feed.Matcher(VerdictBlock)
	// maxSecretLen sized to the registered token so the hold-back window is
	// maxSecretLen−1 — the boundary the secret is split across.
	maxSecretLen := feed.MaxTokenLen()
	if maxSecretLen != len(seededToken) {
		t.Fatalf("feed.MaxTokenLen()=%d, want %d (the seeded token length)", maxSecretLen, len(seededToken))
	}
	gate := NewScanGate(matcher, maxSecretLen, matcher.keyedLoaded())

	// A clean prefix, then the canary split at the maxSecretLen−1 boundary: the
	// first chunk ends mid-token (the prefix), the second carries the tail. Without
	// hold-back the prefix would egress before the matcher ever saw the whole token.
	prefix := "lots of clean preamble bytes that should release cleanly. now the secret: "
	splitAt := maxSecretLen - 1 // hold-back window width — the worst-case straddle
	chunk1 := []byte(prefix + seededToken[:splitAt])
	chunk2 := []byte(seededToken[splitAt:] + " trailing clean bytes")

	v1 := gate.ScanChunk(chunk1, false, ScanCtx{Direction: DirectionIngress})
	// chunk1 must NOT yet block — the token is incomplete — but the matched-token
	// bytes at the tail must be HELD (not released): the released count must leave
	// at least the trailing hold-back window buffered.
	if v1.Kind == VerdictBlock {
		t.Fatalf("chunk1 must not block before the whole token is seen; got %v", v1.Kind)
	}
	if held := gate.Buffer().Len(); held < splitAt {
		t.Fatalf("chunk1 hold-back: buffer holds %d bytes, want >= %d (the straddling prefix held)", held, splitAt)
	}

	v2 := gate.ScanChunk(chunk2, true, ScanCtx{Direction: DirectionIngress})
	if v2.Kind != VerdictBlock {
		t.Fatalf("chunk2 completes the token across the boundary; want Block, got %v", v2.Kind)
	}

	// The recording upstream surface: ZERO matched token bytes may have egressed.
	egressed := gate.Egressed()
	if strings.Contains(string(egressed), seededToken) {
		t.Fatalf("the whole token egressed — hold-back failed: egressed=%q", egressed)
	}
	// The straddling tail of the token (its second half, present only after the
	// boundary) must NEVER have egressed — it was inside the held window when Block
	// fired.
	tail := seededToken[splitAt:]
	if strings.Contains(string(egressed), tail) {
		t.Fatalf("the token tail egressed past the hold-back boundary: egressed=%q", egressed)
	}
	// And the maxSecretLen−1 worst-case straddle byte count is honored: at least
	// the hold-back window's worth of the token never left the buffer.
	if strings.Contains(string(egressed), seededToken[:splitAt+1]) {
		t.Fatalf("more of the token egressed than the hold-back window permits: egressed=%q", egressed)
	}
}

// chunkBoundary_PerChunkAccounting walks EVERY split point 0..len(token) and
// asserts the token never egresses whole at any boundary (the per-chunk accounting
// the acceptance calls for: compute the boundary cases, split across them, verify
// zero matched bytes egress).
func TestScan_PerChunkAccounting_EveryBoundary_ZeroWholeTokenEgress(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	maxSecretLen := feed.MaxTokenLen()
	preamble := "clean-preamble-"
	for splitAt := 0; splitAt <= len(seededToken); splitAt++ {
		matcher := feed.Matcher(VerdictBlock)
		gate := NewScanGate(matcher, maxSecretLen, matcher.keyedLoaded())
		chunk1 := []byte(preamble + seededToken[:splitAt])
		chunk2 := []byte(seededToken[splitAt:])
		gate.ScanChunk(chunk1, false, ScanCtx{Direction: DirectionIngress})
		gate.ScanChunk(chunk2, true, ScanCtx{Direction: DirectionIngress})
		if strings.Contains(string(gate.Egressed()), seededToken) {
			t.Fatalf("split at %d: the whole token egressed (hold-back failed): %q", splitAt, gate.Egressed())
		}
	}
}

// ───────────────────────────────────────────────────────────────────────────
// (4) PASS-THROUGH NOT SCANNED — the opaque TLS-4 tunnel never calls the scanner.
// Mirrors boundary TestSecretScan_PassThroughNotScanned_GuaranteeBoundaryDocumented.
// It drives the REAL PassThroughDispatcher (tlsproxyinspect.go) over a LISTED
// domain with the SAME canary in the opaque body, and asserts the scanner's
// ScanInbound was NEVER invoked.
// ───────────────────────────────────────────────────────────────────────────

func TestScan_PassThroughNotScanned_GuaranteeBoundaryDocumented(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	// The configured scanner exists (wired for the inspected path) but the opaque
	// pass-through leg must NEVER reach it — callCount stays 0 (the guarantee's
	// boundary). The PassThroughDispatcher has no Scanner field by design: the
	// opaque leg is byte-spliced verbatim, never handed to a body-filter scanner.
	scanner := &scanningScanner{delegate: NewKeyedSecretScanner(feed.Matcher(VerdictBlock))}
	hook := NewRecordingHook()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const domain = "pinned.example"

	// A LISTED domain → the dispatcher takes the opaque pass-through (DialRaw) leg,
	// which NEVER terminates TLS, NEVER mints a leaf, and NEVER reaches a scanner.
	policy := newPassThroughPolicy()
	policy.setPassThrough(domain, true)

	// Real-plane seams. The opaque upstream delivers the canary in its reply
	// untouched (the pass-through guarantee: the listed origin's bytes reach the VM
	// by design). The dispatcher dials it raw via the real StrictWebPKIDialer.
	minter := NewCAMinter()
	realCA, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}
	dialer := NewStrictWebPKIDialer(tlsproxy.Config{}, 0)
	disp := &PassThroughDispatcher{
		Policy: policy,
		CA:     realCA,
		Dialer: dialer,
		Sink:   NewCapturingEventSink(),
	}

	upAddr, _ := startRawEchoUpstream(t, []byte("opaque delivery: "+seededToken))
	clientHello := []byte("GET /secret HTTP/1.1\r\nHost: " + domain + "\r\n\r\n")
	route, reply, _, err := disp.Dispatch(ctx(), sess, domain, upAddr, clientHello)
	if err != nil {
		t.Fatalf("pass-through Dispatch: %v", err)
	}
	if route != RoutePassThrough {
		t.Fatalf("listed domain must route pass-through, got %v", route)
	}
	// The token reaches the VM — documented, by design, for listed domains.
	if !strings.Contains(string(reply), seededToken) {
		t.Fatalf("opaque tunnel must deliver the origin bytes untouched; reply=%q", reply)
	}

	// The scan guarantee's boundary: the scanner was NEVER invoked for an opaque
	// pass-through flow (scanning is on the inspected path ONLY).
	if n := scanner.callCount(); n != 0 {
		t.Errorf("ScanInbound must never be invoked for an opaque pass-through flow; calls=%d", n)
	}
	if len(hook.Findings()) != 0 {
		t.Errorf("no findings may fire for pass-through flows; got %d", len(hook.Findings()))
	}
}

// inspectStillScans is the DUAL of the pass-through row: an UNLISTED domain takes
// the inspected leg, and the SAME canary in the body IS caught by the scanner —
// proving the scanner is wired on (only) the inspected path. It exercises the
// scanner directly on the body the inspected leg would terminate.
func TestScan_InspectedPath_SameCanaryIsScanned(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	scanner := NewKeyedSecretScanner(feed.Matcher(VerdictBlock))
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	body := []byte("inspected body carrying: " + seededToken)
	findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, body)
	if err != nil {
		t.Fatalf("ScanInbound: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("the inspected path MUST scan and catch the canary (the dual of the pass-through boundary)")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// fail-closed-when-keyed — an UNSEALED keyed plane (mint-before-attach
// unsatisfied) Holds (no byte released); the scanner surfaces it as an error so
// the caller never silently delivers an unscanned body (doc 12 §13.5, D73).
// ───────────────────────────────────────────────────────────────────────────

func TestScan_FailClosedWhenKeyed_UnsealedPlaneHolds(t *testing.T) {
	feed := newCanaryFeedWithSeed(t)
	matcher := feed.UnsealedMatcher(VerdictBlock) // present but NOT sealed
	scanner := NewKeyedSecretScanner(matcher)
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	// A perfectly clean body — but the keyed plane is loaded-and-unsealed, so the
	// matcher fails closed: the gate Holds and the scanner surfaces an error rather
	// than reporting a vacuous clean result.
	_, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, []byte("totally clean body"))
	if err == nil {
		t.Fatal("an unsealed keyed plane (mint-before-attach unsatisfied) must fail closed, not report clean")
	}

	// Gate-level: an unsealed matcher Holds and releases ZERO bytes.
	gate := NewScanGate(matcher, feed.MaxTokenLen(), matcher.keyedLoaded())
	v := gate.ScanChunk([]byte("clean bytes here"), true, ScanCtx{Direction: DirectionIngress})
	if v.Kind != VerdictHold {
		t.Fatalf("unsealed keyed plane must Hold (fail-closed), got %v", v.Kind)
	}
	if len(gate.Egressed()) != 0 {
		t.Fatalf("fail-closed must release zero bytes; egressed=%q", gate.Egressed())
	}
}

// HoldBackBuffer unit invariants — the proxy-owned byte hold-back primitive.
func TestHoldBackBuffer_RetainsTrailingWindow(t *testing.T) {
	b := NewHoldBackBuffer(8) // retain 7
	if b.RetainWindow() != 7 {
		t.Fatalf("RetainWindow()=%d, want 7", b.RetainWindow())
	}
	b.Append([]byte("0123456789")) // 10 bytes
	if got := b.ReleasableFloor(); got != 3 {
		t.Fatalf("ReleasableFloor()=%d, want 3 (10-7)", got)
	}
	rel := b.DrainFront(b.ReleasableFloor())
	if string(rel) != "012" {
		t.Fatalf("DrainFront released %q, want %q", rel, "012")
	}
	if b.Len() != 7 {
		t.Fatalf("after releasing the floor, buffer holds %d, want the 7-byte window", b.Len())
	}
	if string(b.DrainAll()) != "3456789" {
		t.Fatalf("DrainAll mismatch")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// (5) VARIANT ENCODINGS — the canary registered as one digest per encoding
// (raw / base64 / urlenc / hex) is caught when it appears on the wire in THAT
// encoding. The variant invariant (doc 14 §7): the producer pushes one digest
// per encoding computed over the ENCODED form; the matcher hashes the wire window
// AS-IS, so a base64'd / url-encoded / hex secret matches as readily as raw bytes.
// This re-expresses the boundary TestSecretScanBlock_Keyed* family (each variant
// encoding a planted canary egresses through and is caught at the scan hook).
// ───────────────────────────────────────────────────────────────────────────

// newVariantFeedWithSeed plants the seeded token under EVERY Stage-0 encoding
// variant, so the matcher catches the canary in any on-wire encoding.
func newVariantFeedWithSeed(t *testing.T) *CanaryFeed {
	t.Helper()
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16)
	feed.RegisterAllVariants("ghp-canary", tokenClass, seededToken)
	return feed
}

func TestScan_VariantEncodings_EachEncodingCaught(t *testing.T) {
	feed := newVariantFeedWithSeed(t)
	scanner := NewKeyedSecretScanner(feed.Matcher(VerdictBlock))
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	for _, vt := range []VariantTag{VariantRaw, VariantBase64, VariantUrlEnc, VariantHex} {
		t.Run(vt.String(), func(t *testing.T) {
			onWire := encodeVariant(vt, []byte(seededToken))
			// The encoded canary planted in a request body on the inspected path.
			body := append([]byte("here is the credential: "), onWire...)
			body = append(body, []byte(" trailing")...)
			findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, body)
			if err != nil {
				t.Fatalf("ScanInbound(%s): %v", vt, err)
			}
			if len(findings) == 0 {
				t.Fatalf("variant %s: the canary in %s encoding must be caught at the scan hook", vt, vt)
			}
			f := findings[0]
			if f.Kind != tokenClass {
				t.Errorf("variant %s: Finding.Kind = %q, want %q", vt, f.Kind, tokenClass)
			}
			if f.Fingerprint == "" || f.Where != "body" {
				t.Errorf("variant %s: malformed finding %+v", vt, f)
			}
			// never-log-the-secret holds for EVERY variant: no field carries the
			// raw token NOR its on-wire encoded form.
			if findingContains(f, seededToken) || findingContains(f, string(onWire)) {
				t.Errorf("variant %s: finding leaked the secret (raw or encoded): %+v", vt, f)
			}
		})
	}
}

// VariantEncodings_HeaderAndQueryLocations proves the same per-variant digest set
// catches the canary regardless of WHERE on the request it sits (a header value,
// a query string) — the matcher is location-agnostic over the cleartext span; the
// boundary Finding.Where names the location.
func TestScan_VariantEncodings_LocationAgnostic(t *testing.T) {
	feed := newVariantFeedWithSeed(t)
	matcher := feed.Matcher(VerdictBlock)

	for _, vt := range []VariantTag{VariantBase64, VariantUrlEnc, VariantHex} {
		t.Run(vt.String(), func(t *testing.T) {
			onWire := encodeVariant(vt, []byte(seededToken))
			// Drive the matcher directly over a header-shaped span and a query-shaped
			// span: both must hit (the matcher scans the cleartext span; the location
			// is the gate/bridge's Where, not the matcher's concern).
			header := append([]byte("Authorization: Bearer "), onWire...)
			query := append([]byte("GET /x?token="), onWire...)
			for name, span := range map[string][]byte{"header": header, "query": query} {
				v, err := matcher.Scan(span, true, ScanCtx{Direction: DirectionEgress})
				if err != nil {
					t.Fatalf("variant %s %s: Scan: %v", vt, name, err)
				}
				if v.Kind != VerdictBlock {
					t.Errorf("variant %s %s: want Block, got %v", vt, name, v.Kind)
				}
				if v.Prov.Plane != PlaneKeyed {
					t.Errorf("variant %s %s: want plane=keyed, got %v", vt, name, v.Prov.Plane)
				}
			}
		})
	}
}

// VariantEncodings_ChunkBoundary splits each encoded canary across the worst-case
// maxSecretLen−1 boundary and asserts ZERO matched bytes (raw OR encoded) reach the
// recording upstream — the chunk-boundary hold-back holds for every encoding, not
// just raw. (The acceptance: "raw and each variant encoding ... chunk boundaries —
// canary split across TLS records".)
func TestScan_VariantEncodings_ChunkBoundary_ZeroMatchedBytesEgress(t *testing.T) {
	feed := newVariantFeedWithSeed(t)
	maxSecretLen := feed.MaxTokenLen() // longest ENCODED form across variants

	for _, vt := range []VariantTag{VariantRaw, VariantBase64, VariantUrlEnc, VariantHex} {
		t.Run(vt.String(), func(t *testing.T) {
			onWire := encodeVariant(vt, []byte(seededToken))
			matcher := feed.Matcher(VerdictBlock)
			gate := NewScanGate(matcher, maxSecretLen, matcher.keyedLoaded())

			// Split the encoded canary at the worst-case hold-back boundary relative to
			// its own length, so the first chunk ends mid-secret and the second carries
			// the tail across the (TLS-record) boundary.
			splitAt := len(onWire) - 1
			if splitAt < 1 {
				splitAt = len(onWire) / 2
			}
			prefix := []byte("clean preamble before the secret: ")
			chunk1 := append(append([]byte(nil), prefix...), onWire[:splitAt]...)
			chunk2 := append(append([]byte(nil), onWire[splitAt:]...), []byte(" clean tail")...)

			v1 := gate.ScanChunk(chunk1, false, ScanCtx{Direction: DirectionEgress})
			if v1.Kind == VerdictBlock {
				t.Fatalf("variant %s: chunk1 blocked before the whole encoded secret was seen", vt)
			}
			v2 := gate.ScanChunk(chunk2, true, ScanCtx{Direction: DirectionEgress})
			if v2.Kind != VerdictBlock {
				t.Fatalf("variant %s: chunk2 completes the encoded secret across the boundary; want Block, got %v", vt, v2.Kind)
			}
			egressed := string(gate.Egressed())
			if strings.Contains(egressed, string(onWire)) {
				t.Fatalf("variant %s: the whole encoded secret egressed (hold-back failed): %q", vt, egressed)
			}
			// The straddling tail (present only after the boundary) must never egress.
			tail := string(onWire[splitAt:])
			if len(tail) > 0 && strings.Contains(egressed, tail) {
				t.Fatalf("variant %s: the encoded secret tail egressed past the hold-back: %q", vt, egressed)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// (6) MULTIPLE / OVERLAPPING KEYED DIGESTS — several digests with overlapping
// payloads loaded at once; each is caught and reports its OWN rule id and
// plane=keyed (the acceptance: "multiple digests with overlapping payloads",
// "multiple overlapping keyed rules"). Overlap = one token is a substring of
// another, plus shared-prefix tokens — the matcher must not collapse them.
// ───────────────────────────────────────────────────────────────────────────

func TestScan_MultipleOverlappingKeyedDigests_EachReportsOwnRule(t *testing.T) {
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v2", 16)
	// Overlapping payloads: tokenLong CONTAINS tokenShort; tokenPrefixA / tokenPrefixB
	// share a long common prefix and differ only in the tail.
	const (
		tokenShort   = "ghp_SHORTcanary00"
		tokenLong    = "PREghp_SHORTcanary00POST" // contains tokenShort as a substring
		tokenPrefixA = "sk-live-AAAAAAAAAAAAAAAA-tailA"
		tokenPrefixB = "sk-live-AAAAAAAAAAAAAAAA-tailB"
	)
	feed.Register("rule-short", "github-token", tokenShort)
	feed.Register("rule-long", "github-token", tokenLong)
	feed.Register("rule-prefixA", "openai-key", tokenPrefixA)
	feed.Register("rule-prefixB", "openai-key", tokenPrefixB)

	matcher := feed.Matcher(VerdictBlock)

	rows := []struct {
		name      string
		token     string
		wantRule  string
		wantClass string
	}{
		{"short-token-alone", tokenShort, "rule-short", "github-token"},
		{"prefixA", tokenPrefixA, "rule-prefixA", "openai-key"},
		{"prefixB", tokenPrefixB, "rule-prefixB", "openai-key"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			body := []byte("payload carrying " + row.token + " end")
			v, err := matcher.Scan(body, true, ScanCtx{Direction: DirectionEgress})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if v.Kind != VerdictBlock {
				t.Fatalf("overlapping digest %q must Block, got %v", row.token, v.Kind)
			}
			if v.Prov.Plane != PlaneKeyed {
				t.Errorf("want plane=keyed, got %v", v.Prov.Plane)
			}
			if v.Prov.RuleID != row.wantRule {
				t.Errorf("RuleID = %q, want %q (the matched overlapping rule, not a sibling)", v.Prov.RuleID, row.wantRule)
			}
			if v.Prov.Kind != row.wantClass {
				t.Errorf("Kind = %q, want %q", v.Prov.Kind, row.wantClass)
			}
			// the BlockEvent the policy engine would observe: never-log-the-secret —
			// the provenance carries rule metadata only, no token bytes.
			f := findingFromVerdict(v, "body")
			if findingContains(f, row.token) {
				t.Errorf("finding leaked the token: %+v", f)
			}
		})
	}

	// The contained-token case: tokenLong contains tokenShort. The body carries the
	// LONG token; SOME keyed rule must fire (the shorter substring digest is the
	// minimal-window hit). Either rule-short (the substring) or rule-long is a
	// correct keyed Block — the invariant is that the secret never passes clean.
	t.Run("contained-token-some-rule-fires", func(t *testing.T) {
		body := []byte("payload carrying " + tokenLong + " end")
		v, err := matcher.Scan(body, true, ScanCtx{Direction: DirectionEgress})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if v.Kind != VerdictBlock || v.Prov.Plane != PlaneKeyed {
			t.Fatalf("a body carrying overlapping tokens must keyed-Block, got kind=%v plane=%v", v.Kind, v.Prov.Plane)
		}
		if v.Prov.RuleID != "rule-short" && v.Prov.RuleID != "rule-long" {
			t.Errorf("RuleID = %q, want one of the overlapping rules (rule-short|rule-long)", v.Prov.RuleID)
		}
	})
}

// ───────────────────────────────────────────────────────────────────────────
// (7) GENERIC PLANE — the POL-4 generic pack (pattern rules capped at block+log).
// A generic-rule canary in a body is caught with plane=generic and the matched
// rule id; the keyword prefilter and allowlist suppression behave; near-miss
// content does not fire. Re-expresses the boundary TestSecretScanBlock_Generic_
// family (a generic-pack forbidden-class pattern caught at the scan hook, the
// BlockEvent carrying plane=generic + the correct rule id).
// ───────────────────────────────────────────────────────────────────────────

// awsSecretPack is a small fake POL-4 generic pack: an AWS-secret-shaped literal
// rule with a keyword prefilter, plus an allowlisted example the curated ruleset
// suppresses.
func awsSecretPack() GenericPack {
	return GenericPack{
		PackVersion: "pack-v3",
		PolicyLayer: "fleet-generic",
		Rules: []GenericRule{
			{
				ID:         "aws-secret-access-key",
				Regex:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				Keywords:   []string{"aws", "AKIA", "secret"},
				Kind:       "aws-secret-access-key",
				Allowlists: []string{"EXAMPLE-ALLOWLISTED-CONTEXT"},
			},
		},
	}
}

func TestScan_GenericPlane_PatternCanaryCaught_PlaneGeneric(t *testing.T) {
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16) // no keyed digests
	matcher := feed.MatcherWithGeneric(VerdictBlock, awsSecretPack())
	scanner := NewKeyedSecretScanner(matcher)
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	// A body that trips the keyword prefilter AND the literal confirm.
	body := []byte("aws secret config: aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	findings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, body)
	if err != nil {
		t.Fatalf("ScanInbound: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("generic-pack canary must yield exactly one finding, got %d", len(findings))
	}
	if findings[0].Kind != "aws-secret-access-key" {
		t.Errorf("Finding.Kind = %q, want the generic rule class", findings[0].Kind)
	}
	if findings[0].Fingerprint == "" {
		t.Error("generic finding must carry a fingerprint")
	}

	// Drive the matcher directly to inspect provenance plane + rule id (the
	// BlockEvent the policy engine observes carries plane=generic + correct rule id).
	v, err := matcher.Scan(body, true, ScanCtx{Direction: DirectionEgress})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Kind != VerdictBlock {
		t.Fatalf("generic forbidden-class pattern must Block (capped block+log), got %v", v.Kind)
	}
	if v.Prov.Plane != PlaneGeneric {
		t.Errorf("BlockEvent plane = %v, want generic", v.Prov.Plane)
	}
	if v.Prov.RuleID != "aws-secret-access-key" {
		t.Errorf("BlockEvent RuleID = %q, want the matched generic rule id", v.Prov.RuleID)
	}
	if v.Prov.RulesetVersion != "pack-v3" {
		t.Errorf("BlockEvent RulesetVersion = %q, want the pack version", v.Prov.RulesetVersion)
	}
}

func TestScan_GenericPlane_KeywordPrefilterAndAllowlist(t *testing.T) {
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16)
	matcher := feed.MatcherWithGeneric(VerdictBlock, awsSecretPack())

	rows := []struct {
		name      string
		body      string
		wantBlock bool
	}{
		// No keyword present → the prefilter skips the rule → no confirm runs.
		{"no-keyword-no-fire", "totally unrelated content without the trigger words", false},
		// Keyword present but the confirm literal absent → no fire.
		{"keyword-but-no-confirm", "aws region us-east-1 with no secret material here", false},
		// Keyword + confirm + an allowlisted context → suppressed (known FP).
		{"allowlisted-context-suppressed", "aws secret in EXAMPLE-ALLOWLISTED-CONTEXT: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", false},
		// Keyword + confirm, no allowlist → fires.
		{"keyword-and-confirm-fires", "aws secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			v, err := matcher.Scan([]byte(row.body), true, ScanCtx{Direction: DirectionEgress})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			gotBlock := v.Kind == VerdictBlock
			if gotBlock != row.wantBlock {
				t.Fatalf("body %q: block=%v, want %v (verdict %v)", row.body, gotBlock, row.wantBlock, v.Kind)
			}
			if gotBlock && v.Prov.Plane != PlaneGeneric {
				t.Errorf("generic block must carry plane=generic, got %v", v.Prov.Plane)
			}
		})
	}
}

// TwoPlanePrecedence proves the KEYED plane is checked FIRST: when a body carries
// BOTH a keyed canary AND generic-pack-matching content, the keyed plane wins (the
// only plane inline-block verdicts fully trust), reporting plane=keyed.
func TestScan_TwoPlanePrecedence_KeyedWinsOverGeneric(t *testing.T) {
	feed := newCanaryFeedWithSeed(t) // raw keyed canary = seededToken
	matcher := feed.MatcherWithGeneric(VerdictBlock, awsSecretPack())

	// A body carrying BOTH the keyed canary and the generic-pack literal.
	body := []byte("aws secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and token " + seededToken)
	v, err := matcher.Scan(body, true, ScanCtx{Direction: DirectionEgress})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Kind != VerdictBlock {
		t.Fatalf("a body tripping both planes must Block, got %v", v.Kind)
	}
	if v.Prov.Plane != PlaneKeyed {
		t.Errorf("keyed plane must take precedence; got plane=%v", v.Prov.Plane)
	}
}

// GenericPlane_NotSealGated proves the generic plane (a policy artifact, not
// session-lifecycle data) matches WITHOUT the keyed mint-before-attach seal —
// only the keyed plane is seal-gated.
func TestScan_GenericPlane_MatchesWithoutKeyedSeal(t *testing.T) {
	// Build a matcher with ONLY a generic pack (no keyed digests, so present=false
	// and the seal gate is irrelevant).
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16)
	matcher := feed.MatcherWithGeneric(VerdictBlock, awsSecretPack())
	if matcher.keyedLoaded() {
		t.Fatal("no keyed digests registered; keyed plane must not be present")
	}
	body := []byte("aws secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	v, err := matcher.Scan(body, true, ScanCtx{Direction: DirectionEgress})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Kind != VerdictBlock || v.Prov.Plane != PlaneGeneric {
		t.Fatalf("generic plane must match without a keyed seal; got kind=%v plane=%v", v.Kind, v.Prov.Plane)
	}
}
