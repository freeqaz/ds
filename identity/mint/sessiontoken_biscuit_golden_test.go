// SPDX-License-Identifier: Apache-2.0

// Biscuit appended-block READ-PATH golden guard (doc 19 §4/§6, D98).
//
// WHY THIS EXISTS. The session-token library reads the EFFECTIVE (deepest) claim
// set off an attenuated Biscuit through biscuit-go's DEBUG Code() renderer
// (sessiontoken_biscuit.go: claimsTermRe over b.Code()[n-1]) — because biscuit-go
// v2.2.0 surfaces APPENDED blocks only through that render path, not the authority
// Query path used for the base token. That makes the renderer's BLOCK SHAPE a
// load-bearing parse contract: a biscuit-go upgrade that changes how an appended
// block renders (the `Block { }` scaffold, the `session_token_claims(N, "...")`
// term form, spacing/quoting) would SILENTLY break the read path — a child token
// would mis-parse instead of failing loudly. The go.mod pin is biscuit-go v2.2.0;
// this golden is the tripwire that fires if that pin ever moves to a version with a
// different renderer.
//
// SELF-CHECKING (the brief's requirement). Each assertion below regenerates the
// render live (a fresh in-test Ed25519 key, synthetic claims, D50) and compares it
// to the committed testdata/biscuit-block-render-golden.json. A renderer-shape or
// payload-encoding drift fails the assertion at test time. The golden carries the
// pinned biscuit-go version so a mismatch points straight at the upgrade.
package mint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
)

// biscuitBlockRenderGolden mirrors testdata/biscuit-block-render-golden.json.
type biscuitBlockRenderGolden struct {
	BiscuitGoVersion string `json:"biscuit_go_version"`
	ClaimsFactName   string `json:"claims_fact_name"`
	AppendedBlock    struct {
		Depth              int    `json:"depth"`
		RenderTemplate     string `json:"render_template"`
		PayloadPlaceholder string `json:"payload_placeholder"`
	} `json:"appended_block"`
	RoundTrip struct {
		BaseClaims          SessionTokenClaims `json:"base_claims"`
		Narrow              goldenNarrow       `json:"narrow"`
		ExpectedChildClaims SessionTokenClaims `json:"expected_child_claims"`
		ExpectedPayloadB64  string             `json:"expected_payload_b64url"`
	} `json:"round_trip"`
}

type goldenNarrow struct {
	ChildSessionUUID string   `json:"ChildSessionUUID"`
	Services         []string `json:"Services"`
	TaskRef          string   `json:"TaskRef"`
}

func loadBiscuitBlockRenderGolden(t *testing.T) biscuitBlockRenderGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "biscuit-block-render-golden.json"))
	if err != nil {
		t.Fatalf("read biscuit-block-render golden: %v", err)
	}
	var g biscuitBlockRenderGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse biscuit-block-render golden: %v", err)
	}
	return g
}

// TestBiscuitBlockRender_ScaffoldGolden pins the biscuit-go v2.2.0 appended-block
// render SCAFFOLD. It mints + attenuates a synthetic token, renders the appended
// block via the same Code() surface the read path uses, and asserts the render
// equals the golden's render_template with %PAYLOAD% substituted. A biscuit-go
// upgrade that changes the scaffold (the `Block { }` frame, the term form, the
// tab/newline shape) breaks this assertion LOUDLY — exactly what the read-path
// guard the brief asks for must do.
func TestBiscuitBlockRender_ScaffoldGolden(t *testing.T) {
	g := loadBiscuitBlockRenderGolden(t)
	if g.ClaimsFactName != claimsFactName {
		t.Fatalf("golden claims_fact_name = %q, want %q (the read path's fact name drifted)", g.ClaimsFactName, claimsFactName)
	}

	signer := newGoldenSigner(t)
	child := mintAttenuateGolden(t, signer, g)

	// Render the appended block exactly as the read path does (Code()[n-1]).
	code := signerCode(t, signer, child)
	if len(code) == 0 {
		t.Fatal("rendered code has no blocks")
	}
	rendered := code[len(code)-1]

	// The pinned scaffold with the golden payload substituted MUST equal the live
	// render. Any renderer-shape drift in a biscuit-go upgrade fails here.
	wantRender := strings.Replace(g.AppendedBlock.RenderTemplate, g.AppendedBlock.PayloadPlaceholder, g.RoundTrip.ExpectedPayloadB64, 1)
	if rendered != wantRender {
		t.Fatalf("biscuit-go appended-block RENDER drifted from the v%s golden\n got=%q\nwant=%q\n(go.mod pin is biscuit-go %s; a renderer change there breaks the session-token read path)",
			g.BiscuitGoVersion, rendered, wantRender, g.BiscuitGoVersion)
	}
}

// TestBiscuitBlockRender_RegexExtractsGolden proves the read path's extraction
// regex (claimsTermRe) still pulls the correct (depth, payload) pair out of the
// pinned render scaffold. This is the second half of the read-path contract: even
// if the scaffold were tweaked, the regex that consumes it must keep matching the
// golden depth + payload, or a child token's effective claims silently vanish.
func TestBiscuitBlockRender_RegexExtractsGolden(t *testing.T) {
	g := loadBiscuitBlockRenderGolden(t)
	wantRender := strings.Replace(g.AppendedBlock.RenderTemplate, g.AppendedBlock.PayloadPlaceholder, g.RoundTrip.ExpectedPayloadB64, 1)

	m := claimsTermRe.FindStringSubmatch(wantRender)
	if m == nil {
		t.Fatal("claimsTermRe did NOT match the pinned render scaffold — read-path regex drifted from the renderer shape")
	}
	if m[1] != "1" {
		t.Fatalf("extracted depth = %q, want %q", m[1], "1")
	}
	if m[2] != g.RoundTrip.ExpectedPayloadB64 {
		t.Fatalf("extracted payload mismatch\n got=%q\nwant=%q", m[2], g.RoundTrip.ExpectedPayloadB64)
	}
	// And the extracted payload decodes back to the golden child claims.
	claims, err := decodeClaimPayload(m[2])
	if err != nil {
		t.Fatalf("decode pinned payload: %v", err)
	}
	assertClaimsEqual(t, claims, g.RoundTrip.ExpectedChildClaims)
}

// TestBiscuitBlockRender_RoundTripGolden pins the full mint->attenuate->Verify
// round trip on the synthetic claim set: the live Verify must decode the
// attenuated child to EXACTLY the golden child claims, AND the live appended
// payload must equal the pinned base64url payload. This catches a payload-encoding
// drift (the base64url/JSON claim encoding) in addition to the renderer scaffold.
func TestBiscuitBlockRender_RoundTripGolden(t *testing.T) {
	g := loadBiscuitBlockRenderGolden(t)
	signer := newGoldenSigner(t)
	child := mintAttenuateGolden(t, signer, g)

	gotClaims, depth, err := signer.Verify(child)
	if err != nil {
		t.Fatalf("verify attenuated child: %v", err)
	}
	if depth != g.AppendedBlock.Depth {
		t.Fatalf("child depth = %d, want golden %d", depth, g.AppendedBlock.Depth)
	}
	assertClaimsEqual(t, gotClaims, g.RoundTrip.ExpectedChildClaims)

	// The live appended payload must equal the pinned base64url payload (encoding
	// stability). Re-render and re-extract through the read path's own regex.
	code := signerCode(t, signer, child)
	m := claimsTermRe.FindStringSubmatch(code[len(code)-1])
	if m == nil {
		t.Fatal("claimsTermRe did not match the LIVE render")
	}
	if m[2] != g.RoundTrip.ExpectedPayloadB64 {
		t.Fatalf("live appended payload drifted from the golden\n got=%q\nwant=%q", m[2], g.RoundTrip.ExpectedPayloadB64)
	}
}

// --- golden helpers --------------------------------------------------------

// newGoldenSigner returns a fresh Biscuit signer (synthetic key, D50). The key is
// fresh per run; the golden pins only RENDER SHAPE + payload (a function of the
// claim record), neither of which depends on the signing key, so the assertions
// are deterministic across runs.
func newGoldenSigner(t *testing.T) *biscuitSigner {
	t.Helper()
	s, err := newBiscuitSigner()
	if err != nil {
		t.Fatalf("new biscuit signer: %v", err)
	}
	return s
}

// mintAttenuateGolden mints the golden base claims and attenuates with the golden
// narrow, returning the serialized child token.
func mintAttenuateGolden(t *testing.T, s *biscuitSigner, g biscuitBlockRenderGolden) []byte {
	t.Helper()
	base, _, err := s.Mint(g.RoundTrip.BaseClaims)
	if err != nil {
		t.Fatalf("mint golden base: %v", err)
	}
	child, _, err := s.Attenuate(base, SessionTokenAttenuation{
		ChildSessionUUID: g.RoundTrip.Narrow.ChildSessionUUID,
		Services:         g.RoundTrip.Narrow.Services,
		TaskRef:          g.RoundTrip.Narrow.TaskRef,
	})
	if err != nil {
		t.Fatalf("attenuate golden child: %v", err)
	}
	return child
}

// assertClaimsEqual compares two claim records by their canonical JSON (the same
// surface the read path decodes), with Expiry compared as an instant so a
// time-zone render difference does not spuriously fail.
func assertClaimsEqual(t *testing.T, got, want SessionTokenClaims) {
	t.Helper()
	if !got.Expiry.Equal(want.Expiry) {
		t.Fatalf("claims expiry = %v, want %v", got.Expiry, want.Expiry)
	}
	got.Expiry = want.Expiry // normalize the instant for the JSON compare below
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("claim-set mismatch\n got=%s\nwant=%s", gotJSON, wantJSON)
	}
}

// signerCode unmarshals the token and returns biscuit-go's Code() render — the
// exact surface the read path (Verify) consumes for an appended block. Driving the
// render through the real biscuit-go API (not a re-serialized fixture) is what
// makes the golden a live tripwire on a version bump.
func signerCode(t *testing.T, _ *biscuitSigner, token []byte) []string {
	t.Helper()
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		t.Fatalf("unmarshal token for render: %v", err)
	}
	return b.Code()
}
