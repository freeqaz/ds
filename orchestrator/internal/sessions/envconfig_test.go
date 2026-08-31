package sessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// goodCoupling is a complete, unsplit D74/D49 coupled-invariant set: a CC pin at the
// floor, auto-update off, a pack version, and the downloads.claude.ai pack-exclusion.
func goodCoupling() CoupledInvariants {
	return CoupledInvariants{
		CCPin:         "2.1.116",
		AutoUpdateOff: true,
		PackVersion:   "v2",
		PackExclusion: "downloads.claude.ai",
	}
}

// TestCoupledInvariants_ValidateAcceptsComplete proves a fully-recorded coupling
// validates (D74/D49): all three coupled facts present and consistent.
func TestCoupledInvariants_ValidateAcceptsComplete(t *testing.T) {
	if err := goodCoupling().Validate(); err != nil {
		t.Fatalf("complete coupling must validate, got %v", err)
	}
	// A pin ABOVE the floor also validates (≥, not ==).
	c := goodCoupling()
	c.CCPin = "2.2.0"
	if err := c.Validate(); err != nil {
		t.Errorf("above-floor pin must validate, got %v", err)
	}
	// A leading "v" on the pin is tolerated.
	c = goodCoupling()
	c.CCPin = "v2.1.117"
	if err := c.Validate(); err != nil {
		t.Errorf("v-prefixed above-floor pin must validate, got %v", err)
	}
}

// TestCoupledInvariants_ValidateRefusesSplit proves the D74/D49 STRUCTURAL guard: any
// HALF-set coupling is refused fail-closed (ErrCouplingSplit) — the coupling cannot
// silently split. Each case removes/breaks exactly one coupled fact.
func TestCoupledInvariants_ValidateRefusesSplit(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*CoupledInvariants)
	}{
		{"no CC pin (pack-exclusion recorded against no pin)", func(c *CoupledInvariants) { c.CCPin = "" }},
		{"below-floor CC pin", func(c *CoupledInvariants) { c.CCPin = "2.1.115" }},
		{"below-floor on minor", func(c *CoupledInvariants) { c.CCPin = "2.0.999" }},
		{"malformed CC pin", func(c *CoupledInvariants) { c.CCPin = "2.x.1" }},
		{"auto-update still on (pin would drift)", func(c *CoupledInvariants) { c.AutoUpdateOff = false }},
		{"no pack version", func(c *CoupledInvariants) { c.PackVersion = "" }},
		{"pack-exclusion missing (re-admits the host)", func(c *CoupledInvariants) { c.PackExclusion = "" }},
		{"pack-exclusion is a different host", func(c *CoupledInvariants) { c.PackExclusion = "api.anthropic.com" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodCoupling()
			tc.mut(&c)
			err := c.Validate()
			if !errors.Is(err, ErrCouplingSplit) {
				t.Fatalf("split coupling must refuse with ErrCouplingSplit, got %v", err)
			}
		})
	}
}

// TestRecordEnvConfig_InlineStoresCoupledUnit proves RecordEnvConfig over an INLINE
// spec: it hashes the opaque body, records the coupled invariants as a unit, and
// persists through the store seam — the stored record carries all three coupled facts.
func TestRecordEnvConfig_InlineStoresCoupledUnit(t *testing.T) {
	mem := store.NewMemory()
	body := []byte("opaque-env-spec-body")
	got, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{
		InlineSpec: body,
		ImageID:    "img-abc123",
		Coupled:    goodCoupling(),
	})
	if err != nil {
		t.Fatalf("RecordEnvConfig(inline): unexpected error: %v", err)
	}
	if got.Ref == "" {
		t.Fatal("recorded env config must carry a non-empty ref")
	}
	// The spec hash is the SHA-256 of the opaque body (the spec is never parsed).
	want := sha256.Sum256(body)
	if got.SpecHash != hex.EncodeToString(want[:]) {
		t.Errorf("inline spec hash = %q, want SHA-256 of the body", got.SpecHash)
	}
	if got.CoupledPin != "2.1.116" || got.PackVersion != "v2" || got.PackExclusion != "downloads.claude.ai" {
		t.Errorf("coupled invariants not recorded as a unit: %+v", got)
	}
	// It is readable back through the store (it is the second-key the two-key check reads).
	back, err := mem.GetEnvConfig(context.Background(), got.Ref)
	if err != nil {
		t.Fatalf("recorded env config must be readable back: %v", err)
	}
	if back.ImageID != "img-abc123" {
		t.Errorf("stored image lineage = %q, want img-abc123", back.ImageID)
	}
}

// TestRecordEnvConfig_Idempotent proves recording the SAME lineage twice yields the
// SAME ref (content-addressed, idempotent record).
func TestRecordEnvConfig_Idempotent(t *testing.T) {
	mem := store.NewMemory()
	in := RecordEnvConfigInput{RepoRef: "github.com/acme/repo", SpecHash: "deadbeef", ImageID: "img-1", Coupled: goodCoupling()}
	a, err := RecordEnvConfig(context.Background(), mem, in)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	b, err := RecordEnvConfig(context.Background(), mem, in)
	if err != nil {
		t.Fatalf("second record: %v", err)
	}
	if a.Ref != b.Ref {
		t.Errorf("same lineage must record to the same ref: %q vs %q", a.Ref, b.Ref)
	}
	// A different image ID is a DISTINCT record (the image is in the content-address).
	in2 := in
	in2.ImageID = "img-2"
	c, err := RecordEnvConfig(context.Background(), mem, in2)
	if err != nil {
		t.Fatalf("third record: %v", err)
	}
	if c.Ref == a.Ref {
		t.Errorf("a re-resolved image must record to a distinct ref, got the same %q", c.Ref)
	}
}

// TestRecordEnvConfig_RefusesSplitCoupling proves RecordEnvConfig refuses to PERSIST a
// half-coupled record — the structural guard fires before the store is touched.
func TestRecordEnvConfig_RefusesSplitCoupling(t *testing.T) {
	mem := store.NewMemory()
	bad := goodCoupling()
	bad.PackExclusion = "" // the silent split
	_, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{
		InlineSpec: []byte("x"), ImageID: "img-1", Coupled: bad,
	})
	if !errors.Is(err, ErrCouplingSplit) {
		t.Fatalf("split coupling must refuse the record with ErrCouplingSplit, got %v", err)
	}
}

// TestRecordEnvConfig_RefusesMissingSpecAndImage proves the spec-source and resolved-
// image preconditions: no spec source (ErrEnvSpecInvalid); no resolved image (error).
func TestRecordEnvConfig_RefusesMissingSpecAndImage(t *testing.T) {
	mem := store.NewMemory()
	// No spec source at all.
	if _, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{ImageID: "img-1", Coupled: goodCoupling()}); !errors.Is(err, ErrEnvSpecInvalid) {
		t.Errorf("no spec source must refuse with ErrEnvSpecInvalid, got %v", err)
	}
	// Spec source but no resolved image.
	if _, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{InlineSpec: []byte("x"), Coupled: goodCoupling()}); err == nil {
		t.Error("missing resolved image must refuse")
	}
	// Repo ref with no upstream hash and no inline body: nothing to content-address.
	if _, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{RepoRef: "github.com/acme/repo", ImageID: "img-1", Coupled: goodCoupling()}); !errors.Is(err, ErrEnvSpecInvalid) {
		t.Errorf("repo ref with no hash/body must refuse with ErrEnvSpecInvalid, got %v", err)
	}
}
