// SPDX-License-Identifier: Apache-2.0

package cow

import (
	"strings"
	"testing"
)

// goldenfastpath_test.go drives the VM-runtime side of the M2 instant-start fast
// path (goldenfastpath.go): the raw golden image at rest + per-session qcow2
// overlay clone (D29). It proves the backing-chain invariant — the golden image
// is the READ-ONLY backing file and session writes land in the overlay — on
// synthetic fixtures, with zero qemu (D50; the live overlay-create leg is behind
// DS_KVM_LIVE in overlay-create.sh, a deferred manual step).

// TestGoldenImage_Validate covers the pre-clone gate: a well-formed golden image
// passes; an empty content-address or raw path or an unknown class is refused
// fail-closed (the M0 posture, mirroring enumerate.go's parse refusals).
func TestGoldenImage_Validate(t *testing.T) {
	cases := []struct {
		name    string
		img     GoldenImage
		wantErr bool
	}{
		{"golden ok", GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw", Class: ImageGolden}, false},
		{"base ok", GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-base.raw", Class: ImageBase}, false},
		{"default class ok", GoldenImage{ImageID: "sha256:abc", RawPath: "/x.raw"}, false},
		{"empty image id", GoldenImage{RawPath: "/x.raw"}, true},
		{"whitespace image id", GoldenImage{ImageID: "  ", RawPath: "/x.raw"}, true},
		{"empty raw path", GoldenImage{ImageID: "sha256:abc"}, true},
		{"unknown class", GoldenImage{ImageID: "sha256:abc", RawPath: "/x.raw", Class: "warmish"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.img.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestGoldenImage_DefaultClassIsGolden pins the resolution: an unset class is the
// WARM golden case (the fast path resolves a pre-baked golden image), never a
// hidden cold fall-through.
func TestGoldenImage_DefaultClassIsGolden(t *testing.T) {
	g := GoldenImage{ImageID: "sha256:abc", RawPath: "/x.raw"}
	if got := g.resolveClass(); got != ImageGolden {
		t.Fatalf("resolveClass()=%q, want %q", got, ImageGolden)
	}
}

// TestPlanOverlayClone_BackingChainInvariant is the core assertion: planning the
// §4.1 step-7 overlay clone derives a per-session overlay whose backing file IS
// the golden raw image at rest, and the overlay is a DISTINCT file from the base
// (the write delta never IS the base — D29).
func TestPlanOverlayClone_BackingChainInvariant(t *testing.T) {
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw", Class: ImageGolden}
	clone, err := PlanOverlayClone(golden, "01HEXSESS", "/var/lib/ds/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	if clone.OverlayPath != "/var/lib/ds/sessions/01HEXSESS/overlay.qcow2" {
		t.Fatalf("overlay path = %q, want the canonical per-session path", clone.OverlayPath)
	}
	if clone.Backing.RawPath != golden.RawPath {
		t.Fatalf("backing = %q, want the golden raw base %q", clone.Backing.RawPath, golden.RawPath)
	}
	if clone.OverlayPath == clone.Backing.RawPath {
		t.Fatal("overlay must be DISTINCT from the read-only base (D29)")
	}
	if err := clone.ValidateBackingChain(); err != nil {
		t.Fatalf("ValidateBackingChain: %v", err)
	}
}

// TestPlanOverlayClone_Refusals proves the fail-closed gates: an invalid golden
// image, an empty session UUID, or an empty overlay dir all refuse a clone.
func TestPlanOverlayClone_Refusals(t *testing.T) {
	ok := GoldenImage{ImageID: "sha256:abc", RawPath: "/golden.raw"}
	cases := []struct {
		name    string
		golden  GoldenImage
		session string
		dir     string
	}{
		{"empty image id", GoldenImage{RawPath: "/golden.raw"}, "s1", "/sessions"},
		{"empty raw path", GoldenImage{ImageID: "sha256:abc"}, "s1", "/sessions"},
		{"empty session", ok, "", "/sessions"},
		{"empty dir", ok, "s1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PlanOverlayClone(tc.golden, tc.session, tc.dir); err == nil {
				t.Fatal("PlanOverlayClone: want refusal, got nil")
			}
		})
	}
}

// TestValidateBackingChain_OverlayEqualsBase pins the read-only-base invariant
// directly: an overlay whose path equals its backing file is refused — a session
// write delta must NEVER be the read-only golden base (D29).
func TestValidateBackingChain_OverlayEqualsBase(t *testing.T) {
	c := OverlayClone{
		SessionUUID: "s1",
		OverlayPath: "/golden.raw",
		Backing:     GoldenImage{ImageID: "sha256:abc", RawPath: "/golden.raw"},
	}
	err := c.ValidateBackingChain()
	if err == nil {
		t.Fatal("want refusal when overlay IS its own backing file")
	}
	if !strings.Contains(err.Error(), "distinct write delta") && !strings.Contains(err.Error(), "READ-ONLY") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAsEnumeration projects the modeled clone onto the cow.Enumeration vocabulary
// the rest of the package speaks: BasePath is the golden raw image, OverlayPath is
// the write delta, and BackingReadOnly is asserted true (the golden image at rest
// IS the read-only base by the D29 contract the model enforces).
func TestAsEnumeration(t *testing.T) {
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw"}
	clone, err := PlanOverlayClone(golden, "s1", "/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	e := clone.AsEnumeration()
	if e.BasePath != golden.RawPath {
		t.Fatalf("enumeration BasePath = %q, want golden base %q", e.BasePath, golden.RawPath)
	}
	if e.OverlayPath != clone.OverlayPath {
		t.Fatalf("enumeration OverlayPath = %q, want %q", e.OverlayPath, clone.OverlayPath)
	}
	if !e.BackingReadOnly {
		t.Fatal("golden image at rest must be the read-only backing file (D29)")
	}
	// No session has run at clone time — no writes enumerated.
	if len(e.Writes) != 0 {
		t.Fatalf("clone-time enumeration must have no writes, got %d", len(e.Writes))
	}
}

// TestVerifyClonedFromGolden_Conforming bridges the pure model to a real
// `qemu-img info --backing-chain` capture (the DS_KVM_LIVE leg's output): a
// capture whose overlay + backing file match the planned clone confirms the
// overlay cloned the INTENDED golden image (the read-only-base invariant tied
// back to the resolved image at rest).
func TestVerifyClonedFromGolden_Conforming(t *testing.T) {
	// A backing-chain capture matching the canonical M0 layout (the same shape as
	// fixtures/qemuimg-conforming.txt; inlined synthetic, D50).
	out := strings.Join([]string{
		"image: /var/lib/ds/sessions/01HEXSESS/overlay.qcow2",
		"file format: qcow2",
		"backing file: /var/lib/ds/base/m0-golden.raw",
		"backing file format: raw",
		"",
		"image: /var/lib/ds/base/m0-golden.raw",
		"file format: raw",
	}, "\n")
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw"}
	plan, err := PlanOverlayClone(golden, "01HEXSESS", "/var/lib/ds/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	e, err := VerifyClonedFromGolden(out, plan, true)
	if err != nil {
		t.Fatalf("VerifyClonedFromGolden: %v", err)
	}
	if e.BasePath != golden.RawPath {
		t.Fatalf("captured base = %q, want golden %q", e.BasePath, golden.RawPath)
	}
	if !e.BackingReadOnly {
		t.Fatal("assumeBackingReadOnly=true must thread through")
	}
}

// TestVerifyClonedFromGolden_WrongBase proves the cross-check catches an overlay
// that cloned the WRONG base: a capture whose backing file differs from the
// resolved golden image is refused (the overlay did not clone the intended golden
// base — the D29 invariant tied to the resolved image_id).
func TestVerifyClonedFromGolden_WrongBase(t *testing.T) {
	out := strings.Join([]string{
		"image: /var/lib/ds/sessions/01HEXSESS/overlay.qcow2",
		"file format: qcow2",
		"backing file: /var/lib/ds/base/SOME-OTHER.raw",
		"backing file format: raw",
	}, "\n")
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw"}
	plan, err := PlanOverlayClone(golden, "01HEXSESS", "/var/lib/ds/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	if _, err := VerifyClonedFromGolden(out, plan, true); err == nil {
		t.Fatal("want refusal when the captured backing file != resolved golden image")
	}
}

// TestVerifyClonedFromGolden_NoBacking proves a capture with NO backing file is
// refused (ParseQemuImgInfo's invariant): a session overlay MUST layer on the raw
// golden base; an overlay with no backing chain is not a valid clone (D29).
func TestVerifyClonedFromGolden_NoBacking(t *testing.T) {
	out := strings.Join([]string{
		"image: /var/lib/ds/sessions/01HEXSESS/overlay.qcow2",
		"file format: qcow2",
	}, "\n")
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-golden.raw"}
	plan, err := PlanOverlayClone(golden, "01HEXSESS", "/var/lib/ds/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	if _, err := VerifyClonedFromGolden(out, plan, true); err == nil {
		t.Fatal("want refusal when the captured overlay has no backing file")
	}
}

// TestVerifyClonedFromGolden_ConformingFixture exercises the SAME path against the
// committed fixture, confirming the model agrees with the package's canonical
// capture shape (fixtures/qemuimg-conforming.txt has base m0-base.raw).
func TestVerifyClonedFromGolden_ConformingFixture(t *testing.T) {
	out := readFixture(t, "qemuimg-conforming.txt")
	golden := GoldenImage{ImageID: "sha256:abc", RawPath: "/var/lib/ds/base/m0-base.raw"}
	plan, err := PlanOverlayClone(golden, "01HEXSESS", "/var/lib/ds/sessions")
	if err != nil {
		t.Fatalf("PlanOverlayClone: %v", err)
	}
	if _, err := VerifyClonedFromGolden(out, plan, true); err != nil {
		t.Fatalf("VerifyClonedFromGolden against committed fixture: %v", err)
	}
}
