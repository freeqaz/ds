// SPDX-License-Identifier: Apache-2.0

package cow

// goldenfastpath.go is the VM-runtime side of the M2 instant-start fast path
// (doc 05 §5; doc 15 §4.1 step 7): a session starts in seconds against a
// PRE-BAKED golden image by CLONING it — a per-session qcow2 overlay layered on
// the raw golden image at rest — rather than building a base image cold. This is
// a pure, testable MODEL of that clone (D29/D5): the golden image is the
// READ-ONLY backing file and every session write lands in the overlay (the
// backing-chain invariant), parsed/validated the way ParseQemuImgInfo parses.
//
// SCOPE (D29, mirroring enumerate.go): the block MECHANISM is out of scope —
// the live overlay-create leg that actually runs `qemu-img create -b
// <golden.raw> -F raw <overlay.qcow2>` lives in the sibling overlay-create.sh
// behind the DS_KVM_LIVE gate (a deferred manual step); this Go code is the pure
// model + the parser that validates a clone's backing chain, so the invariant is
// unit-testable with zero qemu in CI. A golden image is distinguished from a
// cold base image purely by which raw file is the backing file — there is NO new
// state, no new lifecycle branch: golden is an image-resolution input (the warm
// pre-baked artifact), base is the cold one (D12), and both clone the SAME way.

import (
	"fmt"
	"path"
	"strings"
)

// ImageClass distinguishes the WARM pre-baked golden image (the M2
// seconds-to-start optimization, D12) from a COLD base image. It is a property
// of the resolved image at rest, NOT a session lifecycle state — the overlay
// clone is identical either way (doc 15 §4.1 step 7); golden is simply the
// pre-baked artifact whose warm dependencies make the clone→boot→attach fast
// path fast. The class is an annotation the fast path carries for the §8 timing
// trend ("was this create against a warm image?"), never a branch in the clone
// model.
type ImageClass string

const (
	// ImageGolden is a PRE-BAKED golden image (warm deps, M2, D12): the raw image
	// at rest the fast path clones for a seconds-to-start session.
	ImageGolden ImageClass = "golden"
	// ImageBase is a COLD base image (v0, D12): the raw image at rest a non-fast
	// create clones, paying the dependency-warming cost dynamically inside the
	// session. Modeled here only so the class is total — the clone is identical.
	ImageBase ImageClass = "base"
)

// GoldenImage models the raw golden image AT REST (D29/D5): the content-addressed,
// pre-baked, READ-ONLY artifact the fast path clones. It is the backing file every
// per-session overlay layers on; it is NEVER written through an overlay (the D29
// invariant this package exists to assert). It is pure data parsed/validated like
// an Enumeration — no qemu is opened here.
type GoldenImage struct {
	// ImageID is the content-addressed identity of the image (the orchestrator's
	// VmSpec.image_id / store-record ImageID, doc 15 §5.1 — (repo, ref, env-spec
	// hash[, role-layer-set hash])). The fast path resolves it; this model carries
	// it so a clone can be tied back to the image it cloned. Required.
	ImageID string
	// RawPath is the on-host path of the raw golden image at rest (the qcow2
	// backing file every session overlay points at, format=raw per the M0 base
	// layout enumerate.go fixtures use). Required.
	RawPath string
	// Class records whether this is the WARM golden artifact (the common fast-path
	// case) or a COLD base (D12). Defaults to ImageGolden when unset (the fast path
	// resolves a golden image by construction). It NEVER changes the clone — it is
	// the §8 trend annotation only.
	Class ImageClass
}

// resolveClass returns the image class, defaulting an unset value to ImageGolden
// (the fast path resolves a pre-baked golden image; an unset class is the warm
// case, never a hidden cold fall-through).
func (g GoldenImage) resolveClass() ImageClass {
	if g.Class == "" {
		return ImageGolden
	}
	return g.Class
}

// Validate checks the golden image at rest is well-formed enough to clone: a
// content-addressed ID and a raw path, with a recognized class. It is the
// pre-clone gate — a fast path resolves a real pre-baked artifact, never an empty
// reference (the M0 fail-closed posture, mirroring enumerate.go's parse refusals).
func (g GoldenImage) Validate() error {
	if strings.TrimSpace(g.ImageID) == "" {
		return fmt.Errorf("goldenfastpath: golden image has empty content-addressed ImageID (the fast path must resolve a pre-baked image, doc 15 §4.1 step 7)")
	}
	if strings.TrimSpace(g.RawPath) == "" {
		return fmt.Errorf("goldenfastpath: golden image %q has empty RawPath (the raw image at rest is the overlay's backing file, D29)", g.ImageID)
	}
	switch g.resolveClass() {
	case ImageGolden, ImageBase:
	default:
		return fmt.Errorf("goldenfastpath: golden image %q has unknown class %q (want golden|base)", g.ImageID, g.Class)
	}
	return nil
}

// OverlayClone models the result of CLONING a golden image for one session
// (doc 15 §4.1 step 7): a per-session qcow2 overlay (the READ/WRITE delta) layered
// on the golden raw image (the READ-ONLY backing file). It is the data the VM
// runtime hands back as CloneFromImageResponse.overlay_path (doc 15 §5.1) — pure,
// no qemu opened.
type OverlayClone struct {
	// SessionUUID is the session the overlay was cloned for (the per-session
	// delta's owner; the overlay dies with the session, doc 02 §5). Required.
	SessionUUID string
	// OverlayPath is the per-session qcow2 overlay path — the write delta +
	// inspectable artifact + durability unit (D29). Required.
	OverlayPath string
	// Backing is the golden image this overlay layers on (the READ-ONLY base).
	Backing GoldenImage
}

// PlanOverlayClone is the pure model of the §4.1 step-7 CloneFromImage overlay
// for a golden image: it validates the golden image at rest and derives the
// per-session overlay clone WITHOUT touching qemu (the live `qemu-img create -b`
// leg stays behind DS_KVM_LIVE in overlay-create.sh — a deferred manual step).
// The overlay path is derived deterministically under overlayDir so a session's
// write delta has one canonical home (the host-side layout enumerate.go's
// fixtures use: /var/lib/ds/sessions/<sid>/overlay.qcow2). The returned clone is
// the in-rest model; ValidateBackingChain asserts the invariant on it.
func PlanOverlayClone(golden GoldenImage, sessionUUID, overlayDir string) (OverlayClone, error) {
	if err := golden.Validate(); err != nil {
		return OverlayClone{}, err
	}
	if strings.TrimSpace(sessionUUID) == "" {
		return OverlayClone{}, fmt.Errorf("goldenfastpath: empty sessionUUID (the overlay is per-session, D29)")
	}
	if strings.TrimSpace(overlayDir) == "" {
		return OverlayClone{}, fmt.Errorf("goldenfastpath: empty overlayDir (the per-session overlay needs a host-side home)")
	}
	// Derive the canonical per-session overlay path (the layout the host-side
	// scripts + the enumerate.go fixtures use). path (not filepath) keeps this a
	// pure model of the POSIX host layout, independent of the test runner's OS.
	overlayPath := path.Join(overlayDir, sessionUUID, "overlay.qcow2")
	clone := OverlayClone{
		SessionUUID: sessionUUID,
		OverlayPath: overlayPath,
		Backing:     golden,
	}
	if err := clone.ValidateBackingChain(); err != nil {
		return OverlayClone{}, err
	}
	return clone, nil
}

// ValidateBackingChain asserts the D29 backing-chain invariant on the modeled
// clone: the overlay is a DISTINCT file from the golden raw base (the write delta
// never IS the base), and the golden raw base is its backing file. It is the
// in-model twin of ParseQemuImgInfo's invariant check (which validates the SAME
// relationship from a real `qemu-img info --backing-chain` capture): the golden
// image is the read-only backing file and session writes land in the overlay.
func (c OverlayClone) ValidateBackingChain() error {
	if strings.TrimSpace(c.OverlayPath) == "" {
		return fmt.Errorf("goldenfastpath: overlay clone for session %q has empty OverlayPath", c.SessionUUID)
	}
	if err := c.Backing.Validate(); err != nil {
		return fmt.Errorf("goldenfastpath: overlay clone for session %q has invalid backing golden image: %w", c.SessionUUID, err)
	}
	if c.OverlayPath == c.Backing.RawPath {
		return fmt.Errorf("goldenfastpath: overlay %q IS its own backing file — a session overlay MUST be a distinct write delta layered on the READ-ONLY golden base (D29)", c.OverlayPath)
	}
	return nil
}

// AsEnumeration projects the modeled clone onto the cow.Enumeration shape the
// rest of this package speaks (OverlayPath / BasePath / BackingReadOnly), so a
// fast-path clone's backing chain is expressed in the SAME vocabulary a parsed
// `qemu-img info` capture is (ParseQemuImgInfo). It sets BackingReadOnly=true:
// the golden image at rest IS the read-only base by the D29 contract this model
// enforces (the live read-only MOUNT is overlay-create.sh's runtime concern,
// asserted there behind DS_KVM_LIVE — exactly the explicit-flag discipline
// ParseQemuImgInfo keeps). It does NOT enumerate writes (no session has run yet
// at clone time); enumerate.go owns the post-destroy write enumeration.
func (c OverlayClone) AsEnumeration() *Enumeration {
	return &Enumeration{
		OverlayPath:     c.OverlayPath,
		BasePath:        c.Backing.RawPath,
		BackingReadOnly: true,
	}
}

// VerifyClonedFromGolden cross-checks a real `qemu-img info --backing-chain`
// capture (parsed via ParseQemuImgInfo) against the golden image the fast path
// INTENDED to clone: the captured overlay matches the planned overlay path and
// the captured backing file IS the golden raw image at rest. It is the bridge
// from the pure model to the (DS_KVM_LIVE, deferred) live capture — a host that
// actually ran the clone can confirm it layered on the resolved golden image and
// not some other base (the D29 read-only-base invariant tied back to the resolved
// image_id). assumeBackingReadOnly threads through to ParseQemuImgInfo's explicit
// read-only flag (never overclaimed from a static parse).
func VerifyClonedFromGolden(qemuImgInfoOut string, plan OverlayClone, assumeBackingReadOnly bool) (*Enumeration, error) {
	if err := plan.ValidateBackingChain(); err != nil {
		return nil, err
	}
	e, err := ParseQemuImgInfo(qemuImgInfoOut, assumeBackingReadOnly)
	if err != nil {
		return nil, err
	}
	if e.OverlayPath != plan.OverlayPath {
		return nil, fmt.Errorf("goldenfastpath: captured overlay %q != planned overlay %q for session %q", e.OverlayPath, plan.OverlayPath, plan.SessionUUID)
	}
	if e.BasePath != plan.Backing.RawPath {
		return nil, fmt.Errorf("goldenfastpath: captured backing file %q != resolved golden image %q (overlay did NOT clone the intended golden base, D29)", e.BasePath, plan.Backing.RawPath)
	}
	return e, nil
}
