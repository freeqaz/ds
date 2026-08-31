// SPDX-License-Identifier: Apache-2.0

// trustanchor_live_test.go — the DS_HOSTAGENT_LIVE-gated operator conformance for
// the COMPILED liveTrustStoreWriter (trustanchor.go). The offline tests
// (trustanchor_test.go) drive the writer over a recordingRunner FAKE — they pin
// the libguestfs command CONSTRUCTION + result handling but never shell a real
// virt-customize/virt-cat; the create-path tests (cainject_test.go) use an
// in-memory recordingTrustWriter that never touches guestfs at all. So the
// compiled writer — which shells virt-customize/virt-cat through the package's
// execRunner into a REAL qcow2 overlay's trust store — is exercised end-to-end
// ONLY here, and only on the operator host under the gate.
//
// GATE + OFFLINE POSTURE: every test in this file calls requireLiveGate first, so
// with DS_HOSTAGENT_LIVE unset (the sandbox / CI / every unit run) it SKIPS before
// touching any substrate. The file therefore COMPILES offline and is inert in CI —
// the same convention as live_smoke_test.go's TestLiveSmokeCloneBootDestroy. The
// real-qcow2 exercise itself stays with the parent live task (01KV6EX9); this is
// its OFFLINE code slice: the gated harness that runs on the M0 host per
// cmd/host-agent/LIVE-SMOKE.md.
//
// ENV CONTRACT: reuses the operator-host env facts live_smoke_test.go declares in
// this package — DS_HOSTAGENT_LIVE_BASE (the read-only raw golden, D29),
// _OVERLAY_DIR (the writable per-session overlay area), _OVERLAY_SCRIPT (abs path
// to vm/cow/overlay-create.sh), and the optional _VIRSH — so a live run is
// configured exactly like the clone/boot smoke, never hardcoded. The overlay is
// materialized through the live OverlayStore (the same production CoW clone the
// smoke drives), and the writer is the production NewLiveTrustStoreWriter over the
// libguestfs CLI on PATH.
//
// WHAT IT ASSERTS on the real overlay:
//   - a FRESH overlay reports HasTrustAnchor=false (no anchor present before any write);
//   - WriteTrustAnchor -> HasTrustAnchor ROUND-TRIPS (a written anchor is provably
//     present, by re-derived DER fingerprint — never a bare file-exists);
//   - an IDEMPOTENT re-inject converges to ONE anchor (the second InjectCA
//     short-circuits on the present anchor; the store still holds exactly the one CA);
//   - InjectCA FAIL-CLOSES on a real libguestfs error (a bogus overlay path errors
//     the presence probe or the write), so the create would abort at StepOverlay
//     before boot (D17).
//
// The private CA key is never delivered to the guest (only the public cert PEM is
// uploaded) and is never logged — the same fail-closed contract cainject.go pins.

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// liveTrustHarness collects the operator-host facts + the live substrate the gated
// trust-anchor tests share: the golden base, the writable overlay dir, and a live
// OverlayStore that clones a real per-session overlay from the base (the same CoW
// clone the smoke drives). It is only ever built under the gate.
type liveTrustHarness struct {
	base       string
	overlayDir string
	store      OverlayStore
}

// newLiveTrustHarness reads the DS_HOSTAGENT_LIVE_* env contract (identical to
// live_smoke_test.go) and builds the live OverlayStore. It fails the test loudly if
// the gate is set but the operator facts are missing — a misprovisioned host must
// not silently pass. Callers have already passed requireLiveGate.
func newLiveTrustHarness(t *testing.T) *liveTrustHarness {
	t.Helper()

	// Pin the DEFAULT system-trust delivery: NewLiveTrustStoreWriter reads
	// EnvGuestInterceptCAPath ONCE at construction, so a swap-configured operator
	// host (DS_GUEST_INTERCEPT_CA_PATH exported for posture-(b) runs) would
	// silently flip the writer to the fixed-path delivery and skip the system
	// bundle refresh this file's assertions document. The posture-(b) shape has
	// its own coverage (trustanchor_swap_test.go); this conformance pins the
	// byte-identical default. t.Setenv restores the operator's value on cleanup.
	t.Setenv(EnvGuestInterceptCAPath, "")

	base := os.Getenv(envLiveBase)
	overlayDir := os.Getenv(envLiveOverlayDir)
	script := os.Getenv(envLiveOverlayScript)
	if base == "" || overlayDir == "" || script == "" {
		t.Fatalf("live trust-anchor test requires %s (golden base), %s (overlay dir), %s (overlay-create.sh path) — see cmd/host-agent/LIVE-SMOKE.md", envLiveBase, envLiveOverlayDir, envLiveOverlayScript)
	}

	store, err := NewOverlayStore(LiveConfig{
		OverlayCreateScript: script,
		OverlayDir:          overlayDir,
		BaseImage:           base,
	})
	if err != nil {
		t.Fatalf("NewOverlayStore (live): %v", err)
	}
	return &liveTrustHarness{base: base, overlayDir: overlayDir, store: store}
}

// freshOverlay clones a NEW per-session overlay from the golden base for sessionUUID
// and registers its disposal on cleanup, so each test gets an anchor-free CoW layer
// and no overlay leaks across the run. It returns the on-disk overlay path.
func (h *liveTrustHarness) freshOverlay(t *testing.T, sessionUUID string) string {
	t.Helper()

	// Best-effort pre-clean of a leftover overlay from a prior aborted run so the
	// "fresh overlay has no anchor" assertion is not poisoned; the clone is
	// idempotent on --overlay but a stale file could carry an old anchor.
	overlayPath := filepath.Join(h.overlayDir, sessionUUID+".qcow2")
	_ = os.Remove(overlayPath)

	got, err := h.store.CreateOverlay(context.Background(), sessionUUID, "m0-golden")
	if err != nil {
		t.Fatalf("CreateOverlay (live) for %s: %v", sessionUUID, err)
	}
	if got != overlayPath {
		t.Fatalf("overlay path = %q, want %q (the live overlay-create.sh per-session clone path)", got, overlayPath)
	}
	t.Cleanup(func() { _ = os.Remove(overlayPath) })
	return overlayPath
}

// TestLiveTrustAnchor_FreshOverlayHasNoAnchor pins that a just-cloned overlay
// carries NO session anchor before any write: HasTrustAnchor is a normal (false,
// nil), never a spurious present. This is the pre-write baseline the round-trip and
// idempotency assertions rest on (a false-positive here would mask a broken write).
func TestLiveTrustAnchor_FreshOverlayHasNoAnchor(t *testing.T) {
	requireLiveGate(t)
	h := newLiveTrustHarness(t)

	const sessionUUID = "00000000-0000-4000-8000-00000000ca01"
	overlayPath := h.freshOverlay(t, sessionUUID)

	caPEM := mintCAPEM(t)
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}

	w, err := NewLiveTrustStoreWriter()
	if err != nil {
		t.Fatalf("NewLiveTrustStoreWriter: %v", err)
	}
	present, err := w.HasTrustAnchor(context.Background(), sessionUUID, overlayPath, fp)
	if err != nil {
		t.Fatalf("HasTrustAnchor on a fresh overlay must be a benign absent, got err=%v", err)
	}
	if present {
		t.Fatal("a fresh overlay must report HasTrustAnchor=false before any write")
	}
}

// TestLiveTrustAnchor_WriteThenHasRoundTrips is the core round-trip on a REAL
// overlay: the compiled writer uploads the anchor via virt-customize + refreshes
// the system bundle, and HasTrustAnchor reads it back via virt-cat and re-derives
// the DER fingerprint. A matching-fingerprint probe returns present=true; a probe
// for a DIFFERENT CA's fingerprint returns present=false — proving the read-back is
// byte-exact (fingerprint identity), never a bare file-exists.
func TestLiveTrustAnchor_WriteThenHasRoundTrips(t *testing.T) {
	requireLiveGate(t)
	h := newLiveTrustHarness(t)

	const sessionUUID = "00000000-0000-4000-8000-00000000ca02"
	overlayPath := h.freshOverlay(t, sessionUUID)

	caPEM := mintCAPEM(t)
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}

	w, err := NewLiveTrustStoreWriter()
	if err != nil {
		t.Fatalf("NewLiveTrustStoreWriter: %v", err)
	}
	ctx := context.Background()

	if err := w.WriteTrustAnchor(ctx, sessionUUID, overlayPath, caPEM); err != nil {
		t.Fatalf("WriteTrustAnchor into the live overlay: %v", err)
	}

	present, err := w.HasTrustAnchor(ctx, sessionUUID, overlayPath, fp)
	if err != nil {
		t.Fatalf("HasTrustAnchor after write: %v", err)
	}
	if !present {
		t.Fatal("the written anchor must be provably present (write -> has round-trip)")
	}

	// A distinct CA's fingerprint must NOT match the installed anchor — the probe is
	// keyed on the byte-exact DER fingerprint, not a mere file-exists.
	otherFP, err := validateCABundle(mintCAPEM(t))
	if err != nil {
		t.Fatalf("validateCABundle (other): %v", err)
	}
	if otherFP == fp {
		t.Fatal("distinct CAs must have distinct fingerprints")
	}
	otherPresent, err := w.HasTrustAnchor(ctx, sessionUUID, overlayPath, otherFP)
	if err != nil {
		t.Fatalf("HasTrustAnchor for a different fingerprint: %v", err)
	}
	if otherPresent {
		t.Fatal("a different CA's fingerprint must not report present — the probe must be fingerprint-exact")
	}
}

// TestLiveTrustAnchor_InjectIsIdempotent drives the production caInjector over the
// COMPILED writer + the production file CABundleSource (seeded with a minted CA)
// twice against the SAME real overlay. The first InjectCA fetches -> writes ->
// verifies; the second must short-circuit on the already-present anchor and
// converge WITHOUT error, and the overlay must still hold exactly the one CA (a
// probe for a different fingerprint stays false). This is the idempotency contract
// (a step-7 retry never forks the trust store) proven on real guestfs, not a fake.
func TestLiveTrustAnchor_InjectIsIdempotent(t *testing.T) {
	requireLiveGate(t)
	h := newLiveTrustHarness(t)

	const sessionUUID = "00000000-0000-4000-8000-00000000ca03"
	overlayPath := h.freshOverlay(t, sessionUUID)

	caPEM := mintCAPEM(t)
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}

	// The production file source drops the PEM at the trustpath-derived path the
	// injector fetches by ref (the same single-sourced path the orchestrator writes).
	src, err := NewFileCABundleSource(h.overlayDir)
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	const caRef = "live-trust-ref"
	seedCABundle(t, h.overlayDir, caRef, caPEM)

	w, err := NewLiveTrustStoreWriter()
	if err != nil {
		t.Fatalf("NewLiveTrustStoreWriter: %v", err)
	}
	inj, err := NewCAInjector(src, w)
	if err != nil {
		t.Fatalf("NewCAInjector: %v", err)
	}
	ctx := context.Background()

	if err := inj.InjectCA(ctx, overlayPath, caRef); err != nil {
		t.Fatalf("first InjectCA (live): %v", err)
	}
	// The idempotent retry must converge on the present anchor without error.
	if err := inj.InjectCA(ctx, overlayPath, caRef); err != nil {
		t.Fatalf("idempotent retry InjectCA (live) must converge: %v", err)
	}

	// The overlay holds exactly ONE anchor: the seeded CA is present, and a distinct
	// CA is absent (the retry did not fork the store into a second anchor).
	present, err := w.HasTrustAnchor(ctx, sessionUUID, overlayPath, fp)
	if err != nil {
		t.Fatalf("HasTrustAnchor after idempotent inject: %v", err)
	}
	if !present {
		t.Fatal("the injected anchor must remain present after the idempotent retry")
	}
	otherFP, err := validateCABundle(mintCAPEM(t))
	if err != nil {
		t.Fatalf("validateCABundle (other): %v", err)
	}
	if otherFP == fp {
		t.Fatal("distinct CAs must have distinct fingerprints")
	}
	otherPresent, err := w.HasTrustAnchor(ctx, sessionUUID, overlayPath, otherFP)
	if err != nil {
		t.Fatalf("HasTrustAnchor for a different fingerprint after idempotent inject: %v", err)
	}
	if otherPresent {
		t.Fatal("the idempotent retry must not fork the trust store — a distinct CA's fingerprint must stay absent")
	}
}

// TestLiveTrustAnchor_InjectFailsClosedOnWriteError proves the compiled writer
// fail-closes the create at the trust-store step: the injector fetches + validates
// a real CA, then drives the compiled writer against a BOGUS overlay path (a file
// that is not a valid disk image), so the libguestfs CLI errors. On a real host
// that error surfaces at the injector's step-3 presence probe (virt-cat cannot
// inspect the bogus disk, and its error is not the benign "No such file or
// directory" absent) or — if the probe were somehow classified absent — at the
// step-4 virt-customize write; BOTH paths return non-nil, which is the contract
// under test: InjectCA fails CLOSED and the create would abort at StepOverlay
// before boot (D17). No real overlay is written; the create never proceeds to a VM
// whose first TLS byte could bypass the egress gateway.
func TestLiveTrustAnchor_InjectFailsClosedOnWriteError(t *testing.T) {
	requireLiveGate(t)
	h := newLiveTrustHarness(t)

	// A bogus overlay path UNDER the overlay dir that is not a valid qcow2 disk:
	// virt-customize -a <this> must fail, driving the injector fail-closed. It is
	// removed on cleanup.
	bogusOverlay := filepath.Join(h.overlayDir, "00000000-0000-4000-8000-00000000ca04.qcow2")
	if err := os.WriteFile(bogusOverlay, []byte("not a qcow2 disk image"), 0o600); err != nil {
		t.Fatalf("seed bogus overlay: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(bogusOverlay) })

	caPEM := mintCAPEM(t)
	src, err := NewFileCABundleSource(h.overlayDir)
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	const caRef = "live-trust-fail-ref"
	seedCABundle(t, h.overlayDir, caRef, caPEM)

	w, err := NewLiveTrustStoreWriter()
	if err != nil {
		t.Fatalf("NewLiveTrustStoreWriter: %v", err)
	}
	inj, err := NewCAInjector(src, w)
	if err != nil {
		t.Fatalf("NewCAInjector: %v", err)
	}

	if err := inj.InjectCA(context.Background(), bogusOverlay, caRef); err == nil {
		t.Fatal("a virt-customize write failure on a bogus overlay must fail the inject CLOSED (create aborts at StepOverlay before boot, D17)")
	}
}

// seedCABundle drops the PEM at the exact trustpath-derived path the production
// file CABundleSource fetches by ref (the same single-sourced store the
// orchestrator producer writes through), so the injector resolves the ref to real
// bytes on the live path.
func seedCABundle(t *testing.T, overlayDir, caRef string, caPEM []byte) {
	t.Helper()
	src, err := NewFileCABundleSource(overlayDir)
	if err != nil {
		t.Fatalf("seedCABundle: NewFileCABundleSource: %v", err)
	}
	if err := os.WriteFile(src.bundlePath(caRef), caPEM, 0o600); err != nil {
		t.Fatalf("seedCABundle: write %q: %v", caRef, err)
	}
	// Sanity: the source resolves the ref back to the seeded bytes (guards a
	// producer/consumer path drift before the gated inject relies on it).
	got, err := src.FetchCABundle(context.Background(), caRef)
	if err != nil {
		t.Fatalf("seedCABundle: FetchCABundle(%q): %v", caRef, err)
	}
	if string(got) != string(caPEM) {
		t.Fatalf("seedCABundle: fetched bytes for %q do not match the seeded PEM", caRef)
	}
}
