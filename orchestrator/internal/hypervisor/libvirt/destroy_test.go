// SPDX-License-Identifier: Apache-2.0

// destroy_test.go proves the §4.2 host-local teardown driver (destroy.go) — and, for
// the gap-3 serving-leg arc, the OPTIONAL post-destroy hook the daemon wires to reap a
// torn-down session's attach serving child (AttachBridge.Destroy). All offline (D50): no
// VM / libvirt / KVM / qemu / ds-nft / network is touched — the deps are recording fakes.
//
// The hook is the mirror of create.go's PostBootHook: a plain callback (no hostagent
// import here — the adapter lives in the daemon root), nil-guarded so the destroy path is
// BYTE-IDENTICAL when none is wired, invoked AFTER the §4.2 order with the session UUID.

package libvirt

import (
	"context"
	"errors"
	"testing"
)

// destroyHookFakeDomain records destroyed domains (idempotent: an absent domain is a
// no-op, never an error — the §4.2 order must converge on an already-gone session).
type destroyHookFakeDomain struct{ destroyed []string }

func (f *destroyHookFakeDomain) DestroyDomain(_ context.Context, sessionUUID, _ string) error {
	f.destroyed = append(f.destroyed, sessionUUID)
	return nil
}

// destroyHookFakeAttach satisfies AttachPrimitive for the teardown driver — only
// FlushSession is exercised by Destroy (CreateTap/InstantiateSessionNFT are create-side),
// but the interface requires all three.
type destroyHookFakeAttach struct{ flushed []string }

func (f *destroyHookFakeAttach) CreateTap(_ context.Context, _ Binding) error { return nil }
func (f *destroyHookFakeAttach) InstantiateSessionNFT(_ context.Context, _ string, _ Binding) error {
	return nil
}
func (f *destroyHookFakeAttach) FlushSession(_ context.Context, sessionUUID string, _ Binding) error {
	f.flushed = append(f.flushed, sessionUUID)
	return nil
}

// destroyHookFakeOverlay satisfies OverlayStore — only DisposeOverlay is exercised by
// Destroy (CreateOverlay is create-side).
type destroyHookFakeOverlay struct{ disposed []string }

func (f *destroyHookFakeOverlay) CreateOverlay(_ context.Context, sessionUUID, _ string) (string, error) {
	return "/overlays/" + sessionUUID + ".qcow2", nil
}
func (f *destroyHookFakeOverlay) DisposeOverlay(_ context.Context, overlayPath string) error {
	f.disposed = append(f.disposed, overlayPath)
	return nil
}

// destroyHookFakeDurability records finalized durability streams (D29).
type destroyHookFakeDurability struct{ finalized []string }

func (f *destroyHookFakeDurability) FinalizeDurabilityStream(_ context.Context, _ string, overlayPath string) error {
	f.finalized = append(f.finalized, overlayPath)
	return nil
}

// destroyHookFakeFlow records emitted final byte-count events (non-fatal accounting).
type destroyHookFakeFlow struct{ emitted []string }

func (f *destroyHookFakeFlow) EmitDestroyByteCounts(_ context.Context, sessionUUID string, _ Binding) error {
	f.emitted = append(f.emitted, sessionUUID)
	return nil
}

// newDestroyHookFakes assembles a fresh set of recording fakes + a Destroyer over them.
func newDestroyHookFakes(t *testing.T) (*Destroyer, *destroyHookFakeDomain, *destroyHookFakeAttach, *destroyHookFakeOverlay) {
	t.Helper()
	dom := &destroyHookFakeDomain{}
	att := &destroyHookFakeAttach{}
	ov := &destroyHookFakeOverlay{}
	d, err := NewDestroyer(dom, att, ov, &destroyHookFakeDurability{}, &destroyHookFakeFlow{})
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	return d, dom, att, ov
}

// TestDestroyPostDestroyHookRunsForTornDownSession proves the §4.2 destroy invokes the
// post-destroy hook with the SAME session UUID it tore down — the seam the daemon wires to
// AttachBridge.Destroy so a session's serving child is reaped at DESTROY (not only at
// daemon Shutdown). The hook fires AFTER the unconditional flush_session (the §4.2 order
// runs first; the reap is bookkeeping on a child the destroy has already obviated).
func TestDestroyPostDestroyHookRunsForTornDownSession(t *testing.T) {
	d, dom, att, _ := newDestroyHookFakes(t)

	var reaped struct {
		session string
		ran     bool
	}
	d.WithPostDestroyHook(func(_ context.Context, sessionUUID string) error {
		reaped.session = sessionUUID
		reaped.ran = true
		return nil
	})

	const sess = "sess-reap-1"
	res, err := d.Destroy(context.Background(), DestroyRequest{
		SessionUUID: sess,
		DomainUUID:  "dom-1",
		OverlayPath: "/overlays/sess-reap-1.qcow2",
	})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// The §4.2 order ran (domain destroyed, session flushed) BEFORE the hook.
	if !res.DomainDestroyed || !res.SessionFlushed {
		t.Fatalf("§4.2 order did not run: %+v", res)
	}
	if len(dom.destroyed) != 1 || dom.destroyed[0] != sess {
		t.Errorf("domain destroyed = %v, want [%s]", dom.destroyed, sess)
	}
	if len(att.flushed) != 1 || att.flushed[0] != sess {
		t.Errorf("session flushed = %v, want [%s] (unconditional flush, D68)", att.flushed, sess)
	}
	// The hook reaped the SAME session.
	if !reaped.ran {
		t.Fatal("post-destroy hook did not run for the torn-down session")
	}
	if reaped.session != sess {
		t.Errorf("hook reaped session %q, want %q (the torn-down session)", reaped.session, sess)
	}
}

// TestDestroyByteIdenticalWithNoHook proves the destroy path is BYTE-IDENTICAL when no hook
// is wired (nil-guarded, additive): a Destroyer constructed via the unchanged NewDestroyer
// signature — with no WithPostDestroyHook call — runs the exact §4.2 order and returns the
// exact result. This is the additive-default guarantee (the historical choreography).
func TestDestroyByteIdenticalWithNoHook(t *testing.T) {
	// No hook wired (the historical default; NewDestroyer signature unchanged).
	d, dom, att, ov := newDestroyHookFakes(t)

	const sess = "sess-nohook-1"
	res, err := d.Destroy(context.Background(), DestroyRequest{
		SessionUUID: sess,
		DomainUUID:  "dom-1",
		OverlayPath: "/overlays/sess-nohook-1.qcow2",
	})
	if err != nil {
		t.Fatalf("Destroy (no hook): %v", err)
	}
	// The §4.2 order is unchanged: domain destroyed, session flushed, overlay disposed.
	want := DestroyResult{DomainDestroyed: true, SessionFlushed: true, OverlayDisposed: true}
	if res != want {
		t.Errorf("no-hook Destroy result = %+v, want %+v (byte-identical §4.2 order)", res, want)
	}
	if len(dom.destroyed) != 1 || len(att.flushed) != 1 || len(ov.disposed) != 1 {
		t.Errorf("no-hook §4.2 calls: domain=%d flush=%d dispose=%d, want 1/1/1",
			len(dom.destroyed), len(att.flushed), len(ov.disposed))
	}
}

// TestDestroyPostDestroyHookFaultIsSwallowed PINS the chosen fault posture: a post-destroy
// hook fault is SWALLOWED FROM THE VERDICT, the exact mirror of create.go's PostBootHook.
// The §4.2 order ran clean (domain destroyed, session flushed, overlay disposed) BEFORE the
// hook — those host-local objects ARE the teardown contract — so a serving-child reap fault
// must NOT surface on the Destroy verdict: Destroy returns nil. (The fault is no longer
// silently dropped — it is surfaced OUT-OF-BAND through the hookFault observer, asserted by
// TestDestroyPostDestroyHookFaultSurfacesOutOfBand; here the default observer just logs it.)
// This guards against silent drift back to the discarded record/propagate posture, which would
// turn a clean §4.2 teardown into a faulted Destroy over the wire (contradicting the PostBootHook
// mirror). The daemon's real adapter calls AttachBridge.Destroy, which returns nothing, so the
// wired path never errors here; this pins the posture for any FUTURE hook that could.
func TestDestroyPostDestroyHookFaultIsSwallowed(t *testing.T) {
	d, dom, att, ov := newDestroyHookFakes(t)
	d.WithPostDestroyHook(func(_ context.Context, _ string) error {
		return errors.New("reap blew up")
	})

	res, err := d.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-faulty-reap",
		DomainUUID:  "dom-1",
		OverlayPath: "/overlays/sess-faulty-reap.qcow2",
	})
	// THE POSTURE: the hook fault is swallowed — Destroy returns nil despite the faulting
	// reap (the create.go PostBootHook mirror). A non-nil error here is the record/propagate
	// regression this test exists to catch.
	if err != nil {
		t.Fatalf("post-destroy hook fault must be SWALLOWED (PostBootHook mirror), got %v", err)
	}
	// The §4.2 order ran fully and cleanly regardless of the hook fault.
	if !res.DomainDestroyed || !res.SessionFlushed || !res.OverlayDisposed {
		t.Errorf("§4.2 order must run fully despite a hook fault: %+v", res)
	}
	if len(dom.destroyed) != 1 || len(att.flushed) != 1 || len(ov.disposed) != 1 {
		t.Errorf("§4.2 calls after hook fault: domain=%d flush=%d dispose=%d, want 1/1/1",
			len(dom.destroyed), len(att.flushed), len(ov.disposed))
	}
	// Belt-and-suspenders: no *DestroyError leaks out — the swallow is total, not merely a
	// wrapped-but-nil-Step error.
	var de *DestroyError
	if errors.As(err, &de) {
		t.Fatalf("hook fault must NOT surface as *DestroyError (swallowed posture), got %v", de)
	}
}

// TestDestroyHookSkippedWhenNoHookAndPartialState proves the nil-guarded hook site is a
// pure skip even on a binding-less partial teardown (a create-rollback before step 4): the
// §4.2 order still runs unconditionally and no hook is invoked. Belt-and-suspenders that
// the additive seam never fires when unwired.
func TestDestroyHookSkippedWhenNoHookAndPartialState(t *testing.T) {
	d, _, att, _ := newDestroyHookFakes(t)

	// Binding-less partial (no domain, no overlay) — the unconditional flush still runs.
	res, err := d.Destroy(context.Background(), DestroyRequest{SessionUUID: "sess-partial"})
	if err != nil {
		t.Fatalf("Destroy (partial, no hook): %v", err)
	}
	if !res.SessionFlushed {
		t.Error("flush_session must run unconditionally even for a binding-less partial (D68)")
	}
	if res.OverlayDisposed {
		t.Error("no overlay existed; OverlayDisposed must be false")
	}
	if len(att.flushed) != 1 {
		t.Errorf("flush called %d times, want 1 (unconditional)", len(att.flushed))
	}
}

// TestDestroyPostDestroyHookFaultSurfacesOutOfBand completes the wave-1 create-path arc on the
// §4.2 reap path — the exact mirror of create_test.go's
// TestCreateSessionPostBootHookFaultSurfacesOutOfBand. A swallowed post-destroy reap fault is
// surfaced through the HookFaultObserver — EXACTLY ONE structured observation, attributed to
// HookPostDestroy, carrying the torn-down session UUID + the swallowed error — WHILE the Destroy
// VERDICT stays byte-identical (nil; the §4.2 order ran clean). The fault is observable only
// out-of-band, never on the verdict: a faulted reap is now attributable instead of silently lost.
func TestDestroyPostDestroyHookFaultSurfacesOutOfBand(t *testing.T) {
	d, dom, att, ov := newDestroyHookFakes(t)

	hookErr := errors.New("reap failed — swallowed from verdict, surfaced out-of-band")
	d.WithPostDestroyHook(func(_ context.Context, _ string) error { return hookErr })

	var observed []HookFault
	d.WithHookFaultObserver(func(obs HookFault) { observed = append(observed, obs) })

	const sess = "sess-oob-reap"
	res, err := d.Destroy(context.Background(), DestroyRequest{
		SessionUUID: sess,
		DomainUUID:  "dom-1",
		OverlayPath: "/overlays/sess-oob-reap.qcow2",
	})
	// VERDICT byte-identical: the reap fault is swallowed from the result (the §4.2 order ran
	// clean), the exact PostBootHook mirror.
	if err != nil {
		t.Fatalf("post-destroy reap fault must be SWALLOWED from the verdict, got %v", err)
	}
	if !res.DomainDestroyed || !res.SessionFlushed || !res.OverlayDisposed {
		t.Errorf("§4.2 order must run fully despite the reap fault: %+v", res)
	}
	if len(dom.destroyed) != 1 || len(att.flushed) != 1 || len(ov.disposed) != 1 {
		t.Errorf("§4.2 calls under a faulted reap: domain=%d flush=%d dispose=%d, want 1/1/1",
			len(dom.destroyed), len(att.flushed), len(ov.disposed))
	}
	// OUT-OF-BAND: exactly one structured observation, attributed to HookPostDestroy, carrying
	// the session + the swallowed error.
	if len(observed) != 1 {
		t.Fatalf("swallowed reap fault should surface exactly one out-of-band observation, got %d", len(observed))
	}
	if observed[0].Hook != HookPostDestroy {
		t.Errorf("observation hook = %v, want HookPostDestroy", observed[0].Hook)
	}
	if observed[0].SessionUUID != sess {
		t.Errorf("observation session = %q, want %q (the torn-down session)", observed[0].SessionUUID, sess)
	}
	if !errors.Is(observed[0].Err, hookErr) {
		t.Errorf("observation should carry the swallowed reap error, got %v", observed[0].Err)
	}
}

// TestDestroyPostDestroyHookCleanEmitsNoObservation proves the out-of-band seam fires ONLY on an
// actual reap fault: a hook returning nil emits NO observation (the happy path is byte-identical),
// mirroring create_test.go's clean-hook case. The reap still ran (the hook was invoked) — it just
// did not fault, so nothing is surfaced.
func TestDestroyPostDestroyHookCleanEmitsNoObservation(t *testing.T) {
	d, _, _, _ := newDestroyHookFakes(t)

	var ran bool
	d.WithPostDestroyHook(func(_ context.Context, _ string) error { ran = true; return nil })

	var observed []HookFault
	d.WithHookFaultObserver(func(obs HookFault) { observed = append(observed, obs) })

	if _, err := d.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-clean-reap",
		DomainUUID:  "dom-1",
		OverlayPath: "/overlays/sess-clean-reap.qcow2",
	}); err != nil {
		t.Fatalf("Destroy (clean reap): %v", err)
	}
	if !ran {
		t.Fatal("post-destroy hook should have run")
	}
	if len(observed) != 0 {
		t.Errorf("a clean reap must emit NO out-of-band observation, got %d", len(observed))
	}
}

// TestDestroyerInstallsDefaultHookFaultObserver proves NewDestroyer installs a non-nil default
// observer (so a swallowed reap fault is never silently dropped even when no observer is injected),
// and that WithHookFaultObserver(nil) keeps that default rather than nil-ing it — the exact mirror
// of create_test.go's TestHostAgentInstallsDefaultHookFaultObserver.
func TestDestroyerInstallsDefaultHookFaultObserver(t *testing.T) {
	d, _, _, _ := newDestroyHookFakes(t)
	if d.hookFault == nil {
		t.Fatal("NewDestroyer must install a default hook-fault observer (a swallowed reap fault must never be silently dropped)")
	}
	if got := d.WithHookFaultObserver(nil); got.hookFault == nil {
		t.Error("WithHookFaultObserver(nil) must keep the default observer, not nil it")
	}
}

// TestHookPostDestroyDistinctFromPostBoot pins that the destroy-side attribution kind is a
// DISTINCT HookKind value from the create-side HookPostBoot, so a telemetry consumer can tell a
// swallowed reap fault apart from a swallowed post-boot fault by the structured Hook field alone.
func TestHookPostDestroyDistinctFromPostBoot(t *testing.T) {
	if HookPostDestroy == HookPostBoot {
		t.Fatalf("HookPostDestroy (%d) must be a distinct kind from HookPostBoot (%d)", HookPostDestroy, HookPostBoot)
	}
}
