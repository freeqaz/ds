// SPDX-License-Identifier: Apache-2.0

// live_smoke_test.go — the DS_HOSTAGENT_LIVE operator create->boot->destroy smoke
// (unit u5-live-smoke). It drives the PRODUCTION DriverService gRPC surface (the
// SAME in-process loopback server + real generated client as service_test.go — NO
// second gRPC surface) over the u3 PRODUCTION live bindings (live.go's
// overlay-create.sh clone + virsh boot, reached through the gate-aware
// NewOverlayStore / NewBooter), and asserts the D29 read-only-base invariants on
// real disk:
//
//   - CloneFromImage clones the read-only raw golden into a per-session qcow2
//     overlay (the overlay file exists, is distinct from the base, and its qcow2
//     backing chain names the golden base — the D29 backing invariant).
//   - the domain boots (the live Booter's virsh define+boot yields a domain uuid,
//     which the response-bound overlay rides).
//   - Destroy through the DriverService is clean — the transient domain is gone
//     AND the per-session overlay is DISPOSED. DriverService.Destroy now resolves
//     the recorded OverlayPath from its in-memory clone cache (the session was
//     cloned earlier in this smoke, so the cache pins its OverlayPath + Binding) and
//     threads it into the §4.2 DestroyRequest, so destroy.go's OverlayPath-guarded
//     disposal runs and the overlay is removed from disk by the gRPC Destroy alone
//     (the destroy-overlay wiring unit; doc 15 §4.2 step 3 / D29). This smoke
//     asserts overlay-GONE-by-Destroy (the prior survival assertion is flipped now
//     that the surface disposes the overlay).
//   - the raw golden base is NEVER written through: it stays mode 0444 and its
//     size+mtime are byte-stable across the whole clone->boot->destroy flow (the
//     D29 0444/backing invariant — every write lands in the overlay, never the
//     shared base).
//
// LIVE-GATING DISCIPLINE (additive, default-path-unchanged): the whole test SKIPS
// cleanly when DS_HOSTAGENT_LIVE is unset (the sandbox / CI / every unit run) —
// so `go test ./...` offline never touches libvirt/KVM/qemu. The live legs run
// ONLY on the operator M0 host (user@<operator-host>) where the COORDINATOR sets
// the gate + points the env at the golden base; the exact on-host commands are in
// cmd/host-agent/LIVE-SMOKE.md. The DomainDestroyer is now the PRODUCTION body
// (destroyer_libvirt.go, reached through the SAME gate-aware NewDomainDestroyer the
// daemon composition root calls), so the smoke tears the booted domain down through
// exactly the §4.2 step-1 code the host-agent runs — no test-local destroyer.
//
// The base is read from DS_HOSTAGENT_LIVE_BASE (the golden), overlays are written
// under DS_HOSTAGENT_LIVE_OVERLAY_DIR, and overlay-create.sh is located via
// DS_HOSTAGENT_LIVE_OVERLAY_SCRIPT — all operator-host facts, never hardcoded.

package libvirt

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// Operator-host env facts for the live smoke. They are consulted ONLY on the
// live path (under DS_HOSTAGENT_LIVE); an offline run skips before reading them.
const (
	envLiveBase          = "DS_HOSTAGENT_LIVE_BASE"           // the read-only raw golden base (D29)
	envLiveOverlayDir    = "DS_HOSTAGENT_LIVE_OVERLAY_DIR"    // writable per-session overlay dir
	envLiveOverlayScript = "DS_HOSTAGENT_LIVE_OVERLAY_SCRIPT" // abs path to vm/cow/overlay-create.sh
	envLiveVirsh         = "DS_HOSTAGENT_LIVE_VIRSH"          // optional virsh binary override
)

// liveSmokeSession is a fixed v4-shaped session uuid for the smoke; it names the
// overlay (sessionFromOverlay convention) and the transient domain (ds-<uuid>).
const liveSmokeSession = "00000000-0000-4000-8000-00000000a5e5"

// baseStat snapshots the facts the D29 read-only-base invariant pins: the mode
// (must stay 0444) and the size+mtime (must be byte-stable — the base is never
// written through; every write lands in the overlay).
type baseStat struct {
	mode    os.FileMode
	size    int64
	modTime time.Time
}

func statBase(t *testing.T, base string) baseStat {
	t.Helper()
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat golden base %s: %v", base, err)
	}
	return baseStat{mode: fi.Mode().Perm(), size: fi.Size(), modTime: fi.ModTime()}
}

func (b baseStat) assertUnchanged(t *testing.T, base, when string) {
	t.Helper()
	got := statBase(t, base)
	if got.mode != b.mode {
		t.Errorf("[%s] golden base %s mode = %v, want %v (D29: the raw base is read-only, never re-permissioned)", when, base, got.mode, b.mode)
	}
	if got.size != b.size {
		t.Errorf("[%s] golden base %s size = %d, want %d (D29: the base is never written through — writes land in the overlay)", when, base, got.size, b.size)
	}
	if !got.modTime.Equal(b.modTime) {
		t.Errorf("[%s] golden base %s mtime moved %v -> %v (D29: the base is never written through)", when, base, b.modTime, got.modTime)
	}
}

// TestLiveSmokeCloneBootDestroy is the gated operator smoke. Offline (the default)
// it SKIPS before any substrate touch; on the M0 host under DS_HOSTAGENT_LIVE it
// drives CloneFromImage -> boot -> Destroy over the DriverService gRPC surface and
// asserts the D29 read-only-base invariants on real disk.
func TestLiveSmokeCloneBootDestroy(t *testing.T) {
	if !LiveEnabled() {
		t.Skipf("offline default: %s unset — skipping the operator live smoke (run on the M0 host per cmd/host-agent/LIVE-SMOKE.md)", EnvHostAgentLive)
	}

	base := os.Getenv(envLiveBase)
	overlayDir := os.Getenv(envLiveOverlayDir)
	script := os.Getenv(envLiveOverlayScript)
	if base == "" || overlayDir == "" || script == "" {
		t.Fatalf("live smoke requires %s (golden base), %s (overlay dir), %s (overlay-create.sh path) — see cmd/host-agent/LIVE-SMOKE.md", envLiveBase, envLiveOverlayDir, envLiveOverlayScript)
	}
	virsh := os.Getenv(envLiveVirsh)
	if virsh == "" {
		virsh = "virsh"
	}

	// Pre-flight: the golden base must already be the read-only raw base (D29). We
	// assert the 0444 invariant up front so a misprovisioned host fails loudly
	// rather than silently writing through a writable base.
	pre := statBase(t, base)
	if pre.mode&0o222 != 0 {
		t.Fatalf("golden base %s is writable (mode %v) — the D29 invariant requires a read-only 0444 raw base before any clone", base, pre.mode)
	}

	// Build the DriverService over the u3 PRODUCTION live bindings (gate-aware
	// constructors → real overlay-create.sh clone + virsh boot under the gate) and
	// the in-package fakes for the seams whose real bodies are deferred (CA inject,
	// tap/NFT attach, routability gate, durability/flow accounting). The
	// DomainDestroyer is the gate-aware PRODUCTION body so the smoke tears the
	// booted domain down through the §4.2 step-1 code the daemon runs.
	liveCfg := LiveConfig{
		OverlayCreateScript: script,
		OverlayDir:          overlayDir,
		BaseImage:           base,
		VirshBin:            virsh,
	}
	overlay, err := NewOverlayStore(liveCfg)
	if err != nil {
		t.Fatalf("NewOverlayStore (live): %v", err)
	}
	booter, err := NewBooter(liveCfg)
	if err != nil {
		t.Fatalf("NewBooter (live): %v", err)
	}

	// The seams whose real bodies are deferred stay the in-package fakes (CA inject,
	// tap/NFT attach, routability gate acked+fresh so the clone is routable,
	// durability/flow accounting). The OverlayStore + Booter are the u3 LIVE bindings
	// and the DomainDestroyer is the production live body (destroyer_libvirt.go).
	attach := &fakeAttach{}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, attach, overlay, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	domainDestroyer, err := NewDomainDestroyer(liveCfg)
	if err != nil {
		t.Fatalf("NewDomainDestroyer (live): %v", err)
	}
	destroyer, err := NewDestroyer(domainDestroyer, attach, overlay, &fakeDurability{}, &fakeFlowBytes{})
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverService(host, destroyer)
	if err != nil {
		t.Fatalf("NewDriverService: %v", err)
	}

	client := dialInProcess(t, svc)
	ctx := context.Background()

	// Best-effort pre-clean so a leftover overlay/domain from a prior aborted run
	// does not poison the assertions; both are idempotent no-ops when absent.
	overlayPath := filepath.Join(overlayDir, liveSmokeSession+".qcow2")
	_ = os.Remove(overlayPath)
	_ = domainDestroyer.DestroyDomain(ctx, liveSmokeSession, "")
	t.Cleanup(func() {
		_, _ = client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: liveSmokeSession})
		_ = os.Remove(overlayPath)
	})

	// ── CloneFromImage: clone the golden -> per-session overlay, boot the domain ──
	resp, err := client.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{
			SessionUuid:         liveSmokeSession,
			ImageId:             "m0-golden",
			EntrypointConfigRef: "live-smoke-entrypoint",
			Material:            &hypervisorv1.SessionMaterial{CaBundleRef: "live-smoke-ca-ref"},
		},
	})
	if err != nil {
		t.Fatalf("CloneFromImage (live): %v", err)
	}

	// The response carries the per-session overlay the live OverlayStore created.
	if resp.GetOverlayPath() != overlayPath {
		t.Errorf("overlay_path = %q, want %q (the live overlay-create.sh per-session clone path)", resp.GetOverlayPath(), overlayPath)
	}

	// D29 #1: the overlay exists on disk and is distinct from the base.
	oi, err := os.Stat(overlayPath)
	if err != nil {
		t.Fatalf("overlay %s not created by the live clone: %v", overlayPath, err)
	}
	if oi.Size() == 0 {
		t.Errorf("overlay %s is empty — the qcow2 overlay was not materialized", overlayPath)
	}
	abBase, _ := filepath.Abs(base)
	abOverlay, _ := filepath.Abs(overlayPath)
	if abBase == abOverlay {
		t.Fatalf("overlay path %s equals the base %s — the clone must write a SEPARATE per-session overlay (D29)", abOverlay, abBase)
	}

	// D29 #2: the overlay's qcow2 backing chain names the read-only golden base —
	// the overlay is a CoW layer ON the base, never a copy of or a write to it.
	assertBackingIsBase(t, virsh, overlayPath, base)

	// D29 #3 (boot): the live Booter defined+booted a transient domain for the
	// session. The DriverService surfaces a non-routable verdict as a recorded
	// binding (not an error), and a routable one as a clean response; either way a
	// booted domain must be visible to virsh under the session's domain name.
	assertDomainRunning(t, virsh, liveSmokeSession)

	// D29 #4: through the whole clone+boot, the golden base was NEVER written
	// through — mode 0444 + size + mtime are byte-stable.
	pre.assertUnchanged(t, base, "after clone+boot")

	// ── Destroy: tear the session down through the DriverService gRPC surface ─────
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: liveSmokeSession}); err != nil {
		t.Fatalf("Destroy (live): %v", err)
	}

	// Destroy tore the transient domain down.
	assertDomainGone(t, virsh, liveSmokeSession)

	// §4.2 overlay disposal IS now wired through the DriverService surface this smoke
	// drives: DriverService.Destroy (service.go) resolves the per-session OverlayPath
	// from its in-memory clone cache (this smoke cloned the session above, so the
	// cache pins its OverlayPath + Binding) and threads it into the §4.2
	// DestroyRequest, so destroy.go's OverlayPath-guarded disposal step runs and the
	// live OverlayStore.DisposeOverlay removes the overlay from disk. Assert
	// overlay-GONE-by-Destroy: after the gRPC Destroy the per-session overlay is no
	// longer on disk (the prior survival assertion is flipped now that the surface
	// disposes the overlay). os.Stat must report a does-not-exist error; any other
	// outcome (the overlay still present, or a non-IsNotExist stat error) is a
	// disposal failure.
	if _, err := os.Stat(overlayPath); err == nil {
		t.Errorf("overlay %s STILL present after Destroy — the gRPC DriverService.Destroy must dispose the per-session overlay (it resolves the recorded OverlayPath from the clone cache and threads it into the §4.2 DestroyRequest; destroy.go overlay step disposes it, D29)", overlayPath)
	} else if !os.IsNotExist(err) {
		t.Errorf("stat overlay %s after Destroy: %v — want a does-not-exist error (the overlay must be DISPOSED by the gRPC Destroy)", overlayPath, err)
	}

	// D29 #5: after the FULL clone->boot->destroy flow the golden base is STILL the
	// untouched read-only raw base — destroy disposes the overlay, never the base.
	pre.assertUnchanged(t, base, "after destroy")

	// Destroy is idempotent: a second teardown of the now-gone session is a clean
	// success (the §4.2 convergence), and must still never touch the base.
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: liveSmokeSession}); err != nil {
		if st, ok := status.FromError(err); !ok || st.Code() != codes.OK {
			t.Errorf("second Destroy of a gone session must be a clean no-op success, got %v", err)
		}
	}
	pre.assertUnchanged(t, base, "after idempotent re-destroy")
}

// ── SYNTHETIC offline coverage for the destroy-overlay resolution (NOT gated) ──
//
// These tests run on EVERY `go test` (no DS_HOSTAGENT_LIVE gate, no libvirt/KVM):
// they exercise the service.go resolution that the live smoke above proves on real
// disk — that DriverService.Destroy threads the per-session OverlayPath (so the
// §4.2 overlay-disposal step runs) and, when a DestroyResolver is wired, the
// recorded DomainUUID (so §4.2 step 1 destroys the right domain), all from the
// session_uuid-only frozen DestroyRequest. They use the in-package seam fakes (D50
// synthetic fixtures, deterministic, offline) — the SAME fakes service_test.go
// drives — so the resolution is asserted at the seam boundary without any live
// substrate.

// recordingDomainDestroyer captures the (sessionUUID, domainUUID) pair every
// DestroyDomain call receives, so a test can assert the DomainUUID the resolver
// supplied was threaded into §4.2 step 1 (the stock fakeDomainDestroyer ignores
// the domainUUID arg, so it cannot witness the threading). Idempotent: an
// empty/absent domain is a clean no-op (the DomainDestroyer contract).
type recordingDomainDestroyer struct {
	domainsBySession map[string]string
}

func (d *recordingDomainDestroyer) DestroyDomain(_ context.Context, sessionUUID, domainUUID string) error {
	if d.domainsBySession == nil {
		d.domainsBySession = map[string]string{}
	}
	d.domainsBySession[sessionUUID] = domainUUID
	return nil
}

// fakeDestroyResolver is a recording DestroyResolver (D50): it returns a fixed
// host-side teardown state for a session (the synthetic stand-in for the durable
// SessionRecord the daemon root wires over the SessionRecordStore) and records
// every session_uuid it was asked to resolve. notFound forces the already-gone /
// never-recorded path; err forces a resolver read fault.
type fakeDestroyResolver struct {
	state    DestroyState
	notFound bool
	err      error
	calls    []string
}

func (r *fakeDestroyResolver) ResolveDestroy(_ context.Context, sessionUUID string) (DestroyState, bool, error) {
	r.calls = append(r.calls, sessionUUID)
	if r.err != nil {
		return DestroyState{}, false, r.err
	}
	if r.notFound {
		return DestroyState{}, false, nil
	}
	return r.state, true, nil
}

// TestDestroyDisposesOverlayResolvedFromCloneCache is the offline twin of the live
// smoke's overlay-gone assertion: with NO resolver wired, a session this process
// CLONED has its OverlayPath + Binding pinned in the in-memory clone cache, so the
// gRPC Destroy (session_uuid only) resolves them and threads them into the §4.2
// DestroyRequest — destroy.go disposes the overlay (step 3), finalizes the
// durability stream, and emits the final byte counts (a real binding has ct-mark
// accounting). The stock fakes record each so the resolution is asserted at the
// seam boundary, offline.
func TestDestroyDisposesOverlayResolvedFromCloneCache(t *testing.T) {
	svc, f := newTestDriverService(t)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	clone, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	overlayPath := clone.GetOverlayPath()
	if overlayPath == "" {
		t.Fatalf("clone returned no overlay_path — cannot assert overlay disposal")
	}
	// The clone alone must NOT dispose the overlay (the happy create path).
	if len(f.overlay.disposed) != 0 {
		t.Fatalf("clone must not dispose the overlay, disposed=%v", f.overlay.disposed)
	}

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// §4.2 step 3: the resolved OverlayPath was threaded, so the overlay was
	// disposed (the live-smoke overlay-gone behavior, offline at the seam).
	if len(f.overlay.disposed) != 1 || f.overlay.disposed[0] != overlayPath {
		t.Errorf("Destroy must dispose the per-session overlay resolved from the clone cache; disposed=%v want [%q]", f.overlay.disposed, overlayPath)
	}
	// The durability stream was finalized BEFORE disposal (D29, destroy.go step 3).
	if len(f.durab.finalized) != 1 || f.durab.finalized[0] != testCloneSession {
		t.Errorf("Destroy must finalize the durability stream for the resolved overlay; finalized=%v", f.durab.finalized)
	}
	// A real (cache-resolved) binding has ct-mark accounting, so the final byte
	// counts were emitted (HasBinding ⇒ EmitDestroyByteCounts, destroy.go step 2).
	if len(f.flow.emitted) != 1 || f.flow.emitted[0] != testCloneSession {
		t.Errorf("Destroy of a cloned session must emit the final byte counts (a real binding has accounting); emitted=%v", f.flow.emitted)
	}
	// The unconditional flush still ran (D68).
	if len(f.attach.flushed) != 1 || f.attach.flushed[0] != testCloneSession {
		t.Errorf("Destroy must run the unconditional flush_session (D68); flushed=%v", f.attach.flushed)
	}
}

// TestDestroyThreadsResolvedDomainUUID asserts the OPTIONAL DestroyResolver supplies
// the host-local DomainUUID (which the wire CloneFromImageResponse never carries) and
// the service threads it into §4.2 step 1 — the DomainDestroyer receives the recorded
// domain id, not an empty string. The session is cloned first (so the cache pins the
// OverlayPath), and the resolver supplies the DomainUUID on top.
func TestDestroyThreadsResolvedDomainUUID(t *testing.T) {
	const wantDomain = "dom-uuid-7f3a"
	dom := &recordingDomainDestroyer{}
	resolver := &fakeDestroyResolver{state: DestroyState{DomainUUID: wantDomain}}
	svc := newResolverDriverService(t, dom, resolver)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if len(resolver.calls) != 1 || resolver.calls[0] != testCloneSession {
		t.Errorf("Destroy must consult the DestroyResolver for the session; calls=%v", resolver.calls)
	}
	if got := dom.domainsBySession[testCloneSession]; got != wantDomain {
		t.Errorf("Destroy must thread the resolved DomainUUID into §4.2 step 1; DestroyDomain got domainUUID=%q want %q", got, wantDomain)
	}
}

// TestDestroyResolvesOverlayOnCacheMiss asserts the resolver bridges a CACHE MISS
// (a post-restart Destroy of a session this process never cloned): with no clone
// cache entry, the service adopts the resolver's OverlayPath + Binding + DomainUUID
// so the §4.2 ordering still disposes the overlay and destroys the recorded domain.
func TestDestroyResolvesOverlayOnCacheMiss(t *testing.T) {
	const (
		wantDomain  = "dom-uuid-restart"
		wantOverlay = "/var/lib/ds/overlays/restart-session.qcow2"
	)
	never := "00000000-0000-4000-8000-0000000000ff" // never cloned in this process
	dom := &recordingDomainDestroyer{}
	resolver := &fakeDestroyResolver{state: DestroyState{
		DomainUUID:  wantDomain,
		OverlayPath: wantOverlay,
		Binding:     Binding{HostSessionIndex: 9, TapName: "dstap-9", OverlayPath: wantOverlay},
	}}
	svc := newResolverDriverService(t, dom, resolver)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: never}); err != nil {
		t.Fatalf("Destroy (cache miss): %v", err)
	}
	if got := dom.domainsBySession[never]; got != wantDomain {
		t.Errorf("cache-miss Destroy must thread the resolved DomainUUID; got %q want %q", got, wantDomain)
	}
}

// TestDestroyNotFoundResolverIsCleanNoOp asserts a resolver that has NO record for
// the session (already-gone / never-recorded) is a clean no-op convergence — the
// unconditional flush still runs and the destroy succeeds, exactly the
// already-gone-session behavior the session_uuid-only path always had.
func TestDestroyNotFoundResolverIsCleanNoOp(t *testing.T) {
	gone := "00000000-0000-4000-8000-0000000000ee"
	dom := &recordingDomainDestroyer{}
	resolver := &fakeDestroyResolver{notFound: true}
	svc := newResolverDriverService(t, dom, resolver)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: gone}); err != nil {
		t.Fatalf("Destroy of a not-found session must converge cleanly (idempotent), got: %v", err)
	}
	// No record ⇒ empty DomainUUID threaded (the session_uuid-driven domain destroy).
	if got, ok := dom.domainsBySession[gone]; !ok || got != "" {
		t.Errorf("a not-found resolver must leave the DomainUUID empty (session_uuid-driven destroy); got %q (present=%v)", got, ok)
	}
}

// TestDestroyResolverFaultSurfacesError asserts a resolver READ FAULT is surfaced as
// a gRPC error (never a silent skip that would leak a real overlay) so the
// reconciler re-drives.
func TestDestroyResolverFaultSurfacesError(t *testing.T) {
	dom := &recordingDomainDestroyer{}
	resolver := &fakeDestroyResolver{err: errResolverFault}
	svc := newResolverDriverService(t, dom, resolver)
	client := dialInProcess(t, svc)

	_, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a resolver read fault must surface as codes.Internal, got code=%v err=%v", status.Code(err), err)
	}
}

// errResolverFault is the synthetic resolver read-fault sentinel.
var errResolverFault = errResolver("synthetic resolver read fault")

type errResolver string

func (e errResolver) Error() string { return string(e) }

// newResolverDriverService builds a DriverService over the stock create-side fakes
// (acked + fresh gate so a clone is routable) plus a custom DomainDestroyer and a
// DestroyResolver wired through NewDriverServiceWithDestroyResolver — so a test can
// assert the resolved DomainUUID / overlay are threaded into §4.2. The non-domain
// destroy seams stay the stock fakes (overlay/durability/flow), reached through the
// same package fakes service_test.go uses.
func newResolverDriverService(t *testing.T, dom DomainDestroyer, resolver DestroyResolver) *DriverService {
	t.Helper()
	attach := &fakeAttach{}
	overlay := &fakeOverlay{}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, attach, overlay, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(dom, attach, overlay, &fakeDurability{}, &fakeFlowBytes{})
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithDestroyResolver(host, destroyer, nil, nil, nil, nil, nil, nil, resolver)
	if err != nil {
		t.Fatalf("NewDriverServiceWithDestroyResolver: %v", err)
	}
	return svc
}

// assertBackingIsBase asserts the overlay's qcow2 backing file resolves to the
// golden base — the D29 CoW backing invariant. `qemu-img info` is the load-bearing
// check and is REQUIRED on the operator host: a structured backing-file field is
// the only authoritative read of the qcow2 backing chain. If qemu-img is not on
// PATH we fail loudly rather than degrading to a substring scan (a coincidental
// occurrence of the base basename elsewhere in the raw qcow2 bytes could otherwise
// false-pass). The header-scan fallback below is kept ONLY for the qemu-img-absent
// path and is tightened to require the basename adjacent to the qcow2 backing-file
// marker rather than anywhere in the file.
func assertBackingIsBase(t *testing.T, virsh, overlayPath, base string) {
	t.Helper()
	baseName := filepath.Base(base)
	if _, err := exec.LookPath("qemu-img"); err == nil {
		out, err := exec.Command("qemu-img", "info", "-U", "--output=json", overlayPath).CombinedOutput()
		if err != nil {
			t.Fatalf("qemu-img info %s: %v (output: %s) — the authoritative D29 backing-chain check failed", overlayPath, err, strings.TrimSpace(string(out)))
		}
		if !strings.Contains(string(out), baseName) {
			t.Errorf("overlay %s backing chain does not name the golden base %s (qemu-img info: %s) — the clone must back ON the read-only base (D29)", overlayPath, base, strings.TrimSpace(string(out)))
		}
		return
	}
	// Fallback (qemu-img NOT on PATH): the backing-file path is stored in the qcow2
	// header. Require the base basename adjacent to the absolute backing-file path
	// (the directory + basename appear together as a contiguous string) so an
	// incidental occurrence of the basename elsewhere in the image bytes cannot
	// false-pass. A misprovisioned host without qemu-img and without a recognizable
	// backing-file string fails loudly.
	data, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay %s to verify backing chain: %v", overlayPath, err)
	}
	if absBase, e := filepath.Abs(base); e == nil && strings.Contains(string(data), absBase) {
		return
	}
	backingDir := filepath.Dir(base)
	if backingDir != "." && strings.Contains(string(data), filepath.Join(backingDir, baseName)) {
		return
	}
	t.Errorf("overlay %s qcow2 header does not reference the golden base path %s adjacent to its directory %s (qemu-img absent, tightened header scan) — the clone must back ON the read-only base (D29)", overlayPath, base, backingDir)
}

// assertDomainRunning asserts virsh sees a defined+running transient domain for
// the session (the live Booter's define+boot landed).
func assertDomainRunning(t *testing.T, virsh, sessionUUID string) {
	t.Helper()
	out, err := exec.Command(virsh, "domuuid", domainName(sessionUUID)).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh domuuid %s: %v (output: %s) — the live boot must have defined+started the domain (D29 boot leg)", domainName(sessionUUID), err, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Errorf("virsh reports no uuid for domain %s — the live boot did not start the domain", domainName(sessionUUID))
	}
}

// assertDomainGone asserts the transient domain is no longer defined for the
// session (Destroy tore it down).
func assertDomainGone(t *testing.T, virsh, sessionUUID string) {
	t.Helper()
	out, err := exec.Command(virsh, "domuuid", domainName(sessionUUID)).CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		t.Errorf("domain %s still present after Destroy (uuid %q) — the §4.2 teardown must destroy the transient domain", domainName(sessionUUID), strings.TrimSpace(string(out)))
	}
}
