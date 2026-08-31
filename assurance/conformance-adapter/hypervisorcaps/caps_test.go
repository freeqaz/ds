// SPDX-License-Identifier: Apache-2.0

package hypervisorcaps

import (
	"bytes"
	"context"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

const testSession = "00000000-0000-4000-8000-0000000000c1"

// fakeExporter is a deterministic offline DiskDeltaExporter (D50): it yields a
// fixed synthetic delta per (session, ref) so a wire roundtrip can reassemble the
// streamed bytes and assert byte-equality, and records whether Close ran so the
// service's always-Close contract is assertable. No libvirt-go, no qcow2, no VM.
type fakeExporter struct {
	delta  []byte
	closed bool
}

func (f *fakeExporter) OpenDelta(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return &syntheticReadCloser{r: &bytesReader{b: f.delta}, closed: &f.closed}, nil
}

// TestCapabilityHonestyClosure_HonestGap drives the full capability-honesty wire
// closure against the faithful server in its DEFAULT (no-exporter) posture: every
// advertised-true flag is exercised over the wire, and the as-yet-unwired
// ExportDiskDelta is the HONEST GAP (codes.Unimplemented surfaced, never a silently
// passed false-true flag). This is the acceptance bullet "the currently-
// Unimplemented ExportDiskDelta is asserted as the HONEST GAP" (doc 15 §5.1).
func TestCapabilityHonestyClosure_HonestGap(t *testing.T) {
	client, stop, err := dialInProcess(newCapsServer())
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	res, err := exerciseCapabilityHonesty(context.Background(), client, testSession)
	if err != nil {
		t.Fatalf("capability-honesty closure failed: %v", err)
	}

	// Honest libvirt flags (the opposite of EC2's all-false honesty test).
	if !res.SupportsInstantClone {
		t.Error("supports_instant_clone must be TRUE (per-session qcow2 overlay, D29)")
	}
	if !res.SupportsDiskDeltaExport {
		t.Error("supports_disk_delta_export must be TRUE (qcow2 dirty-bitmap delta, D29)")
	}
	if res.SupportsMigrate {
		t.Error("supports_migrate must be FALSE for v0 (migration is M3)")
	}

	// supports_instant_clone TRUE was exercised: a non-empty binding came back over
	// the wire (the instant-clone backing verb's artifact).
	if err := assertNonEmptyBinding(res.InstantCloneBinding); err != nil {
		t.Errorf("instant-clone backing verb produced no honest binding: %v", err)
	}

	// supports_disk_delta_export TRUE is the HONEST GAP today: codes.Unimplemented,
	// surfaced as the documented gap — NOT a silently-passed false-true flag.
	if res.DiskDeltaCode != codes.Unimplemented {
		t.Errorf("ExportDiskDelta honest-gap posture: got code %s, want Unimplemented (the documented disk-delta gap)", res.DiskDeltaCode)
	}
	if len(res.DiskDeltaStreamed) != 0 {
		t.Errorf("ExportDiskDelta honest-gap posture streamed %d bytes; want none (the verb is the gap, not yet wired)", len(res.DiskDeltaStreamed))
	}

	// Migrate is honestly Unimplemented, consistent with the FALSE flag.
	if res.MigrateCode != codes.Unimplemented {
		t.Errorf("Migrate code = %s; want Unimplemented (consistent with supports_migrate=false)", res.MigrateCode)
	}
}

// TestCapabilityHonestyClosure_DiskDeltaBacked drives the closure against the
// server with the DiskDeltaExporter WIRED: the disk-delta-export flag is now FULLY
// backed — ExportDiskDelta STREAMS the delta over the wire (codes.OK, non-empty
// bytes), and the streamed bytes reassemble byte-equal with monotonic + contiguous
// offsets. This is the acceptance bullet "for each advertised-true capability, the
// adapter EXERCISES the backing verb over the wire" in its fully-wired form.
func TestCapabilityHonestyClosure_DiskDeltaBacked(t *testing.T) {
	want := bytes.Repeat([]byte("delta-bytes-"), 8192) // > one 32 KiB frame ⇒ multi-frame stream
	exp := &fakeExporter{delta: append([]byte(nil), want...)}

	client, stop, err := dialInProcess(newCapsServer(withDiskDeltaExporter(exp)))
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	res, err := exerciseCapabilityHonesty(context.Background(), client, testSession)
	if err != nil {
		t.Fatalf("capability-honesty closure (disk-delta backed) failed: %v", err)
	}

	if res.DiskDeltaCode != codes.OK {
		t.Fatalf("ExportDiskDelta backed posture: got code %s, want OK (the verb is wired, it must stream)", res.DiskDeltaCode)
	}
	if !bytes.Equal(res.DiskDeltaStreamed, want) {
		t.Errorf("ExportDiskDelta streamed %d bytes; want %d byte-equal reassembly", len(res.DiskDeltaStreamed), len(want))
	}
	if !exp.closed {
		t.Error("ExportDiskDelta did not Close the exporter reader (the always-Close release contract)")
	}
}

// TestDiskDeltaFramingMonotonicContiguous proves drainDiskDelta's framing
// assertion bites: it drives a multi-frame stream and reassembles by concatenation,
// which only yields the original bytes if every frame's offset was monotonic +
// contiguous (the running-byte-count invariant the closure depends on).
func TestDiskDeltaFramingMonotonicContiguous(t *testing.T) {
	// A payload that spans several 32 KiB frames so the offset bookkeeping is
	// genuinely exercised across frame boundaries.
	want := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF}, exportDeltaChunkSize) // 3*32KiB bytes
	exp := &fakeExporter{delta: append([]byte(nil), want...)}

	client, stop, err := dialInProcess(newCapsServer(withDiskDeltaExporter(exp)))
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	// First clone the session so ExportDiskDelta finds a recorded binding (the
	// Snapshot/Suspend precedent the v0 driver enforces; the faithful server mirrors
	// it).
	if _, err := client.CloneFromImage(context.Background(), &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: testSession, ImageId: "img"},
	}); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	got, code, err := drainDiskDelta(context.Background(), client, testSession, "")
	if err != nil {
		t.Fatalf("drainDiskDelta: code=%s err=%v", code, err)
	}
	if code != codes.OK {
		t.Fatalf("drainDiskDelta code = %s; want OK", code)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled %d bytes != original %d (a non-contiguous offset would corrupt the concat)", len(got), len(want))
	}
}

// TestExportDiskDeltaNotFoundWithoutClone proves the backed verb fails closed for a
// session that never cloned (NotFound) — it cannot stream a delta for a binding that
// does not exist (the v0 driver's precondition the faithful server mirrors).
func TestExportDiskDeltaNotFoundWithoutClone(t *testing.T) {
	exp := &fakeExporter{delta: []byte("unused")}
	client, stop, err := dialInProcess(newCapsServer(withDiskDeltaExporter(exp)))
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	_, code, _ := drainDiskDelta(context.Background(), client, "never-cloned-session", "")
	if code != codes.NotFound {
		t.Errorf("ExportDiskDelta for an un-cloned session: got %s, want NotFound", code)
	}
}

// TestCloneFromImageIdempotentOnSession proves the instant-clone backing verb is
// idempotent on session_uuid (doc 15 §5.1): a retry returns the SAME binding, never
// a second never-recycled index (D66) — the instant-clone artifact stays stable.
func TestCloneFromImageIdempotentOnSession(t *testing.T) {
	client, stop, err := dialInProcess(newCapsServer())
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	req := &hypervisorv1.CloneFromImageRequest{Spec: &hypervisorv1.VmSpec{SessionUuid: testSession, ImageId: "img"}}
	first, err := client.CloneFromImage(context.Background(), req)
	if err != nil {
		t.Fatalf("first CloneFromImage: %v", err)
	}
	second, err := client.CloneFromImage(context.Background(), req)
	if err != nil {
		t.Fatalf("retry CloneFromImage: %v", err)
	}
	if first.GetHostSessionIndex() != second.GetHostSessionIndex() || first.GetTapName() != second.GetTapName() {
		t.Errorf("CloneFromImage not idempotent: first index=%d tap=%s, retry index=%d tap=%s (a retry must re-adopt, not burn a second index)",
			first.GetHostSessionIndex(), first.GetTapName(), second.GetHostSessionIndex(), second.GetTapName())
	}
}

// TestClosureCatchesDishonestEmptyBindingFlag is the ADVERSARIAL regression: a
// driver that advertises supports_instant_clone=TRUE but whose CloneFromImage
// returns an EMPTY binding is the dishonesty the capability-honesty contract exists
// to catch (doc 15 §5.1). The closure MUST flag it — a true flag with no backing
// binding fails, not silently passes.
func TestClosureCatchesDishonestEmptyBindingFlag(t *testing.T) {
	client, stop, err := dialInProcess(&dishonestServer{instantClone: true, emptyBinding: true})
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	_, err = exerciseCapabilityHonesty(context.Background(), client, testSession)
	if err == nil {
		t.Fatal("closure passed a dishonest server (supports_instant_clone=true with an empty binding); the capability-honesty contract must CATCH it")
	}
}

// TestClosureCatchesDishonestEmptyDiskDeltaFlag is the second ADVERSARIAL
// regression: a driver advertising supports_disk_delta_export=TRUE whose
// ExportDiskDelta returns a clean OK with ZERO bytes claims a capability its verb
// does no work for. The closure MUST flag it (an OK-but-empty stream behind a true
// flag is dishonest — neither the honest Unimplemented gap nor a real stream).
func TestClosureCatchesDishonestEmptyDiskDeltaFlag(t *testing.T) {
	client, stop, err := dialInProcess(&dishonestServer{instantClone: true, diskDelta: true, emptyDelta: true})
	if err != nil {
		t.Fatalf("dialInProcess: %v", err)
	}
	defer stop()

	_, err = exerciseCapabilityHonesty(context.Background(), client, testSession)
	if err == nil {
		t.Fatal("closure passed a dishonest server (supports_disk_delta_export=true with a zero-byte OK stream); it must CATCH the empty backing verb")
	}
}

// dishonestServer is an adversarial HypervisorDriverServiceServer that LIES: it
// advertises true capability flags whose backing verbs do no honest work. It exists
// ONLY to prove the closure's assertions bite (the regression twins above) — the
// "deliberately drifted real impl now fails the conformance seam" property
// (grantfetchconform precedent).
type dishonestServer struct {
	hypervisorv1.UnimplementedHypervisorDriverServiceServer
	instantClone bool
	emptyBinding bool
	diskDelta    bool
	emptyDelta   bool
}

func (d *dishonestServer) GetCapabilities(_ context.Context, _ *hypervisorv1.GetCapabilitiesRequest) (*hypervisorv1.GetCapabilitiesResponse, error) {
	return &hypervisorv1.GetCapabilitiesResponse{Capabilities: &hypervisorv1.Capabilities{
		SupportsInstantClone:    d.instantClone,
		SupportsDiskDeltaExport: d.diskDelta,
		SupportsMigrate:         false,
	}}, nil
}

func (d *dishonestServer) CloneFromImage(_ context.Context, _ *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	if d.emptyBinding {
		// The lie: a true instant-clone flag, but no binding behind it.
		return &hypervisorv1.CloneFromImageResponse{}, nil
	}
	return &hypervisorv1.CloneFromImageResponse{
		HostSessionIndex: 0,
		TapName:          "dstap-0",
		GuestIp:          &hypervisorv1.GuestAddress{Family: hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4, Address: []byte{10, 42, 0, 2}},
		OverlayPath:      "/var/lib/ds/overlays/x.qcow2",
	}, nil
}

func (d *dishonestServer) ExportDiskDelta(_ *hypervisorv1.ExportDiskDeltaRequest, stream hypervisorv1.HypervisorDriverService_ExportDiskDeltaServer) error {
	if d.emptyDelta {
		// The lie: a true disk-delta-export flag, but the stream returns OK with no
		// bytes (does no work) — neither the honest Unimplemented gap nor a real delta.
		return nil
	}
	return status.Error(codes.Unimplemented, "not wired")
}
