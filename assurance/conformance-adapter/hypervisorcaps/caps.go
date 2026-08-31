// SPDX-License-Identifier: Apache-2.0

package hypervisorcaps

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// exportDeltaChunkSize is the wire frame payload size for ExportDiskDelta: each
// ExportDiskDeltaResponse carries up to this many delta bytes. Mirrors the v0
// driver's framing (doc 15 §5.1) so the streamed delta reassembles with monotonic,
// contiguous {offset, data} frames — 32 KiB is the stdlib io.Copy default buffer.
const exportDeltaChunkSize = 32 * 1024

// capsServer is a faithful in-process HypervisorDriverServiceServer reproducing
// the v0 libvirt driver's DOCUMENTED capability-honesty contract over the frozen
// hypervisor.v1 wire (doc 15 §5.1). It is NOT the real orchestrator DriverService
// (that lives in an internal/ package this module cannot import — see doc.go); it
// is the conformance stand-in the adapter DRIVES so the true-flag ⇒
// exercised-backing-verb closure runs over a real gRPC wire.
//
// HONESTY POSTURE (the contract this server is faithful to):
//   - GetCapabilities answers the honest libvirt flags: instant-clone TRUE
//     (per-session qcow2 overlay via external snapshots, D29), disk-delta-export
//     TRUE (qcow2 dirty-bitmap delta, D29), migrate FALSE (M3) — the deliberate
//     opposite of the EC2 demo driver's all-false answer;
//   - CloneFromImage (the instant-clone backing verb) returns a NON-EMPTY binding;
//   - ExportDiskDelta (the disk-delta-export backing verb) is the HONEST GAP: with
//     no exporter wired it returns codes.Unimplemented (the documented gap, never a
//     silently-passed false-true flag); WITH an exporter wired it STREAMS the delta;
//   - Migrate is honestly Unimplemented (consistent with supports_migrate=FALSE).
//
// It embeds UnimplementedHypervisorDriverServiceServer for forward-compat; the four
// verbs the capability-honesty closure touches are overridden, the rest stay the
// honest embedded Unimplemented.
type capsServer struct {
	hypervisorv1.UnimplementedHypervisorDriverServiceServer

	// exporter, when non-nil, is the DiskDeltaExporter that backs ExportDiskDelta:
	// nil ⇒ the honest-gap posture (codes.Unimplemented), non-nil ⇒ the verb streams
	// the exporter's bytes. This is the lever that lets the adapter prove BOTH the
	// honest-gap posture (a true flag whose verb is not yet wired surfaces
	// Unimplemented) AND the fully-backed posture (the verb streams the delta).
	exporter DiskDeltaExporter

	// mu guards the per-session clone cache. CloneFromImage is idempotent on
	// session_uuid (doc 15 §5.1): a retry returns the SAME binding rather than
	// forking a second; ExportDiskDelta/Snapshot require a recorded binding.
	mu     sync.Mutex
	clones map[string]*hypervisorv1.CloneFromImageResponse
	// nextIndex hands the next never-recycled host_session_index (D66) — a
	// process-local monotonic counter (the synthetic stand-in for the real durable
	// Allocator; this adapter is offline, doc.go).
	nextIndex uint64
}

// DiskDeltaExporter opens a session's per-session overlay delta as a raw byte
// stream — the seam capsServer.ExportDiskDelta frames into {offset, data} chunks.
// It mirrors the v0 driver's DiskDeltaExporter seam shape (an io.ReadCloser source,
// the service owns the framing) so the conformance server's streaming is faithful
// to the real verb. Synthetic + offline (no libvirt-go, no qcow2, no live VM).
type DiskDeltaExporter interface {
	// OpenDelta opens the dirty-bitmap delta of sessionUUID's overlay as a raw byte
	// stream. An empty sinceSnapshotRef requests the FULL overlay delta; a non-empty
	// one the incremental delta since that opaque base. The returned reader yields
	// ONLY opaque delta bytes (never a libvirt/qcow2 internal); the caller frames
	// them and ALWAYS Closes the reader.
	OpenDelta(ctx context.Context, sessionUUID, sinceSnapshotRef string) (io.ReadCloser, error)
}

// capsOption configures a capsServer.
type capsOption func(*capsServer)

// withDiskDeltaExporter wires the DiskDeltaExporter that backs ExportDiskDelta,
// flipping the verb from the honest-gap codes.Unimplemented posture to streaming.
func withDiskDeltaExporter(e DiskDeltaExporter) capsOption {
	return func(s *capsServer) { s.exporter = e }
}

// newCapsServer builds a faithful capability-honesty server. With no options the
// server is in the HONEST-GAP posture (ExportDiskDelta returns codes.Unimplemented,
// the documented disk-delta gap); withDiskDeltaExporter wires the backing exporter.
func newCapsServer(opts ...capsOption) *capsServer {
	s := &capsServer{clones: make(map[string]*hypervisorv1.CloneFromImageResponse)}
	for _, o := range opts {
		o(s)
	}
	return s
}

// GetCapabilities answers the honest v0 libvirt flags (doc 15 §5.1).
func (s *capsServer) GetCapabilities(_ context.Context, _ *hypervisorv1.GetCapabilitiesRequest) (*hypervisorv1.GetCapabilitiesResponse, error) {
	return &hypervisorv1.GetCapabilitiesResponse{
		Capabilities: &hypervisorv1.Capabilities{
			SupportsInstantClone:    true,  // per-session qcow2 overlay (D29)
			SupportsDiskDeltaExport: true,  // qcow2 dirty-bitmap delta (D29)
			SupportsMigrate:         false, // migration is M3
		},
	}, nil
}

// CloneFromImage is the instant-clone backing verb: it returns a NON-EMPTY binding
// (the instant-clone artifact). Idempotent on session_uuid — a retry returns the
// cached binding, never a second never-recycled index (D66).
func (s *capsServer) CloneFromImage(_ context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	spec := req.GetSpec()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "CloneFromImage requires a VmSpec")
	}
	sessionUUID := spec.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "CloneFromImage requires spec.session_uuid (every verb is idempotent on it)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.clones[sessionUUID]; ok {
		return prior, nil
	}
	idx := s.nextIndex
	s.nextIndex++
	resp := &hypervisorv1.CloneFromImageResponse{
		HostSessionIndex: idx,
		TapName:          fmt.Sprintf("dstap-%d", idx),
		GuestIp: &hypervisorv1.GuestAddress{
			// Synthetic family-tagged IPv4 (10.42.0.<2+idx>) — a well-formed binding
			// guest IP, the D75 family enum + raw bytes (never a fixed32).
			Family:  hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4,
			Address: []byte{10, 42, 0, byte(2 + idx)},
		},
		OverlayPath: fmt.Sprintf("/var/lib/ds/overlays/%s.qcow2", sessionUUID),
	}
	s.clones[sessionUUID] = resp
	return resp, nil
}

// ExportDiskDelta is the disk-delta-export backing verb. With NO exporter wired it
// returns the HONEST codes.Unimplemented gap (the documented disk-delta gap — never
// a silently-passed false-true flag). With an exporter wired it STREAMS the delta as
// {offset, data} frames, offsets monotonic + contiguous (frame N starts where N-1's
// data ended), the reader ALWAYS Closed.
func (s *capsServer) ExportDiskDelta(req *hypervisorv1.ExportDiskDeltaRequest, stream hypervisorv1.HypervisorDriverService_ExportDiskDeltaServer) error {
	if s.exporter == nil {
		return status.Error(codes.Unimplemented, "ExportDiskDelta: D29 dirty-bitmap delta streaming is not wired in this driver (no DiskDeltaExporter); the libvirt dirty-bitmap/qemu-img extraction lands host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return status.Error(codes.InvalidArgument, "ExportDiskDelta requires session_uuid (the session whose overlay delta to export)")
	}

	s.mu.Lock()
	_, ok := s.clones[sessionUUID]
	s.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "ExportDiskDelta: session %s has no recorded binding (it never cloned or was torn down); cannot export its overlay delta", sessionUUID)
	}

	ctx := stream.Context()
	reader, err := s.exporter.OpenDelta(ctx, sessionUUID, req.GetSinceSnapshotRef())
	if err != nil {
		return status.Errorf(codes.Internal, "export disk delta session %s: %v", sessionUUID, err)
	}
	defer func() { _ = reader.Close() }()

	buf := make([]byte, exportDeltaChunkSize)
	var offset uint64
	for {
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			frame := make([]byte, n)
			copy(frame, buf[:n])
			if err := stream.Send(&hypervisorv1.ExportDiskDeltaResponse{Offset: offset, Data: frame}); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return status.Errorf(codes.Internal, "export disk delta session %s: read: %v", sessionUUID, readErr)
		}
	}
}

// Migrate is honestly Unimplemented, consistent with supports_migrate=FALSE (M3).
func (s *capsServer) Migrate(_ context.Context, _ *hypervisorv1.MigrateRequest) (*hypervisorv1.MigrateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Migrate: cross-host migration is M3 (supports_migrate=false); not wired in the v0 libvirt driver")
}

// dialInProcess stands the given HypervisorDriverServiceServer up on a loopback
// gRPC server and returns a connected client (the orchestrator service_test.go
// dialInProcess idiom: net.Listen 127.0.0.1:0 + grpc.NewServer + grpc.NewClient
// with insecure creds — an in-memory wire, no off-box transport). The returned stop
// tears the server + connection down; the caller MUST call it (defer stop()).
func dialInProcess(srv hypervisorv1.HypervisorDriverServiceServer) (client hypervisorv1.HypervisorDriverServiceClient, stop func(), err error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen loopback: %w", err)
	}
	gs := grpc.NewServer()
	hypervisorv1.RegisterHypervisorDriverServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		gs.Stop()
		return nil, nil, fmt.Errorf("dial loopback: %w", err)
	}
	stop = func() {
		_ = conn.Close()
		gs.Stop()
	}
	return hypervisorv1.NewHypervisorDriverServiceClient(conn), stop, nil
}

// CapabilityHonestyResult records what the wire closure observed for each
// advertised capability flag, so a caller (the conformance suite, an operator) can
// see the closure was actually driven, not merely that it returned nil error.
type CapabilityHonestyResult struct {
	// SupportsInstantClone / SupportsDiskDeltaExport / SupportsMigrate are the flags
	// GetCapabilities advertised over the wire.
	SupportsInstantClone    bool
	SupportsDiskDeltaExport bool
	SupportsMigrate         bool

	// InstantCloneBinding is the NON-EMPTY binding CloneFromImage returned (the
	// instant-clone backing verb's wire artifact) when SupportsInstantClone is true.
	InstantCloneBinding *hypervisorv1.CloneFromImageResponse

	// DiskDeltaCode is the gRPC status code ExportDiskDelta surfaced (the
	// disk-delta-export backing verb): codes.Unimplemented when the verb is the
	// honest gap, codes.OK when it streamed. DiskDeltaStreamed is the reassembled
	// delta bytes when the verb streamed (empty when it was the honest gap).
	DiskDeltaCode     codes.Code
	DiskDeltaStreamed []byte

	// MigrateCode is the gRPC status code Migrate surfaced — codes.Unimplemented,
	// consistent with the FALSE supports_migrate flag.
	MigrateCode codes.Code
}

// exerciseCapabilityHonesty is the WIRE CLOSURE the adapter drives against a dialed
// HypervisorDriverServiceClient (doc 15 §5.1, §10): for each advertised-TRUE
// capability flag it exercises the backing verb over the wire and FAILS if a true
// flag has no honest backing; for the FALSE flag it asserts the consistent
// Unimplemented verb. It is the module-agnostic driver — it asserts only the frozen
// hypervisor.v1 wire contract, so the same closure runs against this adapter's
// faithful server here AND, once a non-internal handle exists, the real
// orchestrator DriverService (doc.go's deferred-manual seam).
//
// session is the clone idempotency key (every verb idempotent on it). It returns
// the observed CapabilityHonestyResult or the first contract violation as an error.
func exerciseCapabilityHonesty(ctx context.Context, client hypervisorv1.HypervisorDriverServiceClient, session string) (*CapabilityHonestyResult, error) {
	capResp, err := client.GetCapabilities(ctx, &hypervisorv1.GetCapabilitiesRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetCapabilities over the wire: %w", err)
	}
	caps := capResp.GetCapabilities()
	if caps == nil {
		return nil, fmt.Errorf("GetCapabilities returned nil Capabilities (a driver must answer its honest flags)")
	}
	res := &CapabilityHonestyResult{
		SupportsInstantClone:    caps.GetSupportsInstantClone(),
		SupportsDiskDeltaExport: caps.GetSupportsDiskDeltaExport(),
		SupportsMigrate:         caps.GetSupportsMigrate(),
	}

	// supports_instant_clone TRUE ⇒ CloneFromImage must return a NON-EMPTY binding.
	if res.SupportsInstantClone {
		clone, err := client.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
			Spec: &hypervisorv1.VmSpec{
				SessionUuid:         session,
				ImageId:             "img-content-addressed",
				EntrypointConfigRef: "entrypoint-ref",
				Material:            &hypervisorv1.SessionMaterial{CaBundleRef: "ca-bundle-ref"},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("supports_instant_clone=true but CloneFromImage failed over the wire (the backing verb a true flag claims): %w", err)
		}
		if err := assertNonEmptyBinding(clone); err != nil {
			return nil, fmt.Errorf("supports_instant_clone=true but %w (a true flag with no backing binding is the dishonesty the conformance suite catches)", err)
		}
		res.InstantCloneBinding = clone
	}

	// supports_disk_delta_export TRUE ⇒ ExportDiskDelta must be the backing verb —
	// either the HONEST GAP (codes.Unimplemented surfaced, never a silent false-true)
	// or fully wired (it streams). Both are honest; a flag whose verb returns a
	// SUCCESS with no bytes (or any non-Unimplemented/non-OK shape) would be the lie.
	if res.SupportsDiskDeltaExport {
		streamed, code, err := drainDiskDelta(ctx, client, session, "")
		switch code {
		case codes.Unimplemented:
			// The documented honest gap: the flag's substrate exists (D29) but the
			// streaming verb is not yet wired host-side. Surfaced honestly.
			res.DiskDeltaCode = code
		case codes.OK:
			if err != nil {
				return nil, fmt.Errorf("supports_disk_delta_export=true: ExportDiskDelta stream errored mid-flight: %w", err)
			}
			if len(streamed) == 0 {
				return nil, fmt.Errorf("supports_disk_delta_export=true but ExportDiskDelta streamed ZERO bytes (a true flag whose backing verb does no work is dishonest)")
			}
			res.DiskDeltaCode = code
			res.DiskDeltaStreamed = streamed
		default:
			return nil, fmt.Errorf("supports_disk_delta_export=true but ExportDiskDelta surfaced an unexpected code %s (honest postures are Unimplemented = documented gap, or OK = streamed): %v", code, err)
		}
	}

	// supports_migrate FALSE ⇒ Migrate is allowed to have no backing verb; assert it
	// is the honest Unimplemented (the EC2-honesty direction: a false flag never lies).
	_, mErr := client.Migrate(ctx, &hypervisorv1.MigrateRequest{})
	res.MigrateCode = status.Code(mErr)
	if res.SupportsMigrate {
		return nil, fmt.Errorf("supports_migrate=true is not the v0 honest answer (migration is M3); a true migrate flag would require a backing Migrate verb")
	}
	if res.MigrateCode != codes.Unimplemented {
		return nil, fmt.Errorf("supports_migrate=false but Migrate surfaced %s (a false flag's verb is honestly Unimplemented for v0)", res.MigrateCode)
	}

	return res, nil
}

// assertNonEmptyBinding asserts a CloneFromImageResponse carries the instant-clone
// binding artifact: a tap name, a well-formed family-tagged guest IP, and an
// overlay path. An empty binding behind supports_instant_clone=true is the
// dishonesty the closure fails on.
func assertNonEmptyBinding(b *hypervisorv1.CloneFromImageResponse) error {
	if b == nil {
		return fmt.Errorf("CloneFromImage returned a nil binding")
	}
	if b.GetTapName() == "" {
		return fmt.Errorf("CloneFromImage binding has no tap_name")
	}
	gip := b.GetGuestIp()
	if gip == nil || gip.GetFamily() == hypervisorv1.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED || len(gip.GetAddress()) == 0 {
		return fmt.Errorf("CloneFromImage binding has no well-formed family-tagged guest IP")
	}
	if b.GetOverlayPath() == "" {
		return fmt.Errorf("CloneFromImage binding has no overlay_path")
	}
	return nil
}

// drainDiskDelta drives the ExportDiskDelta server-stream over the wire and
// reassembles the {offset, data} frames by concatenation, asserting offsets are
// MONOTONIC and CONTIGUOUS (frame N's offset equals the running byte count). It
// returns the reassembled bytes, the terminal gRPC status code, and any framing
// violation. A codes.Unimplemented stream (the honest gap) returns no bytes and
// that code — NOT an error (the gap is a valid honest posture).
func drainDiskDelta(ctx context.Context, client hypervisorv1.HypervisorDriverServiceClient, session, sinceRef string) (data []byte, code codes.Code, err error) {
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      session,
		SinceSnapshotRef: sinceRef,
	})
	if err != nil {
		return nil, status.Code(err), err
	}
	var assembled []byte
	var expectedOffset uint64
	for {
		frame, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return assembled, codes.OK, nil
		}
		if recvErr != nil {
			return assembled, status.Code(recvErr), recvErr
		}
		if frame.GetOffset() != expectedOffset {
			return assembled, codes.OK, fmt.Errorf("ExportDiskDelta frame offset %d is not contiguous (expected %d): offsets must be monotonic + contiguous", frame.GetOffset(), expectedOffset)
		}
		assembled = append(assembled, frame.GetData()...)
		expectedOffset += uint64(len(frame.GetData()))
	}
}

// syntheticReadCloser is an offline DiskDeltaExporter source: it yields a fixed
// synthetic delta for the (session, ref) so a wire roundtrip can reassemble the
// streamed bytes and assert byte-equality (D50). It records that Close ran so the
// always-Close contract is assertable.
type syntheticReadCloser struct {
	r      *bytesReader
	closed *bool
}

func (s *syntheticReadCloser) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *syntheticReadCloser) Close() error {
	if s.closed != nil {
		*s.closed = true
	}
	return nil
}

// bytesReader is a minimal io.Reader over a byte slice (stdlib bytes.Reader would
// do; kept local so the synthetic source has no extra import surface and the Read
// chunking is explicit for the framing assertion).
type bytesReader struct {
	b   []byte
	off int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
