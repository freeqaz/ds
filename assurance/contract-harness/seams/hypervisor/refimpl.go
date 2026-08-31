// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"context"
	"crypto/sha256"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// RefImpl is a minimal honest reference implementation of HypervisorDriverService
// — the "real implementation" side of the dual-run. It implements exactly the
// doc 15 §5.1 contract: every verb is idempotent on session_uuid (re-issuing the
// same content-addressed request returns the same binding, never a duplicate),
// capabilities are reported honestly (D35), and a verb gated on a capability the
// driver does not advertise is REFUSED (FailedPrecondition) rather than
// silently no-op-claiming success — the EC2-style honesty test (D32).
//
// This is the M0 stand-in until the production libvirt driver (a skeleton today)
// lands. When that lands it replaces RefImpl as the "real" end and the
// conformance suite is unchanged — which is the whole point: the suite is the
// contract, not the implementation.
//
// The instance is configured with the capability flags it will honestly report
// so the suite can stand up two reference drivers — one capable, one EC2-style
// incapable — and assert both halves of the honesty property against the SAME
// code path. State is held in-memory, keyed by session_uuid; access is
// mutex-guarded so the in-process gRPC server is safe under concurrent calls.
type RefImpl struct {
	hypervisorv1.UnimplementedHypervisorDriverServiceServer

	caps *hypervisorv1.Capabilities

	mu       sync.Mutex
	sessions map[string]*sessionState
	nextIdx  uint64
}

// sessionState is the minimal honest record the reference driver keeps per
// session. It is the idempotency anchor: a verb keyed on an existing
// session_uuid reuses this record rather than allocating a fresh binding.
type sessionState struct {
	binding *hypervisorv1.CloneFromImageResponse
	domain  string
	state   attachv1.SessionStateName
}

// NewRefImpl returns a reference HypervisorDriverService server reporting the
// given capability flags honestly (D35). Pass all-false for the EC2-style
// incapable driver (D32), or selectively true for a fuller hypervisor.
func NewRefImpl(supportsMigrate, supportsInstantClone, supportsDiskDeltaExport bool) *RefImpl {
	return &RefImpl{
		caps: &hypervisorv1.Capabilities{
			SupportsMigrate:         supportsMigrate,
			SupportsInstantClone:    supportsInstantClone,
			SupportsDiskDeltaExport: supportsDiskDeltaExport,
		},
		sessions: map[string]*sessionState{},
	}
}

// GetCapabilities reports the D35 flags at registration (doc 15 §5.1). The flags
// are fixed at construction and reported verbatim — honesty is the whole point
// of the verb (D32).
func (s *RefImpl) GetCapabilities(_ context.Context, _ *hypervisorv1.GetCapabilitiesRequest) (*hypervisorv1.GetCapabilitiesResponse, error) {
	return &hypervisorv1.GetCapabilitiesResponse{
		Capabilities: &hypervisorv1.Capabilities{
			SupportsMigrate:         s.caps.GetSupportsMigrate(),
			SupportsInstantClone:    s.caps.GetSupportsInstantClone(),
			SupportsDiskDeltaExport: s.caps.GetSupportsDiskDeltaExport(),
		},
	}, nil
}

// CloneFromImage materializes a VM and returns its host-side attachment binding
// (doc 15 §5.1). Idempotent on session_uuid: a re-issue with the same
// session_uuid returns the SAME binding (same never-recycled host index / tap),
// never a duplicate — the host index is allocated once and reused.
func (s *RefImpl) CloneFromImage(_ context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	spec := req.GetSpec()
	uuid := spec.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "VmSpec.session_uuid is required (every verb is idempotent on it)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.sessions[uuid]; ok {
		// Idempotent re-issue: same content-addressed request -> same binding.
		return existing.binding, nil
	}

	idx := s.allocIndexLocked()
	binding := &hypervisorv1.CloneFromImageResponse{
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		GuestIp:          guestAddress(idx),
		OverlayPath:      overlayPath(uuid),
	}
	s.sessions[uuid] = &sessionState{
		binding: binding,
		domain:  domainUUID(uuid),
		state:   attachv1.SessionStateName_SESSION_STATE_NAME_READY,
	}
	return binding, nil
}

// IssueAttachHandle mints an attach handle for an existing session (doc 15 §5.4).
// The handle is attach.v1-owned (returned wrapped); the reference driver fills
// the session-scoped fields it owns and echoes the requested role.
func (s *RefImpl) IssueAttachHandle(_ context.Context, req *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "IssueAttachHandleRequest.session_uuid is required")
	}
	s.mu.Lock()
	_, ok := s.sessions[uuid]
	s.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	return &hypervisorv1.IssueAttachHandleResponse{
		Handle: &attachv1.AttachHandle{
			SessionUuid: uuid,
			Role:        req.GetRole(),
		},
	}, nil
}

// Snapshot captures a session (doc 15 §5.1). Idempotent on session_uuid: the
// snapshot reference is derived deterministically from the session so a re-issue
// returns the same reference.
func (s *RefImpl) Snapshot(_ context.Context, req *hypervisorv1.SnapshotRequest) (*hypervisorv1.SnapshotResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "SnapshotRequest.session_uuid is required")
	}
	s.mu.Lock()
	_, ok := s.sessions[uuid]
	s.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	return &hypervisorv1.SnapshotResponse{SnapshotRef: snapshotRef(uuid)}, nil
}

// Suspend pauses a session with a D77-narrowed reason (doc 15 §5.1). Idempotent:
// suspending an already-suspended session is a no-op acknowledged the same way.
// POLICY_BREACH REQUIRES provenance (valid only for the D77 genuine-threat
// classes); a POLICY_BREACH with no provenance is refused.
func (s *RefImpl) Suspend(_ context.Context, req *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "SuspendRequest.session_uuid is required")
	}
	if req.GetReason() == hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH && req.GetProvenance() == nil {
		return nil, status.Error(codes.InvalidArgument, "Suspend(POLICY_BREACH) requires provenance (D77)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	sess.state = attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
	return &hypervisorv1.SuspendResponse{}, nil
}

// Resume restarts a suspended session (doc 15 §5.1). Idempotent: resuming a
// running session is a no-op.
func (s *RefImpl) Resume(_ context.Context, req *hypervisorv1.ResumeRequest) (*hypervisorv1.ResumeResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "ResumeRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	sess.state = attachv1.SessionStateName_SESSION_STATE_NAME_READY
	return &hypervisorv1.ResumeResponse{}, nil
}

// Destroy tears a session down, driving the doc 15 §4.2 ordering (doc 15 §5.1).
// Idempotent: a retried Destroy on an already-gone session SUCCEEDS (it does not
// error NotFound) — the orchestrator must be able to re-drive teardown safely.
func (s *RefImpl) Destroy(_ context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "DestroyRequest.session_uuid is required")
	}
	s.mu.Lock()
	delete(s.sessions, uuid)
	s.mu.Unlock()
	return &hypervisorv1.DestroyResponse{}, nil
}

// Migrate moves a session to another host (doc 15 §5.1). Capability-gated on
// Capabilities.supports_migrate: a driver that does not advertise it REFUSES
// (FailedPrecondition) rather than claiming a no-op success (D32/D35).
func (s *RefImpl) Migrate(_ context.Context, req *hypervisorv1.MigrateRequest) (*hypervisorv1.MigrateResponse, error) {
	if !s.caps.GetSupportsMigrate() {
		return nil, status.Error(codes.FailedPrecondition, "driver does not support Migrate (supports_migrate=false)")
	}
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "MigrateRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	// A fresh per-host index/tap on the target host (per-host index history is
	// the migration re-placement join, doc 15 §5.6).
	idx := s.allocIndexLocked()
	binding := &hypervisorv1.CloneFromImageResponse{
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		GuestIp:          guestAddress(idx),
		OverlayPath:      sess.binding.GetOverlayPath(),
	}
	return &hypervisorv1.MigrateResponse{TargetBinding: binding}, nil
}

// ExportDiskDelta streams the D29 overlay delta (doc 15 §5.1). Capability-gated
// on Capabilities.supports_disk_delta_export: a driver that does not advertise
// it REFUSES (FailedPrecondition) rather than streaming an empty/fabricated
// delta (D32/D35).
func (s *RefImpl) ExportDiskDelta(req *hypervisorv1.ExportDiskDeltaRequest, stream grpc.ServerStreamingServer[hypervisorv1.ExportDiskDeltaResponse]) error {
	if !s.caps.GetSupportsDiskDeltaExport() {
		return status.Error(codes.FailedPrecondition, "driver does not support ExportDiskDelta (supports_disk_delta_export=false)")
	}
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return status.Error(codes.InvalidArgument, "ExportDiskDeltaRequest.session_uuid is required")
	}
	s.mu.Lock()
	_, ok := s.sessions[uuid]
	s.mu.Unlock()
	if !ok {
		return status.Error(codes.NotFound, "no such session")
	}
	for _, frame := range deltaFrames(uuid) {
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	return nil
}

// RecoverSessions enumerates the sessions the driver is still running after a
// restart (doc 15 §5.1) — restart re-adoption. Each is reported as an
// ObservedSession, the §5.2 shape shared with the hostagent.v1 heartbeat. The
// returned sessions are ordered by host index so the report is deterministic.
func (s *RefImpl) RecoverSessions(_ context.Context, req *hypervisorv1.RecoverSessionsRequest) (*hypervisorv1.RecoverSessionsResponse, error) {
	if req.GetHostId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RecoverSessionsRequest.host_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*hypervisorv1.ObservedSession, 0, len(s.sessions))
	for uuid, sess := range s.sessions {
		out = append(out, &hypervisorv1.ObservedSession{
			SessionUuid:      uuid,
			DomainUuid:       sess.domain,
			HostSessionIndex: sess.binding.GetHostSessionIndex(),
			TapName:          sess.binding.GetTapName(),
			OverlayPath:      sess.binding.GetOverlayPath(),
			ObservedState:    &attachv1.SessionState{Name: sess.state},
		})
	}
	sortObservedByIndex(out)
	return &hypervisorv1.RecoverSessionsResponse{Sessions: out}, nil
}

// SeedSession installs a session directly, simulating state a driver re-adopts
// after a restart (the sessions a NEW process inherits, doc 15 §5.1). It is a
// test affordance on the reference impl — not a contract verb — used by the
// suite to stand up a "post-restart" driver whose RecoverSessions must report
// the pre-existing sessions. Synthetic fixtures only (D50).
func (s *RefImpl) SeedSession(uuid string, idx uint64, state attachv1.SessionStateName) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[uuid] = &sessionState{
		binding: &hypervisorv1.CloneFromImageResponse{
			HostSessionIndex: idx,
			TapName:          tapName(idx),
			GuestIp:          guestAddress(idx),
			OverlayPath:      overlayPath(uuid),
		},
		domain: domainUUID(uuid),
		state:  state,
	}
	if idx >= s.nextIdx {
		s.nextIdx = idx + 1
	}
}

// HasSession reports whether the reference driver is tracking the session. It is
// a test affordance used by the fake-programming code to mirror the real impl's
// NotFound gating without re-implementing the store.
func (s *RefImpl) HasSession(uuid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[uuid]
	return ok
}

// allocIndexLocked hands out the next never-recycled per-host index (D66). The
// caller holds s.mu.
func (s *RefImpl) allocIndexLocked() uint64 {
	s.nextIdx++
	return s.nextIdx
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	hypervisorv1.RegisterHypervisorDriverServiceServer(reg, s)
}

// ReadyState / SuspendedState expose the two §3 state values the seam's
// re-adoption fixtures use, so the external _test package can seed a mirror
// without importing attach.v1 directly. Synthetic fixtures only (D50).
func ReadyState() attachv1.SessionStateName {
	return attachv1.SessionStateName_SESSION_STATE_NAME_READY
}

func SuspendedState() attachv1.SessionStateName {
	return attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
}

// DeltaFramesFor exposes the deterministic synthetic overlay-delta stream for a
// session so the external _test package can program an honest ExportDiskDelta
// responder on a hand-built fake (the negative-test drifted fake). Synthetic
// fixtures only (D50).
func DeltaFramesFor(uuid string) []*hypervisorv1.ExportDiskDeltaResponse {
	return deltaFrames(uuid)
}

// --- deterministic synthetic derivations (D50) ------------------------------
//
// All of the following are obviously-synthetic, deterministic functions of the
// session identity so the reference impl and a fake programmed to the same
// contract observe identically. None contains a real session id, host, or path.

func tapName(idx uint64) string {
	return "dstap-" + decimal(idx)
}

func domainUUID(uuid string) string {
	return "dom-" + uuid
}

func overlayPath(uuid string) string {
	return "/var/lib/dream-serpent/overlays/" + uuid + ".qcow2"
}

func snapshotRef(uuid string) string {
	return "snap-" + uuid
}

// guestAddress derives a deterministic synthetic IPv4 in the TEST-NET-1
// documentation range (192.0.2.0/24, RFC 5737) so the bytes are obviously
// synthetic and never collide with a real guest.
func guestAddress(idx uint64) *hypervisorv1.GuestAddress {
	return &hypervisorv1.GuestAddress{
		Family:  hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4,
		Address: []byte{192, 0, 2, byte(idx % 254)},
	}
}

// deltaFrames returns a short deterministic synthetic overlay-delta stream for a
// session (two frames). Content is derived from the session id, so a fake
// programmed to the same derivation streams byte-identically.
func deltaFrames(uuid string) []*hypervisorv1.ExportDiskDeltaResponse {
	seed := digest(uuid)
	return []*hypervisorv1.ExportDiskDeltaResponse{
		{Offset: 0, Data: seed[:4]},
		{Offset: 4, Data: seed[4:8]},
	}
}

func digest(s string) [32]byte {
	return sha256.Sum256([]byte("ds-synthetic-delta/" + s))
}

func decimal(n uint64) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// sortObservedByIndex orders observed sessions by their never-recycled host
// index so RecoverSessions reports deterministically (the suite compares the
// report shape across real and fake). Insertion sort: the slice is tiny.
func sortObservedByIndex(xs []*hypervisorv1.ObservedSession) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1].GetHostSessionIndex() > xs[j].GetHostSessionIndex(); j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
