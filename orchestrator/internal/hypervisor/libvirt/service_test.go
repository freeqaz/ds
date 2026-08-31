// SPDX-License-Identifier: Apache-2.0

// service_test.go drives the production DriverService over an IN-PROCESS gRPC
// roundtrip — a real generated HypervisorDriverServiceClient against the
// DriverService backed by the seam FAKES (the same fakeAttach/fakeOverlay/
// fakeCA/fakeBooter/fakeGate the create-path tests use, in create_test.go, plus
// the destroy-side fakes below). It mirrors the identity/mint grpc_seam_test.go
// in-process pattern: a loopback grpc server + a dialed client, no live VM /
// libvirt / KVM / sudo (D50 synthetic fixtures, deterministic, OFFLINE).
//
// It asserts: GetCapabilities returns the HONEST libvirt flags (instant-clone +
// disk-delta TRUE, migrate FALSE — the opposite of EC2's all-false); CloneFromImage
// invokes OverlayStore.CreateOverlay and returns tap_name/guest_ip/overlay_path
// idempotently; Destroy invokes the §4.2 teardown idempotently (an unknown
// session succeeds); and the 7 unwired verbs return codes.Unimplemented.
package libvirt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// ── destroy-side seam fakes (the create-side fakes live in create_test.go) ────

// fakeDomainDestroyer records destroyed domains; an empty/absent domain is a
// no-op (the idempotency contract destroy.go's DomainDestroyer states).
type fakeDomainDestroyer struct {
	err       error
	destroyed []string
}

func (f *fakeDomainDestroyer) DestroyDomain(_ context.Context, sessionUUID, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.destroyed = append(f.destroyed, sessionUUID)
	return nil
}

// fakeDurability records finalized durability streams (D29 dirty-bitmap close).
type fakeDurability struct {
	err       error
	finalized []string
}

func (f *fakeDurability) FinalizeDurabilityStream(_ context.Context, sessionUUID, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.finalized = append(f.finalized, sessionUUID)
	return nil
}

// fakeReseedCounter is a recording ReseedableCounter for the recovery tests. It
// is the SAME monotonic logic memCounter has (next index, never returned twice)
// PLUS the forward-only SeedAtLeast advance — so one instance backs BOTH the
// Allocator (as its IndexCounter) and the DriverService (as its reseed handle),
// the way the real host wires one persistent counter into both. handed records
// every index drawn; seededTo records the highest SeedAtLeast target so a test
// can assert the resume point moved forward (and only forward).
type fakeReseedCounter struct {
	mu       sync.Mutex
	next     uint64
	handed   []uint64
	seededTo uint64
}

func (c *fakeReseedCounter) Next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.next
	c.next++
	c.handed = append(c.handed, idx)
	return idx, nil
}

// SeedAtLeast advances the counter so the next Next() yields an index strictly
// greater than highest. Forward-only: a highest at or below the current floor is
// a no-op (the counter never moves backward — never-recycle, D66).
func (c *fakeReseedCounter) SeedAtLeast(highest uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if resume := highest + 1; resume > c.next {
		c.next = resume
	}
	if highest > c.seededTo {
		c.seededTo = highest
	}
}

// handedLen returns the number of indices drawn so far, under the lock so the
// ordering-guard test can read it -race-clean. ZERO means no index was burned.
func (c *fakeReseedCounter) handedLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.handed)
}

// fakeRecoverer is a recording SessionRecoverer: it returns a fixed set of
// host-resident sessions (the synthetic re-observation, D50) and records every
// host_id it was asked about, so a test can assert the verb passed the right
// host_id and that an empty set is a clean no-op. err forces a re-observation
// fault.
type fakeRecoverer struct {
	sessions []RecoveredSession
	err      error
	calls    []string
}

func (f *fakeRecoverer) RecoverSessions(_ context.Context, hostID string) ([]RecoveredSession, error) {
	f.calls = append(f.calls, hostID)
	if f.err != nil {
		return nil, f.err
	}
	return f.sessions, nil
}

// fakeFlowBytes records emitted final byte-count events (non-fatal accounting).
type fakeFlowBytes struct {
	err     error
	emitted []string
}

func (f *fakeFlowBytes) EmitDestroyByteCounts(_ context.Context, sessionUUID string, _ Binding) error {
	if f.err != nil {
		return f.err
	}
	f.emitted = append(f.emitted, sessionUUID)
	return nil
}

// mintRecord captures one MintAttachHandle invocation so a test can assert the
// driver minted from the recorded binding in the requested role.
type mintRecord struct {
	sessionUUID string
	binding     Binding
	role        attachv1.Role
}

// fakeMinter is a DETERMINISTIC recording AttachHandleMinter (D50): it mints a
// synthetic attach.v1 handle for a session+binding+role and records every call.
// The handle is a pure function of (sessionUUID, binding, role) — no clock, no
// randomness — so a retry for the same (session, role) yields a byte-equal
// handle, which is exactly what makes the (session_uuid, role) idempotency
// assertable over the wire. It stands in for the real host-side minter (the
// hostbridge D79 transport endpoint + the identity-D22 per-session auth), which
// lands host-side; the fake keeps the wiring offline + stdlib (no socket, no
// identity service, no live VM).
type fakeMinter struct {
	err   error
	calls []mintRecord
}

func (f *fakeMinter) MintAttachHandle(_ context.Context, sessionUUID string, b Binding, role attachv1.Role) (*attachv1.AttachHandle, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, mintRecord{sessionUUID: sessionUUID, binding: b, role: role})
	// Deterministic synthetic handle: the DIRECT endpoint addresses the session's
	// tap-bound host attachment, the auth token is derived from the session+role,
	// and the expiry is a fixed offset — all pure functions of the inputs so a
	// retry is byte-identical (the (session_uuid, role) idempotency contract).
	return &attachv1.AttachHandle{
		SessionUuid: sessionUUID,
		Endpoints: []*attachv1.EndpointCandidate{{
			Transport:  attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT,
			Address:    "unix:///run/ds/attach/" + b.TapName + ".sock",
			ServerName: "host-agent." + sessionUUID,
		}},
		Auth: &attachv1.AuthMaterial{
			Token:     []byte("attach-token-" + sessionUUID + "-" + role.String()),
			ExpiresAt: 1_700_000_900,
		},
		Role:      role,
		ExpiresAt: 1_700_000_900,
	}, nil
}

// suspendRecord captures one Suspender.Suspend invocation so a test can assert
// the driver passed the right session, the vetted reason, and the provenance
// (carried through for the host-side audit record, D77).
type suspendRecord struct {
	sessionUUID string
	reason      hypervisorv1.SuspendReason
	provenance  *boundaryv1.Provenance
}

// fakeSuspender is a DETERMINISTIC recording Suspender (D50): it tracks per-session
// suspended state and records every Suspend/Resume call so a test can assert the
// driver invoked the seam with the vetted reason+provenance AND that the verbs are
// idempotent. Suspend on an already-suspended session and Resume on an
// already-running session are no-op SUCCESSES (the doc 15 §5.1 idempotency
// contract) — the call is still recorded (so a test sees the retry reached the
// seam) but the state does not double-transition. It stands in for the real
// host-side libvirt domain-suspend/managedsave + resume, which lands host-side;
// the fake keeps the wiring offline + stdlib (no managedsave, no live VM).
type fakeSuspender struct {
	suspendErr error
	resumeErr  error
	suspends   []suspendRecord
	resumes    []string
	// suspended tracks per-session pause state so the idempotency no-op is
	// observable: a second Suspend records the call but finds the session already
	// suspended; a Resume clears it.
	suspended map[string]bool
}

func newFakeSuspender() *fakeSuspender {
	return &fakeSuspender{suspended: make(map[string]bool)}
}

func (f *fakeSuspender) Suspend(_ context.Context, sessionUUID string, reason hypervisorv1.SuspendReason, provenance *boundaryv1.Provenance) error {
	if f.suspendErr != nil {
		return f.suspendErr
	}
	f.suspends = append(f.suspends, suspendRecord{sessionUUID: sessionUUID, reason: reason, provenance: provenance})
	// Idempotent: an already-suspended session is a no-op success (the state does
	// not double-transition; the call is recorded so the retry is observable).
	f.suspended[sessionUUID] = true
	return nil
}

func (f *fakeSuspender) Resume(_ context.Context, sessionUUID string) error {
	if f.resumeErr != nil {
		return f.resumeErr
	}
	f.resumes = append(f.resumes, sessionUUID)
	// Idempotent: an already-running session is a no-op success.
	f.suspended[sessionUUID] = false
	return nil
}

// snapshotRecord captures one SnapshotStore.CreateSnapshot invocation so a test
// can assert the driver passed the right session and the optional label.
type snapshotRecord struct {
	sessionUUID string
	label       string
}

// fakeSnapshotStore is a DETERMINISTIC recording SnapshotStore (D50): it captures
// a synthetic opaque snapshot_ref for a (session, label) and records every call.
// The reference is a pure function of (sessionUUID, label) — no clock, no
// randomness — so a retry for the same (session, label) yields a byte-equal ref,
// which is exactly what makes the (session_uuid, label) idempotency assertable
// over the wire, while a DIFFERENT label yields a DIFFERENT ref (a distinct
// point-in-time). It returns ONLY the opaque ref (no libvirt/qcow2 internal),
// standing in for the real host-side libvirt external-snapshot capture of the
// per-session qcow2 overlay, which lands host-side; the fake keeps the wiring
// offline + stdlib (no qcow2, no live VM).
type fakeSnapshotStore struct {
	err   error
	calls []snapshotRecord
}

func (f *fakeSnapshotStore) CreateSnapshot(_ context.Context, sessionUUID, label string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.calls = append(f.calls, snapshotRecord{sessionUUID: sessionUUID, label: label})
	// Deterministic synthetic opaque reference: a pure function of (session, label)
	// so a retry is byte-identical (the (session_uuid, label) idempotency contract)
	// and a different label is a distinct ref. The shape is an opaque delta handle
	// (overlay/<session>@<label>) — never a libvirt snapshot-XML or a qcow2 path
	// (the zero-leakage invariant, D29/D30).
	return "overlay-delta://" + sessionUUID + "@" + label, nil
}

// deltaRecord captures one DiskDeltaExporter.OpenDelta invocation so a test can
// assert the driver passed the right session and the optional base snapshot ref.
type deltaRecord struct {
	sessionUUID      string
	sinceSnapshotRef string
}

// fakeDiskDeltaExporter is a DETERMINISTIC recording DiskDeltaExporter (D50): it
// yields a SYNTHETIC delta that is a pure function of (sessionUUID,
// sinceSnapshotRef) — no clock, no randomness — so a wire roundtrip can reassemble
// the streamed bytes and assert byte-equality, and a different base ref yields a
// different delta (full vs incremental). It records every call (so a test sees the
// driver invoked the seam with the right args) and tracks whether the reader was
// Closed (the service's Close contract). It stands in for the real host-side
// libvirt dirty-bitmap/qemu-img extraction, which lands host-side; the fake keeps
// the wiring offline + stdlib (no qcow2, no live VM). delta overrides the
// synthetic payload when set (e.g. to exercise multi-chunk framing with a payload
// larger than exportDeltaChunkSize).
type fakeDiskDeltaExporter struct {
	err   error
	delta []byte // when nil, syntheticDelta(session, ref) is used
	calls []deltaRecord
	// closed counts reader Closes so a test can assert the service always closes
	// the reader (success AND cancellation). Reads/Closes happen on the server
	// goroutine; the mutex keeps the post-roundtrip assertion race-clean under -race.
	mu     sync.Mutex
	closed int
}

// syntheticDelta is the deterministic delta the fake yields for a (session, ref):
// a pure function of its inputs so a retry is byte-identical and a different base
// ref is a distinct payload (full overlay vs incremental-since-base). The bytes
// are opaque to the service (zero-leakage: the service only frames offset+bytes).
func syntheticDelta(sessionUUID, sinceSnapshotRef string) []byte {
	return []byte("D29-overlay-delta|session=" + sessionUUID + "|since=" + sinceSnapshotRef + "|<synthetic dirty-bitmap bytes>")
}

func (f *fakeDiskDeltaExporter) OpenDelta(_ context.Context, sessionUUID, sinceSnapshotRef string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, deltaRecord{sessionUUID: sessionUUID, sinceSnapshotRef: sinceSnapshotRef})
	payload := f.delta
	if payload == nil {
		payload = syntheticDelta(sessionUUID, sinceSnapshotRef)
	}
	return &recordingReadCloser{r: bytes.NewReader(payload), owner: f}, nil
}

func (f *fakeDiskDeltaExporter) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// recordingReadCloser wraps a byte reader and bumps the owner's close count on
// Close — so a test can assert the service Closed the reader (the OpenDelta Close
// contract: success, fault, or cancellation).
type recordingReadCloser struct {
	r     io.Reader
	owner *fakeDiskDeltaExporter
}

func (rc *recordingReadCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }

func (rc *recordingReadCloser) Close() error {
	rc.owner.mu.Lock()
	rc.owner.closed++
	rc.owner.mu.Unlock()
	return nil
}

// blockingDeltaExporter yields a reader that emits a first chunk and then BLOCKS
// until the stream context is cancelled — exercising the mid-stream cancellation
// path: the service must observe ctx.Err() between frames, stop, return the ctx
// error, AND Close the reader. It records the Close so the test asserts cleanup
// happened even on cancellation.
type blockingDeltaExporter struct {
	mu     sync.Mutex
	closed int
}

func (f *blockingDeltaExporter) OpenDelta(ctx context.Context, _, _ string) (io.ReadCloser, error) {
	return &blockingReadCloser{ctx: ctx, owner: f, first: []byte("first-chunk-before-the-block")}, nil
}

func (f *blockingDeltaExporter) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// blockingReadCloser returns its first chunk once, then blocks every subsequent
// Read until ctx is Done (returning the ctx error). In practice the service checks
// ctx.Err() BEFORE the second Read and stops there; this reader's block is the
// belt that guarantees the test cannot hang past cancellation even if it didn't.
type blockingReadCloser struct {
	ctx   context.Context
	owner *blockingDeltaExporter
	first []byte
	sent  bool
}

func (rc *blockingReadCloser) Read(p []byte) (int, error) {
	if !rc.sent {
		rc.sent = true
		n := copy(p, rc.first)
		return n, nil
	}
	<-rc.ctx.Done()
	return 0, rc.ctx.Err()
}

func (rc *blockingReadCloser) Close() error {
	rc.owner.mu.Lock()
	rc.owner.closed++
	rc.owner.mu.Unlock()
	return nil
}

// serviceFakes bundles the seam fakes so a test can reach into them after the
// wire roundtrip to assert the driver actually invoked the seams.
type serviceFakes struct {
	attach  *fakeAttach
	overlay *fakeOverlay
	ca      *fakeCA
	booter  *fakeBooter
	gate    *fakeGate
	domain  *fakeDomainDestroyer
	durab   *fakeDurability
	flow    *fakeFlowBytes
}

// newTestDriverService builds a DriverService over fresh seam fakes (acked +
// fresh gate so the happy path is routable) and returns the fakes for assertion.
func newTestDriverService(t *testing.T) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverService(host, destroyer)
	if err != nil {
		t.Fatalf("NewDriverService: %v", err)
	}
	return svc, f
}

// recoveryFakes bundles the recovery-side fakes (the seam fakes plus the shared
// counter and the recoverer) so a recovery test can reach into them after the
// wire roundtrip.
type recoveryFakes struct {
	*serviceFakes
	counter   *fakeReseedCounter
	recoverer *fakeRecoverer
}

// newTestDriverServiceWithRecovery builds a recovery-WIRED DriverService: the
// create path and the DriverService share ONE fakeReseedCounter (the way the
// real host wires one persistent counter into both the Allocator and the reseed
// handle), and the supplied recoverer drives RecoverSessions. recovered is the
// host-resident set the recoverer reports.
func newTestDriverServiceWithRecovery(t *testing.T, recovered []RecoveredSession) (*DriverService, *recoveryFakes) {
	t.Helper()
	sf := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	counter := &fakeReseedCounter{}
	recoverer := &fakeRecoverer{sessions: recovered}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	// The SAME counter instance backs the Allocator (as IndexCounter) and the
	// service (as ReseedableCounter) — so a re-seed advances the very counter the
	// next clone's Allocate() draws from.
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, sf.attach, sf.overlay, sf.ca, sf.booter, sf.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(sf.domain, sf.attach, sf.overlay, sf.durab, sf.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithRecovery(host, destroyer, recoverer, counter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithRecovery: %v", err)
	}
	return svc, &recoveryFakes{serviceFakes: sf, counter: counter, recoverer: recoverer}
}

// newTestDriverServiceWithAttach builds an ATTACH-WIRED DriverService: the create
// path over fresh seam fakes (acked + fresh gate so a clone is routable) plus the
// supplied AttachHandleMinter wired into IssueAttachHandle. It returns the seam
// fakes and the minter so a test can clone a session, mint its handle over the
// wire, and assert what the driver passed the minter.
func newTestDriverServiceWithAttach(t *testing.T, minter AttachHandleMinter) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithAttach(host, destroyer, nil, nil, minter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithAttach: %v", err)
	}
	return svc, f
}

// newTestDriverServiceWithSuspend builds a SUSPEND-WIRED DriverService: the create
// path over fresh seam fakes (acked + fresh gate so a clone is routable) plus the
// supplied Suspender wired into Suspend + Resume. It returns the seam fakes so a
// test can clone a session, pause/restore it over the wire, and assert what the
// driver passed the seam.
func newTestDriverServiceWithSuspend(t *testing.T, suspender Suspender) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithSuspend(host, destroyer, nil, nil, nil, suspender)
	if err != nil {
		t.Fatalf("NewDriverServiceWithSuspend: %v", err)
	}
	return svc, f
}

// newTestDriverServiceWithSnapshot builds a SNAPSHOT-WIRED DriverService: the
// create path over fresh seam fakes (acked + fresh gate so a clone is routable)
// plus the supplied SnapshotStore wired into Snapshot. It returns the seam fakes
// so a test can clone a session, capture its overlay over the wire, and assert
// what the driver passed the seam.
func newTestDriverServiceWithSnapshot(t *testing.T, snapshots SnapshotStore) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithSnapshot(host, destroyer, nil, nil, nil, nil, snapshots)
	if err != nil {
		t.Fatalf("NewDriverServiceWithSnapshot: %v", err)
	}
	return svc, f
}

// newTestDriverServiceWithDiskDelta builds a DISK-DELTA-WIRED DriverService: the
// create path over fresh seam fakes (acked + fresh gate so a clone is routable)
// plus the supplied DiskDeltaExporter wired into ExportDiskDelta. It returns the
// seam fakes so a test can clone a session, stream its overlay delta over the
// wire, and assert what the driver passed the seam.
func newTestDriverServiceWithDiskDelta(t *testing.T, exporter DiskDeltaExporter) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithDiskDelta(host, destroyer, nil, nil, nil, nil, nil, exporter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithDiskDelta: %v", err)
	}
	return svc, f
}

// newTestDriverServiceWithSnapshotAndDiskDelta builds a DriverService with BOTH
// the SnapshotStore (Snapshot) AND the DiskDeltaExporter (ExportDiskDelta) wired
// over the same create path — the full D29 capture→export loop on one service: a
// test can clone a session, capture a snapshot_ref over the wire, then export the
// delta SINCE that captured ref and assert the registry let the incremental export
// through (and rejected an unknown base). It returns the seam fakes so a test can
// assert what the driver passed each seam.
func newTestDriverServiceWithSnapshotAndDiskDelta(t *testing.T, snapshots SnapshotStore, exporter DiskDeltaExporter) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithDiskDelta(host, destroyer, nil, nil, nil, nil, snapshots, exporter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithDiskDelta: %v", err)
	}
	return svc, f
}

// drainDelta runs the ExportDiskDelta server-streaming roundtrip to completion and
// returns the REASSEMBLED delta bytes, after asserting every frame's offset is
// monotonic + contiguous (frame N's offset == the running byte count of all prior
// frames). A non-nil error from Recv that is not io.EOF is returned to the caller.
func drainDelta(t *testing.T, stream hypervisorv1.HypervisorDriverService_ExportDiskDeltaClient) ([]byte, error) {
	t.Helper()
	var reassembled []byte
	var want uint64
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return reassembled, nil
		}
		if err != nil {
			return reassembled, err
		}
		if frame.GetOffset() != want {
			t.Fatalf("frame offset = %d, want %d (offsets must be monotonic + contiguous)", frame.GetOffset(), want)
		}
		reassembled = append(reassembled, frame.GetData()...)
		want += uint64(len(frame.GetData()))
	}
}

// recoveredAt builds a synthetic RecoveredSession for an index over the test
// address plan (subnet 10.42.0.0/16, HostOffset 2 — index i → 10.42.0.(2+i)),
// so a recovered binding matches exactly what the Allocator would have derived
// for that index. D50 synthetic, deterministic.
func recoveredAt(t *testing.T, sessionUUID string, index uint64) RecoveredSession {
	t.Helper()
	gip, err := (AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}).guestIP(index)
	if err != nil {
		t.Fatalf("guestIP(%d): %v", index, err)
	}
	return RecoveredSession{
		SessionUUID: sessionUUID,
		DomainUUID:  "domain-" + sessionUUID,
		Binding: Binding{
			HostSessionIndex: index,
			TapName:          tapName(index),
			GuestIP:          gip,
			OverlayPath:      "/var/lib/ds/overlays/" + sessionUUID + ".qcow2",
		},
	}
}

// dialInProcess registers the DriverService on a loopback grpc server and returns
// the real generated client over a dialed connection — the identity/mint
// grpc_seam_test.go pattern. Everything is torn down via t.Cleanup.
func dialInProcess(t *testing.T, svc *DriverService) hypervisorv1.HypervisorDriverServiceClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	hypervisorv1.RegisterHypervisorDriverServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return hypervisorv1.NewHypervisorDriverServiceClient(conn)
}

const testCloneSession = "00000000-0000-4000-8000-0000000000c1"

func cloneReq(session string) *hypervisorv1.CloneFromImageRequest {
	return &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{
			SessionUuid:         session,
			ImageId:             "img-content-addressed",
			EntrypointConfigRef: "entrypoint-ref",
			Material:            &hypervisorv1.SessionMaterial{CaBundleRef: "ca-bundle-ref"},
		},
	}
}

// TestGetCapabilitiesHonestLibvirtFlags drives GetCapabilities over the wire and
// asserts the HONEST libvirt answer — instant-clone TRUE (overlay external
// snapshots, D29), disk-delta-export TRUE (dirty-bitmap, D29), migrate FALSE
// (M3) — the deliberate opposite of the EC2 demo driver's all-false honesty test.
func TestGetCapabilitiesHonestLibvirtFlags(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)

	resp, err := client.GetCapabilities(context.Background(), &hypervisorv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	caps := resp.GetCapabilities()
	if caps == nil {
		t.Fatal("nil Capabilities")
	}
	if !caps.GetSupportsInstantClone() {
		t.Error("libvirt supports_instant_clone must be TRUE (per-session qcow2 overlay via external snapshots, D29) — not EC2's false")
	}
	if !caps.GetSupportsDiskDeltaExport() {
		t.Error("libvirt supports_disk_delta_export must be TRUE (qcow2 dirty-bitmap delta, D29) — not EC2's false")
	}
	if caps.GetSupportsMigrate() {
		t.Error("libvirt supports_migrate must be FALSE for v0 (migration is M3; Migrate returns Unimplemented) — claiming it would fail the capability-honesty test")
	}
}

// TestCloneFromImageWiresOverlayAndBinding drives CloneFromImage over the wire and
// asserts it invoked OverlayStore.CreateOverlay and returned the recorded binding
// (host_session_index / tap_name / guest_ip / overlay_path), with the guest IP
// carried as the D75 family-tagged GuestAddress (IPv4, 4 bytes).
func TestCloneFromImageWiresOverlayAndBinding(t *testing.T) {
	svc, f := newTestDriverService(t)
	client := dialInProcess(t, svc)

	resp, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	// The overlay seam was invoked (the create spine reached step 7).
	if len(f.overlay.disposed) != 0 {
		t.Errorf("happy-path clone must not dispose the overlay, disposed=%v", f.overlay.disposed)
	}
	if len(f.ca.injected) != 1 {
		t.Errorf("clone must inject the interception CA once (fail-closed, D17), injected=%d", len(f.ca.injected))
	}
	if len(f.booter.booted) != 1 {
		t.Errorf("clone must boot once, booted=%d", len(f.booter.booted))
	}

	// The response carries the recorded binding (the tap-create RACI artifact).
	if resp.GetTapName() != "dstap-0" {
		t.Errorf("tap_name = %q, want dstap-0 (the first never-recycled index, D66)", resp.GetTapName())
	}
	if resp.GetOverlayPath() == "" {
		t.Error("overlay_path empty — CloneFromImage must return the OverlayStore.CreateOverlay path (D29)")
	}
	gip := resp.GetGuestIp()
	if gip == nil {
		t.Fatal("nil guest_ip")
	}
	if gip.GetFamily() != hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4 {
		t.Errorf("guest_ip family = %v, want IPV4 (D75 family-tagged)", gip.GetFamily())
	}
	if len(gip.GetAddress()) != 4 {
		t.Errorf("guest_ip address = %d bytes, want 4 (IPv4, never fixed32, D75)", len(gip.GetAddress()))
	}
	// index 0 over subnet 10.42.0.0/16 with HostOffset 2 → 10.42.0.2.
	if got, want := netip.AddrFrom4([4]byte(gip.GetAddress())).String(), "10.42.0.2"; got != want {
		t.Errorf("guest_ip = %s, want %s (base + HostOffset + index)", got, want)
	}
}

// TestCloneFromImageIdempotentOnSessionUUID drives two clones for the SAME
// session over the wire and asserts the second returns the SAME binding without
// burning a second never-recycled index (D66) — the verb-level idempotency the
// service enforces at the clone cache.
func TestCloneFromImageIdempotentOnSessionUUID(t *testing.T) {
	svc, f := newTestDriverService(t)
	client := dialInProcess(t, svc)

	first, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage(first): %v", err)
	}
	second, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage(retry): %v", err)
	}

	if first.GetHostSessionIndex() != second.GetHostSessionIndex() {
		t.Errorf("retry forked a new index: %d vs %d (must be idempotent on session_uuid, D66)", first.GetHostSessionIndex(), second.GetHostSessionIndex())
	}
	if first.GetTapName() != second.GetTapName() {
		t.Errorf("retry forked a new tap: %q vs %q", first.GetTapName(), second.GetTapName())
	}
	// The retry must NOT have re-run the create spine (no second boot/overlay).
	if len(f.booter.booted) != 1 {
		t.Errorf("idempotent retry must not re-boot: booted=%d, want 1", len(f.booter.booted))
	}
}

// TestCloneFromImageRejectsMissingSession asserts a clone with no session_uuid is
// an InvalidArgument (the idempotency key is required), carried as a gRPC status.
func TestCloneFromImageRejectsMissingSession(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)

	_, err := client.CloneFromImage(context.Background(), &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{ImageId: "img", Material: &hypervisorv1.SessionMaterial{CaBundleRef: "ca"}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestCloneFromImageMissingCABundleRefFailsClosed asserts a clone with no CA
// bundle ref is refused (step-7 injection is fail-closed, D17) — the create
// spine's pre-step-4 refusal maps to InvalidArgument over the wire, NOT a faked
// success.
func TestCloneFromImageMissingCABundleRefFailsClosed(t *testing.T) {
	svc, f := newTestDriverService(t)
	client := dialInProcess(t, svc)

	_, err := client.CloneFromImage(context.Background(), &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: testCloneSession, ImageId: "img"}, // no Material → no ca_bundle_ref
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing ca_bundle_ref: code = %v, want InvalidArgument (fail-closed, D17)", status.Code(err))
	}
	// Fail-closed before boot.
	if len(f.booter.booted) != 0 {
		t.Error("a fail-closed clone must not boot (D17)")
	}
}

// TestCloneFromImageNonRoutableStillReturnsBinding asserts a booted-but-not-
// routable result (the step-9 policy-stale case) is NOT a wire error — the
// binding is recorded and CloneFromImageResponse carries it (the frozen §4.1
// precedence: binding recorded before the routable verdict).
func TestCloneFromImageNonRoutableStillReturnsBinding(t *testing.T) {
	svc, f := newTestDriverService(t)
	f.gate.acked = true
	f.gate.fresh = false // host policy stale → step-9 non-routable
	client := dialInProcess(t, svc)

	resp, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("non-routable clone must still return the recorded binding, not an error: %v", err)
	}
	if resp.GetTapName() != "dstap-0" || resp.GetOverlayPath() == "" {
		t.Errorf("non-routable clone must carry the recorded binding: tap=%q overlay=%q", resp.GetTapName(), resp.GetOverlayPath())
	}
	// The domain DID boot (step 8 ran) even though it's not routable.
	if len(f.booter.booted) != 1 {
		t.Errorf("step-9 non-routable means the domain still booted: booted=%d", len(f.booter.booted))
	}
}

// TestDestroyWiresTeardown drives Destroy over the wire and asserts it invoked
// the §4.2 unconditional flush_session teardown.
func TestDestroyWiresTeardown(t *testing.T) {
	svc, f := newTestDriverService(t)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// The UNCONDITIONAL flush ran (D68) — the §4.2 teardown's load-bearing step.
	if len(f.attach.flushed) != 1 || f.attach.flushed[0] != testCloneSession {
		t.Errorf("Destroy must invoke the unconditional flush_session(legs=all) (D68), flushed=%v", f.attach.flushed)
	}
}

// TestDestroyUnknownSessionSucceeds asserts a Destroy of an unknown / already-gone
// session SUCCEEDS (idempotent on session_uuid) — an absent domain is a no-op
// destroy, the flush is unconditional and converges. This is the retry-after-blip
// re-adoption contract (doc 15 §5.1).
func TestDestroyUnknownSessionSucceeds(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: "never-cloned-session"}); err != nil {
		t.Fatalf("Destroy of an unknown session must succeed (idempotent), got: %v", err)
	}
	// A second destroy of the same session also converges.
	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: "never-cloned-session"}); err != nil {
		t.Fatalf("repeat Destroy must converge (idempotent on session_uuid): %v", err)
	}
}

// TestDestroyRejectsMissingSession asserts a Destroy with no session_uuid is an
// InvalidArgument (the teardown idempotency key is required).
func TestDestroyRejectsMissingSession(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)

	_, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestCloneThenDestroyThenReclone asserts the destroy drops the clone cache so a
// re-clone of the SAME session_uuid re-allocates honestly (a fresh never-recycled
// index, D66) rather than returning the torn-down session's stale binding.
func TestCloneThenDestroyThenReclone(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	first, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage(first): %v", err)
	}
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	second, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("CloneFromImage(re-clone after destroy): %v", err)
	}
	if first.GetHostSessionIndex() == second.GetHostSessionIndex() {
		t.Errorf("re-clone after destroy must draw a FRESH never-recycled index (D66), both = %d", first.GetHostSessionIndex())
	}
}

// TestUnwiredVerbsReturnUnimplemented drives each of the 7 unwired verbs over the
// wire and asserts codes.Unimplemented — an honest stub, never a faked success
// (doc 15 §5.1: driver honesty bounded by the capability flags + conformance).
// IssueAttachHandle is unwired HERE because newTestDriverService supplies no
// AttachHandleMinter (the minter-nil ⇒ Unimplemented posture); the attach-wired
// path is exercised by the TestIssueAttachHandle* tests below. Suspend/Resume are
// likewise unwired HERE (no Suspender ⇒ the nil-suspender Unimplemented posture);
// the suspend-wired path is exercised by the TestSuspend*/TestResume* tests below.
func TestUnwiredVerbsReturnUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)
	ctx := context.Background()
	s := testCloneSession

	unary := []struct {
		name string
		call func() error
	}{
		{"IssueAttachHandle", func() error {
			_, err := client.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{SessionUuid: s})
			return err
		}},
		{"Snapshot", func() error {
			_, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: s})
			return err
		}},
		{"Suspend", func() error {
			_, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{SessionUuid: s})
			return err
		}},
		{"Resume", func() error {
			_, err := client.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: s})
			return err
		}},
		{"Migrate", func() error {
			_, err := client.Migrate(ctx, &hypervisorv1.MigrateRequest{SessionUuid: s})
			return err
		}},
		{"RecoverSessions", func() error {
			_, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{})
			return err
		}},
	}
	for _, tc := range unary {
		if code := status.Code(tc.call()); code != codes.Unimplemented {
			t.Errorf("%s: code = %v, want Unimplemented (honest stub, never a faked success)", tc.name, code)
		}
	}

	// ExportDiskDelta is server-streaming: the Unimplemented surfaces on the first
	// Recv (the server returns the status before sending any chunk).
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: s})
	if err == nil {
		_, err = stream.Recv()
	}
	if code := status.Code(err); code != codes.Unimplemented {
		t.Errorf("ExportDiskDelta: code = %v, want Unimplemented", code)
	}
}

// TestIssueAttachHandleMintsForClonedSession clones a session, then drives
// IssueAttachHandle over the wire and asserts the minted attach.v1 handle carries
// the requested role, a reachable DIRECT endpoint candidate, and a whole-handle
// expiry (doc 15 §5.4 / D79) — and that the driver minted FROM the cloned
// session's recorded binding (the tap-bound host attachment).
func TestIssueAttachHandleMintsForClonedSession(t *testing.T) {
	minter := &fakeMinter{}
	svc, _ := newTestDriverServiceWithAttach(t, minter)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// The session must exist: clone it first (its binding is the artifact the
	// handle is issued for).
	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	resp, err := client.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
		SessionUuid: testCloneSession,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if err != nil {
		t.Fatalf("IssueAttachHandle: %v", err)
	}

	handle := resp.GetHandle()
	if handle == nil {
		t.Fatal("nil handle")
	}
	if handle.GetSessionUuid() != testCloneSession {
		t.Errorf("handle session_uuid = %q, want %q", handle.GetSessionUuid(), testCloneSession)
	}
	if handle.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Errorf("handle role = %v, want ROLE_WRITER (the requested D61 seat class)", handle.GetRole())
	}
	if handle.GetExpiresAt() == 0 {
		t.Error("handle expires_at = 0 — the handle must carry a whole-handle expiry (doc 15 §5.4)")
	}
	eps := handle.GetEndpoints()
	if len(eps) != 1 {
		t.Fatalf("handle endpoints = %d, want 1 (the M0 DIRECT candidate)", len(eps))
	}
	if eps[0].GetTransport() != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT {
		t.Errorf("endpoint transport = %v, want DIRECT (M0 client->host-agent)", eps[0].GetTransport())
	}
	if eps[0].GetAddress() == "" {
		t.Error("endpoint address empty — the DIRECT candidate must name a reachable attach endpoint")
	}
	if handle.GetAuth() == nil || len(handle.GetAuth().GetToken()) == 0 {
		t.Error("handle auth empty — the handle must carry short-lived session-scoped auth (D39)")
	}

	// The driver minted exactly once, from the cloned session's recorded binding in
	// the requested role.
	if len(minter.calls) != 1 {
		t.Fatalf("minter calls = %d, want 1", len(minter.calls))
	}
	call := minter.calls[0]
	if call.sessionUUID != testCloneSession {
		t.Errorf("minted for session %q, want %q", call.sessionUUID, testCloneSession)
	}
	if call.role != attachv1.Role_ROLE_WRITER {
		t.Errorf("minted with role %v, want ROLE_WRITER", call.role)
	}
	// index 0 over the test plan → tap dstap-0 (the recorded binding the handle is
	// minted from, not a fresh/empty one).
	if call.binding.TapName != "dstap-0" {
		t.Errorf("minted from binding tap %q, want dstap-0 (the cloned session's recorded binding)", call.binding.TapName)
	}
	if call.binding.HostSessionIndex != 0 {
		t.Errorf("minted from binding index %d, want 0", call.binding.HostSessionIndex)
	}
}

// TestIssueAttachHandleUnknownSessionNotFound asserts IssueAttachHandle for a
// session that never cloned is codes.NotFound — you cannot mint a handle to a
// session with no recorded binding (never a faked handle).
func TestIssueAttachHandleUnknownSessionNotFound(t *testing.T) {
	minter := &fakeMinter{}
	svc, _ := newTestDriverServiceWithAttach(t, minter)
	client := dialInProcess(t, svc)

	_, err := client.IssueAttachHandle(context.Background(), &hypervisorv1.IssueAttachHandleRequest{
		SessionUuid: "00000000-0000-4000-8000-00000000dead",
		Role:        attachv1.Role_ROLE_READER,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: code = %v, want NotFound", status.Code(err))
	}
	if len(minter.calls) != 0 {
		t.Errorf("minter must not be called for an unknown session, calls=%d", len(minter.calls))
	}
}

// TestIssueAttachHandleEmptySessionInvalidArgument asserts an empty session_uuid
// is codes.InvalidArgument (the lookup key is required) — even with a minter
// wired, the precondition is checked before the mint.
func TestIssueAttachHandleEmptySessionInvalidArgument(t *testing.T) {
	minter := &fakeMinter{}
	svc, _ := newTestDriverServiceWithAttach(t, minter)
	client := dialInProcess(t, svc)

	_, err := client.IssueAttachHandle(context.Background(), &hypervisorv1.IssueAttachHandleRequest{
		Role: attachv1.Role_ROLE_WRITER,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(minter.calls) != 0 {
		t.Errorf("minter must not be called for an empty session, calls=%d", len(minter.calls))
	}
}

// TestIssueAttachHandleIdempotentOnSessionRole clones a session and mints its
// handle TWICE for the SAME role over the wire, asserting the two handles are
// equivalent (a deterministic minter ⇒ idempotent on (session_uuid, role), doc 15
// §5.4) — a retry re-issues, never forks a second conflicting seat.
func TestIssueAttachHandleIdempotentOnSessionRole(t *testing.T) {
	minter := &fakeMinter{}
	svc, _ := newTestDriverServiceWithAttach(t, minter)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	req := &hypervisorv1.IssueAttachHandleRequest{SessionUuid: testCloneSession, Role: attachv1.Role_ROLE_WRITER}
	first, err := client.IssueAttachHandle(ctx, req)
	if err != nil {
		t.Fatalf("IssueAttachHandle(first): %v", err)
	}
	second, err := client.IssueAttachHandle(ctx, req)
	if err != nil {
		t.Fatalf("IssueAttachHandle(retry): %v", err)
	}

	// Equivalent handles: same role, same endpoints, same expiry, same auth token —
	// a retried mint for the same (session, role) converges (proto-equal over the
	// wire).
	if !proto.Equal(first.GetHandle(), second.GetHandle()) {
		t.Errorf("retry forked a non-equivalent handle:\n first=%v\nsecond=%v", first.GetHandle(), second.GetHandle())
	}
}

// TestIssueAttachHandleSurfacesMintFault asserts a minter fault is surfaced as a
// gRPC error (codes.Internal) — a real host-side mint failure the caller
// re-drives, not a faked handle.
func TestIssueAttachHandleSurfacesMintFault(t *testing.T) {
	minter := &fakeMinter{err: errors.New("identity-D22 auth mint failed")}
	svc, _ := newTestDriverServiceWithAttach(t, minter)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	_, err := client.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
		SessionUuid: testCloneSession,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("mint fault: code = %v, want Internal", status.Code(err))
	}
}

// recoverSession is the synthetic recovered-session UUID family (D50).
const (
	recoverSessionA = "00000000-0000-4000-8000-0000000000a1"
	recoverSessionB = "00000000-0000-4000-8000-0000000000b2"
)

// TestRecoverSessionsReseedsAllocatorPastHighestIndex drives RecoverSessions over
// the wire for a host with two resident sessions at indices 3 and 7, then asserts
// the next CloneFromImage draws an index STRICTLY PAST the highest recovered one
// (7 → next is 8, never a re-handed 3/7) — the newMemCounter resume point, so
// re-adoption never re-hands a live index (D66 never-recycle).
func TestRecoverSessionsReseedsAllocatorPastHighestIndex(t *testing.T) {
	recovered := []RecoveredSession{
		recoveredAt(t, recoverSessionA, 3),
		recoveredAt(t, recoverSessionB, 7), // highest
	}
	svc, f := newTestDriverServiceWithRecovery(t, recovered)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	resp, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"})
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(resp.GetSessions()) != 2 {
		t.Fatalf("RecoverSessions returned %d observed sessions, want 2", len(resp.GetSessions()))
	}
	if f.counter.seededTo != 7 {
		t.Errorf("counter seeded to %d, want 7 (the highest recovered index)", f.counter.seededTo)
	}

	// The next clone for a NEW session must draw index 8 — strictly past 7. A
	// re-handed 3 or 7 would collide with a live session (D66 violation).
	cloned, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("post-recover CloneFromImage(new session): %v", err)
	}
	if got := cloned.GetHostSessionIndex(); got != 8 {
		t.Errorf("post-recover Allocate handed index %d, want 8 (strictly past the highest recovered index 7, D66)", got)
	}
	if cloned.GetTapName() != "dstap-8" {
		t.Errorf("post-recover tap = %q, want dstap-8", cloned.GetTapName())
	}
}

// TestRecoverSessionsReseedsCloneCache drives RecoverSessions then a
// CloneFromImage for a RECOVERED session, and asserts the clone returns the
// ADOPTED binding (same index/tap/guest-ip/overlay) WITHOUT a fresh Allocate or a
// re-run of the create spine — no second never-recycled index burned (D66). This
// is the load-bearing crash-retry contract: a retried clone after a restart
// re-adopts rather than duplicates.
func TestRecoverSessionsReseedsCloneCache(t *testing.T) {
	rec := recoveredAt(t, recoverSessionA, 5)
	svc, f := newTestDriverServiceWithRecovery(t, []RecoveredSession{rec})
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// A retried clone for the recovered session re-adopts the staged binding.
	resp, err := client.CloneFromImage(ctx, cloneReq(recoverSessionA))
	if err != nil {
		t.Fatalf("post-recover CloneFromImage(recovered session): %v", err)
	}
	if got := resp.GetHostSessionIndex(); got != 5 {
		t.Errorf("re-adopted index = %d, want 5 (the recovered index, not a fresh one)", got)
	}
	if resp.GetTapName() != tapName(5) {
		t.Errorf("re-adopted tap = %q, want %q", resp.GetTapName(), tapName(5))
	}
	if resp.GetOverlayPath() != rec.Binding.OverlayPath {
		t.Errorf("re-adopted overlay = %q, want %q", resp.GetOverlayPath(), rec.Binding.OverlayPath)
	}
	wantGIP, _ := rec.Binding.GuestIP.Addr()
	if gotGIP := netip.AddrFrom4([4]byte(resp.GetGuestIp().GetAddress())); gotGIP != wantGIP {
		t.Errorf("re-adopted guest_ip = %s, want %s", gotGIP, wantGIP)
	}

	// NO fresh index was drawn (the counter never advanced past the seed) and the
	// create spine never ran — the re-adoption short-circuited at the cache.
	if len(f.counter.handed) != 0 {
		t.Errorf("re-adoption must NOT draw a fresh index (D66): counter handed %v", f.counter.handed)
	}
	if len(f.booter.booted) != 0 {
		t.Errorf("re-adoption must NOT re-run the create spine: booted=%v", f.booter.booted)
	}
}

// TestRecoverSessionsEmptySetIsCleanNoOp asserts a fresh host (nothing resident)
// is a clean no-op: an empty observed set, the counter is not advanced (the very
// first clone still draws index 0), and the cache is untouched. Re-invocation
// converges (idempotent on a fresh host).
func TestRecoverSessionsEmptySetIsCleanNoOp(t *testing.T) {
	svc, f := newTestDriverServiceWithRecovery(t, nil) // fresh host: nothing resident
	client := dialInProcess(t, svc)
	ctx := context.Background()

	resp, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "fresh-host"})
	if err != nil {
		t.Fatalf("RecoverSessions(fresh host): %v", err)
	}
	if len(resp.GetSessions()) != 0 {
		t.Errorf("fresh host must observe 0 sessions, got %d", len(resp.GetSessions()))
	}
	if f.counter.seededTo != 0 || f.counter.next != 0 {
		t.Errorf("fresh-host recover must not advance the counter: seededTo=%d next=%d", f.counter.seededTo, f.counter.next)
	}

	// Re-invocation converges (still empty, still no-op).
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "fresh-host"}); err != nil {
		t.Fatalf("RecoverSessions(re-invoke): %v", err)
	}

	// The very first clone on a fresh host still draws index 0 (the counter was
	// never moved).
	cloned, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("post-recover CloneFromImage: %v", err)
	}
	if got := cloned.GetHostSessionIndex(); got != 0 {
		t.Errorf("first clone after a fresh-host recover must draw index 0, got %d", got)
	}
}

// TestRecoverSessionsIdempotentOnReInvocation asserts re-running RecoverSessions
// over an UNCHANGED resident set converges: the second pass re-seeds the same
// adopted bindings (SeedAtLeast is forward-only, the cache re-seed is idempotent),
// and a recovered session still re-adopts its index — no second index burned, the
// counter never moved backward.
func TestRecoverSessionsIdempotentOnReInvocation(t *testing.T) {
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, 4)}
	svc, f := newTestDriverServiceWithRecovery(t, recovered)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
			t.Fatalf("RecoverSessions(pass %d): %v", i, err)
		}
	}
	// The counter floor stayed at 4 across all passes (forward-only; never moved
	// backward, never double-advanced).
	if f.counter.seededTo != 4 {
		t.Errorf("seededTo = %d after repeated recover, want a stable 4 (forward-only)", f.counter.seededTo)
	}

	// The recovered session still re-adopts (cache survived the re-seeds), and a
	// NEW session draws the next strictly-past index 5.
	adopt, err := client.CloneFromImage(ctx, cloneReq(recoverSessionA))
	if err != nil {
		t.Fatalf("post-recover re-adopt: %v", err)
	}
	if adopt.GetHostSessionIndex() != 4 {
		t.Errorf("re-adopted index = %d, want 4", adopt.GetHostSessionIndex())
	}
	fresh, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("post-recover new clone: %v", err)
	}
	if fresh.GetHostSessionIndex() != 5 {
		t.Errorf("new clone after recover drew index %d, want 5 (strictly past the recovered 4)", fresh.GetHostSessionIndex())
	}
	if len(f.booter.booted) != 1 {
		t.Errorf("only the NEW session should have booted, booted=%v", f.booter.booted)
	}
}

// TestRecoverSessionsRequiresHostID asserts a recover with no host_id is an
// InvalidArgument (the host whose resident sessions to re-observe is required).
func TestRecoverSessionsRequiresHostID(t *testing.T) {
	svc, _ := newTestDriverServiceWithRecovery(t, nil)
	client := dialInProcess(t, svc)

	_, err := client.RecoverSessions(context.Background(), &hypervisorv1.RecoverSessionsRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing host_id: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestRecoverSessionsUnwiredReturnsUnimplemented asserts a service built WITHOUT a
// recoverer (the NewDriverService path) answers RecoverSessions with an honest
// codes.Unimplemented — the same host-side-only posture as the other unwired
// verbs; never a faked success.
func TestRecoverSessionsUnwiredReturnsUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t) // no recovery wired
	client := dialInProcess(t, svc)

	_, err := client.RecoverSessions(context.Background(), &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unwired RecoverSessions: code = %v, want Unimplemented", status.Code(err))
	}
}

// TestRecoverSessionsSurfacesReObservationFault asserts a re-observation fault
// (the host-resident enumeration failed) maps to a gRPC error so the reconciler
// re-drives — and the Allocator/cache are left untouched (re-seeding from a failed
// observation could re-hand a live index).
func TestRecoverSessionsSurfacesReObservationFault(t *testing.T) {
	svc, f := newTestDriverServiceWithRecovery(t, nil)
	f.recoverer.err = context.DeadlineExceeded
	client := dialInProcess(t, svc)

	_, err := client.RecoverSessions(context.Background(), &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("re-observation fault: code = %v, want Internal", status.Code(err))
	}
	// The counter was never advanced by a failed observation.
	if f.counter.seededTo != 0 || f.counter.next != 0 {
		t.Errorf("a failed recover must not advance the counter: seededTo=%d next=%d", f.counter.seededTo, f.counter.next)
	}
}

// TestRecoverSessionsRejectsMalformedBinding asserts a recovered binding whose
// keys disagree (tap name not matching its index) is rejected — a malformed
// binding can never satisfy three-keys-agree, so re-adopting it would strand
// state. The counter is left untouched.
func TestRecoverSessionsRejectsMalformedBinding(t *testing.T) {
	bad := RecoveredSession{
		SessionUUID: recoverSessionA,
		Binding: Binding{
			HostSessionIndex: 3,
			TapName:          "dstap-99", // disagrees with index 3
			GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 42, 0, 5}},
		},
	}
	svc, f := newTestDriverServiceWithRecovery(t, []RecoveredSession{bad})
	client := dialInProcess(t, svc)

	_, err := client.RecoverSessions(context.Background(), &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("malformed recovered binding: code = %v, want Internal", status.Code(err))
	}
	if f.counter.seededTo != 0 {
		t.Errorf("a rejected recover must not advance the counter: seededTo=%d", f.counter.seededTo)
	}
}

// TestNewDriverServiceWithRecoveryRequiresLockstepWiring asserts the recovery
// wiring is all-or-nothing: a recoverer without the shared counter (or vice
// versa) is a programming error surfaced at construction — a recoverer without
// the counter could not re-seed the Allocator (it would burn a second index on
// the next clone, D66).
func TestNewDriverServiceWithRecoveryRequiresLockstepWiring(t *testing.T) {
	_, f := newTestDriverService(t)
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	counter := &fakeReseedCounter{}
	alloc, _ := NewAllocator(counter, plan)
	host, _ := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	destroyer, _ := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)

	if _, err := NewDriverServiceWithRecovery(host, destroyer, &fakeRecoverer{}, nil); err == nil {
		t.Error("a recoverer without the shared counter must be rejected (cannot re-seed the Allocator, D66)")
	}
	if _, err := NewDriverServiceWithRecovery(host, destroyer, nil, counter); err == nil {
		t.Error("a counter without a recoverer must be rejected (nothing to observe)")
	}
	// Both nil is the no-recovery path (NewDriverService) — that is valid.
	if _, err := NewDriverServiceWithRecovery(host, destroyer, nil, nil); err != nil {
		t.Errorf("the no-recovery path (both nil) must construct: %v", err)
	}
}

// TestCloneBeforeRecoverGatedOnRecoveryWiredService asserts the recover-before-
// serve precondition (D66, option (a) latch): on a RECOVERY-WIRED service, a
// CloneFromImage issued BEFORE RecoverSessions returns codes.FailedPrecondition
// WITHOUT entering the create spine — no index drawn, no CA inject, no boot, no
// overlay — because the shared counter has not yet been re-seeded past the
// highest recovered index. A clone that ran first could re-hand a live recovered
// index (a never-recycle violation).
func TestCloneBeforeRecoverGatedOnRecoveryWiredService(t *testing.T) {
	// A non-empty resident set so RecoverSessions would re-seed past a real index —
	// the case where serving before recovery is genuinely unsafe.
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, 7)}
	svc, f := newTestDriverServiceWithRecovery(t, recovered)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// Clone a NEW session BEFORE RecoverSessions has run.
	_, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("clone before recover on a recovery-wired host: code = %v, want FailedPrecondition", status.Code(err))
	}

	// The gate fired at the TOP — the create spine was NOT entered: no index drawn,
	// no CA injected, no boot, no overlay disposed. The un-reseeded counter was
	// never touched, so a later recover still re-seeds cleanly past index 7.
	if len(f.counter.handed) != 0 {
		t.Errorf("gated clone must NOT draw an index (the create spine was not entered): counter handed %v", f.counter.handed)
	}
	if len(f.ca.injected) != 0 {
		t.Errorf("gated clone must NOT inject a CA: injected=%v", f.ca.injected)
	}
	if len(f.booter.booted) != 0 {
		t.Errorf("gated clone must NOT boot a domain: booted=%v", f.booter.booted)
	}
	if len(f.overlay.disposed) != 0 {
		t.Errorf("gated clone must NOT touch the overlay: disposed=%v", f.overlay.disposed)
	}
	if f.counter.seededTo != 0 {
		t.Errorf("a gated clone must not move the counter: seededTo=%d", f.counter.seededTo)
	}
}

// TestCloneAfterRecoverServesOnRecoveryWiredService asserts the latch OPENS the
// gate: on the SAME recovery-wired service, a clone that was rejected with
// FailedPrecondition before RecoverSessions SUCCEEDS once RecoverSessions has
// completed, drawing an index strictly past the highest recovered one (7 → 8,
// D66). This is the before-then-after pair the latch governs.
func TestCloneAfterRecoverServesOnRecoveryWiredService(t *testing.T) {
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, 7)} // highest = 7
	svc, f := newTestDriverServiceWithRecovery(t, recovered)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// BEFORE recover: gated.
	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("clone before recover: code = %v, want FailedPrecondition", status.Code(err))
	}

	// Run recovery — sets the latch at the end (counter re-seeded past 7).
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// AFTER recover: the SAME clone now serves and draws index 8 (strictly past 7).
	resp, err := client.CloneFromImage(ctx, cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("clone after recover must succeed: %v", err)
	}
	if got := resp.GetHostSessionIndex(); got != 8 {
		t.Errorf("post-recover clone drew index %d, want 8 (strictly past the highest recovered index 7, D66)", got)
	}
	if resp.GetTapName() != tapName(8) {
		t.Errorf("post-recover tap = %q, want %q", resp.GetTapName(), tapName(8))
	}
	if len(f.booter.booted) != 1 {
		t.Errorf("the ungated clone must boot exactly once, booted=%v", f.booter.booted)
	}

	// The latch is IDEMPOTENT: re-running RecoverSessions keeps it set, and a
	// further clone still serves (a new session draws index 9).
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions(re-invoke): %v", err)
	}
	resp2, err := client.CloneFromImage(ctx, cloneReq("00000000-0000-4000-8000-0000000000d4"))
	if err != nil {
		t.Fatalf("clone after re-invoked recover must still serve: %v", err)
	}
	if got := resp2.GetHostSessionIndex(); got != 9 {
		t.Errorf("clone after re-invoked recover drew index %d, want 9 (latch stayed set, counter only moved forward)", got)
	}
}

// TestCloneOnNoRecoveryServiceNeverGated asserts the NO-RECOVERY
// NewDriverService path (recover == nil) is UNAFFECTED by the recover-before-
// serve latch: a clone issued WITHOUT any RecoverSessions succeeds immediately. A
// driver built without a recoverer has no recovery phase to wait on, so it must
// never gain a latch that blocks its clones.
func TestCloneOnNoRecoveryServiceNeverGated(t *testing.T) {
	svc, f := newTestDriverService(t) // no recovery wired (recover == nil)
	client := dialInProcess(t, svc)

	// No RecoverSessions is ever issued — the clone must still serve.
	resp, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession))
	if err != nil {
		t.Fatalf("no-recovery CloneFromImage must serve without any RecoverSessions: %v", err)
	}
	if got := resp.GetHostSessionIndex(); got != 0 {
		t.Errorf("first no-recovery clone drew index %d, want 0 (the latch never gates the no-recovery path)", got)
	}
	if len(f.booter.booted) != 1 {
		t.Errorf("the no-recovery clone must boot exactly once, booted=%v", f.booter.booted)
	}
}

// TestNewDriverServiceRejectsNilDrivers asserts construction fails closed on a
// nil create or destroy driver (a programming error surfaced at construction).
func TestNewDriverServiceRejectsNilDrivers(t *testing.T) {
	_, f := newTestDriverService(t)
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)
	host, _ := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	destroyer, _ := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)

	if _, err := NewDriverService(nil, destroyer); err == nil {
		t.Error("nil create driver should be rejected")
	}
	if _, err := NewDriverService(host, nil); err == nil {
		t.Error("nil destroy driver should be rejected")
	}
}

// suspendProvenance is a synthetic D77 policy-rule lineage (the attribution a
// POLICY_BREACH pause must carry, doc 15 §4.3). D50 synthetic, deterministic.
func suspendProvenance() *boundaryv1.Provenance {
	return &boundaryv1.Provenance{
		RuleId:        "rule-egress-deny-7",
		PolicyLayer:   "tenant",
		PolicyVersion: 42,
	}
}

// TestSuspendPausesClonedSessionUser clones a session, then drives Suspend over the
// wire with SUSPEND_REASON_USER and asserts the seam paused it with the vetted
// reason and no provenance (USER needs none) — the §3 RUNNING→SUSPENDED(USER)
// transition (doc 15 §4.3).
func TestSuspendPausesClonedSessionUser(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	if _, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	}); err != nil {
		t.Fatalf("Suspend(USER): %v", err)
	}

	if len(susp.suspends) != 1 {
		t.Fatalf("suspend calls = %d, want 1", len(susp.suspends))
	}
	call := susp.suspends[0]
	if call.sessionUUID != testCloneSession {
		t.Errorf("suspended session %q, want %q", call.sessionUUID, testCloneSession)
	}
	if call.reason != hypervisorv1.SuspendReason_SUSPEND_REASON_USER {
		t.Errorf("suspended with reason %v, want SUSPEND_REASON_USER", call.reason)
	}
	if call.provenance != nil {
		t.Errorf("USER suspend carried provenance %v, want nil (only POLICY_BREACH requires it)", call.provenance)
	}
}

// TestSuspendPolicyBreachWithProvenanceOK drives Suspend with
// SUSPEND_REASON_POLICY_BREACH AND a non-nil provenance and asserts it pauses —
// the D77 genuine-threat path is valid when the policy-rule lineage is carried
// (doc 15 §4.3). The driver passes the provenance THROUGH to the seam (the
// host-side audit record).
func TestSuspendPolicyBreachWithProvenanceOK(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	prov := suspendProvenance()
	if _, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		Provenance:  prov,
	}); err != nil {
		t.Fatalf("Suspend(POLICY_BREACH+provenance): %v", err)
	}

	if len(susp.suspends) != 1 {
		t.Fatalf("suspend calls = %d, want 1", len(susp.suspends))
	}
	call := susp.suspends[0]
	if call.reason != hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Errorf("suspended with reason %v, want SUSPEND_REASON_POLICY_BREACH", call.reason)
	}
	// The provenance the D77 narrowing requires was carried THROUGH to the seam.
	if call.provenance == nil {
		t.Fatal("POLICY_BREACH suspend dropped the provenance; the seam must receive it (D77 audit record)")
	}
	if call.provenance.GetRuleId() != prov.GetRuleId() || call.provenance.GetPolicyVersion() != prov.GetPolicyVersion() {
		t.Errorf("seam got provenance %v, want %v (passed through verbatim)", call.provenance, prov)
	}
}

// TestSuspendPolicyBreachWithoutProvenanceInvalidArgument asserts a POLICY_BREACH
// suspend with NO provenance is codes.InvalidArgument (the D77 genuine-threat
// narrowing, doc 15 §4.3) — and the seam is NEVER called (the binding rejects it
// before reaching the host-side pause).
func TestSuspendPolicyBreachWithoutProvenanceInvalidArgument(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	_, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		// no Provenance
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("POLICY_BREACH without provenance: code = %v, want InvalidArgument (D77)", status.Code(err))
	}
	if len(susp.suspends) != 0 {
		t.Errorf("the seam must NOT be called for a D77-invalid suspend, suspends=%d", len(susp.suspends))
	}
}

// TestSuspendUnspecifiedReasonInvalidArgument asserts a suspend with
// SUSPEND_REASON_UNSPECIFIED is codes.InvalidArgument (a reason is REQUIRED — the
// §3 SUSPENDED state is reason-tagged) and the seam is never called.
func TestSuspendUnspecifiedReasonInvalidArgument(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	_, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("UNSPECIFIED reason: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(susp.suspends) != 0 {
		t.Errorf("the seam must NOT be called for an unspecified-reason suspend, suspends=%d", len(susp.suspends))
	}
}

// TestSuspendUnknownSessionNotFound asserts Suspend for a session that never cloned
// is codes.NotFound — you cannot pause a session with no recorded binding (the
// IssueAttachHandle precedent) — and the seam is never called.
func TestSuspendUnknownSessionNotFound(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)

	_, err := client.Suspend(context.Background(), &hypervisorv1.SuspendRequest{
		SessionUuid: "00000000-0000-4000-8000-00000000dead",
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: code = %v, want NotFound", status.Code(err))
	}
	if len(susp.suspends) != 0 {
		t.Errorf("the seam must NOT be called for an unknown session, suspends=%d", len(susp.suspends))
	}
}

// TestSuspendEmptySessionInvalidArgument asserts an empty session_uuid is
// codes.InvalidArgument (the target key is required) — checked before the seam.
func TestSuspendEmptySessionInvalidArgument(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)

	_, err := client.Suspend(context.Background(), &hypervisorv1.SuspendRequest{
		Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(susp.suspends) != 0 {
		t.Errorf("the seam must NOT be called for an empty session, suspends=%d", len(susp.suspends))
	}
}

// TestSuspendIdempotentOnReSuspend clones a session and suspends it TWICE over the
// wire, asserting both calls SUCCEED — re-suspending an already-suspended session
// is a no-op success (doc 15 §5.1 idempotency), never a fault.
func TestSuspendIdempotentOnReSuspend(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	req := &hypervisorv1.SuspendRequest{SessionUuid: testCloneSession, Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER}
	if _, err := client.Suspend(ctx, req); err != nil {
		t.Fatalf("Suspend(first): %v", err)
	}
	if _, err := client.Suspend(ctx, req); err != nil {
		t.Fatalf("Suspend(retry) must be a no-op success (idempotent on session_uuid): %v", err)
	}
	// Both calls reached the seam (the retry converged at the seam, not a faked
	// short-circuit), and the session is suspended exactly once in state.
	if len(susp.suspends) != 2 {
		t.Errorf("both suspends should reach the seam, suspends=%d", len(susp.suspends))
	}
	if !susp.suspended[testCloneSession] {
		t.Error("session should be in the suspended state after a re-suspend")
	}
}

// TestSuspendSurfacesSeamFault asserts a seam pause fault is surfaced as a gRPC
// error (codes.Internal) — a real host-side suspend failure the caller re-drives,
// not a faked success.
func TestSuspendSurfacesSeamFault(t *testing.T) {
	susp := newFakeSuspender()
	susp.suspendErr = errors.New("libvirt managedsave failed")
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	_, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("seam suspend fault: code = %v, want Internal", status.Code(err))
	}
}

// TestSuspendUnwiredReturnsUnimplemented asserts a service built WITHOUT a
// Suspender (the NewDriverService path) answers Suspend with an honest
// codes.Unimplemented — the same host-side-only posture as the other unwired
// verbs; never a faked success.
func TestSuspendUnwiredReturnsUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t) // no suspender wired
	client := dialInProcess(t, svc)

	_, err := client.Suspend(context.Background(), &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unwired Suspend: code = %v, want Unimplemented", status.Code(err))
	}
}

// TestResumeRestoresClonedSession clones + suspends a session, then drives Resume
// over the wire and asserts the seam restored it — the §3 SUSPENDED→RUNNING
// transition (doc 15 §4.3).
func TestResumeRestoresClonedSession(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	if _, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	}); err != nil {
		t.Fatalf("Suspend: %v", err)
	}

	if _, err := client.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if len(susp.resumes) != 1 || susp.resumes[0] != testCloneSession {
		t.Errorf("Resume must restore the session via the seam, resumes=%v", susp.resumes)
	}
	if susp.suspended[testCloneSession] {
		t.Error("session should be running (not suspended) after a Resume")
	}
}

// TestResumeUnknownSessionNotFound asserts Resume for a session that never cloned
// is codes.NotFound (the Suspend/IssueAttachHandle precedent) — the seam is never
// called.
func TestResumeUnknownSessionNotFound(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)

	_, err := client.Resume(context.Background(), &hypervisorv1.ResumeRequest{
		SessionUuid: "00000000-0000-4000-8000-00000000dead",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: code = %v, want NotFound", status.Code(err))
	}
	if len(susp.resumes) != 0 {
		t.Errorf("the seam must NOT be called for an unknown session, resumes=%d", len(susp.resumes))
	}
}

// TestResumeEmptySessionInvalidArgument asserts an empty session_uuid is
// codes.InvalidArgument (the target key is required) — checked before the seam.
func TestResumeEmptySessionInvalidArgument(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)

	_, err := client.Resume(context.Background(), &hypervisorv1.ResumeRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(susp.resumes) != 0 {
		t.Errorf("the seam must NOT be called for an empty session, resumes=%d", len(susp.resumes))
	}
}

// TestResumeIdempotentOnReResume clones + resumes a never-suspended (running)
// session TWICE over the wire, asserting both SUCCEED — re-resuming an
// already-running session is a no-op success (doc 15 §5.1 idempotency).
func TestResumeIdempotentOnReResume(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	req := &hypervisorv1.ResumeRequest{SessionUuid: testCloneSession}
	if _, err := client.Resume(ctx, req); err != nil {
		t.Fatalf("Resume(first): %v", err)
	}
	if _, err := client.Resume(ctx, req); err != nil {
		t.Fatalf("Resume(retry) must be a no-op success (idempotent on session_uuid): %v", err)
	}
	if len(susp.resumes) != 2 {
		t.Errorf("both resumes should reach the seam, resumes=%d", len(susp.resumes))
	}
}

// TestResumeSurfacesSeamFault asserts a seam restore fault is surfaced as a gRPC
// error (codes.Internal) — a real host-side resume failure the caller re-drives.
func TestResumeSurfacesSeamFault(t *testing.T) {
	susp := newFakeSuspender()
	susp.resumeErr = errors.New("libvirt restore-from-managedsave failed")
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	_, err := client.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Internal {
		t.Fatalf("seam resume fault: code = %v, want Internal", status.Code(err))
	}
}

// TestResumeUnwiredReturnsUnimplemented asserts a service built WITHOUT a Suspender
// answers Resume with an honest codes.Unimplemented (the host-side-only posture).
func TestResumeUnwiredReturnsUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t) // no suspender wired
	client := dialInProcess(t, svc)

	_, err := client.Resume(context.Background(), &hypervisorv1.ResumeRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unwired Resume: code = %v, want Unimplemented", status.Code(err))
	}
}

// TestSuspendThenResumeRoundTrip clones a session and drives the full
// RUNNING→SUSPENDED(POLICY_BREACH)→RUNNING lifecycle over the wire, asserting the
// seam saw the pause (with provenance) and the restore in order — the §3 lifecycle
// pair end to end.
func TestSuspendThenResumeRoundTrip(t *testing.T) {
	susp := newFakeSuspender()
	svc, _ := newTestDriverServiceWithSuspend(t, susp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	if _, err := client.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: testCloneSession,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		Provenance:  suspendProvenance(),
	}); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if !susp.suspended[testCloneSession] {
		t.Fatal("session must be SUSPENDED after Suspend")
	}
	if _, err := client.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if susp.suspended[testCloneSession] {
		t.Error("session must be RUNNING after Resume")
	}
	if len(susp.suspends) != 1 || len(susp.resumes) != 1 {
		t.Errorf("lifecycle pair must hit the seam once each: suspends=%d resumes=%d", len(susp.suspends), len(susp.resumes))
	}
}

// TestSnapshotCapturesClonedSessionOverlay clones a session, then drives Snapshot
// over the wire WITHOUT a label and asserts the seam captured its overlay and the
// response carries the opaque snapshot_ref (doc 15 §5.1 / D29). The driver passed
// the seam the cloned session and an empty label (the unlabeled-capture case).
func TestSnapshotCapturesClonedSessionOverlay(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// The session must exist: clone it first (its overlay is the D29 durability
	// unit the snapshot captures).
	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	resp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if resp.GetSnapshotRef() == "" {
		t.Error("snapshot_ref empty — Snapshot must return the SnapshotStore opaque reference (D29)")
	}

	// The driver captured exactly once, for the cloned session, with an empty label.
	if len(snap.calls) != 1 {
		t.Fatalf("snapshot calls = %d, want 1", len(snap.calls))
	}
	call := snap.calls[0]
	if call.sessionUUID != testCloneSession {
		t.Errorf("snapshotted session %q, want %q", call.sessionUUID, testCloneSession)
	}
	if call.label != "" {
		t.Errorf("unlabeled snapshot carried label %q, want empty", call.label)
	}
}

// TestSnapshotCapturesWithLabel clones a session, then drives Snapshot over the
// wire WITH a label and asserts the optional label is passed THROUGH to the seam
// (the frozen SnapshotRequest.label names the point-in-time).
func TestSnapshotCapturesWithLabel(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	const label = "pre-upgrade-checkpoint"
	resp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{
		SessionUuid: testCloneSession,
		Label:       label,
	})
	if err != nil {
		t.Fatalf("Snapshot(labeled): %v", err)
	}
	if resp.GetSnapshotRef() == "" {
		t.Error("labeled snapshot_ref empty — Snapshot must return the opaque reference")
	}
	if len(snap.calls) != 1 {
		t.Fatalf("snapshot calls = %d, want 1", len(snap.calls))
	}
	if snap.calls[0].label != label {
		t.Errorf("seam got label %q, want %q (the optional label passed through)", snap.calls[0].label, label)
	}
}

// TestSnapshotIdempotentOnSessionLabel clones a session and snapshots it TWICE for
// the SAME label over the wire, asserting the two snapshot_refs are EQUIVALENT (a
// deterministic SnapshotStore ⇒ idempotent on (session_uuid, label), doc 15 §5.1)
// — a retry re-names the same point-in-time, never forks a second durable snapshot.
func TestSnapshotIdempotentOnSessionLabel(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	req := &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "nightly"}
	first, err := client.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot(first): %v", err)
	}
	second, err := client.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot(retry): %v", err)
	}
	if first.GetSnapshotRef() != second.GetSnapshotRef() {
		t.Errorf("retry forked a non-equivalent snapshot_ref: %q vs %q (must be idempotent on (session_uuid, label))", first.GetSnapshotRef(), second.GetSnapshotRef())
	}
}

// TestSnapshotDifferentLabelsDistinctRefs clones a session and snapshots it under
// TWO DIFFERENT labels over the wire, asserting the snapshot_refs DIFFER — a
// distinct label is a distinct point-in-time (a distinct durable snapshot), the
// converse of the (session, label) idempotency.
func TestSnapshotDifferentLabelsDistinctRefs(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	a, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "label-a"})
	if err != nil {
		t.Fatalf("Snapshot(label-a): %v", err)
	}
	b, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "label-b"})
	if err != nil {
		t.Fatalf("Snapshot(label-b): %v", err)
	}
	if a.GetSnapshotRef() == b.GetSnapshotRef() {
		t.Errorf("distinct labels must yield distinct snapshot_refs, both = %q", a.GetSnapshotRef())
	}
}

// TestSnapshotUnknownSessionNotFound asserts Snapshot for a session that never
// cloned is codes.NotFound — you cannot capture a session with no recorded binding
// (the IssueAttachHandle/Suspend precedent) — and the seam is never called.
func TestSnapshotUnknownSessionNotFound(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)

	_, err := client.Snapshot(context.Background(), &hypervisorv1.SnapshotRequest{
		SessionUuid: "00000000-0000-4000-8000-00000000dead",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: code = %v, want NotFound", status.Code(err))
	}
	if len(snap.calls) != 0 {
		t.Errorf("the seam must NOT be called for an unknown session, calls=%d", len(snap.calls))
	}
}

// TestSnapshotEmptySessionInvalidArgument asserts an empty session_uuid is
// codes.InvalidArgument (the target key is required) — even with a store wired,
// the precondition is checked before the capture.
func TestSnapshotEmptySessionInvalidArgument(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)

	_, err := client.Snapshot(context.Background(), &hypervisorv1.SnapshotRequest{Label: "no-session"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(snap.calls) != 0 {
		t.Errorf("the seam must NOT be called for an empty session, calls=%d", len(snap.calls))
	}
}

// TestSnapshotSurfacesSeamFault asserts a seam capture fault is surfaced as a gRPC
// error (codes.Internal) — a real host-side snapshot failure the caller re-drives,
// not a faked snapshot_ref.
func TestSnapshotSurfacesSeamFault(t *testing.T) {
	snap := &fakeSnapshotStore{err: errors.New("libvirt external-snapshot capture failed")}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	_, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Internal {
		t.Fatalf("seam snapshot fault: code = %v, want Internal", status.Code(err))
	}
}

// TestSnapshotUnwiredReturnsUnimplemented asserts a service built WITHOUT a
// SnapshotStore (the NewDriverService path) answers Snapshot with an honest
// codes.Unimplemented — the same host-side-only posture as the other unwired
// verbs; never a faked snapshot_ref.
func TestSnapshotUnwiredReturnsUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t) // no snapshot store wired
	client := dialInProcess(t, svc)

	_, err := client.Snapshot(context.Background(), &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unwired Snapshot: code = %v, want Unimplemented", status.Code(err))
	}
}

// TestSnapshotAfterDestroyNotFound clones, destroys, then snapshots the SAME
// session — asserting NotFound: Destroy drops the clone-cache entry, so a snapshot
// of a torn-down session has no recorded binding to capture (the cache-drop
// contract the IssueAttachHandle/Suspend verbs also rely on).
func TestSnapshotAfterDestroyNotFound(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	_, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("snapshot of a torn-down session: code = %v, want NotFound", status.Code(err))
	}
	if len(snap.calls) != 0 {
		t.Errorf("the seam must NOT be called after the session was destroyed, calls=%d", len(snap.calls))
	}
}

// ── ExportDiskDelta (server-streaming over the DiskDeltaExporter seam) ─────────

// TestExportDiskDeltaStreamsClonedSessionDelta clones a session, then drives
// ExportDiskDelta over the wire and asserts the REASSEMBLED stream byte-equals the
// fake's synthetic delta (offsets monotonic + contiguous, via drainDelta), that
// the driver opened the delta for the cloned session with an EMPTY base ref (the
// full-overlay export), and that the service Closed the reader.
func TestExportDiskDeltaStreamsClonedSessionDelta(t *testing.T) {
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// The session must exist: clone it first (its overlay is the D29 durability
	// unit the delta is read from).
	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("ExportDiskDelta: %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining delta stream: %v", err)
	}

	want := syntheticDelta(testCloneSession, "")
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled delta = %q, want %q", got, want)
	}

	// The driver opened the delta exactly once, for the cloned session, with an
	// empty base ref (the full-overlay export).
	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	call := exp.calls[0]
	if call.sessionUUID != testCloneSession {
		t.Errorf("exported session %q, want %q", call.sessionUUID, testCloneSession)
	}
	if call.sinceSnapshotRef != "" {
		t.Errorf("full-overlay export carried since_snapshot_ref %q, want empty", call.sinceSnapshotRef)
	}
	// The service always Closes the reader (the OpenDelta Close contract).
	if exp.closeCount() != 1 {
		t.Errorf("reader Close count = %d, want 1 (the service must close the delta reader)", exp.closeCount())
	}
}

// TestExportDiskDeltaWithSinceSnapshotRef clones a session, CAPTURES a snapshot
// (so its ref is a known base of the session — the D29 capture→export loop
// closure), then drives ExportDiskDelta WITH that since_snapshot_ref and asserts
// the base ref is passed THROUGH to the seam (the incremental-delta-since-base
// case) and the reassembled stream byte-equals the fake's distinct incremental
// payload. A non-empty since_snapshot_ref must now be a ref Snapshot captured for
// this session (an arbitrary uncaptured ref is NotFound — see
// TestCaptureExportLoopUnknownRefNotFound), so the base is established via the
// snapshot+exporter-wired service rather than a hand-picked literal.
func TestExportDiskDeltaWithSinceSnapshotRef(t *testing.T) {
	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	// Capture the base so the ref is a known snapshot of this session.
	snapResp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "base-snapshot"})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	baseRef := snapResp.GetSnapshotRef()

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      testCloneSession,
		SinceSnapshotRef: baseRef,
	})
	if err != nil {
		t.Fatalf("ExportDiskDelta(since): %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining incremental delta stream: %v", err)
	}

	want := syntheticDelta(testCloneSession, baseRef)
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled incremental delta = %q, want %q", got, want)
	}
	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	if exp.calls[0].sinceSnapshotRef != baseRef {
		t.Errorf("incremental export carried since_snapshot_ref %q, want %q", exp.calls[0].sinceSnapshotRef, baseRef)
	}
}

// TestExportDiskDeltaMultiChunkFraming exercises the framing loop with a payload
// LARGER than exportDeltaChunkSize: the stream must arrive in multiple frames with
// monotonic + contiguous offsets that reassemble (by concatenation) to the exact
// payload. drainDelta asserts the offset invariant; here we additionally assert
// more than one frame was sent.
func TestExportDiskDeltaMultiChunkFraming(t *testing.T) {
	// A deterministic payload spanning ~2.5 chunks.
	payload := make([]byte, exportDeltaChunkSize*2+777)
	for i := range payload {
		payload[i] = byte(i % 251) // a non-trivial repeating pattern (251 is prime)
	}
	exp := &fakeDiskDeltaExporter{delta: payload}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("ExportDiskDelta: %v", err)
	}

	// Count frames AND reassemble, asserting the offset invariant inline (so we can
	// also assert frame count > 1 — drainDelta hides the count).
	var reassembled []byte
	var want uint64
	frames := 0
	for {
		frame, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("Recv: %v", recvErr)
		}
		frames++
		if frame.GetOffset() != want {
			t.Fatalf("frame %d offset = %d, want %d (monotonic + contiguous)", frames, frame.GetOffset(), want)
		}
		if len(frame.GetData()) > exportDeltaChunkSize {
			t.Fatalf("frame %d data len = %d, exceeds chunk size %d", frames, len(frame.GetData()), exportDeltaChunkSize)
		}
		reassembled = append(reassembled, frame.GetData()...)
		want += uint64(len(frame.GetData()))
	}
	if frames < 2 {
		t.Errorf("frame count = %d, want >1 (a payload larger than the chunk size must span multiple frames)", frames)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Errorf("reassembled %d bytes != original %d-byte payload", len(reassembled), len(payload))
	}
	if exp.closeCount() != 1 {
		t.Errorf("reader Close count = %d, want 1", exp.closeCount())
	}
}

// TestExportDiskDeltaUnknownSessionNotFound asserts a delta export for a session
// with no recorded binding fails NotFound BEFORE the seam is opened (the
// Snapshot/Suspend precedent; the stream carries the status on the first Recv).
func TestExportDiskDeltaUnknownSessionNotFound(t *testing.T) {
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)

	stream, err := client.ExportDiskDelta(context.Background(), &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid: "00000000-0000-4000-8000-00000000beef",
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("export of an unknown session: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT be opened for an unknown session, calls=%d", len(exp.calls))
	}
}

// TestExportDiskDeltaEmptySessionInvalidArgument asserts an empty session_uuid is
// rejected InvalidArgument before the seam is opened.
func TestExportDiskDeltaEmptySessionInvalidArgument(t *testing.T) {
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)

	stream, err := client.ExportDiskDelta(context.Background(), &hypervisorv1.ExportDiskDeltaRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("export with empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT be opened for an empty session, calls=%d", len(exp.calls))
	}
}

// TestExportDiskDeltaUnwiredReturnsUnimplemented asserts a DriverService built
// WITHOUT a DiskDeltaExporter answers ExportDiskDelta with an honest
// codes.Unimplemented (the nil-seam posture; the streaming gap, not a false
// capability flag — GetCapabilities still honestly advertises the substrate).
func TestExportDiskDeltaUnwiredReturnsUnimplemented(t *testing.T) {
	svc, _ := newTestDriverService(t) // the plain constructor: no exporter wired
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unwired ExportDiskDelta: code = %v, want Unimplemented", status.Code(err))
	}
}

// TestExportDiskDeltaSurfacesSeamFault asserts an OpenDelta fault surfaces as
// codes.Internal on the first Recv (the export did not open).
func TestExportDiskDeltaSurfacesSeamFault(t *testing.T) {
	exp := &fakeDiskDeltaExporter{err: errors.New("libvirt dirty-bitmap extraction failed")}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("OpenDelta fault: code = %v, want Internal", status.Code(err))
	}
}

// TestExportDiskDeltaContextCancelStopsCleanly clones a session, opens the stream
// against a reader that blocks after its first chunk, then CANCELS the client
// context mid-stream — asserting the service stops promptly (the stream ends with
// a cancellation status, not a hang) AND Closed the reader (the cleanup contract
// holds on cancellation). The blocking reader is the belt that guarantees the
// server goroutine cannot leak past cancellation.
func TestExportDiskDeltaContextCancelStopsCleanly(t *testing.T) {
	exp := &blockingDeltaExporter{}
	svc, _ := newTestDriverServiceWithDiskDelta(t, exp)
	client := dialInProcess(t, svc)

	if _, err := client.CloneFromImage(context.Background(), cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("ExportDiskDelta: %v", err)
	}

	// Receive the first chunk (the reader emits it before blocking), then cancel.
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv before cancel: %v", err)
	}
	cancel()

	// The stream must terminate (Recv returns a cancellation error) rather than
	// hang. Drain to EOF/err.
	for {
		_, recvErr := stream.Recv()
		if recvErr != nil {
			if status.Code(recvErr) != codes.Canceled {
				t.Fatalf("post-cancel Recv: code = %v, want Canceled", status.Code(recvErr))
			}
			break
		}
	}

	// The service Closed the reader on cancellation (the deferred Close runs on the
	// ctx-error return path). Poll briefly: the server goroutine's deferred Close
	// races the client's Recv-return, so allow it to land.
	deadline := time.Now().Add(2 * time.Second)
	for exp.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if exp.closeCount() == 0 {
		t.Error("reader was not Closed on cancellation (the cleanup contract must hold mid-stream)")
	}
}

// ── D29 capture→export loop closure (Snapshot ref → ExportDiskDelta base) ──────

// TestCaptureExportLoopSnapshotRefRootsIncrementalDelta drives the WHOLE D29
// capture→export loop over the wire on one service: clone a session, Snapshot it
// to capture an opaque snapshot_ref, then ExportDiskDelta(since_snapshot_ref =
// that captured ref) — asserting the export is ROOTED at the captured ref (the
// fake records the since_snapshot_ref it received == the snapshot_ref Snapshot
// returned) and the reassembled stream is the distinct incremental payload for
// that base. This is the loop closure: a ref Snapshot captured is accepted by
// ExportDiskDelta as a valid incremental base.
func TestCaptureExportLoopSnapshotRefRootsIncrementalDelta(t *testing.T) {
	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	// Capture a snapshot — the ref the control plane names back as the export base.
	snapResp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{
		SessionUuid: testCloneSession,
		Label:       "loop-base",
	})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	baseRef := snapResp.GetSnapshotRef()
	if baseRef == "" {
		t.Fatal("Snapshot returned an empty snapshot_ref — nothing to root the export at")
	}

	// Export the delta SINCE that captured ref: the loop closes here.
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      testCloneSession,
		SinceSnapshotRef: baseRef,
	})
	if err != nil {
		t.Fatalf("ExportDiskDelta(since=captured ref): %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining incremental delta stream: %v", err)
	}

	// The export is rooted at the captured ref: the seam received it verbatim.
	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	if exp.calls[0].sinceSnapshotRef != baseRef {
		t.Errorf("export rooted at since_snapshot_ref %q, want the captured ref %q (the capture→export loop must thread the snapshot_ref through)", exp.calls[0].sinceSnapshotRef, baseRef)
	}
	// And the streamed bytes are the distinct incremental payload for that base
	// (the fake's synthetic delta is a pure function of (session, baseRef)).
	want := syntheticDelta(testCloneSession, baseRef)
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled incremental delta = %q, want %q", got, want)
	}
}

// TestCaptureExportLoopEmptyRefStillFullOverlay asserts that, with the loop wired,
// an EMPTY since_snapshot_ref still streams the FULL overlay (no base to validate)
// — the proto's "empty => full overlay" path is unaffected by the new registry
// check: the seam is opened with an empty base, and the reassembled stream is the
// full-overlay synthetic payload.
func TestCaptureExportLoopEmptyRefStillFullOverlay(t *testing.T) {
	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	// Capture a snapshot so the registry is non-empty — the empty-ref path must
	// still be the FULL overlay regardless of any captured refs.
	if _, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "ignored"}); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("ExportDiskDelta(empty ref): %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining full-overlay delta stream: %v", err)
	}

	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	if exp.calls[0].sinceSnapshotRef != "" {
		t.Errorf("full-overlay export carried since_snapshot_ref %q, want empty", exp.calls[0].sinceSnapshotRef)
	}
	want := syntheticDelta(testCloneSession, "")
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled full-overlay delta = %q, want %q", got, want)
	}
}

// TestCaptureExportLoopUnknownRefNotFound asserts that a NON-EMPTY since_snapshot_ref
// that this session never captured (no Snapshot ever returned it) is rejected
// codes.NotFound BEFORE the seam is opened — the base point-in-time does not exist,
// so OpenDelta is never called. The session IS cloned (so this is the since-ref
// check failing, not the unknown-session check).
func TestCaptureExportLoopUnknownRefNotFound(t *testing.T) {
	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      testCloneSession,
		SinceSnapshotRef: "overlay-delta://never-captured@phantom",
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("export rooted at an unknown since_snapshot_ref: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT be opened for an unknown since_snapshot_ref, calls=%d", len(exp.calls))
	}
}

// TestCaptureExportLoopRefScopedToSession asserts a captured ref is scoped to the
// session that captured it: a ref Snapshot produced for session A is NOT a valid
// since_snapshot_ref base for session B's export — B's export at A's ref is
// codes.NotFound (the base point-in-time is not a snapshot of B), and the seam is
// never opened. This guards the per-session registry keying.
func TestCaptureExportLoopRefScopedToSession(t *testing.T) {
	const sessionA = testCloneSession
	const sessionB = "00000000-0000-4000-8000-0000000000b2"

	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(sessionA)); err != nil {
		t.Fatalf("CloneFromImage(A): %v", err)
	}
	if _, err := client.CloneFromImage(ctx, cloneReq(sessionB)); err != nil {
		t.Fatalf("CloneFromImage(B): %v", err)
	}

	// Capture a ref for A only.
	snapResp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: sessionA, Label: "A-only"})
	if err != nil {
		t.Fatalf("Snapshot(A): %v", err)
	}
	aRef := snapResp.GetSnapshotRef()

	// B's export rooted at A's ref must be NotFound (A's ref is not a snapshot of B).
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      sessionB,
		SinceSnapshotRef: aRef,
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("session B export rooted at session A's ref: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT be opened for a cross-session since_snapshot_ref, calls=%d", len(exp.calls))
	}
}

// TestCaptureExportLoopRefDroppedOnDestroy asserts a captured ref does NOT survive
// the session's teardown: after Destroy, the same session re-cloned has an EMPTY
// snapshot registry, so an export rooted at the previously-captured ref is
// codes.NotFound (the §4.2 teardown dropped the durability unit; a lingering ref
// would root an export at a point-in-time whose overlay is gone). The seam is
// never opened.
func TestCaptureExportLoopRefDroppedOnDestroy(t *testing.T) {
	snap := &fakeSnapshotStore{}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithSnapshotAndDiskDelta(t, snap, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	snapResp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "pre-destroy"})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	staleRef := snapResp.GetSnapshotRef()

	// Tear the session down (drops the binding AND the registered refs), then
	// re-clone the same session_uuid so the export passes the session-known check
	// and fails specifically on the dropped ref.
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage(re-clone): %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      testCloneSession,
		SinceSnapshotRef: staleRef,
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("export rooted at a ref dropped by Destroy: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT be opened for a torn-down session's stale ref, calls=%d", len(exp.calls))
	}
}

// ── concurrency-safe create-spine fakes for the recover-latch RACE test ───────
//
// The create-spine fakes the other tests use (fakeAttach/fakeOverlay/fakeCA/
// fakeBooter in create_test.go) record invocations into plain slices with no
// synchronization — fine for the SEQUENTIAL tests that drive one clone at a time,
// but the recover-latch race test fires MANY CloneFromImage calls concurrently, so
// two clones that BOTH pass the latch enter the create spine at once and would race
// those slice appends (a -race failure in the test fixture, not the production
// latch). These locked variants are the minimal mutex-guarded equivalents — the
// SAME happy-path behavior (acked + fresh ⇒ routable, deterministic overlay path,
// domain-<uuid> boot) — so the race test exercises the real CloneFromImage spine
// concurrently while staying -race clean. They are scoped to this test; the
// sequential tests keep the create_test.go fakes.
type lockedAttach struct {
	mu      sync.Mutex
	taps    []Binding
	nfts    []string
	flushed []string
}

func (f *lockedAttach) CreateTap(_ context.Context, b Binding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taps = append(f.taps, b)
	return nil
}

func (f *lockedAttach) InstantiateSessionNFT(_ context.Context, sessionUUID string, _ Binding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nfts = append(f.nfts, sessionUUID)
	return nil
}

func (f *lockedAttach) FlushSession(_ context.Context, sessionUUID string, _ Binding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushed = append(f.flushed, sessionUUID)
	return nil
}

type lockedOverlay struct {
	mu       sync.Mutex
	disposed []string
}

func (f *lockedOverlay) CreateOverlay(_ context.Context, sessionUUID, _ string) (string, error) {
	return "/var/lib/ds/overlays/" + sessionUUID + ".qcow2", nil
}

func (f *lockedOverlay) DisposeOverlay(_ context.Context, overlayPath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disposed = append(f.disposed, overlayPath)
	return nil
}

type lockedCA struct {
	mu       sync.Mutex
	injected []string
}

func (f *lockedCA) InjectCA(_ context.Context, overlayPath, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.injected = append(f.injected, overlayPath)
	return nil
}

type lockedBooter struct {
	mu     sync.Mutex
	booted []string
}

func (f *lockedBooter) Boot(_ context.Context, sessionUUID, _, _, _ string, _ uint32) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.booted = append(f.booted, sessionUUID)
	return "domain-" + sessionUUID, nil
}

// newRaceDriverServiceWithRecovery builds a recovery-WIRED DriverService over the
// concurrency-safe create-spine fakes above (acked + fresh gate so a served clone is
// routable), sharing ONE fakeReseedCounter between the Allocator and the reseed
// handle exactly as newTestDriverServiceWithRecovery does — so a re-seed advances
// the very counter the next clone's Allocate() draws from. It returns the shared
// counter so the race test can read the resume point. The destroyer is wired from
// the create_test.go destroy fakes (never invoked here — the race test drives only
// CloneFromImage + RecoverSessions), so its lack of synchronization is irrelevant.
func newRaceDriverServiceWithRecovery(t *testing.T, recovered []RecoveredSession) (*DriverService, *fakeReseedCounter) {
	t.Helper()
	counter := &fakeReseedCounter{}
	recoverer := &fakeRecoverer{sessions: recovered}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, &lockedAttach{}, &lockedOverlay{}, &lockedCA{}, &lockedBooter{}, &fakeGate{acked: true, fresh: true})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(&fakeDomainDestroyer{}, &lockedAttach{}, &lockedOverlay{}, &fakeDurability{}, &fakeFlowBytes{})
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithRecovery(host, destroyer, recoverer, counter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithRecovery: %v", err)
	}
	return svc, counter
}

// TestCloneRaceWithRecoverNeverRecyclesIndex is the CONCURRENCY guard the
// recover-before-serve latch exists to make safe (D66, doc 15 §4 / §5.1). The
// sequential gate tests (TestCloneBeforeRecover.../TestCloneAfterRecover...) prove
// the latch reads false-then-true across a serial before/after pair, but they never
// exercise the goroutine INTERLEAVING the atomic.Bool is for: a CloneFromImage for
// a NEW session racing the ONE RecoverSessions that re-seeds the shared counter past
// the highest recovered index (7). The load-bearing safety property is that EVERY
// racing clone either GATES (codes.FailedPrecondition — it observed the latch still
// closed) OR draws a HostSessionIndex STRICTLY GREATER than 7 (it observed the latch
// open, which by the Store-LAST ordering means the counter was already re-seeded) —
// and NEVER an index <= 7, which would re-hand a live recovered index (the D66
// never-recycle violation). A future refactor that moved the latch Store before the
// SeedAtLeast, or dropped the gate, would let a racing clone draw index 0 here and
// fail this assertion with no sequential test regressing.
//
// The whole package is run under -race (the acceptance gate), so the latch read on
// the CloneFromImage hot path racing the Store at the end of RecoverSessions, and the
// concurrent draws from the SHARED fakeReseedCounter (one instance backing both the
// Allocator and the reseed handle), are goroutine-checked — the shared counter is
// exactly what makes the strictly-past-7 index assertion load-bearing rather than
// vacuous. The create-spine fakes are the locked* variants above so two SERVING
// clones in the spine at once don't race the fixture's bookkeeping (the latch and
// the shared counter, the things under test, stay the only contended state).
// Distinct synthetic session UUIDs (D50, deterministic) so each clone is a genuinely
// new session that must DRAW (never re-adopt a cached binding); offline against the
// fakes + the in-process gRPC client (no libvirt/KVM/sudo).
func TestCloneRaceWithRecoverNeverRecyclesIndex(t *testing.T) {
	const highestRecovered = uint64(7)
	// One resident session at the highest recovered index 7: RecoverSessions must
	// re-seed the shared counter strictly past it, so a clone that drew BEFORE the
	// re-seed would hand back a <=7 index — the unsafe interleaving the latch forbids.
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, highestRecovered)}
	svc, _ := newRaceDriverServiceWithRecovery(t, recovered)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// N >= 8 distinct NEW sessions, each cloned from its own goroutine, racing the
	// ONE RecoverSessions goroutine. Distinct deterministic UUIDs so no two clones
	// share a session (each must allocate, never re-adopt) and the run is reproducible.
	const n = 12
	sessions := make([]string, n)
	for i := range sessions {
		// 00000000-0000-4000-8000-0000000000e0, ...e1, ... ...eb — deterministic,
		// distinct, and disjoint from recoverSessionA/B (…a1/…b2) and testCloneSession
		// (…c1). Zero-padded HEX (0xe0+i) so all N=12 node fields stay WELL-FORMED
		// RFC-4122 hex: the prior "…e"+rune('0'+i) form let i=10/11 emit the non-hex
		// ':'/';' tails (rune 0x3a/0x3b), which is harmless under today's CloneFromImage
		// (it only rejects an EMPTY session_uuid) but would make a future uuid.Parse-style
		// clone-path validation return InvalidArgument for those two and trip the
		// unexpected-code branch below — masking the never-recycle property this guards.
		sessions[i] = fmt.Sprintf("00000000-0000-4000-8000-0000000000%02x", 0xe0+i)
	}

	type cloneOutcome struct {
		code  codes.Code
		index uint64
		err   error
	}
	outcomes := make(chan cloneOutcome, n)

	var wg sync.WaitGroup
	// Hold every goroutine at a common start line so the clones and the recover
	// genuinely interleave (rather than all clones finishing before recover is even
	// dispatched) — the start gate maximizes the chance the -race scheduler exercises
	// the latch read/Store overlap.
	start := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		// The ONE recover that sets the latch (after re-seeding the counter past 7).
		// A fault here would be a test-fixture bug, not a property violation; record
		// it so the assertion loop can surface it rather than hang.
		if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
			t.Errorf("RecoverSessions (the racing recover) faulted: %v", err)
		}
	}()

	for _, sess := range sessions {
		wg.Add(1)
		go func(session string) {
			defer wg.Done()
			<-start
			resp, err := client.CloneFromImage(ctx, cloneReq(session))
			if err != nil {
				outcomes <- cloneOutcome{code: status.Code(err), err: err}
				return
			}
			outcomes <- cloneOutcome{code: codes.OK, index: resp.GetHostSessionIndex()}
		}(sess)
	}

	close(start) // release every goroutine at once
	wg.Wait()
	close(outcomes)

	// The D66 never-recycle disjunction: EVERY clone must EITHER have gated
	// (FailedPrecondition — the latch was still closed when it checked) OR drawn an
	// index STRICTLY > 7 (the latch was open, which under the Store-LAST ordering
	// means the counter was already re-seeded past the highest recovered index).
	// NEVER OK with an index <= 7 (a re-handed live index) and never any other code.
	var gated, served int
	for o := range outcomes {
		switch o.code {
		case codes.FailedPrecondition:
			gated++
		case codes.OK:
			if o.index <= highestRecovered {
				t.Errorf("D66 never-recycle VIOLATION: a clone racing recover drew index %d <= the highest recovered index %d (it served from the un-reseeded counter)", o.index, highestRecovered)
			}
			served++
		default:
			t.Errorf("racing clone returned unexpected code %v (err=%v); want FailedPrecondition (gated) or OK with index > %d", o.code, o.err, highestRecovered)
		}
	}

	// Sanity: every goroutine reported exactly one outcome (no lost/duplicated
	// result). The gated/served SPLIT is timing-dependent and deliberately NOT
	// asserted — the property is the per-clone disjunction above, which must hold for
	// every clone regardless of how the schedule fell.
	if gated+served != n {
		t.Fatalf("accounted for %d outcomes (gated=%d served=%d), want %d", gated+served, gated, served, n)
	}
}

// seedProbeCounter is an instrumented ReseedableCounter that wraps a real
// fakeReseedCounter and, at the moment RecoverSessions calls SeedAtLeast, runs the
// test's onSeed probe BEFORE delegating the real forward-only advance. It lets a
// DETERMINISTIC test observe the recover-before-serve latch state (s.recovered)
// at re-seed time without reaching into the unexported field: the probe issues a
// clone and the latch's effect on it (gate vs serve) is the observable. inSeed is
// captured so the test can confirm the probe really ran inside SeedAtLeast.
type seedProbeCounter struct {
	inner  *fakeReseedCounter
	onSeed func() // set AFTER the service is built (it closes over svc); nil ⇒ no probe
	inSeed bool   // recorded: did onSeed actually fire?
}

func (c *seedProbeCounter) Next() (uint64, error) { return c.inner.Next() }

// SeedAtLeast runs the probe (if wired) and THEN performs the real forward-only
// re-seed. RecoverSessions calls this BEFORE s.recovered.Store(true) (the
// Store-LAST ordering), so a probe clone issued here must observe the latch STILL
// CLOSED. A hairline reorder that moved the Store ahead of SeedAtLeast would let
// the probe observe the latch OPEN — the mutation this guard kills.
func (c *seedProbeCounter) SeedAtLeast(highest uint64) {
	if c.onSeed != nil {
		c.inSeed = true
		c.onSeed()
	}
	c.inner.SeedAtLeast(highest)
}

// newProbeDriverServiceWithRecovery builds a recovery-WIRED DriverService over the
// concurrency-safe locked* create-spine fakes (acked + fresh gate so a served clone
// is routable), exactly like newRaceDriverServiceWithRecovery, but threads a
// seedProbeCounter so a test can fire a probe at SeedAtLeast time. The same probe
// counter backs the Allocator (its Next is the inner counter's) and the reseed
// handle, so the re-seed advances the very counter a clone draws from. Returns the
// service and its probe counter.
func newProbeDriverServiceWithRecovery(t *testing.T, recovered []RecoveredSession) (*DriverService, *seedProbeCounter) {
	t.Helper()
	counter := &seedProbeCounter{inner: &fakeReseedCounter{}}
	recoverer := &fakeRecoverer{sessions: recovered}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, &lockedAttach{}, &lockedOverlay{}, &lockedCA{}, &lockedBooter{}, &fakeGate{acked: true, fresh: true})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(&fakeDomainDestroyer{}, &lockedAttach{}, &lockedOverlay{}, &fakeDurability{}, &fakeFlowBytes{})
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithRecovery(host, destroyer, recoverer, counter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithRecovery: %v", err)
	}
	return svc, counter
}

// TestRecoverSeedsCounterBeforeOpeningServeLatch is the DETERMINISTIC (non-race-
// scheduler) companion to TestCloneRaceWithRecoverNeverRecyclesIndex. It pins the
// Store-LAST ordering inside RecoverSessions: the shared counter is re-seeded PAST
// the highest recovered index BEFORE the recover-before-serve latch (s.recovered)
// is opened. The race test robustly catches gate-removal and reseed-removal, but
// by mutation testing it does NOT reliably catch a hairline reorder of
// s.recovered.Store(true) to BEFORE s.counter.SeedAtLeast — the inter-statement
// window is too small for the -race scheduler to interleave an Allocate. This
// guard closes that gap deterministically.
//
// HOW it observes the unexported latch: a seedProbeCounter fires a probe clone at
// the exact instant SeedAtLeast runs (inside RecoverSessions). Under the correct
// Store-LAST ordering the latch is STILL CLOSED then, so the probe clone GATES
// (codes.FailedPrecondition) WITHOUT drawing an index — the gate at the top of
// CloneFromImage returns before any counter draw, so the probe can't deadlock the
// re-seed or burn an index. If a refactor moved Store(true) ahead of SeedAtLeast,
// the probe would observe the latch OPEN and SERVE (codes.OK) instead — and this
// test FAILS (the mutation kill). TEST-ONLY: no service.go change; offline against
// the locked* fakes; deterministic; -race-clean (the probe runs on the same
// goroutine as RecoverSessions, fully ordered before the Store).
func TestRecoverSeedsCounterBeforeOpeningServeLatch(t *testing.T) {
	const highestRecovered = uint64(7)
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, highestRecovered)}
	svc, counter := newProbeDriverServiceWithRecovery(t, recovered)
	ctx := context.Background()

	// The probe: at SeedAtLeast time, issue a clone for a fresh session straight at
	// the DriverService (synchronous, same goroutine as RecoverSessions). Record the
	// status code so the assertion can read the latch's effect after recover returns.
	var probeCode codes.Code
	var probeErr error
	var probeHandedAtSeed int
	probeRan := false
	counter.onSeed = func() {
		probeRan = true
		// A NEW session disjoint from the recovered set and every other UUID, so the
		// clone must DRAW (never re-adopt a cached binding) — making the gate the only
		// thing that can stop it.
		_, err := svc.CloneFromImage(ctx, cloneReq("00000000-0000-4000-8000-0000000000f0"))
		probeCode = status.Code(err)
		probeErr = err
		// Indices drawn as of the gated probe. RecoverSessions itself draws none, so a
		// gate that returns BEFORE the counter draw leaves this at exactly 0.
		probeHandedAtSeed = counter.inner.handedLen()
	}

	// Drive the ONE real RecoverSessions. It re-seeds the counter (firing the probe)
	// and THEN opens the latch.
	if _, err := svc.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions faulted: %v", err)
	}

	// The probe must actually have run inside SeedAtLeast — otherwise the assertion
	// below would be vacuous.
	if !probeRan || !counter.inSeed {
		t.Fatalf("probe did not run at SeedAtLeast time (probeRan=%v inSeed=%v); the ordering guard never observed the latch", probeRan, counter.inSeed)
	}

	// THE GUARD: at re-seed time the serve latch was still closed, so the probe clone
	// GATED. Any other outcome (notably codes.OK — the latch already open) means the
	// Store-LAST ordering was violated: s.recovered.Store(true) ran BEFORE
	// s.counter.SeedAtLeast, the unsafe reorder the race test is too coarse to catch.
	if probeCode != codes.FailedPrecondition {
		t.Fatalf("Store-LAST ordering VIOLATED: a clone issued at SeedAtLeast time returned %v (err=%v), want FailedPrecondition — the recover-before-serve latch was already OPEN when the counter was re-seeded (s.recovered.Store ran before SeedAtLeast)", probeCode, probeErr)
	}

	// ZERO-INDEX-BURNED: the gate at the top of CloneFromImage returns BEFORE the
	// counter draw, so the gated probe drew NOTHING. This closes the future-refactor
	// leak the FailedPrecondition clause alone misses: a refactor that moved the gate
	// BELOW the index draw would STILL return FailedPrecondition yet silently burn a
	// never-recycled index (a D66 leak). RecoverSessions draws no index of its own, so
	// the count at seed time must be exactly 0.
	if probeHandedAtSeed != 0 {
		t.Fatalf("gated probe BURNED %d index(es) at SeedAtLeast time, want 0 — the recover-before-serve gate must return before the counter draw, or a never-recycled index leaks while the clone is still (correctly) gated (D66)", probeHandedAtSeed)
	}

	// Sanity: after RecoverSessions completes, the latch is open and a clone now
	// SERVES a never-recycled index strictly past the highest recovered (the property
	// the ordering protects). This also confirms the re-seed truly advanced the SHARED
	// counter the post-recover clone draws from.
	resp, err := svc.CloneFromImage(ctx, cloneReq("00000000-0000-4000-8000-0000000000f1"))
	if err != nil {
		t.Fatalf("post-recover clone faulted: %v", err)
	}
	if got := resp.GetHostSessionIndex(); got <= highestRecovered {
		t.Fatalf("post-recover clone drew index %d <= highest recovered %d — the re-seed did not advance the shared counter", got, highestRecovered)
	}
}

// TestServeLatchGuardRedensUnderStoreBeforeSeed CI-enforces that the Store-LAST
// ordering guard above (TestRecoverSeedsCounterBeforeOpeningServeLatch) is a REAL
// mutation-kill, not a vacuous assertion. It demonstrates that when the
// recover-before-serve latch is OPEN at SeedAtLeast time — the EXACT observable a
// Store-before-Seed reorder (s.recovered.Store(true) moved ahead of
// s.counter.SeedAtLeast) would expose on a real recover — BOTH of the guard's
// clauses flip to failure: the probe clone SERVES (codes.OK, not FailedPrecondition)
// AND BURNS a never-recycled index (handed grows, not zero). So that hairline
// reorder would redden the guard in CI, replacing the former review-only check (a
// transient service.go reorder + revert by hand).
//
// It produces the open-latch-at-seed condition WITHOUT editing service.go (the
// mutation lives there; this stays service_test.go-only): a FIRST RecoverSessions
// opens the latch correctly, then a SECOND RecoverSessions calls SeedAtLeast again
// with the latch ALREADY open — so a probe fired at that second seed sees precisely
// what the mutation would expose at the first. Deterministic, offline, -race-clean
// (the probe runs on the RecoverSessions goroutine).
func TestServeLatchGuardRedensUnderStoreBeforeSeed(t *testing.T) {
	const highestRecovered = uint64(7)
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, highestRecovered)}
	svc, counter := newProbeDriverServiceWithRecovery(t, recovered)
	ctx := context.Background()

	// First recover: opens the latch correctly (onSeed still nil ⇒ no probe yet).
	if _, err := svc.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("first RecoverSessions faulted: %v", err)
	}

	// Wire the probe, then recover AGAIN: at this SECOND SeedAtLeast the latch is
	// ALREADY open — the precise observable a Store-before-Seed reorder would expose.
	handedBefore := counter.inner.handedLen()
	var probeCode codes.Code
	probeHanded := 0
	probeRan := false
	counter.onSeed = func() {
		probeRan = true
		_, err := svc.CloneFromImage(ctx, cloneReq("00000000-0000-4000-8000-0000000000e0"))
		probeCode = status.Code(err)
		probeHanded = counter.inner.handedLen()
	}
	if _, err := svc.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("second RecoverSessions faulted: %v", err)
	}
	if !probeRan || !counter.inSeed {
		t.Fatalf("probe did not run at the second SeedAtLeast (probeRan=%v inSeed=%v); the mutation observable was never exercised", probeRan, counter.inSeed)
	}

	// THE GUARD'S FIRST CLAUSE FLIPS: with the latch open at seed time the probe clone
	// SERVES instead of gating — so the guard's `want FailedPrecondition` assertion
	// would FAIL under the mutation. (If this is FailedPrecondition, the probe is not
	// observing the open latch and the guard above would be vacuous.)
	if probeCode != codes.OK {
		t.Fatalf("with the latch OPEN at SeedAtLeast time the probe clone must SERVE (codes.OK), got %v — the guard's discriminator does not distinguish the Store-before-Seed observable, so the guard is vacuous", probeCode)
	}

	// THE GUARD'S SECOND CLAUSE FLIPS: a served clone DRAWS a never-recycled index, so
	// the zero-index-burned assertion would also FAIL under the mutation. Together the
	// two clauses make the guard a genuine kill of the Store-before-Seed reorder.
	if probeHanded <= handedBefore {
		t.Fatalf("a SERVED probe must BURN an index (handed grew): before=%d after=%d — the zero-index-burned clause would not catch the Store-before-Seed mutation", handedBefore, probeHanded)
	}
}

// ── snapshotRefs durability across restart (RecoveredSession.SnapshotRefs) ─────
//
// These tests pin the durable half of the snapshotRefs registry: a snapshot_ref a
// PRIOR incarnation captured is host-durable state, not driver-resident truth, so
// RecoverSessions must re-seed the in-memory registry from RecoveredSession.
// SnapshotRefs (the base-authority decision: the host's set is authoritative, the
// driver re-adopts it). A simulated restart is: build a driver whose recoverer
// reports a resident session carrying that captured ref, run RecoverSessions, and
// assert the export gate now admits that ref (rooting an incremental delta) while
// still failing NotFound — before the seam ever opens — for a ref the host never
// held. The recoverer stands in for the host-side SessionRecordStore re-observation
// (D50 synthetic, OFFLINE; no live VM/libvirt/qcow2).

// newTestDriverServiceWithRecoveryAndDiskDelta builds a driver wired for BOTH
// recovery (recoverer + the shared counter, per the D66 lockstep contract) AND the
// full D29 capture→export loop (SnapshotStore + DiskDeltaExporter) over one create
// path — the exact fan-in a simulated restart needs: RecoverSessions re-seeds the
// snapshotRefs registry from the recovered set, and ExportDiskDelta then consults it.
// recovered is the host-resident set the recoverer reports (each RecoveredSession's
// SnapshotRefs are the durable captured refs the host still holds). It returns the
// recovery-side fakes so a test can reach the recoverer/counter after the roundtrip.
func newTestDriverServiceWithRecoveryAndDiskDelta(t *testing.T, recovered []RecoveredSession, snapshots SnapshotStore, exporter DiskDeltaExporter) (*DriverService, *recoveryFakes) {
	t.Helper()
	sf := &serviceFakes{
		attach:  &fakeAttach{},
		overlay: &fakeOverlay{},
		ca:      &fakeCA{},
		booter:  &fakeBooter{},
		gate:    &fakeGate{acked: true, fresh: true},
		domain:  &fakeDomainDestroyer{},
		durab:   &fakeDurability{},
		flow:    &fakeFlowBytes{},
	}
	counter := &fakeReseedCounter{}
	recoverer := &fakeRecoverer{sessions: recovered}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	// The SAME counter backs the Allocator and the reseed handle (as in
	// newTestDriverServiceWithRecovery), so a recovery re-seed advances the very
	// counter a later clone draws from.
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, sf.attach, sf.overlay, sf.ca, sf.booter, sf.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(sf.domain, sf.attach, sf.overlay, sf.durab, sf.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithDiskDelta(host, destroyer, recoverer, counter, nil, nil, snapshots, exporter)
	if err != nil {
		t.Fatalf("NewDriverServiceWithDiskDelta: %v", err)
	}
	return svc, &recoveryFakes{serviceFakes: sf, counter: counter, recoverer: recoverer}
}

// recoveredWithSnapshotRefs builds a synthetic RecoveredSession at an index (like
// recoveredAt) but ALSO carrying a durable captured-ref set — the host-still-holds
// snapshot_refs a prior incarnation's Snapshot registered, the durable state the
// re-seed must re-adopt.
func recoveredWithSnapshotRefs(t *testing.T, sessionUUID string, index uint64, refs ...string) RecoveredSession {
	t.Helper()
	rs := recoveredAt(t, sessionUUID, index)
	rs.SnapshotRefs = refs
	return rs
}

// TestRecoveredSnapshotRefSurvivesReadoptionAndRootsIncrementalDelta is the
// keystone durability assertion: a snapshot_ref a PRIOR incarnation captured (now
// reported by the recoverer as durable host state on RecoveredSession.SnapshotRefs)
// survives a simulated re-adoption and roots an incremental ExportDiskDelta over the
// wire. Without the durable re-seed the registry would be empty after restart and
// this export would falsely fail NotFound even though the host still holds the
// point-in-time — so this test is the direct kill of the "registry lost on restart"
// defect. It also re-adopts the binding (the recovered session is a valid export
// target at all), closing the loop: re-adopted session + re-adopted base ⇒ the
// incremental delta streams, rooted at exactly the captured ref.
func TestRecoveredSnapshotRefSurvivesReadoptionAndRootsIncrementalDelta(t *testing.T) {
	// The durable base ref the host still holds for the recovered session — the same
	// opaque shape Snapshot would have produced pre-restart (overlay-delta://…), but
	// its VALIDITY here comes purely from the recovery re-seed, not any live Snapshot.
	const durableRef = "overlay-delta://" + recoverSessionA + "@pre-restart-base"
	recovered := []RecoveredSession{recoveredWithSnapshotRefs(t, recoverSessionA, 5, durableRef)}

	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithRecoveryAndDiskDelta(t, recovered, &fakeSnapshotStore{}, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// Simulate the restart: run RecoverSessions. This re-adopts the binding AND
	// re-seeds the snapshotRefs registry from the durable set.
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// The captured ref must now root an incremental export — NO live Snapshot ever
	// ran in this process; the ref's validity is the durable re-seed alone.
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: durableRef,
	})
	if err != nil {
		t.Fatalf("ExportDiskDelta(since=recovered ref): %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining incremental delta rooted at the recovered ref: %v", err)
	}

	// The export was ROOTED at the durable ref: the seam received it verbatim — the
	// re-seeded registry admitted it as a valid incremental base.
	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	if exp.calls[0].sinceSnapshotRef != durableRef {
		t.Errorf("export rooted at since_snapshot_ref %q, want the recovered durable ref %q (the registry re-seed must survive re-adoption)", exp.calls[0].sinceSnapshotRef, durableRef)
	}
	if exp.calls[0].sessionUUID != recoverSessionA {
		t.Errorf("export opened for session %q, want the re-adopted session %q", exp.calls[0].sessionUUID, recoverSessionA)
	}
	// And the streamed bytes are the distinct incremental payload for that base.
	if want := syntheticDelta(recoverSessionA, durableRef); !bytes.Equal(got, want) {
		t.Errorf("reassembled incremental delta = %q, want %q", got, want)
	}
}

// TestRecoveredSessionUnknownRefFailsNotFoundBeforeSeam is the fail-closed twin: a
// session re-adopted with SOME durable refs still rejects a since_snapshot_ref the
// host never held — codes.NotFound BEFORE the seam opens, so OpenDelta is never
// called. The recovery re-seed installs EXACTLY the durable set (not a wildcard), so
// the gate admits only the point-in-times the host actually keeps. This is the
// unknown-ref half of the acceptance: an unknown/host-absent ref fails NotFound
// before any seam opens.
func TestRecoveredSessionUnknownRefFailsNotFoundBeforeSeam(t *testing.T) {
	const durableRef = "overlay-delta://" + recoverSessionA + "@kept"
	recovered := []RecoveredSession{recoveredWithSnapshotRefs(t, recoverSessionA, 3, durableRef)}

	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithRecoveryAndDiskDelta(t, recovered, &fakeSnapshotStore{}, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// A ref the durable set does NOT contain (the host never held this point-in-time):
	// NotFound, before the seam.
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: "overlay-delta://" + recoverSessionA + "@never-held",
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("export rooted at a host-absent ref on a re-adopted session: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT open for a host-absent since_snapshot_ref, calls=%d", len(exp.calls))
	}
}

// TestRecoveredHostAbsentSessionRefFailsNotFoundBeforeSeam pins the other
// fail-closed edge: an export for a session the recoverer never reported (the host
// does not hold it) fails NotFound before the seam — even naming a plausible ref.
// The unknown-session check fires first: recovery only re-adopts what the host
// re-observed, so a session (and any ref attributed to it) that was never resident
// is host-absent and rejected before OpenDelta.
func TestRecoveredHostAbsentSessionRefFailsNotFoundBeforeSeam(t *testing.T) {
	// The recoverer reports ONLY recoverSessionA (with a durable ref); recoverSessionB
	// is host-absent.
	const durableRef = "overlay-delta://" + recoverSessionA + "@kept"
	recovered := []RecoveredSession{recoveredWithSnapshotRefs(t, recoverSessionA, 2, durableRef)}

	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithRecoveryAndDiskDelta(t, recovered, &fakeSnapshotStore{}, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionB,
		SinceSnapshotRef: durableRef,
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("export for a host-absent session: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 0 {
		t.Errorf("the seam must NOT open for a host-absent session, calls=%d", len(exp.calls))
	}
}

// TestRecoverEmptySnapshotRefsIsCleanNoOp asserts the common case — a recovered
// session that captured NOTHING (absent/empty SnapshotRefs) re-seeds no base, so its
// registry stays empty: a full-overlay export (empty since_snapshot_ref) still
// streams, but any non-empty ref for it is NotFound before the seam. Recovery never
// invents a base the host does not hold.
func TestRecoverEmptySnapshotRefsIsCleanNoOp(t *testing.T) {
	// No SnapshotRefs on the recovered session — the no-capture case.
	recovered := []RecoveredSession{recoveredAt(t, recoverSessionA, 4)}

	exp := &fakeDiskDeltaExporter{}
	svc, _ := newTestDriverServiceWithRecoveryAndDiskDelta(t, recovered, &fakeSnapshotStore{}, exp)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// Full-overlay export (empty base) streams for the re-adopted session.
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: recoverSessionA})
	if err != nil {
		t.Fatalf("ExportDiskDelta(empty ref, recovered session): %v", err)
	}
	if _, err := drainDelta(t, stream); err != nil {
		t.Fatalf("draining full-overlay delta for the recovered session: %v", err)
	}
	if len(exp.calls) != 1 || exp.calls[0].sinceSnapshotRef != "" {
		t.Fatalf("empty-ref export should open the seam once with an empty base, calls=%+v", exp.calls)
	}

	// But any non-empty ref for it is NotFound before the seam — the re-seed installed
	// no bases, and recovery invented none.
	stream2, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: "overlay-delta://" + recoverSessionA + "@phantom",
	})
	if err == nil {
		_, err = stream2.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("non-empty ref on a no-capture recovered session: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 1 {
		t.Errorf("the seam must NOT open for the phantom ref (calls should stay 1 from the full-overlay export), calls=%d", len(exp.calls))
	}
}

// TestRecoverDoesNotClobberAlreadySeededRefSet pins the first-writer-wins discipline
// the durable re-seed shares with the clone-cache re-seed: once a session's ref set
// is registered (a first recovery re-adopted its durable base, then a live Snapshot
// added a second), a SUBSEQUENT RecoverSessions reporting a DIFFERENT durable set for
// that same session must NOT overwrite the already-seeded set — the existing refs
// stay valid (recovery re-adopts only for a session the registry has not yet seeded).
// On a recovery-wired host the serve latch orders every clone AFTER the first
// recovery, so this second-recovery ordering is the deterministic, wire-reachable
// shape of the "recovery never clobbers a set already owned" guard.
func TestRecoverDoesNotClobberAlreadySeededRefSet(t *testing.T) {
	// First recovery re-adopts this durable base for the session.
	const firstRef = "overlay-delta://" + recoverSessionA + "@first-recovery"
	rec := &fakeRecoverer{sessions: []RecoveredSession{recoveredWithSnapshotRefs(t, recoverSessionA, 6, firstRef)}}

	sf := &serviceFakes{
		attach: &fakeAttach{}, overlay: &fakeOverlay{}, ca: &fakeCA{},
		booter: &fakeBooter{}, gate: &fakeGate{acked: true, fresh: true},
		domain: &fakeDomainDestroyer{}, durab: &fakeDurability{}, flow: &fakeFlowBytes{},
	}
	counter := &fakeReseedCounter{}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, sf.attach, sf.overlay, sf.ca, sf.booter, sf.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(sf.domain, sf.attach, sf.overlay, sf.durab, sf.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	exp := &fakeDiskDeltaExporter{}
	svc, err := NewDriverServiceWithDiskDelta(host, destroyer, rec, counter, nil, nil, &fakeSnapshotStore{}, exp)
	if err != nil {
		t.Fatalf("NewDriverServiceWithDiskDelta: %v", err)
	}
	client := dialInProcess(t, svc)
	ctx := context.Background()

	// First recovery: seeds firstRef and opens the serve latch.
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("first RecoverSessions: %v", err)
	}
	// A live Snapshot on the re-adopted session ADDS a second ref to the same set
	// (re-seeded base and live capture coexist).
	snapResp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: recoverSessionA, Label: "live"})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	liveRef := snapResp.GetSnapshotRef()

	// Second recovery reports a DIFFERENT durable ref for the same session — it must
	// NOT clobber/replace the already-seeded {firstRef, liveRef} set.
	const secondRef = "overlay-delta://" + recoverSessionA + "@second-recovery"
	rec.sessions = []RecoveredSession{recoveredWithSnapshotRefs(t, recoverSessionA, 6, secondRef)}
	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("second RecoverSessions: %v", err)
	}

	// Both the first-recovery base AND the live ref still root an export (the set was
	// preserved across the second recovery).
	for _, ref := range []string{firstRef, liveRef} {
		stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
			SessionUuid:      recoverSessionA,
			SinceSnapshotRef: ref,
		})
		if err != nil {
			t.Fatalf("ExportDiskDelta(preserved ref %q): %v", ref, err)
		}
		if _, err := drainDelta(t, stream); err != nil {
			t.Fatalf("draining export at preserved ref %q: %v", ref, err)
		}
	}

	// The second-recovery ref was NOT merged in (the set was already seeded, so the
	// second recovery re-adopted nothing for this session): NotFound before the seam.
	callsBefore := len(exp.calls)
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: secondRef,
	})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("second-recovery ref against an already-seeded set: code = %v, want NotFound (recovery must not clobber/merge an already-seeded set)", status.Code(err))
	}
	if len(exp.calls) != callsBefore {
		t.Errorf("the seam must NOT open for the un-adopted second-recovery ref, calls grew %d→%d", callsBefore, len(exp.calls))
	}
}

// ── snapshotRefs durability PRODUCER arc (Snapshot durable-write → recovery read-back) ──
//
// The tests above pin the CONSUMER side (RecoverSessions re-seeds the registry from
// RecoveredSession.SnapshotRefs). These pin the PRODUCER side that FEEDS it: Snapshot
// DURABLY records each captured ref into the CapturedRefStore, a §4.2 Destroy purges the
// durable set, and the production capturedRefRecoverer (seams.go) reads the set back out to
// populate RecoveredSession.SnapshotRefs — so a captured ref written on Snapshot survives a
// simulated restart and roots an incremental ExportDiskDelta. The store stands in for the
// host-side durable `.ds-sessions` area (D50 synthetic, OFFLINE; no live VM/libvirt/qcow2).

// fakeCapturedRefStore is a DETERMINISTIC in-memory CapturedRefStore (D50): it records
// each captured ref per session (a SET, idempotent on (session, ref)) in INSERTION ORDER
// so CapturedRefs is deterministic, and tracks removals. The error hooks force a durable
// write / read / purge fault so a test can assert the fail-closed (Snapshot) and fail-loud
// (recover, destroy) postures. It stands in for the real host-side file-backed store, which
// lands host-side; the fake keeps the wiring offline + stdlib (no filesystem, no live VM).
type fakeCapturedRefStore struct {
	mu        sync.Mutex
	order     map[string][]string            // session -> refs in insertion order
	seen      map[string]map[string]struct{} // session -> set (dedup)
	removed   []string                       // sessions purged (RemoveCapturedRefs)
	recordErr error
	readErr   error
	removeErr error
}

func newFakeCapturedRefStore() *fakeCapturedRefStore {
	return &fakeCapturedRefStore{
		order: make(map[string][]string),
		seen:  make(map[string]map[string]struct{}),
	}
}

func (f *fakeCapturedRefStore) RecordCapturedRef(_ context.Context, sessionUUID, snapshotRef string) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	if sessionUUID == "" || snapshotRef == "" {
		return fmt.Errorf("captured ref store: empty session or ref")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[sessionUUID] == nil {
		f.seen[sessionUUID] = make(map[string]struct{})
	}
	if _, ok := f.seen[sessionUUID][snapshotRef]; ok {
		return nil // idempotent set-insert: recording the same (session, ref) converges
	}
	f.seen[sessionUUID][snapshotRef] = struct{}{}
	f.order[sessionUUID] = append(f.order[sessionUUID], snapshotRef)
	return nil
}

func (f *fakeCapturedRefStore) CapturedRefs(_ context.Context, sessionUUID string) ([]string, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	refs := f.order[sessionUUID]
	if len(refs) == 0 {
		return nil, nil // the common empty case (a session that captured nothing)
	}
	out := make([]string, len(refs))
	copy(out, refs)
	return out, nil
}

func (f *fakeCapturedRefStore) RemoveCapturedRefs(_ context.Context, sessionUUID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, sessionUUID)
	delete(f.order, sessionUUID)
	delete(f.seen, sessionUUID)
	return nil
}

// has reports whether the durable set for a session contains ref (a test observation of
// the write leg's effect across the process boundary).
func (f *fakeCapturedRefStore) has(sessionUUID, ref string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.seen[sessionUUID][ref]
	return ok
}

// Compile-time assertion: the fake satisfies the producer-side durable seam.
var _ CapturedRefStore = (*fakeCapturedRefStore)(nil)

// newTestDriverServiceWithSnapshotAndCapturedRefs builds a SNAPSHOT-wired DriverService
// that ALSO durably persists captured refs into the supplied CapturedRefStore — the
// pre-restart "producer" incarnation: a test clones a session, snapshots it, and asserts
// the ref was durably recorded (and that Destroy purges it). No recovery is wired (the
// write side stands alone).
func newTestDriverServiceWithSnapshotAndCapturedRefs(t *testing.T, snapshots SnapshotStore, refs CapturedRefStore) (*DriverService, *serviceFakes) {
	t.Helper()
	f := &serviceFakes{
		attach: &fakeAttach{}, overlay: &fakeOverlay{}, ca: &fakeCA{},
		booter: &fakeBooter{}, gate: &fakeGate{acked: true, fresh: true},
		domain: &fakeDomainDestroyer{}, durab: &fakeDurability{}, flow: &fakeFlowBytes{},
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, f.attach, f.overlay, f.ca, f.booter, f.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(f.domain, f.attach, f.overlay, f.durab, f.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithCapturedRefStore(host, destroyer, nil, nil, nil, nil, snapshots, nil, nil, refs)
	if err != nil {
		t.Fatalf("NewDriverServiceWithCapturedRefStore: %v", err)
	}
	return svc, f
}

// newRestartDriverServiceWithCapturedRefs builds the POST-restart incarnation: a
// recovery-wired DriverService whose SessionRecoverer is the production capturedRefRecoverer
// (seams.go) decorating a fakeRecoverer (the inner host-resident re-observation, reporting
// bindings with NO SnapshotRefs) over the SAME durable store — so the read-back leg layers
// the durable captured refs onto each RecoveredSession. It also wires the DiskDeltaExporter
// (so a recovered ref can root an incremental export) and the store (so a post-restart
// Snapshot also persists). innerRecovered is what the inner recoverer reports.
func newRestartDriverServiceWithCapturedRefs(t *testing.T, innerRecovered []RecoveredSession, refs CapturedRefStore, snapshots SnapshotStore, exporter DiskDeltaExporter) (*DriverService, *recoveryFakes) {
	t.Helper()
	sf := &serviceFakes{
		attach: &fakeAttach{}, overlay: &fakeOverlay{}, ca: &fakeCA{},
		booter: &fakeBooter{}, gate: &fakeGate{acked: true, fresh: true},
		domain: &fakeDomainDestroyer{}, durab: &fakeDurability{}, flow: &fakeFlowBytes{},
	}
	counter := &fakeReseedCounter{}
	innerRec := &fakeRecoverer{sessions: innerRecovered}
	recoverer, err := NewSessionRecovererWithCapturedRefs(innerRec, refs)
	if err != nil {
		t.Fatalf("NewSessionRecovererWithCapturedRefs: %v", err)
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	host, err := NewHostAgent(alloc, sf.attach, sf.overlay, sf.ca, sf.booter, sf.gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	destroyer, err := NewDestroyer(sf.domain, sf.attach, sf.overlay, sf.durab, sf.flow)
	if err != nil {
		t.Fatalf("NewDestroyer: %v", err)
	}
	svc, err := NewDriverServiceWithCapturedRefStore(host, destroyer, recoverer, counter, nil, nil, snapshots, exporter, nil, refs)
	if err != nil {
		t.Fatalf("NewDriverServiceWithCapturedRefStore: %v", err)
	}
	return svc, &recoveryFakes{serviceFakes: sf, counter: counter, recoverer: innerRec}
}

// TestSnapshotDurablyRecordsCapturedRef asserts the WRITE LEG: a successful Snapshot
// durably records the captured ref into the CapturedRefStore (not only the in-memory
// registry), so the ref outlives the process. This is the direct producer-side twin of the
// landed consumer re-seed — without it RecoveredSession.SnapshotRefs is always empty.
func TestSnapshotDurablyRecordsCapturedRef(t *testing.T) {
	store := newFakeCapturedRefStore()
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshotAndCapturedRefs(t, snap, store)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	resp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "cp"})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	ref := resp.GetSnapshotRef()
	if ref == "" {
		t.Fatal("Snapshot returned an empty snapshot_ref")
	}
	if !store.has(testCloneSession, ref) {
		t.Errorf("captured ref %q was not durably recorded — the Snapshot write leg must persist it into the CapturedRefStore", ref)
	}
}

// TestSnapshotDurableWriteFaultFailsClosed asserts a durable-write fault fails the RPC
// (codes.Internal) rather than reporting a capture whose base a restart would silently lose
// — the fail-closed posture. The physical capture (the SnapshotStore seam) succeeded, but a
// ref that is not provably durable must not be reported as a stable since_snapshot_ref base.
func TestSnapshotDurableWriteFaultFailsClosed(t *testing.T) {
	store := newFakeCapturedRefStore()
	store.recordErr = errors.New("durable store: disk full")
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshotAndCapturedRefs(t, snap, store)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	_, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Snapshot with a durable-write fault: code = %v, want Internal", status.Code(err))
	}
	// The physical capture seam WAS driven (the fault is on the durable persist, after).
	if len(snap.calls) != 1 {
		t.Errorf("SnapshotStore.CreateSnapshot calls = %d, want 1 (the seam runs before the durable persist)", len(snap.calls))
	}
}

// TestSnapshotDurableWriteDefaultOffByteIdentical asserts that with NO CapturedRefStore
// wired (the default-off posture), Snapshot behaves exactly as the in-memory-only path: it
// captures and returns the ref with no durable side effect. This is the byte-identical
// default the production fail-closed contract rests on.
func TestSnapshotDurableWriteDefaultOffByteIdentical(t *testing.T) {
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshot(t, snap) // no capturedRefs store
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	resp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession, Label: "cp"})
	if err != nil {
		t.Fatalf("Snapshot (no durable store): %v", err)
	}
	if resp.GetSnapshotRef() == "" {
		t.Error("Snapshot must still return the opaque ref with no CapturedRefStore wired")
	}
}

// TestDestroyPurgesDurableCapturedRefs asserts the §4.2 teardown purges the durable
// captured-ref set (the producer-half twin of the in-memory drop) so a later recovery never
// re-adopts a since_snapshot_ref base whose overlay the teardown destroyed.
func TestDestroyPurgesDurableCapturedRefs(t *testing.T) {
	store := newFakeCapturedRefStore()
	snap := &fakeSnapshotStore{}
	svc, _ := newTestDriverServiceWithSnapshotAndCapturedRefs(t, snap, store)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	resp, err := client.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: testCloneSession})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	ref := resp.GetSnapshotRef()
	if !store.has(testCloneSession, ref) {
		t.Fatalf("precondition: captured ref %q should be durably recorded before Destroy", ref)
	}

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if store.has(testCloneSession, ref) {
		t.Errorf("Destroy must purge the durable captured-ref set; ref %q still present", ref)
	}
}

// failingSessionRecordStore is a SessionRecordStore whose Remove always faults, so a
// test can assert the §4.2 record purge is BEST-EFFORT: a removal fault leaves a stale
// record but must NEVER turn a clean teardown (domain gone, NFT objects flushed, overlay
// disposed) into a faulted Destroy over the wire. Put/Get are unused by the service.
type failingSessionRecordStore struct {
	removed []string
}

func (s *failingSessionRecordStore) Put(_ context.Context, _ SessionRecord) error { return nil }

func (s *failingSessionRecordStore) Get(_ context.Context, _ string) (SessionRecord, bool, error) {
	return SessionRecord{}, false, nil
}

func (s *failingSessionRecordStore) Remove(_ context.Context, sessionUUID string) error {
	s.removed = append(s.removed, sessionUUID)
	return errors.New("record dir is read-only")
}

var _ SessionRecordStore = (*failingSessionRecordStore)(nil)

// TestDestroyRemovesDurableSessionRecord asserts the §4.2 teardown removes the durable
// SessionRecord the create path Put at boot (sessionrecord.go's Remove contract, "the §4.2
// teardown"). Left behind, the liveSessionRecoverer re-adopts the DESTROYED session on the
// next host-agent restart and the reconciler orphan-quarantines a session with no VM.
func TestDestroyRemovesDurableSessionRecord(t *testing.T) {
	store, err := NewFileSessionRecordStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionRecordStore: %v", err)
	}
	svc, _ := newTestDriverService(t)
	svc.WithSessionRecordStore(store)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if err := store.Put(ctx, SessionRecord{SessionUUID: testCloneSession, DomainUUID: "dom-1"}); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	if _, found, err := store.Get(ctx, testCloneSession); err != nil || !found {
		t.Fatalf("precondition: record must exist before Destroy (found=%v err=%v)", found, err)
	}

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	_, found, err := store.Get(ctx, testCloneSession)
	if err != nil {
		t.Fatalf("Get after Destroy: %v", err)
	}
	if found {
		t.Error("Destroy must remove the durable session record; a destroyed session would be re-adopted on restart")
	}
	// Idempotent: a re-drive over the already-removed record still converges (a missing
	// record is a no-op success by contract).
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (re-drive): %v", err)
	}
}

// TestDestroyRecordRemovalIsBestEffort asserts a record-removal fault is swallowed from the
// §4.2 verdict (recorded to the log, never re-surfaced): the host-local teardown IS the
// teardown contract and it already converged, and the only residue is a stale record — the
// missing-record case is already a success by contract.
func TestDestroyRecordRemovalIsBestEffort(t *testing.T) {
	store := &failingSessionRecordStore{}
	svc, _ := newTestDriverService(t)
	svc.WithSessionRecordStore(store)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("a record-removal fault must NOT fail the §4.2 destroy, got %v", err)
	}
	if len(store.removed) != 1 || store.removed[0] != testCloneSession {
		t.Fatalf("Destroy must attempt the record removal, got %v", store.removed)
	}
}

// TestDestroyWithoutSessionRecordStoreIsUnchanged pins the OFF-by-default posture: with no
// store wired (every unit test and the offline default) the destroy is byte-identical to the
// historical path — no purge, no fault.
func TestDestroyWithoutSessionRecordStoreIsUnchanged(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)
	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (no record store wired): %v", err)
	}
}

// TestNewSessionRecovererWithCapturedRefsRejectsNilArgs asserts the read-back decorator
// constructor rejects a nil inner recoverer or a nil store (a programming error surfaced at
// construction, not at the first recover), the seams.go/service.go construction-time posture.
func TestNewSessionRecovererWithCapturedRefsRejectsNilArgs(t *testing.T) {
	if _, err := NewSessionRecovererWithCapturedRefs(nil, newFakeCapturedRefStore()); err == nil {
		t.Error("a nil inner recoverer must be a construction error")
	}
	if _, err := NewSessionRecovererWithCapturedRefs(&fakeRecoverer{}, nil); err == nil {
		t.Error("a nil captured-ref store must be a construction error")
	}
}

// TestCapturedRefRecovererReadsBackDurableSet asserts the READ-BACK LEG directly (no gRPC):
// the decorator layers each recovered session's durable captured-ref set onto
// RecoveredSession.SnapshotRefs, and a session that captured nothing gets an EMPTY set
// (fail-closed re-seed) — the inner recoverer never reports SnapshotRefs, the store is the
// sole source.
func TestCapturedRefRecovererReadsBackDurableSet(t *testing.T) {
	ctx := context.Background()
	store := newFakeCapturedRefStore()
	if err := store.RecordCapturedRef(ctx, recoverSessionA, "overlay-delta://a@r1"); err != nil {
		t.Fatalf("seed r1: %v", err)
	}
	if err := store.RecordCapturedRef(ctx, recoverSessionA, "overlay-delta://a@r2"); err != nil {
		t.Fatalf("seed r2: %v", err)
	}
	// recoverSessionB captured nothing (absent from the store).
	inner := &fakeRecoverer{sessions: []RecoveredSession{
		recoveredAt(t, recoverSessionA, 3),
		recoveredAt(t, recoverSessionB, 4),
	}}
	dec, err := NewSessionRecovererWithCapturedRefs(inner, store)
	if err != nil {
		t.Fatalf("NewSessionRecovererWithCapturedRefs: %v", err)
	}

	got, err := dec.RecoverSessions(ctx, "host-1")
	if err != nil {
		t.Fatalf("decorated RecoverSessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("recovered %d sessions, want 2", len(got))
	}
	bySession := map[string][]string{}
	for _, rs := range got {
		bySession[rs.SessionUUID] = rs.SnapshotRefs
	}
	if a := bySession[recoverSessionA]; len(a) != 2 {
		t.Errorf("session A SnapshotRefs = %v, want 2 durable refs read back", a)
	}
	if b := bySession[recoverSessionB]; len(b) != 0 {
		t.Errorf("session B SnapshotRefs = %v, want empty (it captured nothing) — recovery must not invent a base", b)
	}
}

// TestCapturedRefRecovererSurfacesStoreFault asserts a CapturedRefStore read fault is
// surfaced non-nil (fail-loud) — a corrupt durable set must not silently drop a still-held
// base, mirroring the inner recoverer's corrupt-SessionRecord posture.
func TestCapturedRefRecovererSurfacesStoreFault(t *testing.T) {
	ctx := context.Background()
	store := newFakeCapturedRefStore()
	store.readErr = errors.New("durable store: corrupt captured-ref record")
	inner := &fakeRecoverer{sessions: []RecoveredSession{recoveredAt(t, recoverSessionA, 3)}}
	dec, err := NewSessionRecovererWithCapturedRefs(inner, store)
	if err != nil {
		t.Fatalf("NewSessionRecovererWithCapturedRefs: %v", err)
	}
	if _, err := dec.RecoverSessions(ctx, "host-1"); err == nil {
		t.Error("a CapturedRefStore read fault must surface (fail-loud), got nil")
	}
}

// TestCapturedRefRecovererEmptyInnerIsCleanNoOp asserts a fresh host (the inner recoverer
// reports nothing) is a clean no-op: no store reads, an empty result — the decorator adds no
// behavior when there is nothing to annotate.
func TestCapturedRefRecovererEmptyInnerIsCleanNoOp(t *testing.T) {
	ctx := context.Background()
	store := newFakeCapturedRefStore()
	store.readErr = errors.New("must not be consulted on an empty inner result")
	inner := &fakeRecoverer{sessions: nil}
	dec, err := NewSessionRecovererWithCapturedRefs(inner, store)
	if err != nil {
		t.Fatalf("NewSessionRecovererWithCapturedRefs: %v", err)
	}
	got, err := dec.RecoverSessions(ctx, "fresh-host")
	if err != nil {
		t.Fatalf("decorated RecoverSessions(fresh host): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("fresh host recovered %d sessions, want 0", len(got))
	}
}

// TestCapturedRefWrittenOnSnapshotSurvivesRestartAndRootsIncrementalDelta is the KEYSTONE
// producer-arc acceptance: a ref written on Snapshot in one incarnation survives a simulated
// restart (a fresh in-memory registry) and roots an incremental ExportDiskDelta in the next —
// wired end to end through the durable CapturedRefStore (write leg) and the production
// capturedRefRecoverer (read-back leg). One store spans the two "processes". It also pins the
// fail-closed edge: a ref the store never held is NotFound before the seam after the restart.
func TestCapturedRefWrittenOnSnapshotSurvivesRestartAndRootsIncrementalDelta(t *testing.T) {
	store := newFakeCapturedRefStore()
	ctx := context.Background()

	// ── Process 1 (pre-restart): clone + Snapshot DURABLY records the captured ref. ──
	svc1, _ := newTestDriverServiceWithSnapshotAndCapturedRefs(t, &fakeSnapshotStore{}, store)
	client1 := dialInProcess(t, svc1)
	if _, err := client1.CloneFromImage(ctx, cloneReq(recoverSessionA)); err != nil {
		t.Fatalf("pre-restart CloneFromImage: %v", err)
	}
	snapResp, err := client1.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: recoverSessionA, Label: "pre-restart"})
	if err != nil {
		t.Fatalf("pre-restart Snapshot: %v", err)
	}
	capturedRef := snapResp.GetSnapshotRef()
	if capturedRef == "" {
		t.Fatal("pre-restart Snapshot returned an empty ref")
	}
	if !store.has(recoverSessionA, capturedRef) {
		t.Fatalf("the write leg must durably record %q (it must survive the process boundary)", capturedRef)
	}

	// ── Process 2 (post-restart): FRESH in-memory registry. The recoverer is the ──
	// production decorator reading the SAME durable store; the inner recoverer reports the
	// resident binding with NO SnapshotRefs (the record never carried them). Recovery reads
	// the durable set back to re-seed the registry — no live Snapshot runs here.
	inner := []RecoveredSession{recoveredAt(t, recoverSessionA, 5)} // no SnapshotRefs on the inner report
	exp := &fakeDiskDeltaExporter{}
	svc2, _ := newRestartDriverServiceWithCapturedRefs(t, inner, store, &fakeSnapshotStore{}, exp)
	client2 := dialInProcess(t, svc2)

	if _, err := client2.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("post-restart RecoverSessions: %v", err)
	}

	// The captured ref survived the restart: it roots an incremental ExportDiskDelta whose
	// base the seam receives verbatim — the registry re-seed came purely from the durable
	// read-back (no live Snapshot ran in Process 2).
	stream, err := client2.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: capturedRef,
	})
	if err != nil {
		t.Fatalf("post-restart ExportDiskDelta(since=captured ref): %v", err)
	}
	got, err := drainDelta(t, stream)
	if err != nil {
		t.Fatalf("draining incremental delta rooted at the surviving ref: %v", err)
	}
	if len(exp.calls) != 1 {
		t.Fatalf("OpenDelta calls = %d, want 1", len(exp.calls))
	}
	if exp.calls[0].sinceSnapshotRef != capturedRef {
		t.Errorf("export rooted at %q, want the surviving captured ref %q (the producer arc must thread it through a restart)", exp.calls[0].sinceSnapshotRef, capturedRef)
	}
	if want := syntheticDelta(recoverSessionA, capturedRef); !bytes.Equal(got, want) {
		t.Errorf("reassembled incremental delta = %q, want %q", got, want)
	}

	// Fail-closed after the restart: a ref the durable store never held is NotFound BEFORE
	// the seam — the re-seed installed exactly the durable set, not a wildcard.
	callsBefore := len(exp.calls)
	stream2, err := client2.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: "overlay-delta://" + recoverSessionA + "@never-captured",
	})
	if err == nil {
		_, err = stream2.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("a ref the store never held, after restart: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != callsBefore {
		t.Errorf("the seam must NOT open for a host-absent ref after restart, calls grew %d→%d", callsBefore, len(exp.calls))
	}
}

// TestCapturedRefEmptyRecordYieldsEmptySnapshotRefsAcrossRestart asserts the fail-closed
// empty-record behavior end to end: a session the durable store has NO record for (it
// captured nothing before the restart) recovers with an EMPTY SnapshotRefs set, so a
// full-overlay export still streams but any non-empty ref is NotFound before the seam.
// Recovery never invents a base the durable store does not hold.
func TestCapturedRefEmptyRecordYieldsEmptySnapshotRefsAcrossRestart(t *testing.T) {
	store := newFakeCapturedRefStore() // empty: the session captured nothing pre-restart
	ctx := context.Background()

	inner := []RecoveredSession{recoveredAt(t, recoverSessionA, 4)}
	exp := &fakeDiskDeltaExporter{}
	svc, _ := newRestartDriverServiceWithCapturedRefs(t, inner, store, &fakeSnapshotStore{}, exp)
	client := dialInProcess(t, svc)

	if _, err := client.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: "host-1"}); err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}

	// Full-overlay export (empty base) streams for the re-adopted session.
	stream, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: recoverSessionA})
	if err != nil {
		t.Fatalf("ExportDiskDelta(empty base): %v", err)
	}
	if _, err := drainDelta(t, stream); err != nil {
		t.Fatalf("draining full-overlay delta: %v", err)
	}
	if len(exp.calls) != 1 || exp.calls[0].sinceSnapshotRef != "" {
		t.Fatalf("empty-base export should open the seam once with an empty base, calls=%+v", exp.calls)
	}

	// But any non-empty ref is NotFound before the seam — the empty durable record re-seeds
	// an empty set (fail-closed), and recovery invents no base.
	stream2, err := client.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{
		SessionUuid:      recoverSessionA,
		SinceSnapshotRef: "overlay-delta://" + recoverSessionA + "@phantom",
	})
	if err == nil {
		_, err = stream2.Recv()
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("non-empty ref against an empty durable record: code = %v, want NotFound", status.Code(err))
	}
	if len(exp.calls) != 1 {
		t.Errorf("the seam must NOT open for the phantom ref (calls should stay 1), calls=%d", len(exp.calls))
	}
}

// ── §4.2 per-session HOST-STATE purge (attach token / config drive / mode marker) ──
//
// The §4.2 ordering (destroy.go) unwinds the substrate the session ran ON; these purges
// drop the per-session state the host wrote BESIDE it under the OverlayDir, which no
// destroy step owned and which therefore outlived every teardown (doc 15 §4.2; the doc 06
// §(b) clean-teardown row's "no leftover minted identity").

// recordingTokenDisposer is an in-memory AttachTokenDisposer: it records each purged
// session and can be made to fault, so a test can assert BOTH that the §4.2 teardown
// purges the D39 bearer token and that a purge fault is FAIL-LOUD (a credential the host
// could not delete must not read as a clean teardown).
type recordingTokenDisposer struct {
	removed []string
	err     error
}

func (d *recordingTokenDisposer) RemoveToken(_ context.Context, sessionUUID string) error {
	d.removed = append(d.removed, sessionUUID)
	return d.err
}

var _ AttachTokenDisposer = (*recordingTokenDisposer)(nil)

// recordingConfigDriveDisposer is the ConfigDriveDisposer twin of the above (the
// credential-bearing image + staging dir).
type recordingConfigDriveDisposer struct {
	removed []string
	err     error
}

func (d *recordingConfigDriveDisposer) RemoveConfigDrive(_ context.Context, sessionUUID string) error {
	d.removed = append(d.removed, sessionUUID)
	return d.err
}

var _ ConfigDriveDisposer = (*recordingConfigDriveDisposer)(nil)

// TestDestroyPurgesPerSessionHostState asserts a CONVERGED §4.2 Destroy purges all three
// per-session host artifacts — the attach token, the config drive, and the resolved-mode
// marker — each named with the torn-down session, and that a RE-DRIVE still converges (an
// absent artifact is a clean no-op by every seam's contract).
func TestDestroyPurgesPerSessionHostState(t *testing.T) {
	tokens := &recordingTokenDisposer{}
	drives := &recordingConfigDriveDisposer{}
	modes := newRecordingModeStore()
	modes.put[testCloneSession] = SessionModeTerminal

	svc, _ := newTestDriverService(t)
	svc.WithAttachTokenDisposer(tokens).WithConfigDriveDisposer(drives).WithSessionModeStore(modes)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if len(tokens.removed) != 1 || tokens.removed[0] != testCloneSession {
		t.Errorf("Destroy must purge the per-session attach token (D39 bearer credential), got %v", tokens.removed)
	}
	if len(drives.removed) != 1 || drives.removed[0] != testCloneSession {
		t.Errorf("Destroy must dispose the per-session config drive (config.pb holds injected env creds), got %v", drives.removed)
	}
	if len(modes.removed) != 1 || modes.removed[0] != testCloneSession {
		t.Errorf("Destroy must purge the per-session resolved-mode marker, got %v", modes.removed)
	}
	if _, still := modes.put[testCloneSession]; still {
		t.Error("the resolved-mode marker must be gone after the §4.2 teardown")
	}

	// Idempotent: a re-drive over the already-purged session still converges.
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (re-drive): %v", err)
	}
}

// TestDestroyAttachTokenPurgeIsFailLoud: a token-purge fault is surfaced as a gRPC error,
// NOT swallowed — the residue is a LIVE bearer credential (its TTL is the store's only
// revocation mechanism, doc 19 §7), so the reconciler must re-drive the idempotent purge.
// This is the capturedRefs posture, deliberately NOT the best-effort record posture.
func TestDestroyAttachTokenPurgeIsFailLoud(t *testing.T) {
	tokens := &recordingTokenDisposer{err: errors.New("token dir is read-only")}
	svc, _ := newTestDriverService(t)
	svc.WithAttachTokenDisposer(tokens)
	client := dialInProcess(t, svc)

	_, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession})
	if err == nil {
		t.Fatal("a token-purge fault must fail the §4.2 Destroy (a live credential is left on disk)")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("token-purge fault code = %v, want Internal", status.Code(err))
	}
	if len(tokens.removed) != 1 {
		t.Fatalf("Destroy must attempt the token purge, got %v", tokens.removed)
	}
}

// TestDestroyConfigDrivePurgeIsFailLoud: same posture for the config drive — the staging
// dir holds config.pb 0400 (the rendered EntrypointConfig with the session's injected env
// credentials), so an undisposed drive is a credential leak, not bookkeeping.
func TestDestroyConfigDrivePurgeIsFailLoud(t *testing.T) {
	drives := &recordingConfigDriveDisposer{err: errors.New("overlay dir is read-only")}
	svc, _ := newTestDriverService(t)
	svc.WithConfigDriveDisposer(drives)
	client := dialInProcess(t, svc)

	_, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession})
	if err == nil {
		t.Fatal("a config-drive disposal fault must fail the §4.2 Destroy (credential material is left on disk)")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("config-drive fault code = %v, want Internal", status.Code(err))
	}
}

// TestDestroyModeMarkerPurgeIsBestEffort: the mode marker's residue is ONE stale
// bookkeeping file, so a purge fault is recorded to the log and swallowed from the §4.2
// verdict — it must not convert an otherwise-clean teardown (domain gone, NFT objects
// flushed, overlay disposed) into a faulted Destroy over the wire. This is the
// sessionRecords posture, deliberately NOT the fail-loud credential posture above.
func TestDestroyModeMarkerPurgeIsBestEffort(t *testing.T) {
	modes := newRecordingModeStore()
	modes.removeErr = errors.New("mode dir is read-only")
	svc, _ := newTestDriverService(t)
	svc.WithSessionModeStore(modes)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("a mode-marker purge fault must NOT fail the §4.2 destroy, got %v", err)
	}
	if len(modes.removed) != 1 || modes.removed[0] != testCloneSession {
		t.Fatalf("Destroy must attempt the marker purge, got %v", modes.removed)
	}
}

// TestFaultedDestroyKeepsPerSessionHostState pins the keep-for-re-drive semantics the
// capturedRefs/sessionRecords purges already hold: a Destroy whose §4.2 ordering FAULTED
// (here a domain that will not die) purges NOTHING, so the reconciler's re-drive still
// finds the session's host state to reap. The purges run only after a CONVERGED teardown.
func TestFaultedDestroyKeepsPerSessionHostState(t *testing.T) {
	tokens := &recordingTokenDisposer{}
	drives := &recordingConfigDriveDisposer{}
	modes := newRecordingModeStore()
	modes.put[testCloneSession] = SessionModeTerminal
	records := &failingSessionRecordStore{}

	svc, fakes := newTestDriverService(t)
	fakes.domain.err = errors.New("libvirtd unreachable")
	svc.WithAttachTokenDisposer(tokens).WithConfigDriveDisposer(drives).
		WithSessionModeStore(modes).WithSessionRecordStore(records)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err == nil {
		t.Fatal("a §4.2 teardown fault must surface so the reconciler re-drives")
	}
	if len(tokens.removed) != 0 {
		t.Errorf("a FAULTED destroy must not purge the attach token, got %v", tokens.removed)
	}
	if len(drives.removed) != 0 {
		t.Errorf("a FAULTED destroy must not dispose the config drive, got %v", drives.removed)
	}
	if len(modes.removed) != 0 {
		t.Errorf("a FAULTED destroy must not purge the mode marker, got %v", modes.removed)
	}
	if len(records.removed) != 0 {
		t.Errorf("a FAULTED destroy must keep the durable record for the re-drive, got %v", records.removed)
	}
}

// TestDestroyWithoutHostStateSeamsIsUnchanged pins the OFF-by-default posture: with none
// of the three seams wired (every unit test, and the offline default for the token/mode
// stores) the destroy is byte-identical to the historical path — no purge, no fault.
func TestDestroyWithoutHostStateSeamsIsUnchanged(t *testing.T) {
	svc, _ := newTestDriverService(t)
	client := dialInProcess(t, svc)
	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (no host-state seams wired): %v", err)
	}
}

// ── §4.2 teardown purge (CABundleDisposer) ───────────────────────────────────
//
// The interception-CA bundle is the FOURTH per-session artifact the host wrote beside the
// session and no destroy step owned: the cert the orchestrator producer dropped under
// .ds-ca-bundles and its proxy-bound PKCS#8 PRIVATE KEY sibling (D82; doc 16 §4; doc 25
// §12). Unlike the other three it is keyed on the caBundleRef, not the session_uuid, so
// these tests also pin that the ref is threaded out of the durable SessionRecord via the
// DestroyResolver — on the cacheHit path too, since the wire clone response never names
// the CA.

// recordingCABundleDisposer is the CABundleDisposer twin of recordingTokenDisposer: it
// records every ref it was asked to dispose and can be made to fault.
type recordingCABundleDisposer struct {
	disposed []string
	err      error
}

func (d *recordingCABundleDisposer) DisposeCABundle(_ context.Context, caBundleRef string) error {
	d.disposed = append(d.disposed, caBundleRef)
	return d.err
}

var _ CABundleDisposer = (*recordingCABundleDisposer)(nil)

// TestDestroyDisposesCABundle: a CONVERGED §4.2 Destroy disposes the session's CA bundle
// exactly once, named by the ref the resolver read off the durable record. The session is
// CLONED first, so this exercises the cacheHit path — the common in-process case, and the
// one where the ref could most easily be dropped (the clone cache pins the wire response,
// which carries no CA ref, so the ref must still be taken from the record).
func TestDestroyDisposesCABundle(t *testing.T) {
	const wantRef = "ca:sess-clone"
	bundles := &recordingCABundleDisposer{}
	resolver := &fakeDestroyResolver{state: DestroyState{DomainUUID: "dom-1", CABundleRef: wantRef}}
	svc := newResolverDriverService(t, &fakeDomainDestroyer{}, resolver)
	svc.WithCABundleDisposer(bundles)
	client := dialInProcess(t, svc)
	ctx := context.Background()

	if _, err := client.CloneFromImage(ctx, cloneReq(testCloneSession)); err != nil {
		t.Fatalf("CloneFromImage: %v", err)
	}
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if len(bundles.disposed) != 1 || bundles.disposed[0] != wantRef {
		t.Fatalf("Destroy must dispose the interception CA bundle (cert + proxy-bound key) named by the record's ref, got %v want [%q]", bundles.disposed, wantRef)
	}
}

// TestDestroyCABundleDisposeIsFailLoud: a disposal fault is surfaced as a gRPC Internal
// error with NO response — the residue is a live CA private key, so an undisposed bundle
// must not read as a clean teardown. This is the attach-token/config-drive posture,
// deliberately NOT the best-effort record posture.
func TestDestroyCABundleDisposeIsFailLoud(t *testing.T) {
	bundles := &recordingCABundleDisposer{err: errors.New("ca bundle dir is read-only")}
	resolver := &fakeDestroyResolver{state: DestroyState{CABundleRef: "ca:sess-x"}}
	svc := newResolverDriverService(t, &fakeDomainDestroyer{}, resolver)
	svc.WithCABundleDisposer(bundles)
	client := dialInProcess(t, svc)

	resp, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession})
	if err == nil {
		t.Fatal("a CA-bundle disposal fault must fail the §4.2 Destroy (a live CA private key is left on disk)")
	}
	if resp != nil {
		t.Errorf("a faulted destroy must return no response, got %v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("CA-bundle disposal fault code = %v, want Internal", status.Code(err))
	}
	if len(bundles.disposed) != 1 {
		t.Fatalf("Destroy must attempt the CA-bundle disposal, got %v", bundles.disposed)
	}
}

// TestFaultedDestroyKeepsCABundle: a Destroy whose §4.2 ordering FAULTED (here a domain
// that will not die) disposes NOTHING, so the reconciler's re-drive can still resolve the
// ref and re-purge. The disposal runs only after a CONVERGED teardown — the same
// keep-for-re-drive semantics the other host-state purges hold.
func TestFaultedDestroyKeepsCABundle(t *testing.T) {
	bundles := &recordingCABundleDisposer{}
	resolver := &fakeDestroyResolver{state: DestroyState{CABundleRef: "ca:sess-x"}}
	svc := newResolverDriverService(t, &fakeDomainDestroyer{err: errors.New("libvirtd unreachable")}, resolver)
	svc.WithCABundleDisposer(bundles)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err == nil {
		t.Fatal("a §4.2 teardown fault must surface so the reconciler re-drives")
	}
	if len(bundles.disposed) != 0 {
		t.Errorf("a FAULTED destroy must not dispose the CA bundle, got %v", bundles.disposed)
	}
}

// TestDestroyWithoutCABundleDisposerIsUnchanged pins the OFF-by-default posture: with the
// seam unwired (every unit test, and the offline default — no producer drop ever lands off
// the gate) the destroy is byte-identical to the historical path, resolver and all.
func TestDestroyWithoutCABundleDisposerIsUnchanged(t *testing.T) {
	resolver := &fakeDestroyResolver{state: DestroyState{CABundleRef: "ca:sess-x"}}
	svc := newResolverDriverService(t, &fakeDomainDestroyer{}, resolver)
	client := dialInProcess(t, svc)
	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (no CA-bundle disposer wired): %v", err)
	}
}

// TestDestroyEmptyCARefSkipsCABundleDispose: a PRE-UPGRADE record (written before
// SessionRecord carried the ref) resolves with an empty CABundleRef, and the disposal is
// SKIPPED rather than driven with "" — a sanitize of the empty ref names the literal
// "session" leaf and would delete an unrelated bundle. The operator `down --purge` sweep is
// the backstop for that residue.
func TestDestroyEmptyCARefSkipsCABundleDispose(t *testing.T) {
	bundles := &recordingCABundleDisposer{}
	resolver := &fakeDestroyResolver{state: DestroyState{DomainUUID: "dom-old"}} // no CABundleRef
	svc := newResolverDriverService(t, &fakeDomainDestroyer{}, resolver)
	svc.WithCABundleDisposer(bundles)
	client := dialInProcess(t, svc)

	if _, err := client.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: testCloneSession}); err != nil {
		t.Fatalf("Destroy (pre-upgrade record): %v", err)
	}
	if len(bundles.disposed) != 0 {
		t.Fatalf("an empty CABundleRef must SKIP the disposal, got %v", bundles.disposed)
	}
}
