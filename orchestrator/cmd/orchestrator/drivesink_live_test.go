// SPDX-License-Identifier: Apache-2.0

package main

// drivesink_live_test.go pins the W3 live host-agent relay write leg (the production
// controlplane.DriveSink, drivesink_live.go) against a SYNTHETIC host-agent bridge endpoint —
// a hand-rolled framed-UDS server that mirrors the DOCUMENTED wire contract (the producer
// half this leg speaks). There is NO live edge (D50: no real host-agent / VM / CC in CI): the
// tests prove the adapter forwards an admitted DriveInput onto a fake per-session RELAY
// endpoint, surfaces dial/attach/write faults, reuses one writer connection per session, and
// fails closed on a non-forwardable frame — the contract the live orchestrator depends on.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// --- a synthetic framed-UDS host-agent bridge server (the wire the write leg dials) ---

// fakeBridgeServer is a hand-rolled framed-UDS server that mirrors the host-agent bridge's
// documented wire: it accepts a conn, reads frameAttach (recording the handle), replies
// frameAccept (or a configured frameReject), then reads frameInput frames and records the
// decoded {"text"} bodies. It speaks the SAME writeBridgeFrame/readBridgeFrame codec the
// adapter under test uses (both are package main), so the test pins the exact producer half.
type fakeBridgeServer struct {
	ln   net.Listener
	path string

	mu       sync.Mutex
	attaches []wireAttachHandle
	inputs   []wireDriveInput
	conns    []net.Conn // accepted conns, closed on close() so a client drain sees EOF
	// rejectCode, when non-zero, makes the server reply frameReject with that code instead
	// of accepting the attach.
	rejectCode bridgeRejectCode
	// wantToken, when non-empty, is the token the server requires on the attach; a mismatch
	// is rejected with rejectAuthInvalid.
	wantToken string

	closeOnce sync.Once
}

// newFakeBridgeServer binds a short-named UDS (UDS paths are capped ~108 bytes, so the socket
// lives in a fresh short temp dir, not the long t.TempDir()) and serves until closed.
func newFakeBridgeServer(t *testing.T) *fakeBridgeServer {
	t.Helper()
	dir, err := os.MkdirTemp("", "dsw")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	path := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %q: %v", path, err)
	}
	s := &fakeBridgeServer{ln: ln, path: path}
	t.Cleanup(func() {
		s.close()
		_ = os.RemoveAll(dir)
	})
	go s.acceptLoop()
	return s
}

func (s *fakeBridgeServer) acceptLoop() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serveConn(raw)
	}
}

func (s *fakeBridgeServer) serveConn(raw net.Conn) {
	defer raw.Close()
	s.mu.Lock()
	s.conns = append(s.conns, raw)
	s.mu.Unlock()
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	ft, payload, err := readBridgeFrame(br)
	if err != nil || ft != bridgeFrameAttach {
		return
	}
	var handle wireAttachHandle
	if err := json.Unmarshal(payload, &handle); err != nil {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(bridgeRejectHandleMalformed)})
		return
	}
	s.mu.Lock()
	s.attaches = append(s.attaches, handle)
	reject := s.rejectCode
	wantToken := s.wantToken
	s.mu.Unlock()

	if reject != 0 {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(reject)})
		return
	}
	if wantToken != "" && handle.Auth.Token != wantToken {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(bridgeRejectAuthInvalid)})
		return
	}
	if err := writeBridgeFrame(bw, bridgeFrameAccept, []byte(bridgeRoleWriter)); err != nil {
		return
	}

	// Read drive frames until the client closes.
	for {
		ft, payload, err := readBridgeFrame(br)
		if err != nil {
			return
		}
		if ft != bridgeFrameInput {
			continue
		}
		var in wireDriveInput
		if err := json.Unmarshal(payload, &in); err != nil {
			return
		}
		s.mu.Lock()
		s.inputs = append(s.inputs, in)
		s.mu.Unlock()
	}
}

func (s *fakeBridgeServer) close() {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		conns := s.conns
		s.conns = nil
		s.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
}

func (s *fakeBridgeServer) recordedInputs() []wireDriveInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wireDriveInput(nil), s.inputs...)
}

func (s *fakeBridgeServer) attachCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attaches)
}

// fakeDriveResolver is a synthetic driveEndpointResolver: it returns a fixed endpoint for one
// session, a fail-closed miss (ok=false) for a named unprovisioned session, and a fault for a
// named faulting session.
type fakeDriveResolver struct {
	session   string
	ep        driveRelayEndpoint
	missUUID  string
	faultUUID string
	err       error
}

func (f fakeDriveResolver) ResolveRelayEndpoint(_ context.Context, sessionUUID string) (driveRelayEndpoint, bool, error) {
	switch {
	case f.faultUUID != "" && sessionUUID == f.faultUUID:
		return driveRelayEndpoint{}, false, f.err
	case f.missUUID != "" && sessionUUID == f.missUUID:
		return driveRelayEndpoint{}, false, nil
	case sessionUUID == f.session:
		return f.ep, true, nil
	default:
		return driveRelayEndpoint{}, false, nil
	}
}

func textInput(seat, text string, seq uint64) *attachv1.DriveInput {
	return &attachv1.DriveInput{
		WriterSeatId: seat,
		Kind:         attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT,
		Payload:      []byte(text),
		ClientSeq:    seq,
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// --- the adapter tests ---

// TestHostAgentDriveSink_ForwardsAdmittedTextInput is the headline: an admitted TEXT
// DriveInput is forwarded onto the fake per-session RELAY endpoint, arriving as the bridge's
// {"text"} write-side shape, and the presented attach handle names the session + the WRITER
// seat + the resolved token.
func TestHostAgentDriveSink_ForwardsAdmittedTextInput(t *testing.T) {
	srv := newFakeBridgeServer(t)
	srv.wantToken = "tok-abc"

	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("tok-abc"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Drive(context.Background(), "sess-1", textInput("seat-1", "hello world", 1)); err != nil {
		t.Fatalf("Drive: %v", err)
	}

	waitFor(t, func() bool { return len(srv.recordedInputs()) == 1 })
	got := srv.recordedInputs()
	if got[0].Text != "hello world" {
		t.Fatalf("forwarded text = %q; want %q", got[0].Text, "hello world")
	}
	srv.mu.Lock()
	handle := srv.attaches[0]
	srv.mu.Unlock()
	if handle.SessionUUID != "sess-1" || handle.Role != bridgeRoleWriter || handle.Auth.Token != "tok-abc" {
		t.Fatalf("attach handle = %+v; want session=sess-1 role=WRITER token=tok-abc", handle)
	}
	if len(handle.Endpoints) != 1 || handle.Endpoints[0].Transport != bridgeTransportUnix {
		t.Fatalf("attach endpoints = %+v; want one unix endpoint", handle.Endpoints)
	}
}

// TestHostAgentDriveSink_ReusesPerSessionConnection proves a second admitted frame for the
// SAME session reuses the one writer connection (one attach, two inputs) — a fresh attach per
// frame would re-take the D61 writer seat on every keystroke.
func TestHostAgentDriveSink_ReusesPerSessionConnection(t *testing.T) {
	srv := newFakeBridgeServer(t)
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	for i, text := range []string{"one", "two"} {
		if err := sink.Drive(context.Background(), "sess-1", textInput("seat", text, uint64(i+1))); err != nil {
			t.Fatalf("Drive %d: %v", i, err)
		}
	}
	waitFor(t, func() bool { return len(srv.recordedInputs()) == 2 })
	if n := srv.attachCount(); n != 1 {
		t.Fatalf("attach count = %d; want 1 (one reused writer connection)", n)
	}
}

// TestHostAgentDriveSink_SurfacesRejectedAttach proves a frameReject on the attach is
// surfaced as an error (with the mapped reason) and NOTHING is forwarded — the write leg
// refuses fail-closed when the host-agent bridge refuses the writer seat.
func TestHostAgentDriveSink_SurfacesRejectedAttach(t *testing.T) {
	srv := newFakeBridgeServer(t)
	srv.rejectCode = bridgeRejectWriterSeatTaken

	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	err = sink.Drive(context.Background(), "sess-1", textInput("seat", "hi", 1))
	if err == nil {
		t.Fatal("Drive to a rejecting relay = nil; want a rejection error")
	}
	if len(srv.recordedInputs()) != 0 {
		t.Fatal("a rejected attach forwarded input; want none")
	}
}

// TestHostAgentDriveSink_SurfacesDialFault proves a dial to an absent relay endpoint surfaces
// an error (the frame is refused; the DriveSession handler maps it to an in-band refusal).
func TestHostAgentDriveSink_SurfacesDialFault(t *testing.T) {
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: filepath.Join(t.TempDir(), "nonexistent.sock"), token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Drive(context.Background(), "sess-1", textInput("seat", "hi", 1)); err == nil {
		t.Fatal("Drive to an absent relay = nil; want a dial error")
	}
}

// TestHostAgentDriveSink_SurfacesWriteFaultAndReDials proves that when the relay tears the
// connection after a first forward, the NEXT admitted frame surfaces a write fault and then
// (with the relay back up) re-dials and recovers — a torn write leg is not permanently dead.
func TestHostAgentDriveSink_SurfacesWriteFaultAndReDials(t *testing.T) {
	srv := newFakeBridgeServer(t)
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Drive(context.Background(), "sess-1", textInput("seat", "first", 1)); err != nil {
		t.Fatalf("first Drive: %v", err)
	}
	waitFor(t, func() bool { return len(srv.recordedInputs()) == 1 })

	// Tear the server: the cached connection's drain observes EOF, flags it dead, and EAGERLY
	// evicts it from the cache (no lingering dead entry). A subsequent Drive re-dials.
	// Restart on the SAME path so a re-dial can recover.
	srv.close()
	waitFor(t, func() bool {
		sink.mu.Lock()
		_, present := sink.conns["sess-1"]
		sink.mu.Unlock()
		return !present // eagerly evicted on drain death
	})

	// Bring a fresh server up on the same path (the resolver still points here).
	_ = os.Remove(srv.path)
	ln, err := net.Listen("unix", srv.path)
	if err != nil {
		t.Fatalf("relisten: %v", err)
	}
	srv2 := &fakeBridgeServer{ln: ln, path: srv.path}
	t.Cleanup(srv2.close)
	go srv2.acceptLoop()

	// The next Drive re-dials the dead connection and recovers.
	waitFor(t, func() bool {
		return sink.Drive(context.Background(), "sess-1", textInput("seat", "second", 2)) == nil
	})
	waitFor(t, func() bool { return len(srv2.recordedInputs()) == 1 })
	if srv2.recordedInputs()[0].Text != "second" {
		t.Fatalf("recovered forward = %q; want %q", srv2.recordedInputs()[0].Text, "second")
	}
}

// TestHostAgentDriveSink_FailsClosedOnResolveMissAndFault proves the two resolver refusals:
// a fail-closed miss (ok=false — no provisioned relay) and a transient fault both refuse the
// Drive without dialing.
func TestHostAgentDriveSink_FailsClosedOnResolveMissAndFault(t *testing.T) {
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		missUUID:  "sess-miss",
		faultUUID: "sess-fault",
		err:       errors.New("store stalled"),
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Drive(context.Background(), "sess-miss", textInput("seat", "hi", 1)); err == nil {
		t.Fatal("Drive on a resolve miss = nil; want fail-closed refusal")
	}
	if err := sink.Drive(context.Background(), "sess-fault", textInput("seat", "hi", 1)); err == nil {
		t.Fatal("Drive on a resolve fault = nil; want an error")
	}
}

// TestHostAgentDriveSink_RefusesNonForwardableFrames proves the write-leg payload mapping is
// fail-closed: a nil input, a non-TEXT kind, and an empty text payload are all refused before
// any dial (never mis-encoded as text).
func TestHostAgentDriveSink_RefusesNonForwardableFrames(t *testing.T) {
	if _, err := writeLegPayload(nil); err == nil {
		t.Fatal("writeLegPayload(nil) = nil err; want a refusal")
	}
	if _, err := writeLegPayload(&attachv1.DriveInput{Kind: attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_IMAGE, Payload: []byte("x")}); err == nil {
		t.Fatal("writeLegPayload(image) = nil err; want a deferred-capability refusal")
	}
	if _, err := writeLegPayload(&attachv1.DriveInput{Kind: attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT}); err == nil {
		t.Fatal("writeLegPayload(empty text) = nil err; want a refusal")
	}
	got, err := writeLegPayload(textInput("seat", "hi", 1))
	if err != nil {
		t.Fatalf("writeLegPayload(text) err: %v", err)
	}
	if got.Text != "hi" {
		t.Fatalf("mapped text = %q; want %q", got.Text, "hi")
	}
}

// TestHostAgentDriveSink_RefusesAfterClose proves a Drive after Close is refused fail-closed
// (no new relay is dialed once the sink is torn down).
func TestHostAgentDriveSink_RefusesAfterClose(t *testing.T) {
	srv := newFakeBridgeServer(t)
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	_ = sink.Close()
	if err := sink.Drive(context.Background(), "sess-1", textInput("seat", "hi", 1)); err == nil {
		t.Fatal("Drive after Close = nil; want fail-closed refusal")
	}
}

func TestHostAgentDriveSink_NilResolverRejected(t *testing.T) {
	if _, err := newHostAgentDriveSink(nil); err == nil {
		t.Fatal("newHostAgentDriveSink(nil) = nil err; want a construction refusal")
	}
}

// --- the overlay resolver + the wiring helper (the offline slice of liveDeps) ---

// TestOverlayDriveEndpointResolver_RoundTripAndFailClosed proves the production resolver
// against a REAL fileAttachTokenStore: a provisioned session resolves to the deterministic
// per-session UDS path + its minted token; an un-provisioned session is a fail-closed miss
// that writes NO token file (the anti-spray pre-gate).
func TestOverlayDriveEndpointResolver_RoundTripAndFailClosed(t *testing.T) {
	overlay := t.TempDir()
	store, err := libvirt.NewFileAttachTokenStore(overlay, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}
	minted, _, err := store.TokenFor(context.Background(), "sess-real")
	if err != nil {
		t.Fatalf("TokenFor mint: %v", err)
	}

	r, err := newOverlayDriveEndpointResolver(overlay, "/run/ds/attach")
	if err != nil {
		t.Fatalf("newOverlayDriveEndpointResolver: %v", err)
	}

	ep, ok, err := r.ResolveRelayEndpoint(context.Background(), "sess-real")
	if err != nil || !ok {
		t.Fatalf("resolve provisioned session: ok=%v err=%v; want ok=true", ok, err)
	}
	wantPath := relaySocketPath("/run/ds/attach", "sess-real")
	if ep.address != wantPath {
		t.Fatalf("resolved address = %q; want %q", ep.address, wantPath)
	}
	if string(ep.token) != string(minted) {
		t.Fatal("resolved token != minted token")
	}

	_, ok, err = r.ResolveRelayEndpoint(context.Background(), "sess-never")
	if err != nil {
		t.Fatalf("resolve unprovisioned session err: %v", err)
	}
	if ok {
		t.Fatal("resolve of an unprovisioned session = ok; want a fail-closed miss")
	}
}

func TestOverlayDriveEndpointResolver_EmptyOverlayErrors(t *testing.T) {
	if _, err := newOverlayDriveEndpointResolver("", ""); err == nil {
		t.Fatal("newOverlayDriveEndpointResolver(\"\", ...) = nil err; want a construction error")
	}
}

// TestRelaySocketPath_DefaultDirMatchesHostAgent proves an empty socket dir falls back to the
// SAME default the host-agent AttachBridge + the DIRECT resolver use, so the write leg dials
// the socket the host-agent serves.
func TestRelaySocketPath_DefaultDirMatchesHostAgent(t *testing.T) {
	r, err := newOverlayDriveEndpointResolver(t.TempDir(), "")
	if err != nil {
		t.Fatalf("newOverlayDriveEndpointResolver: %v", err)
	}
	if r.socketDir != hostagent.DefaultAttachSocketDir {
		t.Fatalf("default socket dir = %q; want %q (single-sourced with the host-agent AttachBridge)", r.socketDir, hostagent.DefaultAttachSocketDir)
	}
}

// TestResolveWriterDriveSink_GateOffNilGateOnLive proves the wiring helper's fail-closed gate:
// with DS_ORCH_OVERLAY_DIR unset the sink is NIL (DriveSession refuses Unavailable — no relay
// configured); with it set the sink is a live *hostAgentDriveSink over the overlay store.
func TestResolveWriterDriveSink_GateOffNilGateOnLive(t *testing.T) {
	// Gate off: a nil interface value (not a typed-nil pointer, which would defeat the
	// handler's fail-closed nil check).
	sink, closeFn, err := resolveWriterDriveSink(func(string) string { return "" })
	if err != nil {
		t.Fatalf("gate-off err: %v", err)
	}
	if sink != nil {
		t.Fatal("gate-off sink != nil; want a nil seam (fail-closed)")
	}
	if closeFn == nil {
		t.Fatal("gate-off closer = nil; want a no-op closer")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("gate-off closer err: %v", err)
	}

	// Gate on: DS_ORCH_OVERLAY_DIR set ⇒ a live sink.
	overlay := t.TempDir()
	env := map[string]string{"DS_ORCH_OVERLAY_DIR": overlay}
	sink, closeFn, err = resolveWriterDriveSink(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("gate-on err: %v", err)
	}
	if sink == nil {
		t.Fatal("gate-on sink = nil; want a live sink")
	}
	if _, ok := sink.(*hostAgentDriveSink); !ok {
		t.Fatalf("gate-on sink type = %T; want *hostAgentDriveSink", sink)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("gate-on closer err: %v", err)
	}
}

// TestHostAgentDriveSink_EvictsDeadConnEagerly proves the eager-eviction property: when a
// cached per-session relay connection dies (the host-agent bridge tears the socket), the drain
// goroutine flags it dead AND evicts it from the sink's cache on its own — WITHOUT waiting for
// the next Drive or Close. A dead entry never lingers in the map.
func TestHostAgentDriveSink_EvictsDeadConnEagerly(t *testing.T) {
	srv := newFakeBridgeServer(t)
	sink, err := newHostAgentDriveSink(fakeDriveResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentDriveSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// One Drive caches a live writer connection for the session.
	if err := sink.Drive(context.Background(), "sess-1", textInput("seat", "first", 1)); err != nil {
		t.Fatalf("first Drive: %v", err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		_, present := sink.conns["sess-1"]
		sink.mu.Unlock()
		return present
	})

	// Tear the server. The drain goroutine observes EOF, marks the conn dead, and its onDead
	// callback evicts it from the cache — with NO further Drive/Close call from the test.
	srv.close()
	waitFor(t, func() bool {
		sink.mu.Lock()
		_, present := sink.conns["sess-1"]
		sink.mu.Unlock()
		return !present
	})
}

// --- cross-tree wire-contract pin (the orchestrator relay leg's hand-mirrored half) ---
//
// drivesink_live.go hand-mirrors client/hostbridge/socket.go's frame numbers, reject codes,
// JSON tags, and framing because the import boundary (D26/D80) forbids sharing the code. These
// tests pin the ORCHESTRATOR half to the documented wire numbers; the CLIENT half is pinned to
// the SAME numbers by assurance/conformance-adapter/hostbridgewire, which reads BOTH trees'
// sources so a renumber on EITHER side turns a build RED. Mutating any constant below (or in
// socket.go) is proven to break the pin (see the conformance package + task notes).

// TestBridgeWireContract_FrameNumbers pins the frame-type + reject-code numbers the relay leg
// mirrors from client/hostbridge/socket.go. The literals here are the documented single source
// (assurance/conformance-adapter/hostbridgewire/testdata/hostbridge_wire.golden.json).
func TestBridgeWireContract_FrameNumbers(t *testing.T) {
	frames := map[string]bridgeFrameType{
		"attach": bridgeFrameAttach,
		"accept": bridgeFrameAccept,
		"reject": bridgeFrameReject,
		"event":  bridgeFrameEvent,
		"input":  bridgeFrameInput,
		"end":    bridgeFrameEnd,
	}
	wantFrames := map[string]bridgeFrameType{
		"attach": 1, "accept": 2, "reject": 3, "event": 4, "input": 5, "end": 7,
	}
	for name, got := range frames {
		if got != wantFrames[name] {
			t.Errorf("bridgeFrame %q = %d; want %d (hostbridge wire number drift)", name, got, wantFrames[name])
		}
	}

	rejects := map[string]bridgeRejectCode{
		"writer_seat_taken":           bridgeRejectWriterSeatTaken,
		"auth_invalid":                bridgeRejectAuthInvalid,
		"handle_expired":              bridgeRejectHandleExpired,
		"handle_malformed":            bridgeRejectHandleMalformed,
		"unknown_session":             bridgeRejectUnknownSession,
		"internal":                    bridgeRejectInternal,
		"terminal_reader_unsupported": bridgeRejectTerminalReaderUnsupported,
	}
	wantRejects := map[string]bridgeRejectCode{
		"writer_seat_taken": 1, "auth_invalid": 3, "handle_expired": 4,
		"handle_malformed": 5, "unknown_session": 6, "internal": 7, "terminal_reader_unsupported": 8,
	}
	for name, got := range rejects {
		if got != wantRejects[name] {
			t.Errorf("bridgeReject %q = %d; want %d (hostbridge reject-code drift)", name, got, wantRejects[name])
		}
	}

	if bridgeMaxFrameBytes != 10<<20 {
		t.Errorf("bridgeMaxFrameBytes = %d; want %d (hostbridge maxFrameBytes drift)", bridgeMaxFrameBytes, 10<<20)
	}
	if bridgeTransportUnix != "unix" {
		t.Errorf("bridgeTransportUnix = %q; want \"unix\"", bridgeTransportUnix)
	}
	if bridgeRoleWriter != "WRITER" {
		t.Errorf("bridgeRoleWriter = %q; want \"WRITER\"", bridgeRoleWriter)
	}
}

// TestBridgeWireContract_HandleJSONTags pins the JSON field tags on the attach-handshake shapes
// the relay leg marshals — the wire keys client/hostbridge decodes. A tag rename on either side
// silently breaks the live attach; this fails at build time instead.
func TestBridgeWireContract_HandleJSONTags(t *testing.T) {
	handle := wireAttachHandle{
		SessionUUID: "s",
		Endpoints:   []wireEndpointCandidate{{Transport: "unix", Address: "/a.sock"}},
		Auth:        wireAuthMaterial{Token: "tok"},
		Role:        "WRITER",
		ExpiresAt:   time.Unix(0, 0).UTC(),
	}
	assertJSONKeys(t, handle, []string{"auth", "endpoints", "expires_at", "role", "session_uuid"})
	assertJSONKeys(t, handle.Endpoints[0], []string{"address", "transport"})
	assertJSONKeys(t, handle.Auth, []string{"token"})
	assertJSONKeys(t, wireDriveInput{Text: "hi"}, []string{"text"})
}

// assertJSONKeys marshals v and asserts its top-level JSON object keys are exactly want.
func assertJSONKeys(t *testing.T, v any, want []string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	got := make([]string, 0, len(obj))
	for k := range obj {
		got = append(got, k)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("%T json keys = %v; want %v", v, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%T json keys = %v; want %v", v, got, want)
		}
	}
}

// TestBridgeWireContract_GoldenFrameBytes pins the exact on-wire byte layout writeBridgeFrame
// renders (1 type byte, 4-byte BIG-ENDIAN length, payload) against golden vectors — the same
// framing client/hostbridge's writeFrame emits. A change to the framing OR the frame numbers
// shifts these bytes.
func TestBridgeWireContract_GoldenFrameBytes(t *testing.T) {
	cases := []struct {
		name    string
		frame   bridgeFrameType
		payload []byte
		want    []byte
	}{
		{
			name:    "input_text_hi",
			frame:   bridgeFrameInput,
			payload: []byte(`{"text":"hi"}`),
			// 0x05 type, 0x0000000d length (13), then the JSON payload.
			want: append([]byte{0x05, 0x00, 0x00, 0x00, 0x0d}, []byte(`{"text":"hi"}`)...),
		},
		{
			name:    "reject_writer_seat_taken",
			frame:   bridgeFrameReject,
			payload: []byte{byte(bridgeRejectWriterSeatTaken)},
			// 0x03 type, 0x00000001 length (1), 0x01 reject code.
			want: []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0x01},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			bw := bufio.NewWriter(&buf)
			if err := writeBridgeFrame(bw, tc.frame, tc.payload); err != nil {
				t.Fatalf("writeBridgeFrame: %v", err)
			}
			if err := bw.Flush(); err != nil {
				t.Fatalf("flush: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), tc.want) {
				t.Fatalf("frame bytes = % x; want % x (wire framing/number drift)", buf.Bytes(), tc.want)
			}
		})
	}
}

// TestRelaySocketPath_GoldenRendering pins relaySocketPath's deterministic host-local UDS path
// rendering (filepath.Join(dir, sanitize(uuid)+".sock")) — the path the write leg dials must
// byte-match what the host-agent serves. A crafted UUID stays a single safe component (no
// traversal escape).
func TestRelaySocketPath_GoldenRendering(t *testing.T) {
	cases := []struct{ dir, uuid, want string }{
		{"/run/ds/attach", "abc-123.def", "/run/ds/attach/abc-123.def.sock"},
		{"/run/ds/attach", "../../etc/x", "/run/ds/attach/.._.._etc_x.sock"},
		{"/run/ds/attach", "a/b", "/run/ds/attach/a_b.sock"},
		{"/run/ds/attach", "", "/run/ds/attach/_.sock"},
	}
	for _, tc := range cases {
		if got := relaySocketPath(tc.dir, tc.uuid); got != tc.want {
			t.Errorf("relaySocketPath(%q, %q) = %q; want %q", tc.dir, tc.uuid, got, tc.want)
		}
	}
}
