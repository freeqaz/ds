// SPDX-License-Identifier: Apache-2.0

package main

// contentsource_live_test.go pins the read-stream live host-agent content leg (the production
// controlplane.ContentSource, contentsource_live.go) against a SYNTHETIC host-agent bridge
// endpoint — a hand-rolled framed-UDS server that mirrors the DOCUMENTED wire contract (the
// consumer half this leg speaks). There is NO live edge (D50: no real host-agent / VM / CC in
// CI): the tests prove the adapter attaches as a READER, decodes the bridge's frameEvent stream
// onto the seam channel as frozen attach.v1.SessionEvents, closes the channel on frameEnd / EOF,
// re-opens after a transient close, and fails closed on a reject / dial fault / resolve miss —
// the contract the live content relay depends on.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// --- a synthetic framed-UDS host-agent bridge server (the reader wire the content leg dials) ---

// fakeContentBridgeServer is a hand-rolled framed-UDS server that mirrors the host-agent bridge's
// documented READER wire: it accepts a conn, reads frameAttach (recording the handle), replies
// frameAccept (or a configured frameReject), then pushes a queued sequence of frameEvent frames
// (each an attach.Event JSON) and — optionally — a terminal frameEnd. It speaks the SAME
// writeBridgeFrame/readBridgeFrame codec the adapter under test uses (both are package main), so
// the test pins the exact consumer half.
type fakeContentBridgeServer struct {
	ln   net.Listener
	path string

	mu       sync.Mutex
	attaches []wireAttachHandle
	conns    []net.Conn
	// events is the queue of attach.Event JSON payloads pushed as frameEvent on accept.
	events [][]byte
	// sendEnd, when true, pushes a terminal frameEnd after draining the event queue (else the
	// server holds the conn open so the client blocks on the next read until the conn is torn).
	sendEnd bool
	// rejectCode, when non-zero, makes the server reply frameReject with that code.
	rejectCode bridgeRejectCode
	// wantToken, when non-empty, is the token the server requires; a mismatch is rejected.
	wantToken string
	// wantRole, when non-empty, is the role the server requires; a mismatch is rejected auth.
	wantRole string
	// expectResume, when true, makes the server (after accept) read one client frame expecting a
	// frameResume and reply frameResumeReply with resumeSpan — the re-open resume path. The
	// afterSeq it carried is recorded in resumeReqs.
	expectResume bool
	// preResumeEvents are live frameEvent payloads written IMMEDIATELY after accept, BEFORE the
	// server reads the client's frameResume — the real bridge's outbox drainer racing ahead of
	// answerResume on the wire. The client must hold these until the span replays.
	preResumeEvents [][]byte
	// resumeSpan is the recovered attach.Event JSON blobs the server replies in the
	// frameResumeReply span (the gap between a transient drop and this re-open).
	resumeSpan [][]byte
	// rejectResume, when true, makes the server read the client's frameResume and reply
	// frameResumeReject{window_exceeded} instead of a span (the aged-out ring) — the read leg then
	// rejoins at the live head.
	rejectResume bool
	// resumeReqs records the afterSeq of every frameResume the server received.
	resumeReqs []uint64

	closeOnce sync.Once
}

func newFakeContentBridgeServer(t *testing.T) *fakeContentBridgeServer {
	t.Helper()
	dir, err := os.MkdirTemp("", "dsc")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	path := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %q: %v", path, err)
	}
	s := &fakeContentBridgeServer{ln: ln, path: path}
	t.Cleanup(func() {
		s.close()
		_ = os.RemoveAll(dir)
	})
	go s.acceptLoop()
	return s
}

func (s *fakeContentBridgeServer) acceptLoop() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serveConn(raw)
	}
}

func (s *fakeContentBridgeServer) serveConn(raw net.Conn) {
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
	wantRole := s.wantRole
	events := s.events
	sendEnd := s.sendEnd
	expectResume := s.expectResume
	preResumeEvents := s.preResumeEvents
	resumeSpan := s.resumeSpan
	rejectResume := s.rejectResume
	s.mu.Unlock()

	if reject != 0 {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(reject)})
		return
	}
	if wantToken != "" && handle.Auth.Token != wantToken {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(bridgeRejectAuthInvalid)})
		return
	}
	if wantRole != "" && handle.Role != wantRole {
		_ = writeBridgeFrame(bw, bridgeFrameReject, []byte{byte(bridgeRejectAuthInvalid)})
		return
	}
	if err := writeBridgeFrame(bw, bridgeFrameAccept, []byte(bridgeRoleReader)); err != nil {
		return
	}
	// The outbox-drainer race: live frameEvents written BEFORE the server reads the resume
	// request (the two are independent writers on the real bridge, serialized per-frame only).
	for _, ev := range preResumeEvents {
		if err := writeBridgeFrame(bw, bridgeFrameEvent, ev); err != nil {
			return
		}
	}
	// Re-open resume path: read the client's frameResume (recording its afterSeq) and reply the
	// recovered span — or a resume-reject — before the live events, the SAME order the bridge
	// answers a resume in.
	if expectResume || rejectResume {
		ft, payload, err := readBridgeFrame(br)
		if err != nil || ft != bridgeFrameResume || len(payload) != 8 {
			return
		}
		s.mu.Lock()
		s.resumeReqs = append(s.resumeReqs, be64(payload))
		s.mu.Unlock()
		if rejectResume {
			if err := writeBridgeFrame(bw, bridgeFrameResumeReject, []byte{byte(bridgeResumeRejectWindowExceeded)}); err != nil {
				return
			}
		} else if err := writeBridgeFrame(bw, bridgeFrameResumeReply, encodeResumeReplyPayload(resumeSpan)); err != nil {
			return
		}
	}
	for _, ev := range events {
		if err := writeBridgeFrame(bw, bridgeFrameEvent, ev); err != nil {
			return
		}
	}
	if sendEnd {
		_ = writeBridgeFrame(bw, bridgeFrameEnd, nil)
		return
	}
	// Hold the conn open: the client blocks on the next read until close() tears it (EOF).
	select {}
}

// be64 reads an 8-byte big-endian uint64 (the frameResume afterSeq payload).
func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

// encodeResumeReplyPayload packs recovered attach.Event JSON blobs into a frameResumeReply payload
// (4-byte BE count, then per event a 4-byte BE length + the JSON) — the SAME layout the bridge's
// encodeSpan emits and decodeResumeSpan unpacks.
func encodeResumeReplyPayload(events [][]byte) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(events)))
	out := append([]byte(nil), buf[:]...)
	for _, ev := range events {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(ev)))
		out = append(out, l[:]...)
		out = append(out, ev...)
	}
	return out
}

// resumeReqCount reports how many frameResume requests the server has received.
func (s *fakeContentBridgeServer) resumeReqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.resumeReqs)
}

func (s *fakeContentBridgeServer) close() {
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

func (s *fakeContentBridgeServer) attachCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attaches)
}

// fakeContentResolver is a synthetic driveEndpointResolver for the content leg: a fixed endpoint
// for one session, a fail-closed miss for a named unprovisioned session, and a fault for a named
// faulting session.
type fakeContentResolver struct {
	session   string
	ep        driveRelayEndpoint
	missUUID  string
	faultUUID string
	err       error
}

func (f fakeContentResolver) ResolveRelayEndpoint(_ context.Context, sessionUUID string) (driveRelayEndpoint, bool, error) {
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

// chatEventJSON renders one attach.Event chat.message JSON — the SAME shape the host-agent
// bridge's projected attach.Event marshals (mirrored by wireContentEvent), so the decode round-
// trips.
func chatEventJSON(t *testing.T, seq uint64, text string) []byte {
	t.Helper()
	body := map[string]any{
		"seq":         seq,
		"session_id":  "sess-1",
		"observed_at": time.UnixMilli(1_700_000_000_000).UTC().Format(time.RFC3339Nano),
		"type":        "chat.message",
		"chat_message": map[string]any{
			"message_id": "m1",
			"role":       "assistant",
			"blocks":     []map[string]any{{"kind": "text", "text": text}},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal chat event: %v", err)
	}
	return b
}

// envelopeOnlyEventJSON renders an attach.Event JSON whose type is a genuine CONTENT type but
// carries NO payload pointer — a hollow envelope a misbehaving content source might push. The
// content leg must drop it at decode (fail-closed) so it never reaches the fan-out.
func envelopeOnlyEventJSON(t *testing.T, seq uint64) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"seq":        seq,
		"session_id": "sess-1",
		"type":       "chat.message", // a content type…
		// …but no "chat_message" payload: the projected event's oneof is unset (envelope-only).
	})
	if err != nil {
		t.Fatalf("marshal envelope-only event: %v", err)
	}
	return b
}

func waitForContent(t *testing.T, cond func() bool) {
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

// TestHostAgentContentSource_ForwardsDecodedContent is the headline: an attach.Event chat.message
// pushed as a frameEvent is decoded onto the seam channel as a frozen attach.v1.SessionEvent with
// the right type + payload, and the presented attach handle names the session + the READER role +
// the resolved token.
func TestHostAgentContentSource_ForwardsDecodedContent(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.wantToken = "tok-abc"
	srv.wantRole = bridgeRoleReader
	srv.events = [][]byte{chatEventJSON(t, 7, "hello reader")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("tok-abc"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}

	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}

	ev := recvOne(t, ch)
	if ev.GetType() != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE {
		t.Fatalf("decoded type = %v; want CHAT_MESSAGE", ev.GetType())
	}
	if ev.GetSeq() != 7 || ev.GetSessionId() != "sess-1" {
		t.Fatalf("decoded envelope seq=%d session=%q; want 7/sess-1", ev.GetSeq(), ev.GetSessionId())
	}
	cm := ev.GetChatMessage()
	if cm == nil || cm.GetMessageId() != "m1" || len(cm.GetBlocks()) != 1 || cm.GetBlocks()[0].GetText() != "hello reader" {
		t.Fatalf("decoded chat payload = %+v; want message m1 with one 'hello reader' block", cm)
	}
	if ev.GetObservedAt() != 1_700_000_000_000 {
		t.Fatalf("decoded observed_at = %d; want the round-tripped unix millis", ev.GetObservedAt())
	}

	// The stream closes (frameEnd) ⇒ the channel is closed.
	waitForContent(t, func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	})

	srv.mu.Lock()
	handle := srv.attaches[0]
	srv.mu.Unlock()
	if handle.SessionUUID != "sess-1" || handle.Role != bridgeRoleReader || handle.Auth.Token != "tok-abc" {
		t.Fatalf("attach handle = %+v; want session=sess-1 role=READER token=tok-abc", handle)
	}
	if len(handle.Endpoints) != 1 || handle.Endpoints[0].Transport != bridgeTransportUnix {
		t.Fatalf("attach endpoints = %+v; want one unix endpoint", handle.Endpoints)
	}
}

// TestHostAgentContentSource_ClosesChannelOnStreamEnd proves a frameEnd (the host-side stream
// terminal) closes the seam channel after draining the queued events — the relay then re-opens.
func TestHostAgentContentSource_ClosesChannelOnStreamEnd(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{chatEventJSON(t, 1, "one"), chatEventJSON(t, 2, "two")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}

	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	got := drainChannel(t, ch)
	if len(got) != 2 {
		t.Fatalf("drained %d events; want 2 before the stream-end close", len(got))
	}
	if got[0].GetChatMessage().GetBlocks()[0].GetText() != "one" || got[1].GetChatMessage().GetBlocks()[0].GetText() != "two" {
		t.Fatalf("drained texts = %q/%q; want one/two", got[0].GetChatMessage().GetBlocks()[0].GetText(), got[1].GetChatMessage().GetBlocks()[0].GetText())
	}
}

// TestHostAgentContentSource_ClosesChannelOnTransportClose proves a torn conn (EOF, not a clean
// frameEnd) also closes the seam channel — the relay re-opens on the next pump iteration.
func TestHostAgentContentSource_ClosesChannelOnTransportClose(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{chatEventJSON(t, 1, "one")}
	// sendEnd stays false: the server holds the conn open after the one event, then close() tears
	// it — the client observes EOF, not frameEnd.

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	// Consume the first event, then tear the server.
	_ = recvOne(t, ch)
	srv.close()
	// The transport close (EOF) closes the channel.
	waitForContent(t, func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	})
}

// TestHostAgentContentSource_CancelClosesChannel proves cancelling the pump context (the relay's
// stop on DESTROYED / shutdown) closes the seam channel promptly, even while the server holds the
// conn open with no further events.
func TestHostAgentContentSource_CancelClosesChannel(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	// No events, conn held open: the pump blocks on the read until ctx-cancel tears the conn.

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := src.OpenContent(ctx, "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	cancel()
	waitForContent(t, func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	})
}

// TestHostAgentContentSource_ReDialsAfterClose proves the relay's re-open discipline: a second
// OpenContent after the first stream ended attaches a fresh reader (two attaches) and streams the
// new content — a torn read leg is not permanently dead.
func TestHostAgentContentSource_ReDialsAfterClose(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{chatEventJSON(t, 1, "first")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}

	ch1, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("first OpenContent: %v", err)
	}
	got1 := drainChannel(t, ch1)
	if len(got1) != 1 || got1[0].GetChatMessage().GetBlocks()[0].GetText() != "first" {
		t.Fatalf("first stream = %+v; want one 'first' event", got1)
	}

	// The relay re-opens: a fresh OpenContent attaches again and streams the next content.
	srv.mu.Lock()
	srv.events = [][]byte{chatEventJSON(t, 2, "second")}
	srv.mu.Unlock()

	ch2, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("re-open OpenContent: %v", err)
	}
	got2 := drainChannel(t, ch2)
	if len(got2) != 1 || got2[0].GetChatMessage().GetBlocks()[0].GetText() != "second" {
		t.Fatalf("re-opened stream = %+v; want one 'second' event", got2)
	}
	waitForContent(t, func() bool { return srv.attachCount() == 2 })
}

// TestHostAgentContentSource_SurfacesRejectedAttach proves a frameReject on the reader attach is
// surfaced as an error (with the mapped reason) and NO stream is opened — the content leg refuses
// fail-closed when the host-agent bridge refuses the reader subscription.
func TestHostAgentContentSource_SurfacesRejectedAttach(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.rejectCode = bridgeRejectUnknownSession

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	if _, err := src.OpenContent(context.Background(), "sess-1"); err == nil {
		t.Fatal("OpenContent to a rejecting relay = nil; want a rejection error")
	}
}

// TestHostAgentContentSource_SurfacesDialFault proves a dial to an absent relay endpoint surfaces
// an error (no stream opened; the relay retries with backoff).
func TestHostAgentContentSource_SurfacesDialFault(t *testing.T) {
	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: filepath.Join(t.TempDir(), "nonexistent.sock"), token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	if _, err := src.OpenContent(context.Background(), "sess-1"); err == nil {
		t.Fatal("OpenContent to an absent relay = nil; want a dial error")
	}
}

// TestHostAgentContentSource_FailsClosedOnResolveMissAndFault proves the two resolver refusals: a
// fail-closed miss (ok=false — no provisioned relay) and a transient fault both refuse OpenContent
// without dialing.
func TestHostAgentContentSource_FailsClosedOnResolveMissAndFault(t *testing.T) {
	src, err := newHostAgentContentSource(fakeContentResolver{
		missUUID:  "sess-miss",
		faultUUID: "sess-fault",
		err:       errors.New("store stalled"),
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	if _, err := src.OpenContent(context.Background(), "sess-miss"); err == nil {
		t.Fatal("OpenContent on a resolve miss = nil; want fail-closed refusal")
	}
	if _, err := src.OpenContent(context.Background(), "sess-fault"); err == nil {
		t.Fatal("OpenContent on a resolve fault = nil; want an error")
	}
	if _, err := src.OpenContent(context.Background(), ""); err == nil {
		t.Fatal("OpenContent with empty session = nil; want a refusal")
	}
}

func TestHostAgentContentSource_NilResolverRejected(t *testing.T) {
	if _, err := newHostAgentContentSource(nil); err == nil {
		t.Fatal("newHostAgentContentSource(nil) = nil err; want a construction refusal")
	}
}

// TestHostAgentContentSource_SkipsMalformedEvent proves a single malformed frameEvent (a non-JSON
// body) is SKIPPED, not fatal: the surrounding well-formed events still reach the channel.
func TestHostAgentContentSource_SkipsMalformedEvent(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{
		chatEventJSON(t, 1, "before"),
		[]byte("{not valid json"),
		chatEventJSON(t, 3, "after"),
	}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	got := drainChannel(t, ch)
	if len(got) != 2 {
		t.Fatalf("drained %d events; want 2 (the malformed one skipped)", len(got))
	}
	if got[0].GetChatMessage().GetBlocks()[0].GetText() != "before" || got[1].GetChatMessage().GetBlocks()[0].GetText() != "after" {
		t.Fatalf("drained texts = %q/%q; want before/after", got[0].GetChatMessage().GetBlocks()[0].GetText(), got[1].GetChatMessage().GetBlocks()[0].GetText())
	}
}

// TestHostAgentContentSource_ResumeReplayFillsGapExactlyOnce is the resume headline: after a
// transient drop, the re-open sends frameResume{lastSeq} and REPLAYS the recovered ring span
// before rejoining the live head, so a spectator sees no content gap — and an event already
// delivered (in the span's overlap with the pre-drop head) is dropped exactly once.
func TestHostAgentContentSource_ResumeReplayFillsGapExactlyOnce(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	// First stream: deliver seq 1 ("one"), then a clean stream-end (the transient drop).
	srv.events = [][]byte{chatEventJSON(t, 1, "one")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}

	ch1, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("first OpenContent: %v", err)
	}
	got1 := drainChannel(t, ch1)
	if len(got1) != 1 || got1[0].GetChatMessage().GetBlocks()[0].GetText() != "one" || got1[0].GetSeq() != 1 {
		t.Fatalf("first stream = %+v; want one 'one' event at seq 1", got1)
	}

	// Re-open: the server now answers a resume. The span overlaps the delivered head (seq 1 again)
	// plus the gap the drop swallowed (seq 2, 3). Only seq 2, 3 must reach the channel.
	srv.mu.Lock()
	srv.expectResume = true
	srv.resumeSpan = [][]byte{
		chatEventJSON(t, 1, "one-dup"), // already delivered — must be deduped by the cursor.
		chatEventJSON(t, 2, "two"),     // the gap.
		chatEventJSON(t, 3, "three"),   // the gap.
	}
	srv.events = nil
	srv.sendEnd = true
	srv.mu.Unlock()

	ch2, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("re-open OpenContent: %v", err)
	}
	got2 := drainChannel(t, ch2)
	if len(got2) != 2 {
		t.Fatalf("resumed stream delivered %d events; want 2 (the gap, seq 1 deduped): %+v", len(got2), got2)
	}
	if got2[0].GetChatMessage().GetBlocks()[0].GetText() != "two" || got2[1].GetChatMessage().GetBlocks()[0].GetText() != "three" {
		t.Fatalf("resumed texts = %q/%q; want two/three (no gap, no dup)",
			got2[0].GetChatMessage().GetBlocks()[0].GetText(), got2[1].GetChatMessage().GetBlocks()[0].GetText())
	}
	// The re-open actually issued a frameResume from the delivered cursor (seq 1), not a rejoin at head.
	waitForContent(t, func() bool { return srv.resumeReqCount() == 1 })
	srv.mu.Lock()
	afterSeq := srv.resumeReqs[0]
	srv.mu.Unlock()
	if afterSeq != 1 {
		t.Fatalf("frameResume afterSeq = %d; want 1 (the highest delivered seq)", afterSeq)
	}
}

// TestHostAgentContentSource_ResumeHoldsRacingLiveEvents pins the outbox-drainer race: on the real
// bridge the per-conn event drainer and answerResume are independent writers, so a live frameEvent
// with a seq ABOVE the whole recovered span can hit the wire BEFORE the frameResumeReply. The pump
// must HOLD it until the span replays — delivering it eagerly would advance the high-water cursor
// past the span and drop the entire gap (the exact loss the resume exists to prevent). Expected:
// the span (2, 3) then the raced live head (4), in order, each exactly once — including the span/
// live overlap (3 appears in both and is delivered once).
func TestHostAgentContentSource_ResumeHoldsRacingLiveEvents(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	// First stream: deliver seq 1, then the transient drop.
	srv.events = [][]byte{chatEventJSON(t, 1, "one")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch1, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("first OpenContent: %v", err)
	}
	if got := drainChannel(t, ch1); len(got) != 1 || got[0].GetSeq() != 1 {
		t.Fatalf("first stream = %+v; want one event at seq 1", got)
	}

	// Re-open: the server pushes live events (seq 3 overlap + seq 4 head) BEFORE reading the
	// resume, then answers the span (2, 3). The gap is 2, 3; the live head is 4.
	srv.mu.Lock()
	srv.expectResume = true
	srv.preResumeEvents = [][]byte{chatEventJSON(t, 3, "three-live"), chatEventJSON(t, 4, "four")}
	srv.resumeSpan = [][]byte{chatEventJSON(t, 2, "two"), chatEventJSON(t, 3, "three")}
	srv.events = nil
	srv.sendEnd = true
	srv.mu.Unlock()

	ch2, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("re-open OpenContent: %v", err)
	}
	got := drainChannel(t, ch2)
	if len(got) != 3 {
		t.Fatalf("resumed stream delivered %d events; want 3 (2,3,4 exactly once, in order): %+v", len(got), got)
	}
	for i, wantSeq := range []uint64{2, 3, 4} {
		if got[i].GetSeq() != wantSeq {
			t.Fatalf("resumed order = [%d %d %d]; want [2 3 4] (span first, held live head after)",
				got[0].GetSeq(), got[1].GetSeq(), got[2].GetSeq())
		}
	}
	// The span copy of 3 won the race (delivered from the replay), the raced live copy deduped.
	if got[1].GetChatMessage().GetBlocks()[0].GetText() != "three" {
		t.Fatalf("seq-3 text = %q; want the span copy 'three' (the held live duplicate deduped)",
			got[1].GetChatMessage().GetBlocks()[0].GetText())
	}
}

// TestHostAgentContentSource_FirstOpenSendsNoResume proves the cursor semantics from the other
// side: a FIRST attach (no prior delivery) sends NO frameResume — there is no gap to recover, so
// rejoining at the head is correct and the server is never left blocked waiting for a resume.
func TestHostAgentContentSource_FirstOpenSendsNoResume(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{chatEventJSON(t, 5, "hi")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	got := drainChannel(t, ch)
	if len(got) != 1 {
		t.Fatalf("first open drained %d events; want 1", len(got))
	}
	if srv.resumeReqCount() != 0 {
		t.Fatalf("first open issued %d resume requests; want 0 (no gap to recover)", srv.resumeReqCount())
	}
}

// TestHostAgentContentSource_ResumeRejectRejoinsAtHead proves a window-exceeded resume (the ring
// aged the span out) is NOT fatal: the leg rejoins at the live head and streams the fresh events,
// rather than tearing the stream.
func TestHostAgentContentSource_ResumeRejectRejoinsAtHead(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{chatEventJSON(t, 1, "one")}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch1, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("first OpenContent: %v", err)
	}
	_ = drainChannel(t, ch1)

	// Re-open: the server rejects the resume (window exceeded), then streams the live head.
	srv.mu.Lock()
	srv.rejectResume = true
	srv.events = [][]byte{chatEventJSON(t, 9, "live-head")}
	srv.sendEnd = true
	srv.mu.Unlock()

	ch2, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("re-open OpenContent: %v", err)
	}
	got := drainChannel(t, ch2)
	if len(got) != 1 || got[0].GetChatMessage().GetBlocks()[0].GetText() != "live-head" {
		t.Fatalf("post-reject stream = %+v; want the live head 'live-head' (rejoin, not a torn stream)", got)
	}
}

// TestHostAgentContentSource_DropsEnvelopeOnlyContentEvent proves the fail-closed decode fold: a
// content-typed event that arrives WITHOUT its payload (a hollow envelope) is dropped at decode +
// counted, and the surrounding well-formed events still stream — a misbehaving source is inert.
func TestHostAgentContentSource_DropsEnvelopeOnlyContentEvent(t *testing.T) {
	srv := newFakeContentBridgeServer(t)
	srv.events = [][]byte{
		chatEventJSON(t, 1, "before"),
		envelopeOnlyEventJSON(t, 2), // type=chat.message, no payload — must be dropped.
		chatEventJSON(t, 3, "after"),
	}
	srv.sendEnd = true

	src, err := newHostAgentContentSource(fakeContentResolver{
		session: "sess-1",
		ep:      driveRelayEndpoint{address: srv.path, token: []byte("t"), expiresAt: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("newHostAgentContentSource: %v", err)
	}
	ch, err := src.OpenContent(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	got := drainChannel(t, ch)
	if len(got) != 2 {
		t.Fatalf("drained %d events; want 2 (the envelope-only one dropped): %+v", len(got), got)
	}
	if got[0].GetChatMessage().GetBlocks()[0].GetText() != "before" || got[1].GetChatMessage().GetBlocks()[0].GetText() != "after" {
		t.Fatalf("drained texts = %q/%q; want before/after", got[0].GetChatMessage().GetBlocks()[0].GetText(), got[1].GetChatMessage().GetBlocks()[0].GetText())
	}
	if n := src.DroppedEnvelopeOnly(); n != 1 {
		t.Fatalf("DroppedEnvelopeOnly = %d; want 1 (the hollow envelope counted)", n)
	}
}

// TestClassifyContentEvent_EnvelopeOnlyAndControlEdge pins the decode classifier directly: a
// content type with no payload is EnvelopeOnly (dropped); a control-edge type (session.state) with
// no payload is NOT envelope-only (it stays OK — the relay's filter drops it, so the leg never
// re-originates a state edge); a non-JSON body is Malformed.
func TestClassifyContentEvent_EnvelopeOnlyAndControlEdge(t *testing.T) {
	// A content type without its payload → envelope-only.
	if ev, res := classifyContentEvent([]byte(`{"type":"chat.message"}`)); res != contentDecodeEnvelopeOnly || ev.GetType() != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE {
		t.Fatalf("chat.message w/o payload: res=%v type=%v; want EnvelopeOnly/CHAT_MESSAGE", res, ev.GetType())
	}
	// A control edge (session.state) legitimately carries no payload from this leg → OK, not dropped.
	if _, res := classifyContentEvent([]byte(`{"type":"session.state","session_state":{"state":"WORKING"}}`)); res != contentDecodeOK {
		t.Fatalf("session.state: res=%v; want OK (the relay filter drops it, not the decode)", res)
	}
	// A non-JSON body → malformed.
	if _, res := classifyContentEvent([]byte("nope")); res != contentDecodeMalformed {
		t.Fatalf("garbage: res=%v; want Malformed", res)
	}
	// A well-formed content event with its payload → OK.
	if ev, res := classifyContentEvent([]byte(`{"type":"chat.delta","chat_delta":{"text":"hi"}}`)); res != contentDecodeOK || ev.GetChatDelta().GetText() != "hi" {
		t.Fatalf("chat.delta w/ payload: res=%v ev=%+v; want OK", res, ev)
	}
}

// TestDecodeResumeSpan pins the frameResumeReply span codec: a well-formed span unpacks to its
// event blobs; a truncated/oversized span is rejected fail-closed (the cleanly-parsed prefix, never
// a panic or an over-allocation).
func TestDecodeResumeSpan(t *testing.T) {
	blobs := [][]byte{[]byte(`{"a":1}`), []byte(`{"b":2}`)}
	got := decodeResumeSpan(encodeResumeReplyPayload(blobs))
	if len(got) != 2 || string(got[0]) != `{"a":1}` || string(got[1]) != `{"b":2}` {
		t.Fatalf("decodeResumeSpan round-trip = %q; want the two blobs", got)
	}
	// A payload shorter than the 4-byte count is an empty span (never a panic).
	if got := decodeResumeSpan([]byte{0x00, 0x01}); got != nil {
		t.Fatalf("decodeResumeSpan(truncated count) = %q; want nil", got)
	}
	// A count of 2 but only one event present → the cleanly-parsed prefix (one blob), then stop.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 2)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], 3)
	truncated := append(append(append([]byte(nil), hdr[:]...), l[:]...), []byte("abc")...) // count=2, one 3-byte event, then nothing
	if got := decodeResumeSpan(truncated); len(got) != 1 || string(got[0]) != "abc" {
		t.Fatalf("decodeResumeSpan(truncated span) = %q; want one 'abc' blob then stop", got)
	}
}

// --- the conversion (the reverse of eventmap) ---

// TestToSessionEvent_ProjectsPayloadsFaithfully proves the attach.Event JSON -> proto projection
// across a representative payload set: the envelope + a tool.invoked + an ask.requested (the
// distinct tool_use_id/request_id reconstruction) + a plan.delta (the enum + todos) all map
// field-for-field onto the frozen proto.
func TestToSessionEvent_ProjectsPayloadsFaithfully(t *testing.T) {
	// tool.invoked: envelope + opaque input passthrough.
	{
		ev := decode(t, map[string]any{
			"seq": 5, "session_id": "s", "type": "tool.invoked",
			"tool_invoked": map[string]any{"node_id": "n1", "name": "Bash", "kind": "native", "input": json.RawMessage(`{"cmd":"ls"}`)},
		})
		ti := ev.GetToolInvoked()
		if ev.GetType() != attachv1.EventType_EVENT_TYPE_TOOL_INVOKED || ti == nil || ti.GetNodeId() != "n1" || ti.GetName() != "Bash" || string(ti.GetInput()) != `{"cmd":"ls"}` {
			t.Fatalf("tool.invoked projection = %+v", ti)
		}
	}
	// ask.requested: the working model's single ask_id/node_id fan out to tool_use_id/request_id/node_id.
	{
		ev := decode(t, map[string]any{
			"type":          "ask.requested",
			"ask_requested": map[string]any{"ask_id": "req-9", "node_id": "tool-7", "tool_name": "Write", "source": "control"},
		})
		ar := ev.GetAskRequested()
		if ar == nil || ar.GetToolUseId() != "tool-7" || ar.GetRequestId() != "req-9" || ar.GetNodeId() != "tool-7" || ar.GetSource() != "control" {
			t.Fatalf("ask.requested projection = %+v; want tool_use_id=tool-7 request_id=req-9 node_id=tool-7", ar)
		}
	}
	// plan.delta: kind string -> enum, todos list.
	{
		ev := decode(t, map[string]any{
			"type": "plan.delta",
			"plan_delta": map[string]any{
				"node_id": "p1", "kind": "todo_write",
				"todos": []map[string]any{{"content": "do a thing", "status": "in_progress"}},
			},
		})
		pd := ev.GetPlanDelta()
		if pd == nil || pd.GetToolUseId() != "p1" || pd.GetKind() != attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TODO_WRITE || len(pd.GetTodos()) != 1 || pd.GetTodos()[0].GetContent() != "do a thing" {
			t.Fatalf("plan.delta projection = %+v", pd)
		}
	}
	// session.state is a control edge: mapped to the SESSION_STATE type (so the relay's filter can
	// drop it) but carries NO proto payload from this leg.
	{
		ev := decode(t, map[string]any{"type": "session.state", "session_state": map[string]any{"state": "WORKING"}})
		if ev.GetType() != attachv1.EventType_EVENT_TYPE_SESSION_STATE {
			t.Fatalf("session.state type = %v; want SESSION_STATE", ev.GetType())
		}
		if ev.GetSessionState() != nil {
			t.Fatal("session.state carried a proto payload; the content leg must not re-originate a state edge")
		}
	}
	// An unknown type maps to UNSPECIFIED (the relay drops it, fail-closed).
	{
		ev := decode(t, map[string]any{"type": "not.a.real.type"})
		if ev.GetType() != attachv1.EventType_EVENT_TYPE_UNSPECIFIED {
			t.Fatalf("unknown type = %v; want UNSPECIFIED", ev.GetType())
		}
	}
}

// TestDecodeContentEvent_RejectsNonJSON proves a non-JSON payload is a clean decode miss (ok=false)
// the pump skips, never a panic.
func TestDecodeContentEvent_RejectsNonJSON(t *testing.T) {
	if _, ok := decodeContentEvent([]byte("garbage")); ok {
		t.Fatal("decodeContentEvent(garbage) = ok; want a decode miss")
	}
	if ev, ok := decodeContentEvent([]byte(`{"type":"chat.delta","chat_delta":{"text":"hi"}}`)); !ok || ev.GetChatDelta().GetText() != "hi" {
		t.Fatalf("decodeContentEvent(valid) ok=%v ev=%+v", ok, ev)
	}
}

// --- the wiring helper (the offline slice of liveDeps) ---

// TestResolveContentSource_GateOffNilGateOnLive proves the wiring helper's fail-closed gate: with
// DS_ORCH_OVERLAY_DIR unset the source is NIL (NewControlPlane leaves the content relay
// unconstructed — the documented degrade); with it set the source is a live *hostAgentContentSource.
func TestResolveContentSource_GateOffNilGateOnLive(t *testing.T) {
	// Gate off: a nil interface value (not a typed-nil pointer, which would defeat the relay's nil check).
	source, err := resolveContentSource(func(string) string { return "" })
	if err != nil {
		t.Fatalf("gate-off err: %v", err)
	}
	if source != nil {
		t.Fatal("gate-off source != nil; want a nil seam (fail-closed degrade)")
	}

	// Gate on: DS_ORCH_OVERLAY_DIR set ⇒ a live source.
	overlay := t.TempDir()
	env := map[string]string{"DS_ORCH_OVERLAY_DIR": overlay}
	source, err = resolveContentSource(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("gate-on err: %v", err)
	}
	if source == nil {
		t.Fatal("gate-on source = nil; want a live source")
	}
	if _, ok := source.(*hostAgentContentSource); !ok {
		t.Fatalf("gate-on source type = %T; want *hostAgentContentSource", source)
	}
}

// --- helpers ---

func decode(t *testing.T, body map[string]any) *attachv1.SessionEvent {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal event body: %v", err)
	}
	ev, ok := decodeContentEvent(b)
	if !ok {
		t.Fatalf("decodeContentEvent(%s) = miss; want ok", b)
	}
	return ev
}

func recvOne(t *testing.T, ch <-chan *attachv1.SessionEvent) *attachv1.SessionEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before an event arrived")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no event within deadline")
		return nil
	}
}

// drainChannel reads every event until the channel is closed, returning them in order.
func drainChannel(t *testing.T, ch <-chan *attachv1.SessionEvent) []*attachv1.SessionEvent {
	t.Helper()
	var out []*attachv1.SessionEvent
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline:
			t.Fatalf("channel did not close within deadline (drained %d)", len(out))
			return out
		}
	}
}
