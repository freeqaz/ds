package hostbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/canary"
	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// --- the fixture-fed synthetic CC stdio fake ---------------------------------
//
// No live podman / claude / cia: the CC process is a fixture replayer. ccStdout
// replays client/fixtures/*.cc-wire.ndjson (READ-ONLY — Unit goldentrace-harness
// owns fixtures/) into the bridge's CC-stdout side; ccStdin captures whatever the
// bridge writes (the driver's encoded records). The fixtures are exactly the
// synthetic cassettes client/goldentrace/replay drives, so the deltas the bridge
// projects here are byte-identical to that proven read path.

const fixtureSuffix = ".cc-wire.ndjson"

// loadFixture reads a CC-wire fixture's lines (the ds_fixture header line
// included; the adapter skips it). It is read-only use of fixtures/ — the test
// never writes there.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.FromSlash("../fixtures/" + name + fixtureSuffix)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fixtureCCStdout is an io.Reader over a fixture's bytes — the synthetic CC
// process's stdout. It is just the fixture content; the Bridge's Pump scans it
// line by line exactly as it would a real CC stdout pipe.
func fixtureCCStdout(t *testing.T, name string) *bytes.Reader {
	return bytes.NewReader(loadFixture(t, name))
}

// captureStdin is the synthetic CC process's stdin: it records every record the
// bridge writes (the driver's output). Concurrency-safe because the bridge
// serializes writes under its own mutex, but the test reads after the drive, so a
// mutex keeps the race detector happy.
type captureStdin struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureStdin) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// records returns the newline-framed records the bridge wrote, trimmed of the
// trailing newline the bridge frames each with.
func (c *captureStdin) records() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var recs [][]byte
	sc := bufio.NewScanner(bytes.NewReader(c.buf.Bytes()))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		recs = append(recs, append([]byte(nil), line...))
	}
	return recs
}

// pinnedClock returns a deterministic adapter clock (one second per call from a
// fixed base) so projected deltas are byte-stable — the same determinism
// client/goldentrace/replay uses.
func pinnedClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// pinnedServer builds a Server with a deterministic clock and a fixed token
// minter so handle expiry and auth are testable.
func pinnedServer(t *testing.T, now time.Time, token string) *Server {
	return NewServer(
		WithClock(func() time.Time { return now }),
		WithTokenMinter(func() string { return token }),
	)
}

// collectSub is a Subscriber that records every event and the close error.
type collectSub struct {
	mu     sync.Mutex
	events []attach.Event
	closed bool
	err    error
}

func (s *collectSub) OnEvent(ev attach.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *collectSub) OnClose(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.err = err
}

func (s *collectSub) snapshot() ([]attach.Event, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]attach.Event(nil), s.events...), s.closed, s.err
}

// --- ACCEPTANCE (1): WRITER attaches and receives adapter-projected deltas ----

func TestWriterAttachReceivesProjectedDeltas(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "00000000-0000-4000-8000-000000000003"

	var stdin captureStdin
	bridge := NewBridge(&stdin, BridgeConfig{
		Adapter: claudecode.New(claudecode.WithClock(pinnedClock())),
	})
	srv := pinnedServer(t, now, "tok-writer")
	srv.AddSession(sessUUID, bridge)

	handle, err := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)
	if err != nil {
		t.Fatalf("IssueHandle: %v", err)
	}

	transport := NewLoopbackTransport(srv)
	conn, err := transport.Dial(handle)
	if err != nil {
		t.Fatalf("Dial WRITER: %v", err)
	}
	defer conn.Close()
	if conn.Role() != RoleWriter {
		t.Fatalf("Role = %q, want WRITER", conn.Role())
	}

	// Collect events off the Conn concurrently while the pump runs.
	var got []attach.Event
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for ev := range conn.Events() {
			got = append(got, ev)
		}
	}()

	// Drive the fixture's CC stdout through the bridge — this is the synthetic CC
	// process emitting its stream-json. ask-control exercises init + assistant +
	// control ask + result, a representative mix.
	if err := bridge.Pump(context.Background(), fixtureCCStdout(t, "ask-control")); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	collectWG.Wait()

	if len(got) == 0 {
		t.Fatal("WRITER received no deltas from the fixture-driven CC stream")
	}

	// The deltas must be EXACTLY what the existing adapter projects from the same
	// fixture (import-don't-duplicate: assert against the adapter, do not re-derive
	// the projection). Re-run the adapter standalone over the same bytes.
	want := adapterProject(t, "ask-control")
	if len(got) != len(want) {
		t.Fatalf("delta count = %d, adapter projects %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Seq != want[i].Seq {
			t.Fatalf("delta[%d] = {seq:%d type:%s}, adapter = {seq:%d type:%s}",
				i, got[i].Seq, got[i].Type, want[i].Seq, want[i].Type)
		}
	}

	// At least one ask must have surfaced (ask-control carries a can_use_tool ask).
	if !hasType(got, attach.TypeAskRequested) {
		t.Fatal("expected an ask.requested delta from ask-control fixture")
	}
}

// adapterProject runs the standalone adapter over the same fixture so the bridge
// path can be asserted byte-against the existing read half.
func adapterProject(t *testing.T, name string) []attach.Event {
	t.Helper()
	a := claudecode.New(claudecode.WithClock(pinnedClock()))
	evs, err := a.ProcessStream(fixtureCCStdout(t, name))
	if err != nil {
		t.Fatalf("adapter ProcessStream %s: %v", name, err)
	}
	return evs
}

func hasType(evs []attach.Event, ty attach.Type) bool {
	for _, ev := range evs {
		if ev.Type == ty {
			return true
		}
	}
	return false
}

// --- ACCEPTANCE (2): drive input + grant; bytes byte-match the driver ---------

func TestWriterDrivesInputAndGrantThroughDriver(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-drive"

	var stdin captureStdin
	bridge := NewBridge(&stdin, BridgeConfig{})
	srv := pinnedServer(t, now, "tok")
	srv.AddSession(sessUUID, bridge)
	handle, err := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)
	if err != nil {
		t.Fatalf("IssueHandle: %v", err)
	}
	conn, err := NewLoopbackTransport(srv).Dial(handle)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	in := DriveInput{Text: "ship it"}
	grant := DriveGrant{
		RequestID: "creq_synthetic_0301",
		ToolUseID: "toolu_SYNTHETIC000000000301",
		Allow:     true,
	}

	if err := conn.DriveInput(in); err != nil {
		t.Fatalf("DriveInput: %v", err)
	}
	if err := conn.DriveGrant(grant, GrantRoutePromptTool); err != nil {
		t.Fatalf("DriveGrant promptTool: %v", err)
	}
	if err := conn.DriveGrant(grant, GrantRouteNativeControl); err != nil {
		t.Fatalf("DriveGrant native: %v", err)
	}

	recs := stdin.records()
	if len(recs) != 3 {
		t.Fatalf("captured %d records on CC stdin, want 3", len(recs))
	}

	// Assert against the EXISTING driver — do NOT re-encode independently. The
	// bytes landing on CC stdin must be exactly the driver's output.
	drv := claudecode.NewDriver()

	wantInput, err := drv.EncodeInput(in)
	if err != nil {
		t.Fatalf("driver EncodeInput: %v", err)
	}
	if !bytes.Equal(recs[0], wantInput) {
		t.Fatalf("CC stdin input record\n got: %s\nwant: %s", recs[0], wantInput)
	}

	wantPrompt, err := drv.EncodeGrantPromptTool(grant)
	if err != nil {
		t.Fatalf("driver EncodeGrantPromptTool: %v", err)
	}
	if !bytes.Equal(recs[1], wantPrompt) {
		t.Fatalf("CC stdin promptTool grant\n got: %s\nwant: %s", recs[1], wantPrompt)
	}

	wantNative, err := drv.EncodeGrant(grant)
	if err != nil {
		t.Fatalf("driver EncodeGrant: %v", err)
	}
	if !bytes.Equal(recs[2], wantNative) {
		t.Fatalf("CC stdin native grant\n got: %s\nwant: %s", recs[2], wantNative)
	}
}

// --- ACCEPTANCE (3): second WRITER rejected; N READERs read, cannot write -----

func TestWriterSeatArbitration(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-arb"

	var stdin captureStdin
	bridge := NewBridge(&stdin, BridgeConfig{
		Adapter: claudecode.New(claudecode.WithClock(pinnedClock())),
	})
	srv := pinnedServer(t, now, "tok")
	srv.AddSession(sessUUID, bridge)
	transport := NewLoopbackTransport(srv)

	writerHandle, _ := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)
	readerHandle, _ := srv.IssueHandle(sessUUID, RoleReader, "loopback://sess", time.Hour)

	// First WRITER takes the seat.
	w1, err := transport.Dial(writerHandle)
	if err != nil {
		t.Fatalf("first WRITER Dial: %v", err)
	}
	defer w1.Close()

	// Second WRITER is rejected server-side.
	if _, err := transport.Dial(writerHandle); err != ErrWriterSeatTaken {
		t.Fatalf("second WRITER err = %v, want ErrWriterSeatTaken", err)
	}

	// N READERs all attach.
	var readers []*Conn
	for i := 0; i < 3; i++ {
		r, err := transport.Dial(readerHandle)
		if err != nil {
			t.Fatalf("READER %d Dial: %v", i, err)
		}
		readers = append(readers, r)
	}

	// Collect each reader's events.
	collected := make([][]attach.Event, len(readers))
	var wg sync.WaitGroup
	for i, r := range readers {
		wg.Add(1)
		go func(i int, r *Conn) {
			defer wg.Done()
			for ev := range r.Events() {
				collected[i] = append(collected[i], ev)
			}
		}(i, r)
	}

	if err := bridge.Pump(context.Background(), fixtureCCStdout(t, "ask-control")); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	wg.Wait()

	// Every READER received events.
	for i := range readers {
		if len(collected[i]) == 0 {
			t.Fatalf("READER %d received no events", i)
		}
	}

	// A READER write is refused.
	if err := readers[0].DriveInput(DriveInput{Text: "nope"}); err != ErrReaderCannotWrite {
		t.Fatalf("READER DriveInput err = %v, want ErrReaderCannotWrite", err)
	}
	if err := readers[0].DriveGrant(DriveGrant{ToolUseID: "x"}, GrantRoutePromptTool); err != ErrReaderCannotWrite {
		t.Fatalf("READER DriveGrant err = %v, want ErrReaderCannotWrite", err)
	}
	// Nothing a READER attempted reached CC stdin.
	if recs := stdin.records(); len(recs) != 0 {
		t.Fatalf("READER writes leaked %d records onto CC stdin", len(recs))
	}
}

// After the writer detaches, the seat frees for a later WRITER (driver handoff).
func TestWriterSeatReleasedOnDetach(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-handoff"
	bridge := NewBridge(&captureStdin{}, BridgeConfig{})
	srv := pinnedServer(t, now, "tok")
	srv.AddSession(sessUUID, bridge)
	transport := NewLoopbackTransport(srv)
	wh, _ := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)

	w1, err := transport.Dial(wh)
	if err != nil {
		t.Fatalf("first WRITER: %v", err)
	}
	// Seat held: a second writer is rejected.
	if _, err := transport.Dial(wh); err != ErrWriterSeatTaken {
		t.Fatalf("seat not held: %v", err)
	}
	w1.Close() // detach releases the seat
	w2, err := transport.Dial(wh)
	if err != nil {
		t.Fatalf("WRITER handoff after detach failed: %v", err)
	}
	w2.Close()
}

// --- ACCEPTANCE (4): expired or invalid auth handle is rejected ---------------

func TestAttachRejectsExpiredAndInvalidAuth(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-auth"
	bridge := NewBridge(&captureStdin{}, BridgeConfig{})
	srv := pinnedServer(t, now, "the-real-token")
	srv.AddSession(sessUUID, bridge)
	transport := NewLoopbackTransport(srv)
	sub := &collectSub{}

	// Expired-at-in-the-past handle: issue with a negative TTL.
	expired, _ := srv.IssueHandle(sessUUID, RoleReader, "loopback://sess", -time.Minute)
	if _, err := srv.Attach(expired, sub); err != ErrHandleExpired {
		t.Fatalf("expired handle err = %v, want ErrHandleExpired", err)
	}
	if _, err := transport.Dial(expired); err != ErrHandleExpired {
		t.Fatalf("expired Dial err = %v, want ErrHandleExpired", err)
	}

	// Invalid AuthMaterial: a valid-looking handle with the wrong token.
	valid, _ := srv.IssueHandle(sessUUID, RoleReader, "loopback://sess", time.Hour)
	bad := valid
	bad.Auth = AuthMaterial{Token: "forged-token"}
	if _, err := srv.Attach(bad, sub); err != ErrAuthInvalid {
		t.Fatalf("forged-token handle err = %v, want ErrAuthInvalid", err)
	}

	// Empty token is also invalid.
	empty := valid
	empty.Auth = AuthMaterial{}
	if _, err := srv.Attach(empty, sub); err != ErrAuthInvalid {
		t.Fatalf("empty-token handle err = %v, want ErrAuthInvalid", err)
	}

	// Unknown session.
	stranger := valid
	stranger.SessionUUID = "no-such-session"
	if _, err := srv.Attach(stranger, sub); err != ErrUnknownSession {
		t.Fatalf("unknown-session err = %v, want ErrUnknownSession", err)
	}

	// Malformed: no endpoints.
	noEP := valid
	noEP.Endpoints = nil
	if _, err := srv.Attach(noEP, sub); err != ErrHandleMalformed {
		t.Fatalf("no-endpoints err = %v, want ErrHandleMalformed", err)
	}

	// Malformed: only a relay endpoint (no M0 direct endpoint to serve).
	relayOnly := valid
	relayOnly.Endpoints = []EndpointCandidate{{Transport: TransportRelay, Address: "relay://x"}}
	if _, err := srv.Attach(relayOnly, sub); err != ErrHandleMalformed {
		t.Fatalf("relay-only err = %v, want ErrHandleMalformed", err)
	}

	// Malformed: bad role.
	badRole := valid
	badRole.Role = Role("SPECTATOR")
	if _, err := srv.Attach(badRole, sub); err != ErrHandleMalformed {
		t.Fatalf("bad-role err = %v, want ErrHandleMalformed", err)
	}

	// The valid handle still attaches.
	att, err := srv.Attach(valid, sub)
	if err != nil {
		t.Fatalf("valid handle rejected: %v", err)
	}
	att.Detach()
}

// --- live gate stays closed in the fleet --------------------------------------

func TestRunLiveBridgeGated(t *testing.T) {
	// The fleet never sets DS_E2E_LIVE; assert RunLiveBridge refuses without ever
	// launching anything.
	if v := os.Getenv(LiveGateEnv); v == "1" {
		t.Skipf("%s=1 set; skipping the gated-refusal assertion (operator live run)", LiveGateEnv)
	}
	err := RunLiveBridge(context.Background(), LiveConfig{SessionUUID: "s", Endpoint: "uds://x"})
	if err != ErrLiveGateUnset {
		t.Fatalf("RunLiveBridge gated err = %v, want ErrLiveGateUnset", err)
	}
}

// --- input-close fails closed -------------------------------------------------

func TestDriveAfterCloseInputFailsClosed(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-close"
	bridge := NewBridge(&captureStdin{}, BridgeConfig{})
	srv := pinnedServer(t, now, "tok")
	srv.AddSession(sessUUID, bridge)
	wh, _ := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)
	conn, err := NewLoopbackTransport(srv).Dial(wh)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := bridge.CloseInput(); err != nil {
		t.Fatalf("CloseInput: %v", err)
	}
	if err := conn.DriveInput(DriveInput{Text: "late"}); err != ErrInputClosed {
		t.Fatalf("DriveInput after CloseInput = %v, want ErrInputClosed", err)
	}
}

// --- live-text plumbing: BridgeConfig.LiveText arms WithPartials (D145) --------
//
// The client half of the U-PARTIALS-ARM live-text path: NewBridge with
// BridgeConfig.LiveText builds the DEFAULT adapter WithPartials, so it projects the
// runtime's typing deltas as render-only attach.ChatDeltas. The partial-stream
// fixture carries the stream_event records (a thinking block streams; the tool_use
// input_json_delta does not), so pumping it through a LiveText bridge surfaces
// ChatDeltas and through the default (LiveText:false) bridge surfaces NONE — the
// byte-identical partials-off invariant. (No live CC/podman: the fixture replayer is
// the synthetic CC process, exactly as the other bridge tests.)

// countChatDeltas returns the number of attach.TypeChatDelta events in evs.
func countChatDeltas(evs []attach.Event) int {
	n := 0
	for _, ev := range evs {
		if ev.Type == attach.TypeChatDelta {
			n++
		}
	}
	return n
}

// pumpFixtureCollect builds a Bridge over cfg, attaches a collecting WRITER, pumps
// the named fixture through it, and returns every fanned event. It drives the SAME
// loopback transport + seat path the acceptance tests use, so a LiveText difference
// is observed through the real fan-out, not a direct adapter call.
func pumpFixtureCollect(t *testing.T, cfg BridgeConfig, fixture string) []attach.Event {
	t.Helper()
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const sessUUID = "sess-livetext"
	bridge := NewBridge(&captureStdin{}, cfg)
	srv := pinnedServer(t, now, "tok")
	srv.AddSession(sessUUID, bridge)
	handle, err := srv.IssueHandle(sessUUID, RoleWriter, "loopback://sess", time.Hour)
	if err != nil {
		t.Fatalf("IssueHandle: %v", err)
	}
	conn, err := NewLoopbackTransport(srv).Dial(handle)
	if err != nil {
		t.Fatalf("Dial WRITER: %v", err)
	}
	defer conn.Close()

	var got []attach.Event
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range conn.Events() {
			got = append(got, ev)
		}
	}()
	if err := bridge.Pump(context.Background(), fixtureCCStdout(t, fixture)); err != nil {
		t.Fatalf("Pump %s: %v", fixture, err)
	}
	wg.Wait()
	return got
}

// TestBridgeLiveTextArmsPartials pins the LiveText plumbing: the DEFAULT adapter
// built with BridgeConfig.LiveText:true projects ChatDeltas from the partial-stream
// fixture, while the default (LiveText:false) bridge projects NONE — proof the flag
// reaches claudecode.WithPartials on the bridge's default adapter.
func TestBridgeLiveTextArmsPartials(t *testing.T) {
	// LiveText OFF (the default): the stream_event records are dropped (P11), no ChatDeltas.
	offEvs := pumpFixtureCollect(t, BridgeConfig{}, "partial-stream")
	if c := countChatDeltas(offEvs); c != 0 {
		t.Errorf("LiveText:false bridge fanned %d ChatDeltas, want 0 (partials-off byte-identical drop)", c)
	}

	// LiveText ON: the default adapter is armed WithPartials, so the thinking block's
	// typing deltas surface as render-only ChatDeltas.
	onEvs := pumpFixtureCollect(t, BridgeConfig{LiveText: true}, "partial-stream")
	deltas := countChatDeltas(onEvs)
	if deltas == 0 {
		t.Fatal("LiveText:true bridge fanned 0 ChatDeltas, want >0 (the default adapter must be armed WithPartials)")
	}

	// The ChatDeltas are render-only / non-canonical (P11): dropping every ChatDelta
	// from the LiveText projection yields the SAME canonical event count as the
	// LiveText-off projection. The live typing animation is the ONLY difference.
	if onNonDelta := len(onEvs) - deltas; onNonDelta != len(offEvs) {
		t.Errorf("LiveText:true canonical (non-delta) events = %d, want %d (== LiveText:false count; ChatDeltas must be strictly additive/non-canonical)", onNonDelta, len(offEvs))
	}

	// The surfaced ChatDeltas carry a well-formed payload (the thinking block, joined
	// to the finalizing message by id, kind thinking).
	var sawThinking bool
	for _, ev := range onEvs {
		if ev.Type != attach.TypeChatDelta {
			continue
		}
		if ev.ChatDelta == nil {
			t.Fatalf("ChatDelta event carries a nil ChatDelta payload: %+v", ev)
		}
		if ev.ChatDelta.MessageID == "" {
			t.Errorf("ChatDelta has empty MessageID (%+v); want the finalizing message id", ev.ChatDelta)
		}
		if ev.ChatDelta.Kind == "thinking" {
			sawThinking = true
		}
	}
	if !sawThinking {
		t.Error("LiveText:true projected no thinking ChatDelta from partial-stream, want the thinking block to stream")
	}
}

// TestBridgeLiveTextIgnoredForInjectedAdapter pins the precise honored-path: LiveText
// governs ONLY the Adapter==nil default-adapter construction. An INJECTED adapter is
// used VERBATIM — a caller that builds its own adapter (e.g. the clock-pinned replay
// adapters) controls WithPartials itself, and BridgeConfig.LiveText is ignored for
// it. Here an injected NON-partials adapter must NOT emit ChatDeltas even with
// LiveText:true.
func TestBridgeLiveTextIgnoredForInjectedAdapter(t *testing.T) {
	cfg := BridgeConfig{
		LiveText: true, // ignored: an Adapter is injected below
		Adapter:  claudecode.New(claudecode.WithClock(pinnedClock())),
	}
	evs := pumpFixtureCollect(t, cfg, "partial-stream")
	if c := countChatDeltas(evs); c != 0 {
		t.Errorf("LiveText:true with an injected non-partials adapter fanned %d ChatDeltas, want 0 (the injected adapter is used verbatim; LiveText is ignored for it)", c)
	}
}

// --- every fixture pumps clean (the synthetic CC fake over all cassettes) ------

func TestPumpAllFixtures(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	matches, err := filepath.Glob(filepath.FromSlash("../fixtures/*" + fixtureSuffix))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no *.cc-wire.ndjson fixtures found")
	}
	for _, m := range matches {
		name := filepath.Base(m)
		name = name[:len(name)-len(fixtureSuffix)]
		t.Run(name, func(t *testing.T) {
			bridge := NewBridge(&captureStdin{}, BridgeConfig{
				Adapter: claudecode.New(claudecode.WithClock(pinnedClock())),
			})
			srv := pinnedServer(t, now, "tok")
			srv.AddSession(name, bridge)
			h, _ := srv.IssueHandle(name, RoleWriter, "loopback://sess", time.Hour)
			conn, err := NewLoopbackTransport(srv).Dial(h)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			var n int
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range conn.Events() {
					n++
				}
			}()
			if err := bridge.Pump(context.Background(), fixtureCCStdout(t, name)); err != nil {
				t.Fatalf("Pump %s: %v", name, err)
			}
			wg.Wait()

			// The bridge fan-out must match the standalone adapter exactly.
			want := adapterProject(t, name)
			if n != len(want) {
				t.Fatalf("%s: bridge fanned %d deltas, adapter projects %d", name, n, len(want))
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
//
// --- attach-seam keyed-secret-digest matcher on the LIVE drive path ------------
//
// These tests prove the EXISTING wrapper attach matcher (claudecode.
// AttachDigestMatcher) is invoked AT RUNTIME on Bridge.DriveInput — the real
// production stdin-drive path — not only in the canary unit's direct-call tests.
// A user-PASTED swap-class token never traverses ds-tlsproxy (the wrapper drives
// it straight onto CC stdin), so this seam is the only place it can be matched +
// evented; wiring it live closes the doc 20 §4 canary residual AT RUNTIME (D73;
// doc 12 §10).
//
// SYNTHETIC ONLY (D50): the canary, HMAC key, and feed are made-up markers built
// via canary.BuildAttachCanaryFeed — no live claude / ds-capture / podman /
// network. The constants mirror the canary unit's planted-canary fixture so the
// two seams test the SAME feed shape.

const (
	matcherCanarySecret     = "ds-test-attach-canary-PASTEDTOKEN-7Q2W9E+/"
	matcherCanaryInfix      = "PASTEDTOKEN-7Q2W9E"
	matcherCanaryKeyID      = "synthetic-attach-key-epoch-1"
	matcherCanaryServiceID  = "" // FORBIDDEN class: a guarded credential pasted in.
	matcherCanaryDigestSetV = "attach-digest-set-v1"
)

var matcherCanaryHMACKey = []byte("synthetic-attach-hmac-key-do-not-use-in-prod")

// newBridgeMatcher builds the EXISTING attach matcher from a synthetic keyed feed
// planted with the canary — the same feed the canary unit and ds-tlsproxy
// consume, reused verbatim (no new feed contract).
func newBridgeMatcher(t *testing.T, serviceID string) *AttachDigestMatcher {
	t.Helper()
	feed := canary.BuildAttachCanaryFeed(matcherCanaryKeyID, matcherCanaryHMACKey, []byte(matcherCanarySecret), serviceID, matcherCanaryDigestSetV)
	m, err := claudecode.NewAttachDigestMatcher(feed.KeyID, feed.HMACKey, feed.TruncLen, feed.DigestSetVersion, feed.Entries)
	if err != nil {
		t.Fatalf("NewAttachDigestMatcher: %v", err)
	}
	return m
}

// recordingSink captures the fingerprint-only match sets routed to it on the live
// drive path and counts its invocations (concurrency-safe; DriveInput is
// serialized but the race detector still sees the field accesses).
type recordingSink struct {
	mu      sync.Mutex
	calls   int
	matches [][]DigestMatch
	err     error // returned from OnDigestMatches when non-nil (fail-closed test)
}

func (s *recordingSink) OnDigestMatches(matches []DigestMatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.matches = append(s.matches, append([]DigestMatch(nil), matches...))
	return s.err
}

func (s *recordingSink) snapshot() (int, [][]DigestMatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([][]DigestMatch, len(s.matches))
	copy(cp, s.matches)
	return s.calls, cp
}

// ACCEPTANCE (a): a DriveInput carrying a planted synthetic canary IS matched on
// the LIVE drive path and the sink receives exactly one fingerprint-only
// DigestMatch — in each encoding the producer minted (raw/base64/urlenc/hex).
func TestDriveInputMatchesPlantedCanaryOnLivePath(t *testing.T) {
	pastes := map[string]string{
		"raw":    "here is my token: " + matcherCanarySecret + " please use it",
		"base64": "decoded creds " + base64.StdEncoding.EncodeToString([]byte(matcherCanarySecret)) + " end",
		"urlenc": "url encoded form: " + url.QueryEscape(matcherCanarySecret) + " end",
		"hex":    "hexdump " + hex.EncodeToString([]byte(matcherCanarySecret)) + " end",
	}
	for name, pasted := range pastes {
		t.Run(name, func(t *testing.T) {
			stdin := &captureStdin{}
			sink := &recordingSink{}
			bridge := NewBridge(stdin, BridgeConfig{
				Driver:          claudecode.NewDriver(),
				AttachMatcher:   newBridgeMatcher(t, matcherCanaryServiceID),
				DigestMatchSink: sink,
			})

			if err := bridge.DriveInput(DriveInput{Text: pasted}); err != nil {
				t.Fatalf("DriveInput: %v", err)
			}

			calls, got := sink.snapshot()
			if calls != 1 {
				t.Fatalf("sink invoked %d times on a %s canary paste, want exactly 1 (the matcher must fire on the live drive path)", calls, name)
			}
			if len(got[0]) != 1 {
				t.Fatalf("sink received %d matches, want exactly 1 fingerprint-only DigestMatch", len(got[0]))
			}
			hit := got[0][0]
			if hit.KeyID != matcherCanaryKeyID {
				t.Errorf("match KeyID = %q, want %q", hit.KeyID, matcherCanaryKeyID)
			}
			if hit.CredClass != "forbidden" {
				t.Errorf("match CredClass = %q, want forbidden", hit.CredClass)
			}
			if hit.DigestSetVersion != matcherCanaryDigestSetV {
				t.Errorf("match DigestSetVersion = %q, want %q", hit.DigestSetVersion, matcherCanaryDigestSetV)
			}
			// The input STILL drives (matcher events, it does not block a non-keyed
			// match): the encoded record must reach CC stdin verbatim.
			if recs := stdin.records(); len(recs) != 1 {
				t.Fatalf("wrote %d records to CC stdin, want 1 (the input must still drive after an evented match)", len(recs))
			}
		})
	}
}

// ACCEPTANCE (b): NEVER-LOG-THE-SECRET (D73). On the live drive path, the planted
// canary appears in ZERO bytes of any emission the matcher seam produces — the
// DigestMatch rendering and any error text. (The legitimate stdin TRANSPORT
// necessarily carries the user's own bytes verbatim; the invariant is about the
// seam's OWN emissions, scanned here for the secret and its high-entropy infix in
// raw, base64, url-encoded, AND hex forms.)
func TestDriveInputMatchNeverLeaksSecret(t *testing.T) {
	stdin := &captureStdin{}
	// A sink that records the matches AND surfaces an error, so both the routed
	// DigestMatch values AND the returned (fail-closed) error text are scanned.
	sink := &recordingSink{err: errors.New("sink-disk-full")}
	bridge := NewBridge(stdin, BridgeConfig{
		Driver:          claudecode.NewDriver(),
		AttachMatcher:   newBridgeMatcher(t, matcherCanaryServiceID),
		DigestMatchSink: sink,
	})

	err := bridge.DriveInput(DriveInput{Text: "credentials: " + matcherCanarySecret})
	if !errors.Is(err, ErrDigestSinkFailed) {
		t.Fatalf("DriveInput err = %v, want ErrDigestSinkFailed (fail-closed)", err)
	}

	// Build the full surface a secret could leak through: the routed DigestMatch
	// values rendered every way (%v/%+v/%#v + JSON) AND the error text DriveInput
	// returned.
	var emitted bytes.Buffer
	_, got := sink.snapshot()
	for _, set := range got {
		for _, hit := range set {
			fmt.Fprintf(&emitted, "%v\n%+v\n%#v\n", hit, hit, hit)
			j, jerr := json.Marshal(hit)
			if jerr != nil {
				t.Fatalf("marshal match event: %v", jerr)
			}
			emitted.Write(j)
			emitted.WriteByte('\n')
		}
	}
	emitted.WriteString(err.Error())

	hay := emitted.Bytes()
	needles := map[string][]byte{
		"plaintext": []byte(matcherCanarySecret),
		"infix":     []byte(matcherCanaryInfix),
		"base64":    []byte(base64.StdEncoding.EncodeToString([]byte(matcherCanarySecret))),
		"urlenc":    []byte(url.QueryEscape(matcherCanarySecret)),
		"hex":       []byte(hex.EncodeToString([]byte(matcherCanarySecret))),
	}
	for form, needle := range needles {
		if bytes.Contains(hay, needle) {
			t.Fatalf("NEVER-LOG VIOLATION: the %s form of the canary leaked into a matcher-seam emission", form)
		}
	}
}

// ACCEPTANCE (c): matcher==nil leaves DriveInput byte-identical to today
// (additive / behavior-preserving) — the same encoded record reaches CC stdin
// whether or not a matcher is configured, and no sink is consulted.
func TestDriveInputNilMatcherByteIdentical(t *testing.T) {
	const pasted = "here is my token: " + matcherCanarySecret + " please use it"

	// Baseline: no matcher (today's behavior).
	noMatcher := &captureStdin{}
	bNo := NewBridge(noMatcher, BridgeConfig{Driver: claudecode.NewDriver()})
	if err := bNo.DriveInput(DriveInput{Text: pasted}); err != nil {
		t.Fatalf("DriveInput (no matcher): %v", err)
	}

	// A matcher configured but with a NIL sink: matches are computed and dropped
	// (no routing target) and the input STILL drives — a matcher with no sink is an
	// inspection with nowhere to report, never a fail-closed.
	withMatcher := &captureStdin{}
	bMatch := NewBridge(withMatcher, BridgeConfig{
		Driver:        claudecode.NewDriver(),
		AttachMatcher: newBridgeMatcher(t, matcherCanaryServiceID),
		// DigestMatchSink left nil.
	})
	if err := bMatch.DriveInput(DriveInput{Text: pasted}); err != nil {
		t.Fatalf("DriveInput (matcher, nil sink): %v", err)
	}

	// The bytes written to CC stdin must be IDENTICAL across the two — the matcher
	// never mutates the drive, it only observes.
	if !bytes.Equal(noMatcher.buf.Bytes(), withMatcher.buf.Bytes()) {
		t.Fatalf("matcher changed the bytes driven onto CC stdin:\n no-matcher: %q\n  w/matcher: %q", noMatcher.buf.Bytes(), withMatcher.buf.Bytes())
	}
}

// ACCEPTANCE (d): a non-canary prompt produces NO sink call and drives unchanged
// (no false positive on the live path).
func TestDriveInputInnocuousNoSinkCall(t *testing.T) {
	stdin := &captureStdin{}
	sink := &recordingSink{}
	bridge := NewBridge(stdin, BridgeConfig{
		Driver:          claudecode.NewDriver(),
		AttachMatcher:   newBridgeMatcher(t, matcherCanaryServiceID),
		DigestMatchSink: sink,
	})

	if err := bridge.DriveInput(DriveInput{Text: "Please refactor the parser and add a test."}); err != nil {
		t.Fatalf("DriveInput: %v", err)
	}
	if calls, _ := sink.snapshot(); calls != 0 {
		t.Fatalf("sink invoked %d times on an innocuous prompt, want 0 (no false positive)", calls)
	}
	if recs := stdin.records(); len(recs) != 1 {
		t.Fatalf("wrote %d records to CC stdin, want 1 (an innocuous prompt drives unchanged)", len(recs))
	}
}

// TestDriveInputFailsClosedRefusesWrite pins the fail-closed-when-keyed posture
// exactly: a sink error must REFUSE the write — NOTHING reaches CC stdin past a
// failed inspection (mirroring the proxy mint-before-attach / Rust SecretMatcher
// Holds fail-closed).
func TestDriveInputFailsClosedRefusesWrite(t *testing.T) {
	stdin := &captureStdin{}
	sink := &recordingSink{err: errors.New("downstream sink unavailable")}
	bridge := NewBridge(stdin, BridgeConfig{
		Driver:          claudecode.NewDriver(),
		AttachMatcher:   newBridgeMatcher(t, matcherCanaryServiceID),
		DigestMatchSink: sink,
	})

	err := bridge.DriveInput(DriveInput{Text: "token " + matcherCanarySecret})
	if !errors.Is(err, ErrDigestSinkFailed) {
		t.Fatalf("DriveInput err = %v, want ErrDigestSinkFailed", err)
	}
	// Fail-closed: the input must NOT have been driven onto CC stdin.
	if recs := stdin.records(); len(recs) != 0 {
		t.Fatalf("wrote %d records to CC stdin after a sink failure, want 0 (fail-closed must refuse the write)", len(recs))
	}
}

// TestDriveInputMatcherIssuedClassEventsServiceID proves the ISSUED{service_id}
// class is carried into the routed match event for attribution parity with the
// proxy plane, on the live path, while STILL never leaking the secret.
func TestDriveInputMatcherIssuedClassEventsServiceID(t *testing.T) {
	const svc = "api.example-service"
	stdin := &captureStdin{}
	sink := &recordingSink{}
	bridge := NewBridge(stdin, BridgeConfig{
		Driver:          claudecode.NewDriver(),
		AttachMatcher:   newBridgeMatcher(t, svc),
		DigestMatchSink: sink,
	})

	if err := bridge.DriveInput(DriveInput{Text: "token " + matcherCanarySecret}); err != nil {
		t.Fatalf("DriveInput: %v", err)
	}
	calls, got := sink.snapshot()
	if calls != 1 || len(got[0]) != 1 {
		t.Fatalf("issued-class match: calls=%d matches=%v, want 1 call / 1 match", calls, got)
	}
	hit := got[0][0]
	if hit.CredClass != "issued" {
		t.Errorf("CredClass = %q, want issued", hit.CredClass)
	}
	if hit.ServiceID != svc {
		t.Errorf("ServiceID = %q, want %q", hit.ServiceID, svc)
	}
	if got := fmt.Sprintf("%+v", hit); bytes.Contains([]byte(got), []byte(matcherCanaryInfix)) {
		t.Fatalf("NEVER-LOG VIOLATION: issued-class event leaked the canary infix")
	}
}
