// SPDX-License-Identifier: Apache-2.0

// serve_test.go — OFFLINE proof of the gap-3 serving leg (--serve-uds): the
// host-local UDS attach server bridged to a GuestIP:4242 TCP leg, exercised end to
// end against an IN-PROCESS FAKE guest TCP listener feeding a synthetic
// stream-json. No live KVM/VM/container/claude/cia and no network beyond a
// loopback socketpair — the same synthetic-fixtures, zero-egress posture the
// hostbridge package's socket_test.go and client/goldentrace/e2e hold (D50).
//
// The fake guest is the U5/U6 in-guest listener's stand-in: it accepts the host
// agent's net.Dial("tcp", guestAddr) (the host→guest carriage), feeds the
// synthetic CC stdout (stream-json) the bridge projects into attach.v1 deltas, and
// captures any writer-seat input the bridge writes back onto the guest leg (the CC
// stdin direction). The real listener is the DS_HOSTAGENT_LIVE / operator step;
// here it is a loopback TCP server.
//
// Three clauses, all in-process:
//
//  1. serve-uds with a VALID token + the writer seat round-trips: a client
//     SocketTransport.Dial attaches over the host-local UDS, drives one DriveInput
//     (which lands on the guest TCP leg as the Driver's encoded record), and
//     observes the projected attach.v1 events from the synthetic stream.
//  2. a WRONG token is rejected (errors.Is ErrAuthInvalid) over the wire — the
//     token-file-backed Server refuses an attach whose token does not match the
//     minter's store.
//  3. an empty / corrupt token file fails CLOSED at readSessionToken (the serving
//     leg never stands up an un-authenticatable session).
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// serveTestStream is the synthetic CC stdout the fake guest feeds — the same
// shape as main.go's selfCheckStream (init + an assistant turn + a result), so the
// adapter projects a non-empty attach.v1 delta sequence including the assistant
// turn. Synthetic by construction (D50): no real ids, paths, or creds.
const serveTestStream = `{"type":"system","subtype":"init","session_id":"00000000-0000-4000-8000-0000000000bb","uuid":"00000000-0000-4000-8000-0000000000b0","cwd":"/work","claude_code_version":"2.1.173","model":"claude-sonnet-4-6","permissionMode":"default","apiKeySource":"none","tools":["Bash"],"agents":[],"slash_commands":[],"skills":[]}
{"type":"assistant","session_id":"00000000-0000-4000-8000-0000000000bb","uuid":"00000000-0000-4000-8000-0000000000b1","parent_tool_use_id":null,"request_id":"req_serve_0001","message":{"id":"msg_serve_0001","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"hello from the synthetic serve-mode guest stream"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":8}}}
{"type":"result","subtype":"success","session_id":"00000000-0000-4000-8000-0000000000bb","uuid":"00000000-0000-4000-8000-0000000000b2","is_error":false,"num_turns":1,"duration_ms":120,"total_cost_usd":0.0001,"result":"done"}`

const (
	serveTestSession = "00000000-0000-4000-8000-000000000099"
	// serveTestToken is the hex AuthMaterial token the minter's file carries (the
	// same hex-encoded-opaque-bytes shape attachminter.go writes); the client
	// presents the identical hex string.
	serveTestToken = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

// fakeGuest is the in-process stand-in for the in-guest attach TCP listener (the
// U5/U6 forwarder). It accepts exactly one host→guest dial, then (after release)
// writes the synthetic stream-json the bridge projects and captures everything the
// bridge writes back onto the guest leg (the writer-seat input direction). It is a
// loopback TCP server: a real net.Conn over 127.0.0.1, never a live VM.
type fakeGuest struct {
	ln      net.Listener
	release chan struct{} // closed to let the guest start emitting the stream
	stream  string

	mu    sync.Mutex
	gotIn []byte // bytes the bridge wrote onto the guest leg (CC stdin direction)
}

// newFakeGuest binds a loopback TCP listener and serves one connection. The
// emitted stream is held until release is closed so a client can attach to the UDS
// FIRST and thus receive the full fan-out.
func newFakeGuest(t *testing.T, stream string) *fakeGuest {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake guest listen: %v", err)
	}
	g := &fakeGuest{
		ln:      ln,
		release: make(chan struct{}),
		stream:  stream,
	}
	t.Cleanup(func() { _ = ln.Close() })
	go g.serve()
	return g
}

func (g *fakeGuest) addr() string { return g.ln.Addr().String() }

// startEmitting releases the guest so it writes the synthetic stream.
func (g *fakeGuest) startEmitting() { close(g.release) }

func (g *fakeGuest) serve() {
	conn, err := g.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Drain the writer-seat input direction concurrently (the bridge writes the
	// Driver-encoded DriveInput record onto this guest leg as CC stdin). Capture it
	// so the test can assert the round-trip reached the guest.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				g.mu.Lock()
				g.gotIn = append(g.gotIn, buf[:n]...)
				g.mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Hold the stream until released so the client attaches first.
	<-g.release
	// Give the client a moment to complete its attach handshake before the fan-out
	// runs (the bridge fans synchronously; a client that attaches after the pump
	// would miss the deltas — the same ordering the package self-checks observe).
	time.Sleep(50 * time.Millisecond)
	_, _ = io.WriteString(conn, g.stream)
	// Closing the write half EOFs the host's Pump (session end). Keep reading the
	// input direction until the host tears its side down.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = conn.Close()
	}
	<-done
}

func (g *fakeGuest) drivenInput() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]byte, len(g.gotIn))
	copy(out, g.gotIn)
	return out
}

// writeTokenFile writes a minter-shaped token file (the persistedAttachToken JSON)
// under a tmpdir and returns its path. An empty token writes an empty Token field
// (the fail-closed case).
func writeTokenFile(t *testing.T, hexToken string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, serveTestSession+".json")
	body, err := json.Marshal(persistedAttachToken{
		Token:     hexToken,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal token file: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// pinnedServeClock pins the projection clock so the test is deterministic (one
// second per call from a fixed base) — the same determinism the package replay
// suites use.
func pinnedServeClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// runServeUDSAsync stands up serveUDS in a goroutine against the fake guest and
// returns its UDS path, a cancel, and a done channel carrying the helper's exit
// error. It waits for the UDS to appear so a client can dial immediately.
func runServeUDSAsync(t *testing.T, g *fakeGuest, token string) (udsPath string, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	udsPath = filepath.Join(t.TempDir(), "attach.sock")
	ctx, cancelFn := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveUDS(ctx, serveUDSConfig{
			sessionUUID:  serveTestSession,
			udsPath:      udsPath,
			guestAddr:    g.addr(),
			sessionToken: token,
			adapterClock: pinnedServeClock(),
		})
	}()
	if err := waitForSocket(udsPath, 5*time.Second); err != nil {
		cancelFn()
		t.Fatalf("serve-uds never bound the UDS: %v", err)
	}
	return udsPath, cancelFn, errCh
}

// clientHandle forges the AttachHandle a serpent-tui client would present after
// mapping the proto DIRECT endpoint to a host-local unix endpoint: the served UDS
// path, the presented token, the requested role. The serving Server re-validates
// it (token, expiry, seat) — this is purely the client's side of the wire.
func clientHandle(udsPath, token string, role hostbridge.Role) hostbridge.AttachHandle {
	return hostbridge.AttachHandle{
		SessionUUID: serveTestSession,
		Endpoints: []hostbridge.EndpointCandidate{
			{Transport: hostbridge.TransportUnix, Address: udsPath},
		},
		Auth:      hostbridge.AuthMaterial{Token: token},
		Role:      role,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// --- (1) valid token + writer seat: drive one input, observe projected events --

func TestServeUDSValidTokenWriterRoundTrip(t *testing.T) {
	g := newFakeGuest(t, serveTestStream)
	udsPath, cancel, serveDone := runServeUDSAsync(t, g, serveTestToken)
	defer cancel()

	// Attach as the WRITER over the host-local UDS (the client's SocketTransport.Dial
	// path), BEFORE the guest emits — so the client receives the full fan-out.
	conn, err := hostbridge.NewSocketTransport().Dial(clientHandle(udsPath, serveTestToken, hostbridge.RoleWriter))
	if err != nil {
		t.Fatalf("client Dial WRITER over UDS: %v", err)
	}
	defer conn.Close()
	if conn.Role() != hostbridge.RoleWriter {
		t.Fatalf("granted role = %q, want WRITER", conn.Role())
	}

	// Collect events off the wire concurrently while the guest stream fans out.
	var got []attach.Event
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		timeout := time.After(10 * time.Second)
		for {
			select {
			case ev, ok := <-conn.Events():
				if !ok {
					return
				}
				got = append(got, ev)
			case <-timeout:
				return
			}
		}
	}()

	// Drive one writer-seat input — it crosses the UDS to the server's drive reader,
	// is encoded by the EXISTING Driver, and lands on the GuestIP:4242 TCP leg (the
	// fake guest captures it).
	const driveText = "drive the bridged guest session over the UDS"
	if err := conn.DriveInput(hostbridge.DriveInput{Text: driveText}); err != nil {
		t.Fatalf("DriveInput over UDS: %v", err)
	}

	// Release the guest to emit the synthetic stream; the host pumps it, projects the
	// deltas, and fans them to this WRITER. The guest then EOFs, ending the session.
	g.startEmitting()
	collectWG.Wait()

	if len(got) == 0 {
		t.Fatal("WRITER received no attach.v1 deltas from the bridged guest stream")
	}
	// The init + assistant turn + result stream must surface the session-init delta
	// (from the init record) and the assistant chat-message delta (from the
	// assistant turn) — proving the synthetic guest stdout was projected through the
	// EXISTING adapter and fanned over the UDS.
	if !hasEventType(got, attach.TypeSessionInit) {
		t.Fatalf("expected a session.init delta from the init record; got types %v", eventTypes(got))
	}
	if !hasEventType(got, attach.TypeChatMessage) {
		t.Fatalf("expected a chat.message delta from the assistant turn; got types %v", eventTypes(got))
	}

	// The driven input reached the GuestIP:4242 leg: the fake guest captured the
	// Driver-encoded record, and it carries the driven text (the bridge wrote the
	// Driver's bytes onto the guest leg, never re-encoding).
	waitFor(t, 5*time.Second, func() bool {
		return len(g.drivenInput()) > 0
	}, "driven input never reached the guest TCP leg")
	gotIn := g.drivenInput()
	var rec map[string]any
	if err := json.Unmarshal(firstJSONLine(gotIn), &rec); err != nil {
		t.Fatalf("guest-leg input record is not a JSON line: %v (raw %q)", err, gotIn)
	}
	if !jsonContains(rec, driveText) {
		t.Fatalf("guest-leg input record %s does not carry the driven text %q", gotIn, driveText)
	}

	// serveUDS returns cleanly once the guest leg EOFs.
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveUDS returned error on clean guest EOF: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUDS did not return after the guest stream ended")
	}
}

// --- (2) wrong token is rejected over the wire --------------------------------

func TestServeUDSWrongTokenRejected(t *testing.T) {
	g := newFakeGuest(t, serveTestStream)
	udsPath, cancel, _ := runServeUDSAsync(t, g, serveTestToken)
	defer cancel()

	// A handle carrying a DIFFERENT token must be rejected with ErrAuthInvalid,
	// surfaced via errors.Is across the wire (the token-file-backed Server compares
	// the presented token against the minter's store).
	const wrongToken = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"
	_, err := hostbridge.NewSocketTransport().Dial(clientHandle(udsPath, wrongToken, hostbridge.RoleReader))
	if !errors.Is(err, hostbridge.ErrAuthInvalid) {
		t.Fatalf("Dial with wrong token err = %v, want errors.Is(_, ErrAuthInvalid)", err)
	}

	// The valid token still attaches — proving the rejection was token-specific, not
	// a dead server.
	conn, err := hostbridge.NewSocketTransport().Dial(clientHandle(udsPath, serveTestToken, hostbridge.RoleReader))
	if err != nil {
		t.Fatalf("valid READER token rejected: %v", err)
	}
	_ = conn.Close()
	// Let the session unwind cleanly (release + cancel the serve).
	g.startEmitting()
	cancel()
}

// --- (3) token-file validation fails closed -----------------------------------

func TestReadSessionTokenFailsClosed(t *testing.T) {
	// Valid file: round-trips the hex token.
	path := writeTokenFile(t, serveTestToken)
	tok, err := readSessionToken(path)
	if err != nil {
		t.Fatalf("readSessionToken(valid) err = %v", err)
	}
	if tok != serveTestToken {
		t.Fatalf("readSessionToken returned %q, want the file's hex token %q", tok, serveTestToken)
	}

	// Empty path, missing file, empty token, and non-hex token all fail CLOSED.
	if _, err := readSessionToken(""); err == nil {
		t.Fatal("empty --session-token-file path must fail closed")
	}
	if _, err := readSessionToken(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing token file must fail closed")
	}
	if _, err := readSessionToken(writeTokenFile(t, "")); err == nil {
		t.Fatal("empty token must fail closed")
	}
	if _, err := readSessionToken(writeTokenFile(t, "not-hex-zz")); err == nil {
		t.Fatal("non-hex token must fail closed")
	}

	// Undecodable JSON also fails closed.
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if _, err := readSessionToken(bad); err == nil {
		t.Fatal("undecodable token file must fail closed")
	}

	// And serveUDS itself refuses an empty token (defence in depth) without dialing.
	if err := serveUDS(context.Background(), serveUDSConfig{
		sessionUUID:  serveTestSession,
		udsPath:      filepath.Join(t.TempDir(), "x.sock"),
		guestAddr:    "127.0.0.1:1", // never dialed: the empty-token guard returns first
		sessionToken: "",
	}); err == nil {
		t.Fatal("serveUDS with an empty token must fail closed before dialing")
	}

	// Sanity: hex round-trips (the file token IS the wire token).
	if _, err := hex.DecodeString(tok); err != nil {
		t.Fatalf("returned token is not hex: %v", err)
	}
}

// --- test helpers --------------------------------------------------------------

func eventTypes(evs []attach.Event) []attach.Type {
	out := make([]attach.Type, len(evs))
	for i, ev := range evs {
		out[i] = ev.Type
	}
	return out
}

func hasEventType(evs []attach.Event, ty attach.Type) bool {
	for _, ev := range evs {
		if ev.Type == ty {
			return true
		}
	}
	return false
}

// firstJSONLine returns the first newline-delimited record from the captured guest
// leg bytes (the bridge frames each record with a trailing newline).
func firstJSONLine(b []byte) []byte {
	sc := bufio.NewScanner(newBytesReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 10<<20)
	if sc.Scan() {
		return append([]byte(nil), sc.Bytes()...)
	}
	return b
}

func newBytesReader(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct {
	b   []byte
	off int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

// jsonContains reports whether want appears anywhere in the JSON value tree (the
// driven text lands in the encoded user-input record; the exact envelope shape is
// the Driver's concern, so the test only asserts the text crossed to the guest).
func jsonContains(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want || containsSubstr(t, want)
	case map[string]any:
		for _, val := range t {
			if jsonContains(val, want) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if jsonContains(val, want) {
				return true
			}
		}
	}
	return false
}

func containsSubstr(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// waitFor polls cond until it holds or the deadline passes, failing with msg.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
