// SPDX-License-Identifier: Apache-2.0
//
// share_test.go — the two-tier shared-stdio smoke for the serpent-share demo.
//
// TIER 1 (always-on, no network, no API spend — the wave gate green):
//
//   - TestSharedFanInFanOut drives ONE Bridge over a captureStdin sink with TWO
//     concurrent goroutines calling DriveInput (two keyboards) and TWO Subscribers
//     (two browsers). It asserts (a) FAN-IN: both authors' encoded records land on
//     the shared stdin whole — each captured stdin frame is parseable as one
//     complete JSON record carrying exactly one author's text (proving stdinMu's
//     byte-atomic serialization: no torn/interleaved record), and (b) FAN-OUT:
//     BOTH subscribers receive the SAME projected chat.message events in Seq order
//     (the shared broadcast).
//
//   - TestServerTwoClientsSharedSession runs the REAL demo HTTP/WS server against
//     the fake/echo CC and connects TWO real WebSocket clients. Both clients send
//     a distinct line; the test asserts BOTH lines reach the shared CC stdin (both
//     author tags appear in the echoed output) and BOTH clients observe BOTH
//     echoes (shared fan-out end-to-end through the WS layer).
//
// TIER 2 (DS_E2E_LIVE=1, opt-in, real CC via ds-capture):
//
//   - TestSharedSessionRealCC launches the demo server against a REAL local claude
//     through a ds-capture gateway and drives two scripted WS clients with
//     distinct prompts; it asserts both prompts reach CC's stdin and both clients
//     observe CC's reply text. Skipped unless DS_E2E_LIVE=1 (real CC spends
//     budget, ~cents/turn). Tier 1 is the always-green stand-in.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// --- Tier-1 (a): byte-atomic fan-in + shared fan-out over one Bridge ----------

// collectSub records every event a subscriber receives.
type collectSub struct {
	mu     sync.Mutex
	events []attach.Event
}

func (s *collectSub) OnEvent(ev attach.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}
func (s *collectSub) OnClose(error) {}
func (s *collectSub) snapshot() []attach.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]attach.Event(nil), s.events...)
}

func TestSharedFanInFanOut(t *testing.T) {
	const perAuthor = 50

	// ONE bridge over the echo CC: DriveInput -> echo stdin (the shared keyboard)
	// -> echo emits an assistant line -> Pump projects chat.message -> BOTH
	// subscribers (two browsers) see it (the shared broadcast).
	echo := newEchoCC()
	bridge := hostbridge.NewBridge(echo, hostbridge.BridgeConfig{})
	sA, sB := &collectSub{}, &collectSub{}
	bridge.Subscribe(sA)
	bridge.Subscribe(sB)

	ctx, cancel := context.WithCancel(context.Background())
	pumpDone := make(chan struct{})
	go func() { defer close(pumpDone); _ = bridge.Pump(ctx, echo.stdout) }()

	// TWO keyboards: two goroutines each driving perAuthor inputs concurrently.
	var wg sync.WaitGroup
	for _, author := range []string{"A", "B"} {
		wg.Add(1)
		go func(tag string) {
			defer wg.Done()
			for i := 0; i < perAuthor; i++ {
				err := bridge.DriveInput(hostbridge.DriveInput{Text: fmt.Sprintf("[%s] line-%d", tag, i)})
				if err != nil {
					t.Errorf("DriveInput[%s] #%d: %v", tag, i, err)
					return
				}
			}
		}(author)
	}
	wg.Wait()

	// FAN-IN: every captured stdin frame is one whole JSON record carrying
	// exactly one author's text — proves byte-atomic serialization under stdinMu.
	recs := stdinRecords(t, echo)
	if len(recs) != 2*perAuthor {
		t.Fatalf("fan-in: want %d whole records on shared stdin, got %d", 2*perAuthor, len(recs))
	}
	countA, countB := 0, 0
	for _, txt := range recs {
		switch {
		case strings.Contains(txt, "[A] "):
			if strings.Contains(txt, "[B] ") {
				t.Fatalf("fan-in: torn record carries BOTH authors: %q", txt)
			}
			countA++
		case strings.Contains(txt, "[B] "):
			countB++
		default:
			t.Fatalf("fan-in: record carries neither author tag: %q", txt)
		}
	}
	if countA != perAuthor || countB != perAuthor {
		t.Fatalf("fan-in: want %d A + %d B records, got %d A + %d B", perAuthor, perAuthor, countA, countB)
	}

	// Drain the echo: close input so the echo CC EOFs its stdout, Pump returns.
	_ = bridge.CloseInput()
	select {
	case <-pumpDone:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("pump did not return after CloseInput")
	}
	cancel()

	// FAN-OUT: both subscribers saw the SAME chat.message events in Seq order.
	evA := chatTexts(sA.snapshot())
	evB := chatTexts(sB.snapshot())
	if len(evA) != 2*perAuthor {
		t.Fatalf("fan-out: subscriber A saw %d chat.messages, want %d", len(evA), 2*perAuthor)
	}
	if len(evA) != len(evB) {
		t.Fatalf("fan-out: subscribers diverged: A=%d B=%d chat.messages", len(evA), len(evB))
	}
	for i := range evA {
		if evA[i] != evB[i] {
			t.Fatalf("fan-out: subscribers diverged at %d: A=%q B=%q", i, evA[i], evB[i])
		}
	}
	// And both authors' inputs are reflected in the broadcast output.
	gotA, gotB := false, false
	for _, txt := range evA {
		if strings.Contains(txt, "[A] ") {
			gotA = true
		}
		if strings.Contains(txt, "[B] ") {
			gotB = true
		}
	}
	if !gotA || !gotB {
		t.Fatalf("fan-out: broadcast missing an author: A-seen=%v B-seen=%v", gotA, gotB)
	}
}

// stdinRecords reads the raw bytes the bridge wrote to the shared CC stdin (the
// echo CC IS the stdin sink, recording every byte via rawWritten) and splits
// them on the bridge's record-framing newline. Each frame MUST parse as one
// whole JSON record — that is the byte-atomic fan-in proof: stdinMu guarantees
// no two authors' records interleave mid-record on the wire. It returns each
// frame's author-tagged user text.
func stdinRecords(t *testing.T, echo *echoCC) []string {
	t.Helper()
	raw := echo.rawWritten()
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Must parse as ONE whole JSON record (proves no torn record).
		var probe map[string]any
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("fan-in: stdin frame is not a whole JSON record (torn?): %v\n  %q", err, string(line))
		}
		out = append(out, parseUserText(line))
	}
	return out
}

func chatTexts(evs []attach.Event) []string {
	var out []string
	for _, ev := range evs {
		if ev.Type == attach.TypeChatMessage && ev.ChatMessage != nil {
			var sb strings.Builder
			for _, blk := range ev.ChatMessage.Blocks {
				if blk.Kind == "text" {
					sb.WriteString(blk.Text)
				}
			}
			out = append(out, sb.String())
		}
	}
	return out
}

// --- Tier-1 (b): the real demo WS server, two clients, fake CC ----------------

func TestServerTwoClientsSharedSession(t *testing.T) {
	// Stand up the real server handlers over the fake echo CC.
	cc := launchFakeCC()
	defer cc.cleanup()
	hub := newHub(cc.bridge)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cc.bridge.Pump(ctx, cc.stdout) }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/ws", hub.handleWS)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	base := "ws://" + ln.Addr().String() + "/ws"

	// Two browsers connect.
	cA := dialWS(t, base)
	defer cA.Close()
	cB := dialWS(t, base)
	defer cB.Close()

	labelA := waitHello(t, cA)
	labelB := waitHello(t, cB)
	if labelA == labelB {
		t.Fatalf("two clients got the same author label %q", labelA)
	}

	// Both keyboards type a distinct line.
	sendWS(t, cA, "apple")
	sendWS(t, cB, "banana")

	// Both clients must observe BOTH echoes (shared fan-out): the echo CC tags its
	// reply "echo: [<author>] <text>".
	wantA := fmt.Sprintf("[%s] apple", labelA)
	wantB := fmt.Sprintf("[%s] banana", labelB)

	for _, c := range []*tWSClient{cA, cB} {
		seen := collectUntil(t, c, 4*time.Second, func(texts []string) bool {
			return anyContains(texts, wantA) && anyContains(texts, wantB)
		})
		if !anyContains(seen, wantA) {
			t.Fatalf("client did not observe author-A input %q in broadcast; saw: %v", wantA, seen)
		}
		if !anyContains(seen, wantB) {
			t.Fatalf("client did not observe author-B input %q in broadcast; saw: %v", wantB, seen)
		}
	}
}

// --- Tier-2: real CC via ds-capture (DS_E2E_LIVE=1) ---------------------------

func TestSharedSessionRealCC(t *testing.T) {
	if os.Getenv("DS_E2E_LIVE") != "1" {
		t.Skip("DS_E2E_LIVE != 1: real-CC shared-session smoke is gated (spends API budget). Tier-1 is the always-green stand-in.")
	}
	claudePath, err := resolveClaudeBin("")
	if err != nil {
		t.Skipf("real CC: %v", err)
	}
	captureBin, err := resolveCaptureBin("")
	if err != nil {
		t.Skipf("real CC: ds-capture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cc, err := launchCC(ctx, ccOptions{
		claudeBin:  claudePath,
		captureBin: captureBin,
		appendSys:  "You are in a shared demo. Answer in one short sentence.",
	})
	if err != nil {
		t.Fatalf("launch real CC: %v", err)
	}
	defer cc.cleanup()
	hub := newHub(cc.bridge)
	go func() { _ = cc.bridge.Pump(ctx, cc.stdout) }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	base := "ws://" + ln.Addr().String() + "/ws"

	cA := dialWS(t, base)
	defer cA.Close()
	cB := dialWS(t, base)
	defer cB.Close()
	labelA := waitHello(t, cA)
	labelB := waitHello(t, cB)

	sendWS(t, cA, "Say the single word apple and nothing else.")
	time.Sleep(500 * time.Millisecond)
	sendWS(t, cB, "Say the single word banana and nothing else.")

	// Both clients see CC's replies; the shared session is end-to-end.
	for _, c := range []*tWSClient{cA, cB} {
		seen := collectUntil(t, c, 3*time.Minute, func(texts []string) bool {
			return anyContainsFold(texts, "apple") && anyContainsFold(texts, "banana")
		})
		if !anyContainsFold(seen, "apple") || !anyContainsFold(seen, "banana") {
			t.Fatalf("real CC: a client did not observe both replies (labels A=%s B=%s); saw: %v", labelA, labelB, seen)
		}
	}
	t.Logf("real CC shared session: both clients observed both authors' replies through ds-capture")
}

// --- tiny test WS client (stdlib) --------------------------------------------

type tWSClient struct {
	conn net.Conn
	br   *bufio.Reader
}

func dialWS(t *testing.T, url string) *tWSClient {
	t.Helper()
	host := strings.TrimPrefix(url, "ws://")
	host = host[:strings.IndexByte(host, '/')]
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	k := base64.StdEncoding.EncodeToString(key)
	req := "GET /ws HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + k + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("ws handshake write: %v", err)
	}
	br := bufio.NewReader(conn)
	// Read the 101 response headers up to the blank line.
	for {
		ln, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("ws handshake read: %v", err)
		}
		if ln == "\r\n" {
			break
		}
	}
	return &tWSClient{conn: conn, br: br}
}

func (c *tWSClient) Close() error { return c.conn.Close() }

// sendWS sends a masked client TEXT frame carrying {"text": s}.
func sendWS(t *testing.T, c *tWSClient, s string) {
	t.Helper()
	payload, _ := json.Marshal(inMsg{Text: s})
	frame := maskedTextFrame(payload)
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatalf("ws send: %v", err)
	}
}

// readWS reads one server TEXT frame's payload (server frames are unmasked).
func (c *tWSClient) readWS() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	op := hdr[0] & 0x0f
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, err
	}
	if op == 0x8 { // close
		return nil, io.EOF
	}
	if op == 0x9 || op == 0xA { // ping/pong: skip, read next
		return c.readWS()
	}
	return payload, nil
}

func waitHello(t *testing.T, c *tWSClient) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, err := c.readWS()
		if err != nil {
			t.Fatalf("waiting for hello: %v", err)
		}
		var m outMsg
		if json.Unmarshal(data, &m) == nil && m.Kind == "hello" {
			_ = c.conn.SetReadDeadline(time.Time{})
			return m.Label
		}
	}
	t.Fatal("no hello frame within deadline")
	return ""
}

// collectUntil reads frames until pred(texts) holds or the timeout elapses,
// returning every chat.message text seen. It tolerates non-chat frames.
func collectUntil(t *testing.T, c *tWSClient, timeout time.Duration, pred func([]string) bool) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var texts []string
	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
		data, err := c.readWS()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		var m outMsg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.Kind == "event" && m.Event != nil && m.Event.Type == attach.TypeChatMessage && m.Event.ChatMessage != nil {
			for _, blk := range m.Event.ChatMessage.Blocks {
				if blk.Kind == "text" {
					texts = append(texts, blk.Text)
				}
			}
		}
		if pred(texts) {
			break
		}
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	return texts
}

func maskedTextFrame(payload []byte) []byte {
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	n := len(payload)
	var hdr []byte
	b0 := byte(0x81) // FIN + text
	switch {
	case n < 126:
		hdr = []byte{b0, byte(0x80 | n)}
	case n < 1<<16:
		hdr = []byte{b0, 0x80 | 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	out := append([]byte{}, hdr...)
	out = append(out, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	return append(out, masked...)
}

func anyContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

func anyContainsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(strings.ToLower(h), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// ensure the claudecode import is referenced (the driver shape backs DriveInput).
var _ = claudecode.NewDriver
