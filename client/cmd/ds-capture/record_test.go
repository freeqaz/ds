// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

const syntheticRecordSSE = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_REC\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"recorded synthetic text\"}}\n\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

// fakeUpstream is an in-process httptest server standing in for
// api.anthropic.com. It records the request headers it saw (to prove the proxy
// strips auth + Accept-Encoding) and replies with synthetic SSE. NO live
// claude/cia/podman/network is involved — D50 / the wave hard fence.
type fakeUpstream struct {
	srv        *httptest.Server
	sawAuth    string
	sawAPIKey  string
	sawAccEnc  string
	sawBeta    string
	gotRequest bool
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotRequest = true
		f.sawAuth = r.Header.Get("Authorization")
		f.sawAPIKey = r.Header.Get("x-api-key")
		f.sawAccEnc = r.Header.Get("Accept-Encoding")
		f.sawBeta = r.Header.Get("anthropic-beta")
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		// Volatile headers the proxy must NOT persist.
		w.Header().Set("request-id", "<synthetic-volatile>")
		w.Header().Set("anthropic-ratelimit-requests-remaining", "999")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, syntheticRecordSSE)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// dialer returns an upstreamDial that ignores the requested host and connects
// to the in-process fake instead (so the proxy never touches the real network).
func (f *fakeUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(f.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// proxyClient builds an http.Client that routes through the recorder/replayer
// proxy at addr and trusts the proxy's CA (so the minted leaf validates).
func proxyClient(t *testing.T, addr, caCertPath string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("CA pem did not parse")
	}
	proxyURL, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func startRecorder(t *testing.T, fake *fakeUpstream) (*recorder, string, func()) {
	t.Helper()
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	// Bind an ephemeral port (:0) so tests never collide and never touch :18080.
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	return rec, addr, func() {
		_ = srv.Close()
		rec.cleanup()
	}
}

// TestRecordTeesSSEAndStripsAuth is the core record test: drive a /v1/messages
// POST through the proxy against an in-process fake upstream emitting synthetic
// SSE, and assert the proxy (a) tees the decoded SSE body + status +
// content-type into the cassette, (b) strips Accept-Encoding before the
// upstream, and (c) strips auth headers so no Bearer/x-api-key reaches the
// cassette.
func TestRecordTeesSSEAndStripsAuth(t *testing.T) {
	fake := newFakeUpstream(t)
	rec, addr, stop := startRecorder(t, fake)
	defer stop()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","system":"synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Auth headers a real CC client would carry — the proxy must strip these
	// before the cassette. Values are obviously-synthetic and below the
	// secret-scan length thresholds.
	req.Header.Set("Authorization", "Bearer synthetic-fake-token")
	req.Header.Set("x-api-key", "synthetic-fake-key")
	req.Header.Set("anthropic-beta", "synthetic-beta")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !fake.gotRequest {
		t.Fatal("fake upstream never saw the request")
	}
	// (b) Accept-Encoding stripped on the upstream leg.
	if fake.sawAccEnc != "" {
		t.Errorf("Accept-Encoding not stripped before upstream: %q", fake.sawAccEnc)
	}
	// The client received the decoded SSE back.
	if string(gotBody) != syntheticRecordSSE {
		t.Errorf("client SSE mismatch:\n got=%q\nwant=%q", gotBody, syntheticRecordSSE)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("content-type not relayed: %q", ct)
	}

	// (a) The cassette captured the interaction.
	if rec.cassette.Len() != 1 {
		t.Fatalf("expected 1 recorded interaction, got %d", rec.cassette.Len())
	}
	it := rec.cassette.Interactions[0]
	if it.StatusCode != 200 {
		t.Errorf("status not teed: %d", it.StatusCode)
	}
	if it.Body != syntheticRecordSSE {
		t.Errorf("cassette body not teed:\n got=%q\nwant=%q", it.Body, syntheticRecordSSE)
	}
	if it.Headers["content-type"] != "text/event-stream" {
		t.Errorf("content-type not teed into cassette: %q", it.Headers["content-type"])
	}
	// (c) Volatile response headers were filtered out of the cassette.
	for _, vol := range []string{"request-id", "anthropic-ratelimit-requests-remaining"} {
		if _, ok := it.Headers[vol]; ok {
			t.Errorf("volatile response header %q survived into the cassette", vol)
		}
	}
	// And no auth value appears anywhere in the persisted cassette.
	for k, v := range it.Headers {
		if cassette.VolatileRequestHeader(k) {
			t.Errorf("auth/volatile header %q survived into the cassette", k)
		}
		if strings.Contains(strings.ToLower(v), "bearer") {
			t.Errorf("a Bearer value survived into a cassette header: %q=%q", k, v)
		}
	}
	// The recorded key matches what cia would derive for this request.
	wantKey := "claude-synthetic-test-1|turns=1|say hi|"
	if !strings.HasPrefix(it.Key, wantKey) {
		t.Errorf("recorded key prefix mismatch:\n got=%q\nwant prefix=%q", it.Key, wantKey)
	}
}

// --- progressive-delivery (incremental tee) test ---------------------------

// event1 and event2 are two distinct SSE events. The blocking fake emits
// event1, then refuses to emit event2 until the proxy's client has OBSERVED
// event1 — so a passing run PROVES the bytes flowed progressively, and the
// proof is by channel SYNCHRONIZATION, never by sleeps/timing (DRIVE-PROTOCOL.md
// forbids timing-derived assertions).
const progEvent1 = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_PROG\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n"

const progEvent2 = "event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

// blockingUpstream is an httptest fake that emits SSE event1, flushes it, then
// BLOCKS until the test signals (via gotEvent1) that the proxy client has seen
// event1 — only then does it emit event2 and finish. Pure in-process fake, no
// live claude/cia/podman/network (D50 / the wave hard fence).
type blockingUpstream struct {
	srv       *httptest.Server
	gotEvent1 chan struct{} // test closes this once the client has observed event1
	emitted2  chan struct{} // fake closes this after event2 is emitted
}

func newBlockingUpstream(t *testing.T) *blockingUpstream {
	t.Helper()
	b := &blockingUpstream{
		gotEvent1: make(chan struct{}),
		emitted2:  make(chan struct{}),
	}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, progEvent1)
		fl.Flush() // push event1 down the wire NOW

		// Block until the proxy's client has demonstrably observed event1. This
		// is the synchronization point: under a true incremental tee the client
		// receives event1 before upstream EOF, so this unblocks; under
		// buffer-then-relay the client gets nothing until EOF, which cannot
		// happen until we emit event2 below — a deadlock the bounded-timeout
		// test surfaces as a failure.
		<-b.gotEvent1

		_, _ = io.WriteString(w, progEvent2)
		fl.Flush()
		close(b.emitted2)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *blockingUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(b.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestRecordTeesProgressively proves recordMessages relays SSE bytes to the
// client AS THEY ARRIVE (an incremental tee), not buffer-then-relay. The fake
// upstream emits event1, then blocks until the client has read event1; only the
// streaming tee lets the client read event1 before upstream EOF, so a
// buffer-then-relay implementation DEADLOCKS here and the bounded timeout fails
// it. It also asserts the recorded cassette body equals the full concatenated
// SSE (event1+event2).
func TestRecordTeesProgressively(t *testing.T) {
	fake := newBlockingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, derr := client.Do(req)
		if derr != nil {
			done <- result{err: derr}
			return
		}
		defer resp.Body.Close()

		// Read incrementally until event1's bytes have been OBSERVED, then
		// signal the upstream it may emit event2. This read MUST complete before
		// upstream EOF — that is exactly what the incremental tee guarantees and
		// buffer-then-relay denies.
		var seen []byte
		rbuf := make([]byte, 256)
		for !strings.Contains(string(seen), "msg_SYNTHETIC_PROG") {
			n, rerr := resp.Body.Read(rbuf)
			seen = append(seen, rbuf[:n]...)
			if rerr != nil {
				done <- result{body: seen, err: rerr}
				return
			}
		}
		// Event1 observed — release the upstream to emit event2.
		close(fake.gotEvent1)

		// Drain the remainder (event2).
		rest, rerr := io.ReadAll(resp.Body)
		seen = append(seen, rest...)
		done <- result{body: seen, err: rerr}
	}()

	wantBody := progEvent1 + progEvent2
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("client read failed: %v", res.err)
		}
		if string(res.body) != wantBody {
			t.Errorf("client SSE mismatch:\n got=%q\nwant=%q", res.body, wantBody)
		}
	case <-time.After(5 * time.Second):
		// A buffer-then-relay implementation lands here: the client never
		// observes event1 (it waits for EOF), so it never closes gotEvent1, so
		// the upstream never emits event2, so EOF never comes — deadlock.
		t.Fatal("progressive delivery timed out: client did not observe event1 before upstream EOF " +
			"(buffer-then-relay would deadlock here; an incremental tee must not)")
	}

	// Belt-and-suspenders: the fake must have emitted event2 (it only does so
	// after the client observed event1), confirming the ordering really held.
	select {
	case <-fake.emitted2:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never emitted event2 — progressive ordering did not hold")
	}

	// The recorded cassette body equals the FULL concatenated SSE stream — one
	// Record call at upstream EOF, byte-identical to what was relayed. The client
	// can observe stream EOF a hair before the proxy's deferred Record runs, so
	// wait for the recorder to settle under its own mutex (a completion barrier,
	// not a timing assertion — the bytes are already proven progressive above).
	var recordedBody string
	settled := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := rec.cassette.Len()
		if n == 1 {
			recordedBody = rec.cassette.Interactions[0].Body
			settled = true
		}
		rec.mu.Unlock()
		if settled {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !settled {
		rec.mu.Lock()
		n := rec.cassette.Len()
		rec.mu.Unlock()
		t.Fatalf("expected 1 recorded interaction, got %d", n)
	}
	if recordedBody != wantBody {
		t.Errorf("cassette body != full concatenated SSE:\n got=%q\nwant=%q", recordedBody, wantBody)
	}
}

// TestRecordPassesThroughNonMessages proves a non-/v1/messages request is
// forwarded (not recorded). The fake replies for any path; only /v1/messages is
// teed.
func TestRecordPassesThroughNonMessages(t *testing.T) {
	fake := newFakeUpstream(t)
	rec, addr, stop := startRecorder(t, fake)
	defer stop()
	client := proxyClient(t, addr, rec.caCertPath)

	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages/count_tokens", strings.NewReader(`{"model":"m"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("count_tokens passthrough failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if rec.cassette.Len() != 0 {
		t.Errorf("count_tokens should not be recorded, got %d interactions", rec.cassette.Len())
	}
}

// TestRecordDefaultPortIsNot18080 asserts the never-:18080 invariant in code:
// the default is :18099 and binding the protected port is refused.
func TestRecordDefaultPortIsNot18080(t *testing.T) {
	if DefaultPort != 18099 {
		t.Fatalf("default port must be 18099, got %d", DefaultPort)
	}
	if DefaultPort == ProtectedMonitorPort {
		t.Fatal("default port must never equal the protected monitor port")
	}
	if err := assertNotProtectedPort(ProtectedMonitorPort); err == nil {
		t.Fatal("assertNotProtectedPort(:18080) must error")
	}
	if err := assertNotProtectedPort(DefaultPort); err != nil {
		t.Fatalf("assertNotProtectedPort(:18099) must pass, got %v", err)
	}
	// listen must also refuse the protected port.
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	defer rec.cleanup()
	if _, _, err := rec.listen("127.0.0.1", ProtectedMonitorPort); err == nil {
		t.Fatal("recorder.listen(:18080) must refuse")
	}
}

// TestRecordedCassetteReplaysHermetically is the end-to-end offline proof: a
// cassette recorded through the proxy replays identically through the replayer
// WITHOUT any upstream dial.
func TestRecordedCassetteReplaysHermetically(t *testing.T) {
	fake := newFakeUpstream(t)
	rec, addr, stop := startRecorder(t, fake)
	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","system":"synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("record request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	recorded := rec.cassette
	stop()

	// Replay the just-recorded cassette, asserting no dial.
	rp, err := newReplayer(recorded, true, false, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	rsrv, raddr, err := rp.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("replayer listen: %v", err)
	}
	go func() { _ = rsrv.Serve(rp.ln) }()
	defer rsrv.Close()

	rclient := proxyClient(t, raddr, rp.caCertPath)
	rreq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	rresp, err := rclient.Do(rreq)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	rbody, _ := io.ReadAll(rresp.Body)
	rresp.Body.Close()

	if string(rbody) != syntheticRecordSSE {
		t.Errorf("replayed SSE mismatch:\n got=%q\nwant=%q", rbody, syntheticRecordSSE)
	}
	if rp.dialedUpstream {
		t.Error("replay dialed upstream — hermetic guarantee broken")
	}
}

// --- partial-on-error (truncated turn) test --------------------------------

// midStreamErrorUpstream is a RAW-TCP in-process fake (not httptest) that lets
// us cut the connection mid-SSE deterministically: it reads the proxied request,
// writes a chunked response head plus exactly one chunk carrying a message_start
// event, flushes, then CLOSES the socket WITHOUT the terminal zero-length chunk
// — so the proxy's body reader sees io.ErrUnexpectedEOF (a mid-stream failure),
// never a clean io.EOF. No live claude/cia/podman/network (D50 / the wave fence).
type midStreamErrorUpstream struct {
	ln net.Listener
}

// truncatedSSE is a synthetic, obviously-fake SSE stream that STOPS after
// message_start — it deliberately carries NO message_stop, so it is not a
// complete turn. Values are synthetic (no real ids/models/costs).
const truncatedSSE = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_TRUNC\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n"

func newMidStreamErrorUpstream(t *testing.T) *midStreamErrorUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("midstream listen: %v", err)
	}
	m := &midStreamErrorUpstream{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *midStreamErrorUpstream) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_, _ = io.ReadAll(req.Body) // drain the request body so the write side unblocks
	_ = req.Body.Close()

	// Response head: chunked text/event-stream.
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	// Exactly one chunk carrying message_start, then a HARD close with NO
	// terminal "0\r\n\r\n" chunk — the upstream "dies after message_start".
	chunk := truncatedSSE
	if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(chunk), chunk); err != nil {
		return
	}
	// Drop the connection mid-stream (no terminal chunk): close immediately.
}

func (m *midStreamErrorUpstream) dialer() func(string) (net.Conn, error) {
	target := m.ln.Addr().String()
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestRecordRefusesTruncatedTurn proves that a mid-stream upstream failure does
// NOT yield a cassette interaction that replays as a complete turn. The fake
// upstream emits message_start, then dies before message_stop. The recorder must
// (a) relay what it got to the client (best-effort, the stream is already
// in-flight) but (b) REFUSE to record the truncated turn — so the cassette stays
// empty and a later replay of that cassette serves a miss, never a complete turn.
func TestRecordRefusesTruncatedTurn(t *testing.T) {
	fake := newMidStreamErrorUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		// The client may or may not surface a read error depending on how the
		// truncation manifests over the chunked relay; either way drain it.
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// (b) THE CORE ASSERTION: the truncated turn was NOT recorded.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("a truncated (mid-stream-error) turn was recorded as %d interaction(s); "+
			"it must be refused so it cannot replay as a complete turn", n)
	}

	// And prove the end-to-end guarantee: replaying the resulting cassette serves
	// a MISS (the synthetic 502), never a complete turn — there is nothing to
	// serve, by construction.
	rp, err := newReplayer(rec.cassette, true, false, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	rsrv, raddr, err := rp.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("replayer listen: %v", err)
	}
	go func() { _ = rsrv.Serve(rp.ln) }()
	defer rsrv.Close()

	rclient := proxyClient(t, raddr, rp.caCertPath)
	rreq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	rresp, err := rclient.Do(rreq)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	rbody, _ := io.ReadAll(rresp.Body)
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusBadGateway {
		t.Errorf("replay of an empty cassette must MISS (502), got status %d", rresp.StatusCode)
	}
	if strings.Contains(string(rbody), "msg_SYNTHETIC_TRUNC") {
		t.Error("the truncated stream leaked into a replay — it must never be served back")
	}
	if !strings.Contains(string(rbody), "cia_replay_miss") {
		t.Errorf("replay of an empty cassette must be a cia_replay_miss, got body %q", rbody)
	}
}

// TestRecordRefusesCleanStreamWithoutMessageStop is a focused unit on the turn
// boundary: even a CLEANLY closed upstream whose SSE lacks a terminal
// message_stop is below a turn boundary, so it must NOT be recorded. This pins
// the "refuse below a message_stop boundary" rule independent of the transport
// error path above.
func TestRecordRefusesCleanStreamWithoutMessageStop(t *testing.T) {
	// Clean EOF but truncated content.
	if hasTurnBoundary([]byte(truncatedSSE)) {
		t.Fatal("truncatedSSE must NOT be a turn boundary (it has no message_stop)")
	}
	// A complete turn DOES carry message_stop.
	if !hasTurnBoundary([]byte(syntheticRecordSSE)) {
		t.Fatal("a complete turn (syntheticRecordSSE) must be a turn boundary")
	}
}

// --- gzip-fallback hardening test ------------------------------------------

// gzipBlockingUpstream is an httptest fake that writes a /v1/messages response
// HEAD with Content-Encoding: gzip (a non-compliant upstream — the recorder
// stripped Accept-Encoding), flushes ONLY the headers, then BLOCKS forever
// without writing any body. It proves the recorder fails closed from the HEADERS
// alone: under the old buffer-then-relay gunzip fallback the proxy would block on
// io.ReadAll of the body and the client would hang (timeout); under the hardened
// path the client gets a 502 immediately, so NO full-body buffering occurs
// before the first client byte. The body bytes are never sent, so this proof is
// by synchronization, not timing (DRIVE-PROTOCOL.md forbids timing assertions).
type gzipBlockingUpstream struct {
	srv     *httptest.Server
	release chan struct{} // closed at test cleanup so the handler can return
}

func newGzipBlockingUpstream(t *testing.T) *gzipBlockingUpstream {
	t.Helper()
	g := &gzipBlockingUpstream{release: make(chan struct{})}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("gzip upstream ResponseWriter is not a Flusher")
			return
		}
		// Advertise gzip despite the recorder having stripped Accept-Encoding.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		fl.Flush() // push ONLY the headers; write NO body
		// Block (never write a body) until the test releases us at cleanup. If the
		// recorder buffered-then-relayed, it would hang here reading the body.
		<-g.release
	}))
	t.Cleanup(func() {
		close(g.release)
		g.srv.Close()
	})
	return g
}

func (g *gzipBlockingUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(g.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestRecordGzipResponseIsHardError proves a gzip-encoded upstream /v1/messages
// response is a HARD gateway error rather than a buffer-then-relay decode. The
// fake advertises Content-Encoding: gzip then blocks WITHOUT writing a body; the
// recorder must respond 502 from the response headers alone (no full-body
// buffering before the first client byte), record NOTHING, and not hang. A
// buffer-then-relay implementation would block on the missing body and time out.
func TestRecordGzipResponseIsHardError(t *testing.T) {
	fake := newGzipBlockingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, derr := client.Do(req)
		if derr != nil {
			done <- result{err: derr}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: b}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("gzip-response request failed: %v", res.err)
		}
		// HARD gateway error: 502, NOT a relayed/decoded body.
		if res.status != http.StatusBadGateway {
			t.Errorf("gzip upstream response must be a hard 502, got status %d", res.status)
		}
		// The error message reports shape only (the encoding), never any secret
		// or body bytes (never-log-the-secret, HARDENING-NOTES §2.2).
		if !strings.Contains(strings.ToLower(string(res.body)), "gzip") {
			t.Errorf("502 body should name the offending encoding, got %q", res.body)
		}
	case <-time.After(5 * time.Second):
		// A buffer-then-relay gunzip fallback lands here: it blocks on io.ReadAll
		// of the never-arriving body, so the client never gets its first byte.
		t.Fatal("gzip response did not fail closed: the client got no 502 before the body arrived " +
			"(buffer-then-relay would block on the missing body; the hardened path must not)")
	}

	// And nothing was recorded — a gzip turn is never persisted.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("a gzip (hard-error) turn must not be recorded, got %d interaction(s)", n)
	}
}

// --- hermetic REAL-tls.Dial record-leg coverage ----------------------------
//
// The fakes above inject r.upstreamDial, so they exercise recordMessages while
// SKIPPING the production crypto/tls dial (dialUpstreamTLS). record_live_test.go
// runs that real dial, but only as a DS_E2E_LIVE-gated bare handshake against a
// public host. The helper + two tests below close the gap: they stand up an
// in-process TLS upstream on an ephemeral 127.0.0.1 port and let the recorder
// reach it through its REAL dialUpstreamTLS path (r.upstreamDial is LEFT at its
// newRecorder default), driving record.go's gzip-hard-error and
// refuse-partial-on-error branches end-to-end with ZERO egress and NO
// DS_E2E_LIVE gate. The seam is record.go's tlsDialAddr/tlsRootCAs, which only
// repoint the dial target + inject a root pool — the tls.Dial, SNI, and
// cert-name verification are the production ones.

// hermeticRecordUpstream is an in-process TLS listener standing in for
// api.anthropic.com on an ephemeral 127.0.0.1 port. Its leaf cert is minted for
// anthropicHost (so the production ServerName-based verification passes) and is
// anchored by rootCAs, which the test injects into the recorder's dial config.
// Each accepted connection is handed to serve, a per-test raw-conn handler that
// reads the proxied HTTP request and writes a synthetic response — letting a
// test serve a gzip-headed response or a truncated chunked stream through the
// REAL tls.Dial leg. No live claude/cia/podman/network is involved (D50 / the
// wave hard fence); the listener is loopback-only and never binds :18080.
type hermeticRecordUpstream struct {
	ln      net.Listener
	rootCAs *x509.CertPool
	serve   func(conn net.Conn)
}

// newHermeticRecordUpstream binds an ephemeral 127.0.0.1 TLS listener whose cert is
// signed by a fresh synthetic CA and minted for anthropicHost, returning the
// listener plus a root pool carrying that CA. serve handles each accepted TLS
// connection. It reuses the production generateCA/mintLeaf so the cert chain is
// exactly the shape the recorder's WebPKI dial expects.
func newHermeticRecordUpstream(t *testing.T, serve func(conn net.Conn)) *hermeticRecordUpstream {
	t.Helper()
	ca, caKey, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	leaf, err := mintLeaf(anthropicHost, ca, caKey)
	if err != nil {
		t.Fatalf("mintLeaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hermetic upstream listen: %v", err)
	}
	tlsLn := tls.NewListener(tcpLn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	u := &hermeticRecordUpstream{ln: tlsLn, rootCAs: pool, serve: serve}
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go u.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = tlsLn.Close() })
	return u
}

// wire points a recorder's REAL dial path (dialUpstreamTLS) at this in-process
// TLS upstream: it overrides ONLY the dial target + root pool and LEAVES
// r.upstreamDial at its newRecorder default (r.dialUpstreamTLS), so the
// production tls.Dial + SNI + cert verification run unchanged.
func (u *hermeticRecordUpstream) wire(rec *recorder) {
	rec.tlsDialAddr = u.ln.Addr().String()
	rec.tlsRootCAs = u.rootCAs
}

// startRecorderHermetic builds a recorder whose upstream leg is the in-process
// TLS upstream reached through the REAL dialUpstreamTLS, binds the proxy on an
// ephemeral 127.0.0.1 port, and returns it with a stop func.
func startRecorderHermetic(t *testing.T, up *hermeticRecordUpstream) (*recorder, string, func()) {
	t.Helper()
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	up.wire(rec) // REAL tls.Dial path; r.upstreamDial is NOT replaced.
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	return rec, addr, func() {
		_ = srv.Close()
		rec.cleanup()
	}
}

// readProxiedRequest drains the HTTP request the recorder replays onto the
// upstream TLS conn, so the write side unblocks before the handler responds.
func readProxiedRequest(conn net.Conn) error {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	_, _ = io.ReadAll(req.Body)
	return req.Body.Close()
}

// TestRecordGzipHardErrorThroughRealDial drives record.go's gzip-hard-error
// branch (record.go ~L312: Content-Encoding: gzip => 502 before any body) end to
// end through the REAL crypto/tls dial path. The in-process TLS upstream replies
// with a gzip-advertising response HEAD and then closes WITHOUT a body; the
// recorder must fail closed with a 502 from the headers alone and record nothing.
// Removing the gzip guard in record.go makes this fail (the recorder would relay
// the empty/garbage body instead of a 502), so the test is non-vacuous.
func TestRecordGzipHardErrorThroughRealDial(t *testing.T) {
	up := newHermeticRecordUpstream(t, func(conn net.Conn) {
		defer conn.Close()
		if err := readProxiedRequest(conn); err != nil {
			return
		}
		// Advertise gzip despite the recorder stripping Accept-Encoding (a
		// non-compliant upstream), then close with NO body. The recorder must
		// reject from the HEAD alone. Synthetic, body-free response.
		head := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Content-Encoding: gzip\r\n" +
			"Content-Length: 0\r\n\r\n"
		_, _ = io.WriteString(conn, head)
	})
	rec, addr, stop := startRecorderHermetic(t, up)
	defer stop()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, derr := client.Do(req)
		if derr != nil {
			done <- result{err: derr}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: b}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("gzip-response request through real dial failed: %v", res.err)
		}
		// HARD gateway error: 502, not a relayed/decoded body — proving the gzip
		// guard fired on the response that came back over the REAL tls.Dial leg.
		if res.status != http.StatusBadGateway {
			t.Errorf("gzip upstream over real dial must be a hard 502, got status %d", res.status)
		}
		// Shape-only: the 502 names the encoding, never a body byte or secret
		// (never-log-the-secret, HARDENING-NOTES §2.2).
		if !strings.Contains(strings.ToLower(string(res.body)), "gzip") {
			t.Errorf("502 body should name the offending encoding, got %q", res.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gzip response over real dial did not fail closed before a body arrived")
	}

	// Nothing was recorded — a gzip turn is never persisted.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("a gzip (hard-error) turn over real dial must not be recorded, got %d interaction(s)", n)
	}
}

// TestRecordRefusesTruncatedTurnThroughRealDial drives record.go's
// refuse-partial-on-error branch (record.go ~L347: record only when cleanEOF &&
// hasTurnBoundary) end to end through the REAL crypto/tls dial path. The
// in-process TLS upstream writes a chunked response head plus exactly one chunk
// carrying a synthetic message_start, then closes WITHOUT the terminal
// zero-length chunk — so the recorder's body reader sees a mid-stream failure
// (no clean io.EOF) on a turn that also lacks message_stop. The recorder must
// record ZERO interactions. Removing the cleanEOF/hasTurnBoundary guard makes
// this fail (the truncated turn would be persisted), so the test is non-vacuous.
func TestRecordRefusesTruncatedTurnThroughRealDial(t *testing.T) {
	up := newHermeticRecordUpstream(t, func(conn net.Conn) {
		defer conn.Close()
		if err := readProxiedRequest(conn); err != nil {
			return
		}
		head := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n"
		if _, err := io.WriteString(conn, head); err != nil {
			return
		}
		// One chunk of message_start, then a HARD close with NO terminal chunk —
		// the upstream "dies after message_start". truncatedSSE is synthetic and
		// carries no message_stop.
		if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(truncatedSSE), truncatedSSE); err != nil {
			return
		}
	})
	rec, addr, stop := startRecorderHermetic(t, up)
	defer stop()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Drive the request to completion on a bounded timeout so a regression that
	// hangs is a failure, not a stuck test.
	done := make(chan struct{}, 1)
	go func() {
		resp, derr := client.Do(req)
		if derr == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("truncated-turn request over real dial did not complete")
	}

	// THE CORE ASSERTION: the truncated turn that came back over the REAL tls.Dial
	// leg was NOT recorded, so it can never replay as a complete turn.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("a truncated turn over real dial was recorded as %d interaction(s); "+
			"it must be refused so it cannot replay as a complete turn", n)
	}

	// End-to-end: replaying the resulting cassette MISSES (the synthetic 502),
	// never serving the truncated stream back.
	rp, err := newReplayer(rec.cassette, true, false, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	rsrv, raddr, err := rp.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("replayer listen: %v", err)
	}
	go func() { _ = rsrv.Serve(rp.ln) }()
	defer rsrv.Close()

	rclient := proxyClient(t, raddr, rp.caCertPath)
	rreq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	rresp, err := rclient.Do(rreq)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	rbody, _ := io.ReadAll(rresp.Body)
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusBadGateway {
		t.Errorf("replay of an empty cassette must MISS (502), got status %d", rresp.StatusCode)
	}
	if strings.Contains(string(rbody), "msg_SYNTHETIC_TRUNC") {
		t.Error("the truncated stream leaked into a replay — it must never be served back")
	}
}

// --- record-persist D50 cassette-wall (twin of the replay --passthrough scrub) -
//
// These tests close the highest-leverage remaining D50 record-path surface
// (CAPTURE-TOOL-DESIGN.md §7 "D50 wall during migration"; HARDENING-NOTES.md
// §2.2): they prove — OFFLINE, against the PERSISTED-TO-DISK cassette artifact,
// not just the in-memory object — that the auth/volatile request headers a real
// CC client attaches to /v1/messages (Authorization, x-api-key, anthropic-beta,
// the session/correlation tells) NEVER survive into what `record` writes, even
// though the recorder forwarded those exact bytes upstream so it could
// authenticate. The header surface is the twin of the replay --passthrough
// scrubUpstreamHeaders wall, but on what record PERSISTS rather than on the
// upstream wire.
//
// WHICH CASE: the persist header-wall already HOLDS by construction — the record
// path never captures request headers into the cassette; recordMessages persists
// only the upstream RESPONSE headers, themselves filtered to the content-type
// allow-list (cassette.FilterReplayHeaders). So these are TEST-ONLY proofs of a
// pre-existing structural guarantee, made non-vacuous (a) by the wire-vs-cassette
// contrast — the upstream leg DID carry the credential — and (b) by being driven
// against the on-disk bytes, so a regression that started persisting request
// headers (or stopped filtering response headers) would fail them.
//
// All synthetic credentials are assembled at runtime via syntheticBearerHeaders()
// (replay_live_test.go) so no full token-shaped literal is committed (D50 /
// the repo secret scan), and assertion failures report header NAME or
// shape/offset only, never the (synthetic) credential bytes
// (never-log-the-secret, HARDENING-NOTES.md §2.2).

// headerCapturingUpstream is an in-process httptest fake that records EVERY
// request header it saw (so the no-leak test can prove the auth/volatile headers
// reached the upstream wire — the non-vacuousness contrast) and replies with
// synthetic, credential-free SSE. It is its own fake (not the shared
// fakeUpstream) so capturing the full header set never perturbs the other
// record tests. No live claude/cia/podman/network is involved (D50 / the wave
// hard fence); the listener is loopback-only and never binds :18080.
type headerCapturingUpstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	sawWire http.Header
}

func newHeaderCapturingUpstream(t *testing.T) *headerCapturingUpstream {
	t.Helper()
	f := &headerCapturingUpstream{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.sawWire = r.Header.Clone()
		f.mu.Unlock()
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, syntheticRecordSSE)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *headerCapturingUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(f.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

func (f *headerCapturingUpstream) wireHeader(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawWire.Get(name)
}

// TestRecordPersistedCassetteIsCredentialFree is the record-persist D50 wall: a
// /v1/messages turn carrying obviously-synthetic auth/volatile request headers
// (the credential rides the HEADERS — the surface the wall governs) is recorded,
// the cassette is SAVED TO DISK, then RELOADED FROM THAT FILE, and we assert:
//
//	(a) no header in the cassette.VolatileRequestHeader set survives in any
//	    persisted interaction's Headers map (only the content-type allow-list);
//	(b) NONE of the synthetic credential bytes appear ANYWHERE in the raw saved
//	    cassette bytes — headers, normalized request, or body — nor does any
//	    Bearer/sk-ant-SHAPED token survive;
//	(c) NON-VACUOUSNESS: the recorder DID forward those exact auth headers and
//	    credential values onto the UPSTREAM wire (it must, to authenticate), so
//	    the wall genuinely stripped a credential the tee carried — the same
//	    wire-vs-persisted contrast the replay --passthrough scrub test proves.
//
// Failure messages report header NAME / shape / offset only, never the synthetic
// credential bytes (never-log-the-secret, HARDENING-NOTES.md §2.2).
func TestRecordPersistedCassetteIsCredentialFree(t *testing.T) {
	fake := newHeaderCapturingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	// A /v1/messages POST whose BODY is credential-free (a clean system prompt +
	// user turn) — the credential rides only the auth/volatile HEADERS, which is
	// the persist surface this wall governs. (A credential planted in the request
	// body or the SSE response body is raw-class by design and is the `scrub`
	// subcommand's responsibility, asserted separately below.)
	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","system":"clean synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Obviously-synthetic auth/volatile headers, assembled at runtime so no full
	// token literal is committed. These are the §2.2 auth-bearing tells.
	syn := syntheticBearerHeaders()
	for k, v := range syn {
		req.Header.Set(k, v)
	}
	// Add the remaining §2.2 correlation tell the helper does not carry.
	const xClientReqID = "synthetic-client-req-0000-0000-0000-000000000000"
	req.Header.Set("x-client-request-id", xClientReqID)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// (c) NON-VACUOUSNESS, part 1: the recorder forwarded the synthetic auth
	// headers + credential VALUES onto the upstream wire (it authenticates as the
	// client would). Prove the tee genuinely carried what the persist wall must
	// then strip — without this the (a)/(b) assertions could pass vacuously.
	if got := fake.wireHeader("Authorization"); got != syn["Authorization"] {
		t.Errorf("non-vacuousness broken: recorder did not forward Authorization upstream (wire header empty/mismatched)")
	}
	if got := fake.wireHeader("x-api-key"); got != syn["x-api-key"] {
		t.Errorf("non-vacuousness broken: recorder did not forward x-api-key upstream")
	}
	if got := fake.wireHeader("anthropic-beta"); got != syn["anthropic-beta"] {
		t.Errorf("non-vacuousness broken: recorder did not forward anthropic-beta upstream")
	}
	if got := fake.wireHeader("x-client-request-id"); got != xClientReqID {
		t.Errorf("non-vacuousness broken: recorder did not forward x-client-request-id upstream")
	}

	// PERSIST the cassette to a real file, then LOAD IT BACK — the whole point is
	// to assert against the on-disk artifact, not the in-memory object.
	path := filepath.Join(t.TempDir(), "recorded.json")
	rec.mu.Lock()
	saveErr := rec.cassette.Save(path)
	rec.mu.Unlock()
	if saveErr != nil {
		t.Fatalf("save cassette: %v", saveErr)
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted cassette: %v", err)
	}
	loaded, err := cassette.Load(path)
	if err != nil {
		t.Fatalf("load persisted cassette: %v", err)
	}
	if loaded.Len() != 1 {
		t.Fatalf("expected exactly 1 persisted interaction, got %d", loaded.Len())
	}

	// (a) No auth/volatile request header survives in the persisted headers — only
	// the content-type allow-list. Report the header NAME only on a breach.
	for _, it := range loaded.Interactions {
		for name := range it.Headers {
			if cassette.VolatileRequestHeader(name) {
				t.Errorf("D50 LEAK: auth/volatile header %q survived into the persisted cassette", strings.ToLower(name))
			}
			if !strings.EqualFold(name, "content-type") {
				t.Errorf("non-allow-list header %q survived into the persisted cassette (only content-type may)", strings.ToLower(name))
			}
		}
	}

	// (b) The synthetic credential VALUES appear NOWHERE in the raw saved bytes
	// (headers + normalized + body), and no Bearer/sk-ant-SHAPED token survives.
	// Compare against the raw file bytes so this covers every persisted field.
	for label, cred := range map[string]string{
		"Authorization value": syn["Authorization"],
		"x-api-key value":     syn["x-api-key"],
		"session-id value":    syn["X-Claude-Code-Session-Id"],
		"client-req-id value": xClientReqID,
	} {
		if bytes.Contains(rawBytes, []byte(cred)) {
			// Report the surface only, never the credential bytes.
			t.Errorf("D50 LEAK: %s survived into the persisted cassette bytes (value redacted)", label)
		}
	}
	if loc := bearerShapedToken.FindIndex(rawBytes); loc != nil {
		t.Errorf("D50 LEAK: a Bearer/sk-ant-shaped token survived in the persisted cassette (offset=%d, len=%d, value redacted)",
			loc[0], loc[1]-loc[0])
	}
	// Belt-and-suspenders on the structured object too: scanSecrets walks headers,
	// normalized, and body; it must find nothing in this synthetic-clean cassette.
	if hits := scanSecrets(loaded); len(hits) > 0 {
		t.Errorf("D50 LEAK: scanSecrets flagged %d secret-shaped survivor(s) in the persisted cassette: %v", len(hits), hits)
	}

	// Sanity: the interaction was genuinely recorded (the body is the synthetic
	// SSE), so (a)/(b) held over a REAL captured turn, not an empty cassette.
	if loaded.Interactions[0].Body != syntheticRecordSSE {
		t.Errorf("persisted body is not the recorded synthetic SSE (the turn was not captured as expected)")
	}
}

// TestRecordRawBodyCredentialIsScrubSubcommandsJob pins the DESIGN BOUNDARY the
// wall above governs: a `record` capture is RAW-CLASS by design (the §3 record
// row: "Cred-bearing"; §7 "every live capture is raw-class"). A credential that
// rides the REQUEST BODY (system prompt / message content) or the SSE RESPONSE
// body is NOT stripped at record-persist time — it persists into the raw
// cassette and is the explicit `scrub` subcommand's job to remove before any
// promotion to git (HARDENING-NOTES.md §2.2/§2.3). This test makes that boundary
// EXPLICIT and TESTED (not merely asserted in prose) so a future reader does not
// mistake the header-wall above for a whole-artifact scrub, and so the
// raw→scrub→synthetic dataflow's first hop is honest. The synthetic credential
// is assembled at runtime; scrubCassette is then shown to catch it — the
// documented wall that DOES close this surface.
func TestRecordRawBodyCredentialIsScrubSubcommandsJob(t *testing.T) {
	// A credential planted in the request body (worst case for raw-class capture).
	const filler = "0000000000000000000000000000"
	bodyCred := "sk-ant-" + "api" + "00-" + "SYNTHETIC" + filler

	fake := newHeaderCapturingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","system":"sys ` + bodyCred + `","messages":[{"role":"user","content":"hi ` + bodyCred + `"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	rec.mu.Lock()
	cas := rec.cassette
	rec.mu.Unlock()
	if cas.Len() != 1 {
		t.Fatalf("expected 1 recorded interaction, got %d", cas.Len())
	}

	// DESIGN FACT: a body-borne credential IS present in the raw record (this is
	// the raw-class behavior the wall above deliberately does NOT touch). If this
	// ever stops being true, the raw→scrub dataflow assumption changed and this
	// test should be revisited — it is the honest boundary marker.
	if scanSecrets(cas) == nil || len(scanSecrets(cas)) == 0 {
		t.Skip("body-borne credential was not present in the raw record — the raw-class assumption changed; revisit the record/scrub boundary")
	}

	// THE WALL THAT CLOSES THIS SURFACE: the `scrub` subcommand fails closed on
	// the raw capture, refusing to emit a committable artifact. This is the
	// documented record→scrub→synthetic path, not record-persist.
	if _, err := scrubCassette(cas, "synthetic", true); err == nil {
		t.Fatal("scrub must FAIL on a raw capture whose body carries a credential (the D50 wall on the record→git path)")
	} else if !strings.Contains(err.Error(), "D50 WALL VIOLATION") {
		t.Errorf("expected a D50 wall violation from scrub, got: %v", err)
	} else if strings.Contains(err.Error(), bodyCred) {
		t.Error("scrub error echoed the synthetic credential — never-log-the-secret breach")
	}
}

// TestRecordNeverLogsTheCredential proves the never-log-the-secret invariant
// (HARDENING-NOTES.md §2.2) on the record path: across a full record round-trip
// carrying synthetic auth/volatile headers, the synthetic credential VALUES
// never appear on the recorder's stderr (its diagnostics, refusal banners, and
// the "wrote N interaction(s)" lines must report shape only, never secret bytes).
// We redirect os.Stderr to a temp file for the duration of the round-trip and
// scan it after.
func TestRecordNeverLogsTheCredential(t *testing.T) {
	fake := newHeaderCapturingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	// Capture os.Stderr to a temp file for the duration of the request so any
	// diagnostic the record path writes is observable.
	errPath := filepath.Join(t.TempDir(), "record-stderr.txt")
	ef, err := os.Create(errPath)
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = ef

	syn := syntheticBearerHeaders()
	client := proxyClient(t, addr, rec.caCertPath)
	reqBody := `{"model":"claude-synthetic-test-1","system":"clean synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range syn {
		req.Header.Set(k, v)
	}
	resp, derr := client.Do(req)
	if derr == nil {
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	os.Stderr = oldStderr
	ef.Close()

	if derr != nil {
		t.Fatalf("proxy request failed: %v", derr)
	}

	errOut, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatalf("read stderr capture: %v", err)
	}
	// No synthetic credential value (nor any Bearer/sk-ant-shaped token) may have
	// been logged. Report the surface only, never the bytes.
	for label, cred := range map[string]string{
		"Authorization value": syn["Authorization"],
		"x-api-key value":     syn["x-api-key"],
		"session-id value":    syn["X-Claude-Code-Session-Id"],
	} {
		if bytes.Contains(errOut, []byte(cred)) {
			t.Errorf("never-log-the-secret breach: %s appeared on the record stderr (value redacted)", label)
		}
	}
	if loc := bearerShapedToken.FindIndex(errOut); loc != nil {
		t.Errorf("never-log-the-secret breach: a Bearer/sk-ant-shaped token appeared on record stderr (offset=%d, len=%d, value redacted)",
			loc[0], loc[1]-loc[0])
	}
}

// --- structured refusal signal (01KTZ1V0RSB) -------------------------------
//
// The three record-path refusals (oversized / gzip / truncated-turn) each emit
// ONE machine-readable line to stderr under the stable key "ds_capture_refusal"
// so a harness can distinguish "refused (and why)" from "nothing happened". The
// tests below pin: (1) the shared vocabulary + JSON shape; (2) each of the three
// classes emits EXACTLY ONE parseable signal carrying the right reason + safe-only
// fields; (3) a SUCCESSFUL capture emits NONE; (4) the signal NEVER carries the
// request/response body, a header, or any (synthetic) credential.

// captureStderr redirects os.Stderr to a temp file for the duration of fn, then
// returns everything written. It mirrors TestRecordNeverLogsTheCredential's
// capture so the refusal lines (which the record path writes to os.Stderr) are
// observable in-process.
func captureStderr(t *testing.T, fn func()) []byte {
	t.Helper()
	errPath := filepath.Join(t.TempDir(), "record-stderr.txt")
	ef, err := os.Create(errPath)
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}
	old := os.Stderr
	os.Stderr = ef
	func() {
		defer func() { os.Stderr = old; ef.Close() }()
		fn()
	}()
	out, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatalf("read stderr capture: %v", err)
	}
	return out
}

// parsedRefusal is the {"ds_capture_refusal": {...}} envelope a harness parses.
type parsedRefusal struct {
	Signal *refusalSignal `json:"ds_capture_refusal"`
}

// parseRefusalSignals scans captured stderr for lines carrying the stable
// refusal key and returns each decoded signal. A line is a refusal signal iff it
// is a single JSON object whose only top-level key is refusalSignalKey — exactly
// what emitRefusal writes — so the human-readable banners on adjacent lines are
// ignored. Fails the test on a line that greps as a refusal but does not parse,
// which would mean the emission is not the one-line JSON object a harness needs.
func parseRefusalSignals(t *testing.T, out []byte) []refusalSignal {
	t.Helper()
	var sigs []refusalSignal
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, refusalSignalKey) {
			continue
		}
		var p parsedRefusal
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatalf("a line carrying %q did not parse as the one-line refusal JSON object (harness-unparseable): %v",
				refusalSignalKey, err)
		}
		if p.Signal == nil {
			t.Fatalf("a line carried %q but decoded to a nil signal: %q", refusalSignalKey, line)
		}
		sigs = append(sigs, *p.Signal)
	}
	return sigs
}

// TestRefusalSignalShapeAndVocabulary is a focused unit on the signal type and
// emitter, independent of the proxy: each of the three reasons round-trips
// through emitRefusal as a SINGLE-LINE JSON object under the stable key, parses
// back to the right reason, and the closed vocabulary holds the three expected
// stable identifiers.
func TestRefusalSignalShapeAndVocabulary(t *testing.T) {
	// The closed vocabulary is exactly these three stable wire identifiers.
	if reasonOversized != "oversized" ||
		reasonGzipUnsupportedEncoding != "gzip-unsupported-encoding" ||
		reasonTruncatedTurn != "truncated-turn" {
		t.Fatalf("refusal reason vocabulary drifted: %q / %q / %q",
			reasonOversized, reasonGzipUnsupportedEncoding, reasonTruncatedTurn)
	}
	for _, reason := range []refusalReason{reasonOversized, reasonGzipUnsupportedEncoding, reasonTruncatedTurn} {
		var buf bytes.Buffer
		emitRefusal(&buf, refusalSignal{Reason: reason, Path: cassette.MessagesPath})
		// Exactly one line, terminated by a single newline.
		if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
			t.Errorf("reason %q: emitted %d newlines, want exactly 1 (the signal must be ONE line)", reason, n)
		}
		// Greppable by the stable key and parseable as the envelope.
		var p parsedRefusal
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &p); err != nil {
			t.Fatalf("reason %q: signal did not parse: %v (%q)", reason, err, buf.String())
		}
		if p.Signal == nil || p.Signal.Reason != reason {
			t.Errorf("reason %q: round-tripped to %+v", reason, p.Signal)
		}
		if p.Signal.Path != cassette.MessagesPath {
			t.Errorf("reason %q: path not preserved: %q", reason, p.Signal.Path)
		}
	}
}

// TestRecordEmitsGzipRefusalSignal drives the gzip refusal end-to-end and asserts
// EXACTLY ONE structured signal with reason=gzip-unsupported-encoding, the request
// path, and the offending encoding named — and no body/credential field.
func TestRecordEmitsGzipRefusalSignal(t *testing.T) {
	fake := newGzipBlockingUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	out := captureStderr(t, func() {
		client := proxyClient(t, addr, rec.caCertPath)
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		done := make(chan struct{}, 1)
		go func() {
			if resp, derr := client.Do(req); derr == nil {
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("gzip request did not complete")
		}
	})

	sigs := parseRefusalSignals(t, out)
	if len(sigs) != 1 {
		t.Fatalf("expected exactly 1 gzip refusal signal, got %d (%q)", len(sigs), out)
	}
	s := sigs[0]
	if s.Reason != reasonGzipUnsupportedEncoding {
		t.Errorf("gzip refusal reason = %q, want %q", s.Reason, reasonGzipUnsupportedEncoding)
	}
	if s.Path != cassette.MessagesPath {
		t.Errorf("gzip refusal path = %q, want %q", s.Path, cassette.MessagesPath)
	}
	if !strings.Contains(strings.ToLower(s.Encoding), "gzip") {
		t.Errorf("gzip refusal encoding must name gzip, got %q", s.Encoding)
	}
	// Safe-only shape: the truncated/oversized-specific fields are absent.
	if s.CleanEOF != nil || s.MessageStop != nil || s.CapBytes != 0 || s.SSEEvents != 0 {
		t.Errorf("gzip signal carried fields outside its class: %+v", s)
	}
}

// TestRecordEmitsOversizedRefusalSignal drives the over-cap refusal and asserts
// EXACTLY ONE structured signal with reason=oversized, the cap value, and an SSE
// event count — diagnostics derived from shape, never body bytes.
func TestRecordEmitsOversizedRefusalSignal(t *testing.T) {
	const cap = 64 * 1024
	fake := newSizedSSEUpstream(t, 4*cap)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	rec.maxBody = cap
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	out := captureStderr(t, func() {
		client := proxyClient(t, addr, rec.caCertPath)
		client.Timeout = 30 * time.Second
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp, derr := client.Do(req)
		if derr != nil {
			t.Fatalf("oversized capture request: %v", derr)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	})

	// The over-cap turn must not be persisted (behavior unchanged).
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("an over-cap turn was recorded as %d interaction(s); behavior must be unchanged (refused)", n)
	}

	sigs := parseRefusalSignals(t, out)
	if len(sigs) != 1 {
		t.Fatalf("expected exactly 1 oversized refusal signal, got %d (%q)", len(sigs), out)
	}
	s := sigs[0]
	if s.Reason != reasonOversized {
		t.Errorf("oversized refusal reason = %q, want %q", s.Reason, reasonOversized)
	}
	if s.Path != cassette.MessagesPath {
		t.Errorf("oversized refusal path = %q, want %q", s.Path, cassette.MessagesPath)
	}
	if s.CapBytes != cap {
		t.Errorf("oversized refusal cap_bytes = %d, want %d", s.CapBytes, cap)
	}
	if s.SSEEvents <= 0 {
		t.Errorf("oversized refusal sse_events should be a positive shape count, got %d", s.SSEEvents)
	}
	if s.Encoding != "" {
		t.Errorf("oversized signal carried an encoding field outside its class: %q", s.Encoding)
	}
}

// TestRecordEmitsTruncatedRefusalSignal drives the partial-on-error refusal and
// asserts EXACTLY ONE structured signal with reason=truncated-turn, clean_eof and
// message_stop reported explicitly false, and an SSE event count.
func TestRecordEmitsTruncatedRefusalSignal(t *testing.T) {
	fake := newMidStreamErrorUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	out := captureStderr(t, func() {
		client := proxyClient(t, addr, rec.caCertPath)
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		if resp, derr := client.Do(req); derr == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		// Wait for the recorder's onEnd to settle (the refusal is emitted there,
		// happens-before the cassette stays empty) so the stderr line is present
		// before we restore stderr. The truncated turn never persists, so we poll a
		// short bounded window for the emission instead of the cassette count.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if b, _ := os.ReadFile(os.Stderr.Name()); bytes.Contains(b, []byte(refusalSignalKey)) {
				break
			}
			time.Sleep(time.Millisecond)
		}
	})

	sigs := parseRefusalSignals(t, out)
	if len(sigs) != 1 {
		t.Fatalf("expected exactly 1 truncated refusal signal, got %d (%q)", len(sigs), out)
	}
	s := sigs[0]
	if s.Reason != reasonTruncatedTurn {
		t.Errorf("truncated refusal reason = %q, want %q", s.Reason, reasonTruncatedTurn)
	}
	if s.Path != cassette.MessagesPath {
		t.Errorf("truncated refusal path = %q, want %q", s.Path, cassette.MessagesPath)
	}
	// A mid-stream-error truncation: not a clean EOF, no message_stop.
	if s.CleanEOF == nil || *s.CleanEOF {
		t.Errorf("truncated refusal clean_eof should be explicit false, got %v", s.CleanEOF)
	}
	if s.MessageStop == nil || *s.MessageStop {
		t.Errorf("truncated refusal message_stop should be explicit false, got %v", s.MessageStop)
	}
	if s.SSEEvents < 1 {
		t.Errorf("truncated refusal sse_events should count the events seen before the cut, got %d", s.SSEEvents)
	}
	if s.CapBytes != 0 || s.Encoding != "" {
		t.Errorf("truncated signal carried fields outside its class: %+v", s)
	}
}

// TestRecordSuccessEmitsNoRefusalSignal proves a clean, complete /v1/messages
// turn — recorded normally — emits ZERO refusal signals. The signal is a refusal
// marker only; a success must be silent on that channel.
func TestRecordSuccessEmitsNoRefusalSignal(t *testing.T) {
	fake := newFakeUpstream(t)
	rec, addr, stop := startRecorder(t, fake)
	defer stop()

	out := captureStderr(t, func() {
		client := proxyClient(t, addr, rec.caCertPath)
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp, derr := client.Do(req)
		if derr != nil {
			t.Fatalf("record request: %v", derr)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// Let the recorder settle so a (wrongly) emitted signal would be observable.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			rec.mu.Lock()
			done := rec.cassette.Len() == 1
			rec.mu.Unlock()
			if done {
				break
			}
			time.Sleep(time.Millisecond)
		}
	})

	// The turn WAS recorded (success), and NO refusal signal was emitted.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 1 {
		t.Fatalf("a clean turn should record exactly 1 interaction, got %d", n)
	}
	if sigs := parseRefusalSignals(t, out); len(sigs) != 0 {
		t.Errorf("a successful capture must emit NO refusal signal, got %d (%q)", len(sigs), out)
	}
}

// TestRefusalSignalNeverCarriesTheCredential is the never-log-the-secret proof for
// the structured signal (HARDENING-NOTES §2.2). It records a turn whose REQUEST
// carries synthetic auth/volatile credential headers AND whose request body and
// SSE RESPONSE body embed a synthetic secret, then FORCES a refusal (the over-cap
// path, which runs onEnd with the clipped body bytes in hand). It asserts: a
// structured signal WAS emitted (non-vacuous), and NO refusal-signal line contains
// any synthetic credential value, any body sentinel, or any Bearer/sk-ant-shaped
// token. Failures report shape/offset only, never the (synthetic) bytes.
func TestRefusalSignalNeverCarriesTheCredential(t *testing.T) {
	const cap = 64 * 1024
	// A synthetic secret sentinel woven into BOTH bodies; if any body byte reached
	// the signal, this exact string would surface in the emitted JSON.
	const bodySecret = "SYNTHETIC-SECRET-SENTINEL-must-never-appear-in-a-signal"
	syn := syntheticBearerHeaders()

	// An over-cap SSE response whose payload embeds the body sentinel — so the
	// clipped `full` the oversized branch inspects literally contains the secret.
	fake := newSecretSizedSSEUpstream(t, 4*cap, bodySecret)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	rec.maxBody = cap
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	out := captureStderr(t, func() {
		client := proxyClient(t, addr, rec.caCertPath)
		client.Timeout = 30 * time.Second
		// Request body ALSO carries the secret sentinel (raw-class by design), so a
		// signal echoing any request bytes would surface it too.
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"` + bodySecret + `"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range syn {
			req.Header.Set(k, v)
		}
		resp, derr := client.Do(req)
		if derr != nil {
			t.Fatalf("secret-bearing oversized request: %v", derr)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	})

	// Non-vacuousness: a structured refusal signal WAS emitted (else "no secret in
	// the signal" would pass trivially).
	sigs := parseRefusalSignals(t, out)
	if len(sigs) != 1 || sigs[0].Reason != reasonOversized {
		t.Fatalf("expected exactly 1 oversized refusal signal to scan, got %d (%q)", len(sigs), out)
	}

	// Scan ONLY the refusal-signal lines (the structured emission this task adds)
	// for any secret byte. Restrict to those lines so the assertion is about the
	// signal, not the adjacent human banner.
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, refusalSignalKey) {
			continue
		}
		lb := []byte(line)
		if bytes.Contains(lb, []byte(bodySecret)) {
			t.Error("never-log-the-secret breach: a body secret sentinel appeared in a refusal signal line (value redacted)")
		}
		for label, cred := range map[string]string{
			"Authorization value": syn["Authorization"],
			"x-api-key value":     syn["x-api-key"],
			"session-id value":    syn["X-Claude-Code-Session-Id"],
		} {
			if bytes.Contains(lb, []byte(cred)) {
				t.Errorf("never-log-the-secret breach: %s appeared in a refusal signal line (value redacted)", label)
			}
		}
		if loc := bearerShapedToken.FindIndex(lb); loc != nil {
			t.Errorf("never-log-the-secret breach: a Bearer/sk-ant-shaped token appeared in a refusal signal line (offset=%d, len=%d, value redacted)",
				loc[0], loc[1]-loc[0])
		}
	}
}

// secretSizedSSEUpstream is a sizedSSEUpstream variant whose padding embeds a
// caller-supplied secret sentinel, so the oversized-clipped body the recorder
// inspects literally contains the secret — letting the never-log-the-secret test
// prove the structured signal still emits ZERO body bytes. Synthetic, loopback,
// no live network (D50 / the wave hard fence); never binds :18080.
type secretSizedSSEUpstream struct {
	srv  *httptest.Server
	body string
}

func newSecretSizedSSEUpstream(t *testing.T, minSize int, secret string) *secretSizedSSEUpstream {
	t.Helper()
	// Pad with repeated copies of the secret sentinel so the sentinel survives the
	// cap clipping no matter where the boundary lands.
	reps := minSize/len(secret) + 1
	pad := strings.Repeat(secret+" ", reps)
	body := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_SECRET\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + pad + "\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	u := &secretSizedSSEUpstream{body: body}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		for i := 0; i < len(body); i += 64 * 1024 {
			end := i + 64*1024
			if end > len(body) {
				end = len(body)
			}
			_, _ = io.WriteString(w, body[i:end])
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *secretSizedSSEUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(u.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}
