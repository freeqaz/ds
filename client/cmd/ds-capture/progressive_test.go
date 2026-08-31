// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// This file proves the progressive-relay + bounded-upstream-read hardening of
// the three ds-capture body-relay paths (task 01KTZ1TGWA):
//
//   - passthroughTLS (record.go): verbatim non-/v1/messages forward — now
//     streamed through a fixed relayBufSize buffer, no io.ReadAll of either body,
//     bounded by an inactivity read deadline.
//   - streamTee (record.go): the /v1/messages capture tee — client write side
//     unbounded (full fidelity), cassette accumulation CAPPED so it can't OOM,
//     and a read deadline bounds a hung upstream.
//   - forwardUpstream (replay.go): the --passthrough escape hatch — streamed +
//     read-deadline-bounded (covered for streaming via large bodies; the D50
//     scrub no-leak guard lives in replay_live_test.go and is untouched).
//
// Every fake is in-process (httptest or a raw 127.0.0.1 TCP listener); NO live
// claude/cia/podman/network is involved (D50 / the wave hard fence). Bounds are
// proven by SYNCHRONIZATION or by a bounded-timeout that a regressed (block /
// OOM-prone) implementation would blow, never by sleeps as assertions
// (DRIVE-PROTOCOL.md forbids timing-derived assertions).

// --- 1. passthrough streams a large body verbatim without a full ReadAll -----

// bigBodyUpstream is an httptest fake that replies to ANY request with a body of
// `size` deterministic bytes (a repeating pattern). It is used to prove the
// passthrough relay streams a body far larger than it would ever hold via a
// single comfortable ReadAll, and that the body round-trips byte-identical
// (verbatim passthrough).
type bigBodyUpstream struct {
	srv  *httptest.Server
	size int
}

func newBigBodyUpstream(t *testing.T, size int) *bigBodyUpstream {
	t.Helper()
	u := &bigBodyUpstream{size: size}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		// Stream the body out in fixed chunks so the test upstream itself never
		// holds the whole body either — the relay must stream it through.
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = byte('a' + (i % 26))
		}
		remaining := size
		for remaining > 0 {
			n := len(chunk)
			if n > remaining {
				n = remaining
			}
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *bigBodyUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(u.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// wantBigBody reproduces the bigBodyUpstream body of `size` bytes so the test can
// hash/compare what the client received against what the upstream emitted.
func wantBigBody(size int) []byte {
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte('a' + (i % 26))
	}
	out := make([]byte, 0, size)
	remaining := size
	for remaining > 0 {
		n := len(chunk)
		if n > remaining {
			n = remaining
		}
		out = append(out, chunk[:n]...)
		remaining -= n
	}
	return out
}

// TestPassthroughStreamsLargeBodyVerbatim drives a NON-/v1/messages request
// (passthroughTLS) whose upstream returns a 16 MiB body. The relay must (a)
// stream it through to the client byte-identical (verbatim passthrough,
// progressive — the relay buffer is a fixed relayBufSize, so the whole 16 MiB is
// never held in a single ReadAll on the relay path) and (b) record NOTHING (a
// non-/v1/messages request is never captured). The body is hashed end-to-end so
// a single dropped/duplicated byte fails the test.
func TestPassthroughStreamsLargeBodyVerbatim(t *testing.T) {
	const size = 16 * 1024 * 1024 // 16 MiB — far past any comfortable single ReadAll on the hot path
	fake := newBigBodyUpstream(t, size)
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
	client.Timeout = 30 * time.Second
	// A non-/v1/messages path so the passthrough relay (not the capture tee) runs.
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("passthrough request: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read relayed body: %v", err)
	}

	if len(got) != size {
		t.Fatalf("relayed body length mismatch: got %d want %d", len(got), size)
	}
	if sha256.Sum256(got) != sha256.Sum256(wantBigBody(size)) {
		t.Fatal("relayed body bytes are NOT verbatim — passthrough corrupted the stream")
	}
	// Verbatim passthrough captures nothing.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("a passthrough (non-/v1/messages) request must not be recorded, got %d", n)
	}
}

// --- 2. a hung upstream is bounded by the read deadline (passthrough leg) -----

// hangAfterHeadUpstream is a RAW-TCP fake that reads the proxied request, writes
// a response HEAD promising a body (Content-Length) it then NEVER sends, and
// blocks until released at cleanup. A relay that reads the response body with a
// read deadline is bounded; one that blocks forever hangs the client. Raw TCP
// (not httptest) so we control the exact "head then silence" shape.
type hangAfterHeadUpstream struct {
	ln      net.Listener
	release chan struct{}
}

func newHangAfterHeadUpstream(t *testing.T) *hangAfterHeadUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hang upstream listen: %v", err)
	}
	h := &hangAfterHeadUpstream{ln: ln, release: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if req, err := http.ReadRequest(br); err == nil {
					_, _ = io.ReadAll(req.Body)
					_ = req.Body.Close()
				}
				// Promise 1 MiB, send the head, then go silent — never write a
				// body byte. A bounded relay times out on the body read.
				head := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/octet-stream\r\n" +
					"Content-Length: 1048576\r\n\r\n"
				_, _ = io.WriteString(c, head)
				<-h.release // hang until cleanup
			}(conn)
		}
	}()
	t.Cleanup(func() {
		close(h.release)
		_ = ln.Close()
	})
	return h
}

func (h *hangAfterHeadUpstream) dialer() func(string) (net.Conn, error) {
	target := h.ln.Addr().String()
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestPassthroughReadDeadlineBoundsAHang proves the passthrough relay does NOT
// block forever on an upstream that sends a response head then goes silent. With
// a short inactivity read deadline the relay's body read fails and the handler
// returns; without the deadline the relay (and the client) would block until the
// upstream eventually closes — here, never (it hangs until cleanup). The proof
// is a bounded-timeout the unbounded implementation blows.
func TestPassthroughReadDeadlineBoundsAHang(t *testing.T) {
	fake := newHangAfterHeadUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	rec.readIdle = 200 * time.Millisecond // dial the bound down so the test is fast
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	client.Timeout = 0 // no client-side timeout: the BOUND must come from the relay's read deadline

	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
		resp, derr := client.Do(req)
		if derr != nil {
			done <- derr
			return
		}
		_, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- rerr
	}()

	select {
	case <-done:
		// Returned (with or without an error) — the point is it did NOT hang.
		// The relay's read deadline fired, the handler returned, and the client's
		// request completed/aborted instead of blocking forever.
	case <-time.After(5 * time.Second):
		t.Fatal("passthrough relay blocked on a silent upstream: the read deadline did not bound the hang " +
			"(an unbounded io.ReadAll/io.Copy would block here until the upstream closes — it never does)")
	}
}

// --- 3. a hung upstream is bounded by the read deadline (capture tee leg) -----

// hangMidStreamUpstream is a RAW-TCP fake that writes a chunked /v1/messages
// response head plus one SSE chunk (message_start) and then goes SILENT — it
// never sends message_stop or closes. It exercises streamTee's read against a
// mid-turn hang: a bounded read deadline lets the tee return; an unbounded read
// blocks forever. The client gets event1 first (progressive), proving the tee
// still streams.
type hangMidStreamUpstream struct {
	ln      net.Listener
	release chan struct{}
}

func newHangMidStreamUpstream(t *testing.T) *hangMidStreamUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hang-midstream listen: %v", err)
	}
	h := &hangMidStreamUpstream{ln: ln, release: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if req, err := http.ReadRequest(br); err == nil {
					_, _ = io.ReadAll(req.Body)
					_ = req.Body.Close()
				}
				head := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/event-stream\r\n" +
					"Transfer-Encoding: chunked\r\n\r\n"
				_, _ = io.WriteString(c, head)
				// One chunk of message_start, then SILENCE (no message_stop, no
				// terminal chunk, no close) until cleanup. truncatedSSE is
				// synthetic and carries no message_stop.
				_, _ = fmt.Fprintf(c, "%x\r\n%s\r\n", len(truncatedSSE), truncatedSSE)
				<-h.release
			}(conn)
		}
	}()
	t.Cleanup(func() {
		close(h.release)
		_ = ln.Close()
	})
	return h
}

func (h *hangMidStreamUpstream) dialer() func(string) (net.Conn, error) {
	target := h.ln.Addr().String()
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestRecordReadDeadlineBoundsAMidStreamHang proves streamTee does NOT block
// forever when the upstream stalls mid-turn. The fake emits message_start then
// goes silent; a short inactivity read deadline fires, the tee returns, and (per
// the refuse-partial rule) NOTHING is recorded — a hung/partial turn is dropped,
// never persisted. A regressed unbounded read would block until cleanup.
func TestRecordReadDeadlineBoundsAMidStreamHang(t *testing.T) {
	fake := newHangMidStreamUpstream(t)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	rec.readIdle = 200 * time.Millisecond
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer srv.Close()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	client.Timeout = 0

	done := make(chan error, 1)
	go func() {
		reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp, derr := client.Do(req)
		if derr != nil {
			done <- derr
			return
		}
		_, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- rerr
	}()

	select {
	case <-done:
		// Bounded — the tee's read deadline fired and the handler returned.
	case <-time.After(5 * time.Second):
		t.Fatal("capture tee blocked on a silent mid-stream upstream: the read deadline did not bound the hang")
	}

	// A hung/partial turn is never recorded (refuse-partial-on-error still holds,
	// now reached via the deadline-induced read error rather than a clean close).
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("a hung mid-stream turn must not be recorded, got %d interaction(s)", n)
	}
}

// --- 4. the cassette cap truncates-with-refusal rather than OOMs --------------

// sizedSSEUpstream is an httptest fake that returns a COMPLETE /v1/messages turn
// (message_start + a padded content_block_delta + message_stop) whose total body
// is at least `minSize` bytes. The padding rides inside a data: line so the body
// is a well-formed SSE stream with a real terminal message_stop — i.e. it is a
// COMPLETE turn that would normally be recorded, except that it exceeds the cap.
type sizedSSEUpstream struct {
	srv  *httptest.Server
	body string
}

func newSizedSSEUpstream(t *testing.T, minSize int) *sizedSSEUpstream {
	t.Helper()
	pad := strings.Repeat("x", minSize)
	body := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_BIG\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + pad + "\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	u := &sizedSSEUpstream{body: body}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		// Write in chunks so the tee reads multiple times (the cap is checked per
		// read).
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

func (u *sizedSSEUpstream) dialer() func(string) (net.Conn, error) {
	target := strings.TrimPrefix(u.srv.URL, "http://")
	return func(_ string) (net.Conn, error) {
		return net.Dial("tcp", target)
	}
}

// TestRecordCassetteCapRefusesOversizedTurn proves the cassette-accumulation cap
// bounds memory WITHOUT corrupting the client stream: with a small maxBody, a
// complete /v1/messages turn whose body exceeds the cap is (a) relayed in FULL to
// the client (every byte — the write side is unbounded, so fidelity on the wire
// is preserved) but (b) NOT recorded (the over-cap turn is refused, exactly like
// a truncated one), so a later replay serves a miss rather than a clipped body.
// This is the truncate-with-marker-not-OOM behavior: the in-memory accumulation
// is bounded, the client is not.
func TestRecordCassetteCapRefusesOversizedTurn(t *testing.T) {
	const cap = 64 * 1024 // tiny cap so a modest body trips it
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

	client := proxyClient(t, addr, rec.caCertPath)
	client.Timeout = 30 * time.Second
	reqBody := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oversized capture request: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// (a) The client received the FULL body, byte-identical — fidelity on the
	// wire is preserved even though the cassette copy was capped.
	if string(got) != fake.body {
		t.Errorf("client did not receive the full SSE body despite the cap: got %d bytes want %d",
			len(got), len(fake.body))
	}
	// (b) The over-cap turn was REFUSED — zero interactions, so it can never
	// replay as a complete-but-clipped turn.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("an over-cap turn was recorded as %d interaction(s); a clipped body must be refused, not persisted", n)
	}
}

// TestStreamTeeUnitBoundsAccumulation is a focused unit on streamTee's bounded
// accumulation, independent of the proxy plumbing: feed it more bytes than the
// cap and assert (a) onEnd reports oversized, (b) the accumulated buffer it hands
// back is bounded (≤ cap+one read), and (c) the client conn still received EVERY
// byte (full fidelity on the write side).
func TestStreamTeeUnitBoundsAccumulation(t *testing.T) {
	const cap = 1000
	payload := strings.Repeat("Z", 10*cap) // 10x the cap
	clientSide, teeSide := net.Pipe()

	// Drain the client side concurrently so streamTee's writes don't block, and
	// count the body bytes the client actually received (de-chunked).
	type drained struct {
		bodyLen int
		err     error
	}
	drainDone := make(chan drained, 1)
	go func() {
		// Parse the HTTP/1.1 chunked response the tee writes.
		br := bufio.NewReader(clientSide)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			drainDone <- drained{err: err}
			return
		}
		b, err := io.ReadAll(resp.Body) // de-chunks transparently
		resp.Body.Close()
		drainDone <- drained{bodyLen: len(b), err: err}
	}()

	var gotFull []byte
	var gotClean, gotOversized bool
	teeErr := streamTee(teeSide, 200, "text/event-stream", strings.NewReader(payload), cap,
		func(full []byte, cleanEOF, oversized bool) {
			gotFull = full
			gotClean = cleanEOF
			gotOversized = oversized
		})
	_ = teeSide.Close()
	if teeErr != nil {
		t.Fatalf("streamTee returned error: %v", teeErr)
	}

	res := <-drainDone
	if res.err != nil {
		t.Fatalf("client drain failed: %v", res.err)
	}

	// (c) The client received every payload byte — write side is unbounded.
	if res.bodyLen != len(payload) {
		t.Errorf("client received %d body bytes, want the full %d (write side must be unbounded)",
			res.bodyLen, len(payload))
	}
	// (a) onEnd saw a clean EOF but flagged oversized.
	if !gotClean {
		t.Error("streamTee should report cleanEOF for a fully-drained reader")
	}
	if !gotOversized {
		t.Error("streamTee must report oversized when accumulation exceeds the cap")
	}
	// (b) The accumulated buffer is bounded — never the whole 10x-cap payload.
	if len(gotFull) > cap+relayBufSize {
		t.Errorf("accumulation not bounded: got %d bytes, cap=%d (+one read of %d)", len(gotFull), cap, relayBufSize)
	}
	if len(gotFull) >= len(payload) {
		t.Errorf("accumulation held the WHOLE payload (%d ≥ %d) — the cap did not bound memory", len(gotFull), len(payload))
	}
}

// --- 5. normal (under-cap) capture+replay still round-trips byte-identical ----

// TestLargeUnderCapTurnCapturesAndReplaysByteIdentical proves the new bounds do
// NOT truncate NORMAL traffic: a complete /v1/messages turn that is large-ish
// (~512 KiB) but comfortably UNDER the production-shaped cap records in full and
// replays byte-identical. This is the regression fence for the cap default —
// real CC turns are well under any reasonable cap and must round-trip whole.
func TestLargeUnderCapTurnCapturesAndReplaysByteIdentical(t *testing.T) {
	const bodyPad = 512 * 1024 // ~512 KiB turn — large, but far under maxCassetteBody
	fake := newSizedSSEUpstream(t, bodyPad)
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.upstreamDial = fake.dialer()
	// maxBody/readIdle left at defaults — exactly the production configuration.
	srv, addr, err := rec.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(rec.ln) }()
	defer rec.cleanup()

	client := proxyClient(t, addr, rec.caCertPath)
	client.Timeout = 30 * time.Second
	reqBody := `{"model":"claude-synthetic-test-1","system":"synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("record request: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	srv.Close()

	if string(got) != fake.body {
		t.Fatalf("client SSE not byte-identical to upstream (len got=%d want=%d)", len(got), len(fake.body))
	}
	// The full turn was recorded (it is complete and under the cap).
	rec.mu.Lock()
	n := rec.cassette.Len()
	var recordedBody string
	if n == 1 {
		recordedBody = rec.cassette.Interactions[0].Body
	}
	rec.mu.Unlock()
	if n != 1 {
		t.Fatalf("a complete under-cap turn must be recorded once, got %d", n)
	}
	if recordedBody != fake.body {
		t.Fatalf("cassette body not byte-identical to the streamed SSE (len got=%d want=%d)",
			len(recordedBody), len(fake.body))
	}

	// Replay it and assert the served body is byte-identical AND hermetic.
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
	rclient.Timeout = 30 * time.Second
	rreq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	rresp, err := rclient.Do(rreq)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	rgot, _ := io.ReadAll(rresp.Body)
	rresp.Body.Close()

	if string(rgot) != fake.body {
		t.Fatalf("replayed SSE not byte-identical to the recorded turn (len got=%d want=%d)",
			len(rgot), len(fake.body))
	}
	if rp.dialedUpstream {
		t.Error("replay dialed upstream — hermetic guarantee broken")
	}
}

// sanity: the cassette SSE parser still sees a turn boundary in the big body, so
// the under-cap recording path is genuinely exercising the complete-turn branch.
func TestSizedSSEUpstreamIsACompleteTurn(t *testing.T) {
	u := newSizedSSEUpstream(t, 1024)
	if !hasTurnBoundary([]byte(u.body)) {
		t.Fatal("sizedSSEUpstream body must carry a terminal message_stop (a complete turn)")
	}
	if got := cassette.EventTypes(u.body); len(got) != 3 {
		t.Fatalf("expected 3 SSE events (start/delta/stop), got %d: %v", len(got), got)
	}
}
