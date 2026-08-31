package tlsproxy

// TLS-8 — protocol breadth through inspection: WebSocket, HTTP/2, gRPC, and
// the QUIC blocked-with-TCP-fallback posture (doc 09 §5 TLS-8, OQ5).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- minimal RFC 6455 helpers (test-side only) ------------------------------

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func wsFrame(opcode byte, payload []byte, masked bool) []byte {
	b := []byte{0x80 | opcode}
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch l := len(payload); {
	case l < 126:
		b = append(b, maskBit|byte(l))
	case l < 1<<16:
		b = append(b, maskBit|126, byte(l>>8), byte(l))
	default:
		panic("test frame too large")
	}
	if masked {
		key := []byte{0x12, 0x34, 0x56, 0x78}
		b = append(b, key...)
		for i, p := range payload {
			b = append(b, p^key[i%4])
		}
		return b
	}
	return append(b, payload...)
}

func readWSFrame(br *bufio.Reader) (opcode byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(br, hdr); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	l := int(hdr[1] & 0x7f)
	if l == 126 {
		ext := make([]byte, 2)
		if _, err = io.ReadFull(br, ext); err != nil {
			return 0, nil, err
		}
		l = int(ext[0])<<8 | int(ext[1])
	}
	var key []byte
	if masked {
		key = make([]byte, 4)
		if _, err = io.ReadFull(br, key); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, l)
	if _, err = io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return opcode, payload, nil
}

// wsUpstream is a fake WebSocket echo origin: 101 upgrade, one unsolicited
// server frame, then a raw byte echo (frames opaque to it).
type wsUpstream struct{ received lockedBuffer }

func (u *wsUpstream) dialTLS(string, netip.AddrPort) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go u.serve(c2)
	return c1, nil
}

func (u *wsUpstream) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		wsAccept(req.Header.Get("Sec-WebSocket-Key")))
	if _, err := c.Write(wsFrame(0x1, []byte("hello-from-upstream"), false)); err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			u.received.Write(buf[:n])
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// planRef: doc 09 §5 TLS-8 Done-when (WebSocket conformance through
// inspection with telemetry)
func TestProtocol_WebSocketThroughInspection(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "ws.example"
	h.policy.allow(domain)
	h.admit(sess, domain, time.Hour, ip("198.51.100.30"))
	up := &wsUpstream{}
	h.dialer.tlsFn = up.dialTLS

	conn, _ := h.startTransparent(sess, ap("198.51.100.30:443"))
	defer conn.Close()
	tc, err := h.sessionTLSClient(conn, sess, domain)
	if err != nil {
		t.Fatalf("inspected handshake: %v", err)
	}
	const wsKey = "x3JJHMbDL1EzLkh9GBhXDw=="
	fmt.Fprintf(tc, "GET /socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", domain, wsKey)
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAccept(wsKey); got != want {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q (inspection must not corrupt the upgrade)", got, want)
	}

	// Server-initiated frame arrives intact (upstream -> VM direction).
	op, payload, err := readWSFrame(br)
	if err != nil {
		t.Fatalf("read server frame: %v", err)
	}
	if op != 0x1 || string(payload) != "hello-from-upstream" {
		t.Errorf("server frame corrupted: op=%#x payload=%q", op, payload)
	}

	// Client frames echo back byte-identically (VM -> upstream -> VM).
	for _, f := range [][]byte{
		wsFrame(0x2, []byte("binary-frame-payload-xyz"), true),
		wsFrame(0x9, []byte("ping"), true), // ping
	} {
		if _, err := tc.Write(f); err != nil {
			t.Fatalf("write frame: %v", err)
		}
		echo := make([]byte, len(f))
		if _, err := io.ReadFull(br, echo); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if !bytes.Equal(echo, f) {
			t.Errorf("frame corrupted in flight: sent %x got %x", f, echo)
		}
	}
	h.requireEvent(EventHTTP, "websocket")
}

// h2Transport builds an HTTP/2-capable client whose every connection runs
// through the inspected transparent path; it records negotiated protocols.
func h2Transport(t *testing.T, h *harness, sess SessionRef, domain string, dst netip.AddrPort, protos *[]string, mu *sync.Mutex) *http.Client {
	t.Helper()
	pool := h.cas.poolFor(t, sess) // pre-minted on the test goroutine
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, _ := h.startTransparent(sess, dst)
			tlsConn := tls.Client(conn, &tls.Config{
				RootCAs:    pool,
				ServerName: domain,
				NextProtos: []string{"h2", "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			mu.Lock()
			*protos = append(*protos, tlsConn.ConnectionState().NegotiatedProtocol)
			mu.Unlock()
			return tlsConn, nil
		},
	}
	return &http.Client{Transport: tr, Timeout: ioTimeout}
}

// planRef: doc 09 §5 TLS-8 (HTTP/2 upstreams, Pingora-native). The fake
// upstream answers HTTP/1.1 behind the DialTLS seam; downstream ALPN h2 and
// per-stream attribution are the contract under test.
func TestProtocol_HTTP2MultiplexedThroughInspection(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "h2.example"
	h.policy.allow(domain)
	h.admit(sess, domain, time.Hour, ip("198.51.100.31"))
	up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "stream-payload:%s", r.URL.Path)
	}}
	h.dialer.tlsFn = up.dialTLS

	var mu sync.Mutex
	var protos []string
	client := h2Transport(t, h, sess, domain, ap("198.51.100.31:443"), &protos, &mu)

	const n = 4
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/stream/%d", i)
			resp, err := client.Get("https://" + domain + path)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", i, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "stream-payload:"+path {
				errs <- fmt.Errorf("stream %d head-of-line corruption: status=%d body=%q", i, resp.StatusCode, body)
				return
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(protos) == 0 {
		t.Fatal("no TLS connections were established")
	}
	for _, p := range protos {
		if p != "h2" {
			t.Errorf("negotiated protocol = %q, want h2 (multiplexed streams must ride one inspected conn)", p)
		}
	}
	for i := 0; i < n; i++ {
		h.requireEvent(EventHTTP, fmt.Sprintf("/stream/%d", i))
	}
}

// planRef: doc 09 §5 TLS-8 Done-when (gRPC conformance clients pass with
// telemetry). gRPC is modeled as h2 + application/grpc + trailers.
func TestProtocol_GRPCUnaryAndStreamingThroughInspection(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "grpc.example"
	const bodySentinel = "grpc-frame-unary-payload"
	h.policy.allow(domain)
	h.admit(sess, domain, time.Hour, ip("198.51.100.32"))

	up := &rawResponder{script: func(req *http.Request, body []byte, w io.Writer) {
		writeChunked := func(chunks ...[]byte) {
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTrailer: Grpc-Status\r\nTransfer-Encoding: chunked\r\n\r\n")
			for _, c := range chunks {
				fmt.Fprintf(w, "%x\r\n", len(c))
				w.Write(c)
				io.WriteString(w, "\r\n")
			}
			io.WriteString(w, "0\r\nGrpc-Status: 0\r\n\r\n")
		}
		switch req.URL.Path {
		case "/echo.Echo/Call":
			writeChunked(body) // unary echo
		case "/echo.Echo/Stream":
			writeChunked([]byte("msg-1"), []byte("msg-2"), []byte("msg-3"))
		default:
			io.WriteString(w, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
		}
	}}
	h.dialer.tlsFn = up.dialTLS

	var mu sync.Mutex
	var protos []string
	client := h2Transport(t, h, sess, domain, ap("198.51.100.32:443"), &protos, &mu)

	call := func(path, body string) (*http.Response, []byte) {
		t.Helper()
		req := newReq(t, http.MethodPost, "https://"+domain+path,
			map[string]string{"Content-Type": "application/grpc+proto"}, body)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("gRPC %s: %v", path, err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, got
	}

	// Unary echo.
	resp, got := call("/echo.Echo/Call", bodySentinel)
	if resp.StatusCode != http.StatusOK || string(got) != bodySentinel {
		t.Errorf("unary: status=%d body=%q, want 200 %q", resp.StatusCode, got, bodySentinel)
	}
	if ts := resp.Trailer.Get("Grpc-Status"); ts != "0" {
		t.Errorf("unary grpc-status trailer = %q, want \"0\" (trailers must survive inspection)", ts)
	}

	// Server streaming.
	resp, got = call("/echo.Echo/Stream", "stream-request")
	if resp.StatusCode != http.StatusOK || string(got) != "msg-1msg-2msg-3" {
		t.Errorf("streaming: status=%d body=%q", resp.StatusCode, got)
	}
	if ts := resp.Trailer.Get("Grpc-Status"); ts != "0" {
		t.Errorf("streaming grpc-status trailer = %q, want \"0\"", ts)
	}

	// Telemetry: :path metadata present, bodies absent (per TLS-6.f).
	h.requireEvent(EventHTTP, "/echo.Echo/Call")
	h.requireEvent(EventHTTP, "/echo.Echo/Stream")
	if ev, found := findEventContaining(h.events.all(), "", bodySentinel); found {
		t.Errorf("gRPC body bytes leaked into a %s event", ev.Kind)
	}
}

// planRef: doc 09 §5 TLS-8 Done-when (QUIC blocked-with-fallback per OQ5);
// NFT-4 udp/443 drop; DNS-4 rule 4 (no alpn=h3 steering). ADVERSARIAL.
// The harness models the NFT-4 drop as a dead UDP path: nothing listens.
func TestProtocol_QUICBlocked_TCPFallbackSucceeds(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "api.anthropic.com"
	h.policy.allow(domain)
	h.admit(sess, domain, time.Hour, ip("104.18.0.5"))
	origin := newTLSOrigin(t, "echo", domain)
	h.dialer.rawFn = origin.dialRaw

	// 1 — the QUIC attempt: udp/443 yields nothing (harness network model of
	// the NFT-4 drop — a port that was just closed, so no handshake exists).
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp probe setup: %v", err)
	}
	deadPort := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", deadPort))
	if err == nil {
		uc.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = uc.Write([]byte("quic-initial-probe"))
		buf := make([]byte, 32)
		if _, rerr := uc.Read(buf); rerr == nil {
			t.Fatal("the QUIC path must be dead: a UDP handshake answered")
		}
		uc.Close()
	}

	// 2 — the TCP fallback lands on the proxy and passes the TLS-1 checks.
	conn, _ := h.startTransparent(sess, ap("104.18.0.5:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: domain})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TCP fallback must succeed through the normal TLS-1 path: %v", err)
	}
	payload := []byte("h3-client-falls-back")
	tc.Write(payload)
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tc, echo); err != nil {
		t.Fatalf("fallback tunnel: %v", err)
	}

	// 3 — only the TCP flow appears in telemetry.
	flows := h.events.byKind(EventFlow)
	if len(flows) != 1 {
		t.Errorf("telemetry must show exactly the one TCP flow; got %d flow events", len(flows))
	}
	for _, ev := range h.events.all() {
		ser := strings.ToLower(string(serializeEvent(ev)))
		if strings.Contains(ser, "quic") || strings.Contains(ser, "udp") {
			t.Errorf("no QUIC/UDP flow may appear in telemetry: %s", ser)
		}
	}
}
