// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// replayMissBody is the synthetic 502 payload returned on a strict-mode miss —
// byte-for-byte the cia_replay_miss shape (cia/proxy.py _maybe_replay), so a
// tier keyed on it stays parity-compatible. The request never reaches upstream.
var replayMissBody = mustJSON(map[string]any{
	"type": "error",
	"error": map[string]any{
		"type":    "cia_replay_miss",
		"message": "no cassette match for request (ds-capture replay strict mode)",
	},
})

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// cmdReplay parses flags and serves a cassette back OFFLINE until a signal.
func cmdReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cassettePath := fs.String("cassette", "", "path to the cassette to replay (required)")
	port := fs.Int("port", DefaultPort, "egress-gateway listen port (never :18080)")
	caDir := fs.String("ca-dir", "", "directory to write the generated CA cert (for NODE_EXTRA_CA_CERTS); default: a temp dir")
	host := fs.String("host", "127.0.0.1", "loopback host to bind")
	strict := fs.Bool("strict", true, "fail a cassette miss offline with a synthetic 502 (hermetic; default)")
	passthrough := fs.Bool("passthrough", false, "DOCUMENTED NON-D50 ESCAPE HATCH: forward a miss upstream (not hermetic)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ds-capture replay --cassette PATH [--port %d] [--strict|--passthrough]\n", DefaultPort)
		fmt.Fprintf(os.Stderr, "\nServes a recorded cassette back OFFLINE — never dials upstream in strict\n")
		fmt.Fprintf(os.Stderr, "mode (the default). --strict miss returns a synthetic 502 cia_replay_miss.\n")
		fmt.Fprintf(os.Stderr, "--passthrough is a non-hermetic escape hatch for incremental recording.\n")
		fmt.Fprintf(os.Stderr, "Default port :%d — NEVER :%d.\n", DefaultPort, ProtectedMonitorPort)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cassettePath == "" {
		fmt.Fprintln(os.Stderr, "ds-capture replay: --cassette is required")
		fs.Usage()
		return 2
	}
	if err := assertNotProtectedPort(*port); err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture replay: %v\n", err)
		return 2
	}

	cas, err := cassette.Load(*cassettePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture replay: %v\n", err)
		return 1
	}

	rp, err := newReplayer(cas, *strict, *passthrough, *caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture replay: %v\n", err)
		return 1
	}
	defer rp.cleanup()

	srv, addr, err := rp.listen(*host, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture replay: %v\n", err)
		return 1
	}
	mode := "strict (hermetic, zero-egress)"
	if *passthrough {
		mode = "passthrough (NON-HERMETIC escape hatch)"
	}
	fmt.Fprintf(os.Stderr, "ds-capture replay: egress gateway on http://%s [%s], %d interaction(s)\n", addr, mode, cas.Len())
	fmt.Fprintf(os.Stderr, "ds-capture replay: NODE_EXTRA_CA_CERTS=%s\n", rp.caCertPath)

	go func() { _ = srv.Serve(rp.ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = srv.Close()
	return 0
}

// replayer serves a cassette back over a TLS-terminating gateway WITHOUT ever
// dialing upstream in strict mode — the hermetic, zero-egress path (D50). It
// reuses the recorder's CA/leaf machinery for the TLS termination but
// short-circuits /v1/messages from the cassette.
type replayer struct {
	ca          *x509.Certificate
	caKey       *ecdsa.PrivateKey
	caCertPath  string
	caDirTemp   bool
	cassette    *cassette.Cassette
	strict      bool
	passthrough bool

	mu        sync.Mutex
	leafCache map[string]*tls.Certificate
	ln        net.Listener

	// dialedUpstream records whether the replayer ever attempted an outbound
	// connection. In strict mode this MUST remain false — the hermetic
	// guarantee — and the test asserts it.
	dialedUpstream bool

	// dialUpstream is the seam forwardUpstream uses to reach upstream on the
	// --passthrough escape hatch. In production it is the real TLS dial to
	// host:443 (set in newReplayer); the offline no-leak test substitutes an
	// in-memory fake upstream so the D50 scrub can be asserted without egress.
	// It is never invoked in strict mode (that path never reaches it).
	dialUpstream func(host string) (net.Conn, error)

	// readIdle is the per-replayer inactivity read deadline applied to the
	// passthrough upstream conn (forwardUpstream), so a hung upstream on the
	// escape hatch can't block forever. A zero value falls back to the package
	// default; a test dials it down to prove the bound. Strict mode never dials,
	// so this is inert there.
	readIdle time.Duration
}

func (r *replayer) upstreamReadIdle() time.Duration {
	if r.readIdle > 0 {
		return r.readIdle
	}
	return upstreamReadIdleTimeout
}

func newReplayer(cas *cassette.Cassette, strict, passthrough bool, caDir string) (*replayer, error) {
	ca, caKey, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	temp := false
	if caDir == "" {
		caDir, err = os.MkdirTemp("", "ds-capture-ca-*")
		if err != nil {
			return nil, fmt.Errorf("ca temp dir: %w", err)
		}
		temp = true
	} else if err := os.MkdirAll(caDir, 0o755); err != nil {
		return nil, fmt.Errorf("ca dir: %w", err)
	}
	caPath := caDir + "/ds-capture-ca.pem"
	if err := writeCertPEM(caPath, ca.Raw); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	// passthrough overrides strict (a miss is forwarded, not failed).
	if passthrough {
		strict = false
	}
	return &replayer{
		ca:          ca,
		caKey:       caKey,
		caCertPath:  caPath,
		caDirTemp:   temp,
		cassette:    cas,
		strict:      strict,
		passthrough: passthrough,
		leafCache:   map[string]*tls.Certificate{},
		// The production upstream dial: real TLS to host:443. This is the only
		// outbound connection ds-capture replay ever opens, and only on the
		// --passthrough escape hatch (D50 non-hermetic, documented).
		dialUpstream: func(host string) (net.Conn, error) {
			return tls.Dial("tcp", host+":443", &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13})
		},
	}, nil
}

func (r *replayer) cleanup() {
	if r.caDirTemp {
		_ = os.RemoveAll(strings.TrimSuffix(r.caCertPath, "/ds-capture-ca.pem"))
	}
}

func (r *replayer) listen(host string, port int) (*http.Server, string, error) {
	if err := assertNotProtectedPort(port); err != nil {
		return nil, "", err
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("listen %s: %w", addr, err)
	}
	r.ln = ln
	srv := &http.Server{Handler: http.HandlerFunc(r.handle)}
	return srv, ln.Addr().String(), nil
}

func (r *replayer) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		r.handleConnect(w, req)
		return
	}
	http.Error(w, "ds-capture: plaintext proxying not supported (HTTPS via CONNECT only)", http.StatusBadGateway)
}

func (r *replayer) handleConnect(w http.ResponseWriter, req *http.Request) {
	host := hostOnly(req.Host)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	leaf, err := r.leafFor(host)
	if err != nil {
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()
	r.serveTLS(tlsConn, host)
}

func (r *replayer) serveTLS(conn net.Conn, host string) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host
		if !r.dispatchTLS(conn, host, req) {
			return
		}
	}
}

// dispatchTLS short-circuits /v1/messages from the cassette. A hit replays the
// recorded SSE; a strict miss returns the synthetic 502; passthrough is the
// only path that would ever dial upstream (the documented non-hermetic escape
// hatch) — and it records that it dialed.
func (r *replayer) dispatchTLS(conn net.Conn, host string, req *http.Request) bool {
	isMessages := host == anthropicHost && stripQuery(req.URL.Path) == cassette.MessagesPath && req.Method == http.MethodPost
	if !isMessages {
		// Non-/v1/messages in replay: strict mode fails it offline so the tier
		// stays hermetic; passthrough would forward it (escape hatch).
		if r.passthrough {
			return r.forwardUpstream(conn, host, req)
		}
		r.writeReplayMiss(conn)
		return false
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	reqJSON := parseJSONBody(bodyBytes)

	r.mu.Lock()
	it := r.cassette.FindMatch(req.Method, req.URL.Path, reqJSON)
	r.mu.Unlock()

	if it != nil {
		headers := http.Header{}
		ct := it.Headers["content-type"]
		if ct == "" {
			ct = "text/event-stream"
		}
		headers.Set("Content-Type", ct)
		writeResponse(conn, it.StatusCode, headers, it.ResponseBytes())
		// Keep the tunnel open: the response is Content-Length-framed, and a
		// keep-alive client (Go's default; the real CC process too) reuses
		// this connection for its next turn. Closing here instead raced that
		// reuse — the next POST sporadically died with EOF / "server closed
		// idle connection" (non-idempotent requests are never auto-retried).
		return true
	}

	// Miss.
	if r.passthrough {
		// Rebuild the request body for the upstream forward.
		req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		return r.forwardUpstream(conn, host, req)
	}
	r.writeReplayMiss(conn)
	return false
}

// writeReplayMiss serves the synthetic 502 cia_replay_miss-equivalent — no
// upstream contact, keeping the tier hermetic (D50).
func (r *replayer) writeReplayMiss(conn net.Conn) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	// The caller severs the tunnel after a miss (fail-closed posture); say so
	// in-band so a keep-alive client retires the connection instead of racing
	// the close with its next request.
	h.Set("Connection", "close")
	writeResponse(conn, http.StatusBadGateway, h, replayMissBody)
}

// forwardUpstream is the passthrough escape hatch. It is the ONLY replay path
// that opens an outbound connection; strict mode never reaches it. It records
// the attempt so the hermetic-replay test can assert strict mode never dials.
//
// D50 wall (HARDENING-NOTES.md §2.2): even on this documented non-hermetic
// path the relay must never carry a real credential upstream. The agent's
// auth/volatile request headers (Authorization, x-api-key, anthropic-beta, the
// session/correlation tells) are STRIPPED before the request leaves the gateway
// — never-log-the-secret applies to the wire too, so what we forward upstream
// is auth-free. A real upstream rejects the credential-less request; that is
// the intended cost of the escape hatch, not a regression. The dial uses the
// r.dialUpstream seam so the offline no-leak test can assert the scrubbed bytes
// without egress.
func (r *replayer) forwardUpstream(conn net.Conn, host string, req *http.Request) bool {
	r.mu.Lock()
	r.dialedUpstream = true
	dial := r.dialUpstream
	r.mu.Unlock()
	// Strip auth/volatile headers so no Bearer/x-api-key/anthropic-beta token
	// survives onto the upstream wire (D50). Done before the dial so a dial
	// failure path is already cred-free as well.
	scrubUpstreamHeaders(req)
	upstream, err := dial(host)
	if err != nil {
		writeGatewayError(conn, fmt.Sprintf("passthrough upstream error: %v", err))
		return false
	}
	// Bound a HUNG upstream: re-arm a read deadline before each read so the
	// response read below can't block forever (inactivity timeout, not a
	// whole-stream budget). Inert if the dialer returns an already-bounded conn.
	upstream = newIdleDeadlineConn(upstream, r.upstreamReadIdle())
	defer upstream.Close()
	// Stream the request body straight to the upstream (req.Write io.Copy's
	// req.Body through — no io.ReadAll), keeping a large request off the heap.
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		writeGatewayError(conn, fmt.Sprintf("passthrough write error: %v", err))
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		writeGatewayError(conn, fmt.Sprintf("passthrough read error: %v", err))
		return false
	}
	defer resp.Body.Close()
	// Relay the response PROGRESSIVELY: resp.Write streams resp.Body to the
	// client conn (it preserves the upstream framing and io.Copy's the body
	// through a fixed buffer), so a large response body is never buffered whole
	// with io.ReadAll. This is the documented non-hermetic escape hatch, so the
	// body is relayed verbatim — no capture, no scrub of the body (only the
	// request auth headers are stripped above, D50).
	if err := resp.Write(conn); err != nil {
		// Client conn went away mid-relay; nothing left to do.
		return false
	}
	return false
}

// scrubUpstreamHeaders removes the auth/volatile request headers from req before
// it is written upstream on the passthrough path, closing the D50 wall on the
// one non-hermetic replay branch. It reuses the cassette layer's canonical
// volatile-header set (the same set scrub strips and the matcher ignores), so
// Authorization, x-api-key, anthropic-beta, and the session/correlation tells
// never reach the upstream wire. Never-log-the-secret: it deletes by header
// NAME and never reads, logs, or returns the (synthetic) header value.
func scrubUpstreamHeaders(req *http.Request) {
	if req.Header == nil {
		return
	}
	for name := range req.Header {
		if cassette.VolatileRequestHeader(name) {
			req.Header.Del(name)
		}
	}
}

func (r *replayer) leafFor(host string) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.leafCache[host]; ok {
		return c, nil
	}
	leaf, err := mintLeaf(host, r.ca, r.caKey)
	if err != nil {
		return nil, err
	}
	r.leafCache[host] = leaf
	return leaf, nil
}
