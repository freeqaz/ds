// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
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

// DefaultPort is the egress gateway's default listen port. It is deliberately
// NOT :18080 — the protected shared monitor (CAPTURE-TOOL-DESIGN.md §4). The
// build asserts this never-:18080 invariant in assertNotProtectedPort.
const DefaultPort = 18099

// ProtectedMonitorPort is the shared-monitor port ds-capture must never bind.
const ProtectedMonitorPort = 18080

const anthropicHost = "api.anthropic.com"

// ---------------------------------------------------------------------- //
// Structured refusal signal                                              //
// ---------------------------------------------------------------------- //

// refusalReason is the shared, closed vocabulary for the three /v1/messages
// record-path refusals. Making it an enum/const set means the three emission
// sites speak ONE language a harness can switch on — never an ad-hoc string per
// site. The values are stable wire identifiers (a harness greps/parses them), so
// they are append-only: never rename or repurpose one.
type refusalReason string

const (
	// reasonOversized: the cassette accumulation exceeded maxCassetteBody, so the
	// buffered body was clipped and the turn is refused (recordMessages onEnd).
	reasonOversized refusalReason = "oversized"
	// reasonGzipUnsupportedEncoding: the upstream returned Content-Encoding: gzip
	// despite a stripped Accept-Encoding — a hard 502, never buffered/decoded.
	reasonGzipUnsupportedEncoding refusalReason = "gzip-unsupported-encoding"
	// reasonTruncatedTurn: the stream ended without a clean EOF and/or without a
	// terminal message_stop, i.e. a partial-on-error turn — refused.
	reasonTruncatedTurn refusalReason = "truncated-turn"
)

// refusalSignalKey is the stable top-level JSON key every refusal line carries.
// A harness consumer (e2e harness / canary / socket-bridge) greps for this exact
// token to find a refusal line and parses the object under it. NEVER rename it.
const refusalSignalKey = "ds_capture_refusal"

// refusalSignal is the SINGLE machine-readable refusal record emitted (one line
// of JSON, to stderr) at each of the three record-path refusal sites. It lets a
// harness machine-distinguish "this turn was REFUSED (and why)" from "nothing
// happened" — a distinction that was previously only a human log line.
//
// It is a DIAGNOSTIC emission only: it never touches the persisted cassette
// schema or the match key. It carries SAFE DIAGNOSTICS EXCLUSIVELY — the cap, the
// offending encoding name, SSE event/byte counts, the request path — and NEVER
// the request/response body, headers, or any credential (never-log-the-secret,
// HARDENING-NOTES §2.2). Every field below is a bounded scalar derived from
// structure, not from body payload bytes.
type refusalSignal struct {
	// Reason is the closed-vocabulary cause; a harness switches on it.
	Reason refusalReason `json:"reason"`
	// Path is the request path (query stripped, so no query params leak). For
	// the record path this is always /v1/messages.
	Path string `json:"path"`
	// CapBytes is the cassette accumulation cap (oversized only); 0/omitted else.
	CapBytes int `json:"cap_bytes,omitempty"`
	// Encoding is the offending Content-Encoding token (gzip case only).
	Encoding string `json:"encoding,omitempty"`
	// SSEEvents is the count of structural SSE event names seen — a shape count,
	// never any data: payload bytes (oversized / truncated cases).
	SSEEvents int `json:"sse_events,omitempty"`
	// CleanEOF / MessageStop describe why a turn was below a boundary (truncated
	// case). Pointers so false is emitted explicitly rather than omitted, which a
	// harness needs to tell "saw a false flag" from "field absent".
	CleanEOF    *bool `json:"clean_eof,omitempty"`
	MessageStop *bool `json:"message_stop,omitempty"`
}

// emitRefusal writes ONE structured refusal line to w as a single-line JSON
// object under the stable refusalSignalKey, e.g.:
//
//	{"ds_capture_refusal":{"reason":"gzip-unsupported-encoding","path":"/v1/messages","encoding":"gzip"}}
//
// Exactly one such line is emitted per refusal that drops a turn; a successful
// capture emits none. The marshal cannot fail (all fields are plain scalars), but
// any error is swallowed so a diagnostic never affects refusal behavior. The
// signal is shape-only by construction: refusalSignal has no field that can hold
// body/header/credential bytes.
func emitRefusal(w io.Writer, sig refusalSignal) {
	line, err := json.Marshal(map[string]refusalSignal{refusalSignalKey: sig})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "%s\n", line)
}

// boolPtr returns a pointer to b, for the explicit-false refusal-signal fields.
func boolPtr(b bool) *bool { return &b }

// Progressive-relay + bounded-upstream-read tunables. These govern the three
// body-relay paths (recordMessages' streamTee, passthroughTLS, and replay's
// forwardUpstream) so none reads a whole body into memory with io.ReadAll and
// none can block forever on a hung upstream. They are package-level vars (not
// consts) ONLY so a test can dial them down to drive the bounded path without
// shipping a multi-MiB fixture; production never reassigns them. Defaults are
// chosen generously so NORMAL traffic is never truncated.
var (
	// relayBufSize is the fixed-size copy buffer every progressive relay uses.
	// A body of any size streams through this many bytes at a time, so peak
	// relay memory is O(relayBufSize), not O(body). 32 KiB matches streamTee's
	// historical chunk size and io.Copy's default.
	relayBufSize = 32 * 1024

	// upstreamReadIdleTimeout bounds a HUNG upstream: it is reset after every
	// successful read, so it is an INACTIVITY deadline, not a whole-stream
	// budget — a long but live SSE turn (bytes still flowing) is never cut,
	// while an upstream that stops sending bytes is failed after this long.
	// 120s is far longer than any gap between SSE events in a healthy turn.
	upstreamReadIdleTimeout = 120 * time.Second

	// maxCassetteBody caps how many SSE bytes recordMessages ACCUMULATES for the
	// cassette. The client still receives every byte (the tee write side is
	// unbounded); only the in-memory accumulation is capped, so a pathological
	// stream cannot OOM the recorder. A real CC /v1/messages turn is orders of
	// magnitude under 64 MiB; a stream that exceeds the cap is marked oversized
	// and REFUSED (not persisted), exactly like a truncated turn, so it can
	// never replay as a complete-but-clipped turn.
	maxCassetteBody = 64 * 1024 * 1024
)

// assertNotProtectedPort fails closed if a caller tries to bind the protected
// shared-monitor port. Returned as an error so tests can assert it without the
// process exiting.
func assertNotProtectedPort(port int) error {
	if port == ProtectedMonitorPort {
		return fmt.Errorf("refusing to bind :%d — the protected shared monitor; "+
			"ds-capture defaults to :%d (CAPTURE-TOOL-DESIGN.md §4)",
			ProtectedMonitorPort, DefaultPort)
	}
	return nil
}

// cmdRecord parses flags and runs the record-mode egress gateway until a
// signal arrives, then writes the cassette.
func cmdRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cassettePath := fs.String("cassette", "", "path to write the recorded cassette (required)")
	port := fs.Int("port", DefaultPort, "egress-gateway listen port (never :18080)")
	caDir := fs.String("ca-dir", "", "directory to write the generated CA cert (for NODE_EXTRA_CA_CERTS); default: a temp dir")
	host := fs.String("host", "127.0.0.1", "loopback host to bind")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ds-capture record --cassette PATH [--port %d] [--ca-dir DIR]\n", DefaultPort)
		fmt.Fprintf(os.Stderr, "\nStands up a TLS-terminating egress gateway and tees /v1/messages SSE into\n")
		fmt.Fprintf(os.Stderr, "the cassette. Default port :%d — NEVER :%d.\n", DefaultPort, ProtectedMonitorPort)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cassettePath == "" {
		fmt.Fprintln(os.Stderr, "ds-capture record: --cassette is required")
		fs.Usage()
		return 2
	}
	if err := assertNotProtectedPort(*port); err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture record: %v\n", err)
		return 2
	}

	rec, err := newRecorder(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture record: %v\n", err)
		return 1
	}
	defer rec.cleanup()

	srv, addr, err := rec.listen(*host, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture record: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "ds-capture record: egress gateway on http://%s\n", addr)
	fmt.Fprintf(os.Stderr, "ds-capture record: NODE_EXTRA_CA_CERTS=%s\n", rec.caCertPath)
	fmt.Fprintln(os.Stderr, "ds-capture record: point CC at this proxy (NODE_USE_ENV_PROXY=1); Ctrl-C to write the cassette.")

	// Serve until a termination signal arrives.
	go func() { _ = srv.Serve(rec.ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = srv.Close()

	if rec.cassette.Len() == 0 {
		fmt.Fprintln(os.Stderr, "ds-capture record: nothing recorded; cassette not written")
		return 0
	}
	if err := rec.cassette.Save(*cassettePath); err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture record: save cassette: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "ds-capture record: wrote %d interaction(s) to %s\n", rec.cassette.Len(), *cassettePath)
	fmt.Fprintln(os.Stderr, "ds-capture record: this is a RAW-class capture — run `ds-capture scrub` before any promotion (D50).")
	return 0
}

// recorder is the record-mode egress gateway: a CONNECT-handling forward proxy
// that terminates TLS for api.anthropic.com with on-the-fly leaf certs minted
// under a generated CA, intercepts POST /v1/messages, tees the decoded SSE body
// into the cassette, and passes everything else through.
type recorder struct {
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caCertPath string
	caDirTemp  bool

	mu        sync.Mutex
	cassette  *cassette.Cassette
	leafCache map[string]*tls.Certificate

	ln net.Listener

	// upstreamDial is the dialer used to reach the real upstream. Tests inject a
	// dialer that points at an in-process httptest fake; production uses a TLS
	// dial to the real host (the live path is never exercised in tests).
	upstreamDial func(host string) (net.Conn, error)

	// tlsDialAddr and tlsRootCAs are test-only seams that let the OFFLINE suite
	// drive the REAL crypto/tls dial path (dialUpstreamTLS) against an in-process
	// TLS upstream on an ephemeral 127.0.0.1 port — with ZERO egress and no
	// DS_E2E_LIVE gate. Both are zero-valued in production, where dialUpstreamTLS
	// dials host:443 with WebPKI defaults exactly as before; setting them changes
	// nothing else. tlsDialAddr overrides ONLY the dial target (the host:443
	// shape) so the in-process listener is reachable; tlsRootCAs is injected as
	// tls.Config.RootCAs so the upstream's per-process synthetic cert validates
	// without touching the system trust store.
	tlsDialAddr string
	tlsRootCAs  *x509.CertPool

	// readIdle and maxBody are per-recorder copies of the package defaults
	// (upstreamReadIdleTimeout / maxCassetteBody). They exist so a test can dial
	// them down to drive the hung-upstream and over-cap paths without a real
	// multi-MiB / multi-minute fixture; production leaves them at the defaults.
	// A zero value falls back to the package default (see the accessors below).
	readIdle time.Duration
	maxBody  int
}

func (r *recorder) upstreamReadIdle() time.Duration {
	if r.readIdle > 0 {
		return r.readIdle
	}
	return upstreamReadIdleTimeout
}

func (r *recorder) cassetteCap() int {
	if r.maxBody > 0 {
		return r.maxBody
	}
	return maxCassetteBody
}

func newRecorder(caDir string) (*recorder, error) {
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
	r := &recorder{
		ca:         ca,
		caKey:      caKey,
		caCertPath: caPath,
		caDirTemp:  temp,
		cassette:   cassette.New(),
		leafCache:  map[string]*tls.Certificate{},
	}
	r.upstreamDial = r.dialUpstreamTLS
	return r, nil
}

func (r *recorder) cleanup() {
	if r.caDirTemp {
		_ = os.RemoveAll(strings.TrimSuffix(r.caCertPath, "/ds-capture-ca.pem"))
	}
}

// listen binds the loopback port and returns an http.Server wired to the proxy
// handler. The server is returned unstarted; the caller drives Serve.
func (r *recorder) listen(host string, port int) (*http.Server, string, error) {
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

// handle is the proxy entry point. CONNECT requests are hijacked, TLS-terminated
// with a minted leaf, and re-served through serveTLS. Plain HTTP requests (rare
// for CC) are forwarded directly.
func (r *recorder) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		r.handleConnect(w, req)
		return
	}
	// Plain (non-TLS) proxying — forward as-is. CC's Anthropic traffic is HTTPS,
	// so this path is exercised only by incidental plaintext requests.
	r.forwardPlain(w, req)
}

func (r *recorder) handleConnect(w http.ResponseWriter, req *http.Request) {
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

// serveTLS reads HTTP requests off the terminated TLS connection and dispatches
// them. /v1/messages POSTs to api.anthropic.com are intercepted and recorded;
// everything else is passed through to the upstream.
func (r *recorder) serveTLS(conn net.Conn, host string) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host
		keepAlive := r.dispatchTLS(conn, host, req)
		if !keepAlive {
			return
		}
	}
}

// dispatchTLS handles one request on a terminated TLS conn. Returns whether the
// connection should be kept alive for another request.
func (r *recorder) dispatchTLS(conn net.Conn, host string, req *http.Request) bool {
	isMessages := host == anthropicHost && stripQuery(req.URL.Path) == cassette.MessagesPath && req.Method == http.MethodPost
	if isMessages {
		return r.recordMessages(conn, host, req)
	}
	return r.passthroughTLS(conn, host, req)
}

// recordMessages forwards a /v1/messages POST upstream with Accept-Encoding
// stripped (so the SSE arrives plaintext), then INCREMENTALLY tees the SSE to
// the client as bytes arrive while accumulating the same bytes for the cassette
// — a streaming tee, not buffer-then-relay. Status + filtered headers
// (Content-Type only) go to the client as soon as upstream response headers
// arrive; body bytes are relayed AS THEY ARRIVE (flushed per upstream read /
// SSE event boundary); cassette.Record is called ONCE at upstream EOF with the
// full concatenated stream.
//
// Why streaming matters: a live CC behind the gateway must see the turn
// progressively (as cia/mitmproxy and the real upstream deliver it), or a long
// turn risks client idle-timeouts and forces unbounded buffering on both legs.
// The buffer-then-relay predecessor handed the whole decoded body to the client
// only after upstream EOF; the 01KTXKJYYW fidelity migration first exercises the
// progressive path against real CC.
func (r *recorder) recordMessages(conn net.Conn, host string, req *http.Request) bool {
	reqBodyBytes, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()

	// STRIP Accept-Encoding so the upstream SSE comes back plaintext (no gzip).
	req.Header.Del("Accept-Encoding")

	resp, err := r.roundTrip(host, req, reqBodyBytes)
	if err != nil {
		// Upstream round-trip failed BEFORE response headers arrived — the
		// gateway-error contract (502, record.go) is preserved unchanged: we
		// have written nothing to the client yet, so a clean 502 is safe.
		writeGatewayError(conn, fmt.Sprintf("upstream error: %v", err))
		return false
	}
	defer resp.Body.Close()

	reqJSON := parseJSONBody(reqBodyBytes)
	respHeaders := flattenHeader(resp.Header)

	// GZIP IS A HARD GATEWAY ERROR (no buffer-then-relay). The recorder strips
	// Accept-Encoding on the upstream leg above, so a compliant upstream returns
	// plaintext SSE that streams incrementally. The predecessor kept a
	// buffer-then-relay gunzip fallback for the rare non-compliant upstream that
	// compressed anyway — but that path read the WHOLE body before the first
	// client byte (a gzip member only decodes once whole), the last place
	// progressive delivery could silently degrade to buffer-then-relay. Rather
	// than reintroduce full-body buffering, treat a returned Content-Encoding:
	// gzip as a hard egress-gateway error: fail closed with a 502 BEFORE reading
	// any body, so progressive delivery cannot silently regress and the recorder
	// never persists a buffered interaction. The 502 is shape-only — it names the
	// encoding, never any body bytes (never-log-the-secret, HARDENING-NOTES §2.2).
	if ce := resp.Header.Get("Content-Encoding"); strings.Contains(strings.ToLower(ce), "gzip") {
		// Structured refusal signal (shape-only): name the offending encoding +
		// path so a harness can machine-distinguish this gzip refusal from a
		// success. Never any body bytes (never-log-the-secret, HARDENING-NOTES §2.2).
		emitRefusal(os.Stderr, refusalSignal{
			Reason:   reasonGzipUnsupportedEncoding,
			Path:     stripQuery(req.URL.Path),
			Encoding: ce,
		})
		writeGatewayError(conn, "upstream returned Content-Encoding: gzip despite stripped "+
			"Accept-Encoding — refusing to buffer-then-relay (progressive delivery would "+
			"silently degrade); treat as a non-compliant upstream")
		return false
	}

	// Incremental tee: write status + filtered headers (Content-Type only) to the
	// client as soon as upstream headers are known, then relay body bytes as they
	// arrive while accumulating the identical bytes for the cassette. The relay
	// uses chunked transfer-encoding because the streamed length is unknown until
	// EOF; no Content-Encoding is set since the body is plaintext SSE.
	//
	// onEnd runs once the upstream stream is done — AFTER every body chunk has been
	// flushed to the client but BEFORE the terminal zero-length chunk that ends the
	// response. It is handed the full concatenated SSE plus whether the upstream
	// ended CLEANLY (a true io.EOF, not a mid-stream read error).
	//
	// PARTIAL-ON-ERROR REFUSAL. The predecessor recorded unconditionally here, so a
	// mid-stream upstream failure (e.g. the upstream dies right after message_start)
	// persisted the TRUNCATED bytes as a normal interaction — and a later replay
	// would serve that truncated stream back as if it were a COMPLETE turn. The
	// cassette's on-disk shape is byte-compatible with cia ({key,normalized,
	// status_code,headers,body}, no truncation field) and is not ours to extend,
	// so we instead REFUSE TO RECORD below a turn boundary: cassette.Record is
	// called ONCE only when the stream both (a) ended cleanly AND (b) carries a
	// terminal message_stop event — i.e. a complete turn. A truncated stream is
	// dropped (zero interactions), so it can never replay as a complete turn.
	//
	// Recording before the terminator preserves the original happens-before (the
	// client cannot observe end-of-stream until Record has completed), and a clean
	// complete turn records byte-identically to the buffer-then-relay predecessor,
	// so the on-disk cassette is unchanged for the normal path.
	ct := resp.Header.Get("Content-Type")
	onEnd := func(full []byte, cleanEOF, oversized bool) {
		if oversized {
			// OVER-CAP REFUSAL. The accumulation hit cassetteCap() before the
			// stream ended, so `full` is CLIPPED (the client got every byte, but
			// the cassette buffer was bounded to avoid OOM). A clipped body is not
			// a complete turn and must NEVER be persisted — a later replay would
			// serve a truncated-but-clean-looking stream. Drop it, exactly like a
			// mid-stream-truncated turn. SHAPE-ONLY diagnostic: report the cap and
			// event count, never any body bytes (never-log-the-secret, §2.2).
			events := len(cassette.EventTypes(string(full)))
			emitRefusal(os.Stderr, refusalSignal{
				Reason:    reasonOversized,
				Path:      stripQuery(req.URL.Path),
				CapBytes:  r.cassetteCap(),
				SSEEvents: events,
			})
			fmt.Fprintf(os.Stderr,
				"ds-capture record: refusing to record an OVERSIZED /v1/messages turn "+
					"(accumulation exceeded %d bytes; %d SSE event(s) buffered); the client "+
					"received the full stream but a clipped body must not replay as a complete turn\n",
				r.cassetteCap(), events)
			return
		}
		if !cleanEOF || !hasTurnBoundary(full) {
			// SHAPE-ONLY diagnostic: report the event count and why we refused,
			// never any body bytes (never-log-the-secret, HARDENING-NOTES §2.2).
			messageStop := hasTurnBoundary(full)
			events := len(cassette.EventTypes(string(full)))
			emitRefusal(os.Stderr, refusalSignal{
				Reason:      reasonTruncatedTurn,
				Path:        stripQuery(req.URL.Path),
				SSEEvents:   events,
				CleanEOF:    boolPtr(cleanEOF),
				MessageStop: boolPtr(messageStop),
			})
			fmt.Fprintf(os.Stderr,
				"ds-capture record: refusing to record a truncated /v1/messages turn "+
					"(cleanEOF=%v, message_stop=%v, %d SSE event(s)); a partial stream "+
					"must not replay as a complete turn\n",
				cleanEOF, messageStop, events)
			return
		}
		r.mu.Lock()
		r.cassette.Record(req.Method, req.URL.Path, reqJSON, resp.StatusCode, respHeaders, string(full))
		r.mu.Unlock()
	}
	_ = streamTee(conn, resp.StatusCode, ct, resp.Body, r.cassetteCap(), onEnd)
	return false
}

// hasTurnBoundary reports whether a concatenated SSE body carries a terminal
// message_stop event — the marker of a COMPLETE /v1/messages turn. A stream that
// ends without it is truncated (the upstream died mid-turn), so the recorder
// refuses to persist it (see recordMessages). It inspects only the structural
// event: names via the cassette SSE parser, never any data: payload bytes.
func hasTurnBoundary(full []byte) bool {
	for _, ev := range cassette.EventTypes(string(full)) {
		if ev == "message_stop" {
			return true
		}
	}
	return false
}

// streamTee writes an HTTP/1.1 response head (status line + filtered headers:
// Content-Type only, chunked transfer-encoding) to conn, then relays body bytes
// from src to conn AS THEY ARRIVE — flushing each upstream read to the client
// immediately — while accumulating the identical bytes. Each upstream read
// becomes its own chunk, so a CC reading the stream observes event N before the
// gateway has seen event N+1: progressive delivery by construction, not by
// timing.
//
// At end-of-stream, onEnd is invoked with the full concatenated body AND whether
// the upstream ended CLEANLY (true io.EOF) versus a mid-stream read error AND
// whether accumulation was BOUNDED at maxAccum (oversized) — BEFORE the terminal
// zero-length chunk is written, so the side effect (cassette.Record) completes
// happens-before the client can see end-of-response. The cleanEOF flag lets
// recordMessages refuse to persist a truncated (partial-on-error) turn; the
// oversized flag lets it refuse an over-cap turn.
//
// BOUNDED ACCUMULATION (no OOM). The client write side is UNBOUNDED — every
// upstream byte is chunked through to the client, so capture fidelity on the
// wire is unchanged. Only the in-memory `acc` (the cassette copy) is capped at
// maxAccum bytes: once it would exceed the cap we STOP appending (so peak
// accumulation is ≤ maxAccum+relayBufSize) and set oversized, while continuing
// to drain+relay the rest of the stream to the client. The copy buffer itself
// is a fixed relayBufSize, so per-read memory is O(relayBufSize) regardless of
// body size. maxAccum ≤ 0 disables the cap (accumulate without bound).
func streamTee(conn net.Conn, status int, contentType string, src io.Reader, maxAccum int, onEnd func(full []byte, cleanEOF, oversized bool)) error {
	bw := bufio.NewWriter(conn)
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if contentType != "" {
		fmt.Fprintf(bw, "Content-Type: %s\r\n", contentType)
	}
	// Chunked because the streamed length is unknown until upstream EOF.
	bw.WriteString("Transfer-Encoding: chunked\r\n\r\n")
	_ = bw.Flush()

	var acc []byte
	var streamErr error
	cleanEOF := false
	oversized := false
	buf := make([]byte, relayBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// Accumulate for the cassette, but only up to the cap. Beyond it we
			// stop appending (oversized) so a pathological stream cannot OOM the
			// recorder — yet we keep relaying every byte to the client below.
			if maxAccum > 0 && len(acc)+n > maxAccum {
				oversized = true
			}
			if !oversized {
				acc = append(acc, chunk...)
			}
			// Write one HTTP chunk per upstream read and flush, so the client
			// receives these bytes before the next upstream read can occur.
			fmt.Fprintf(bw, "%x\r\n", n)
			bw.Write(chunk)
			bw.WriteString("\r\n")
			if ferr := bw.Flush(); ferr != nil {
				streamErr = ferr
				break
			}
		}
		if err != nil {
			// A true io.EOF is a clean upstream close; anything else is a
			// mid-stream failure that leaves acc truncated.
			if err == io.EOF {
				cleanEOF = true
			} else {
				streamErr = err
			}
			break
		}
	}
	// Hand the full stream (and whether it ended cleanly / was bounded) to onEnd
	// BEFORE ending the response, so the cassette write happens-before the
	// client's end-of-stream. onEnd decides whether the turn is recorded at all.
	if onEnd != nil {
		onEnd(acc, cleanEOF, oversized)
	}
	// Terminal zero-length chunk ends the body.
	bw.WriteString("0\r\n\r\n")
	_ = bw.Flush()
	return streamErr
}

// passthroughTLS forwards any non-/v1/messages request upstream verbatim and
// relays the response — the proxy is transparent for everything but recording.
// This path CAPTURES NOTHING, so it streams FREELY: the request body is copied
// straight to the upstream conn and the response body straight back to the
// client, both through a fixed relayBufSize buffer (via req.Write / resp.Write,
// which themselves io.Copy chunk-by-chunk) — NO io.ReadAll of either body, so
// peak memory is O(relayBufSize), not O(body). The upstream conn carries an
// inactivity read deadline (roundTripStreaming), so a hung upstream is bounded.
func (r *recorder) passthroughTLS(conn net.Conn, host string, req *http.Request) bool {
	// Stream the request body directly to the upstream (no buffering): req.Write
	// copies req.Body through to the wire. roundTripStreaming installs the idle
	// read deadline on the upstream conn so the response read below is bounded.
	resp, err := r.roundTripStreaming(host, req)
	if err != nil {
		writeGatewayError(conn, fmt.Sprintf("upstream error: %v", err))
		return false
	}
	defer resp.Body.Close()
	// Relay the response progressively: resp.Write streams resp.Body to the
	// client conn chunk-by-chunk (it preserves the upstream's framing —
	// Content-Length or chunked — and io.Copy's the body through a fixed buffer),
	// so a large response never lands wholly in memory. The upstream returns the
	// body raw (we never set Accept-Encoding on this leg, so we relay
	// Content-Encoding verbatim too — true passthrough).
	if err := resp.Write(conn); err != nil {
		// The client conn may have gone away mid-relay; nothing to do but stop.
		return false
	}
	return false
}

// roundTrip dials the upstream (real host in production; an injected fake in
// tests), replays the request, and returns the response.
func (r *recorder) roundTrip(host string, req *http.Request, body []byte) (*http.Response, error) {
	conn, err := r.upstreamDial(host)
	if err != nil {
		return nil, err
	}
	// Wrap the upstream conn so every read carries a fresh INACTIVITY deadline:
	// a hung upstream (no bytes flowing) is bounded by upstreamReadIdleTimeout,
	// while a long-but-live stream keeps resetting it. This bounds BOTH the
	// /v1/messages tee leg (streamTee reads resp.Body) and the passthrough leg
	// (io.Copy of resp.Body) without a whole-stream budget that could truncate
	// real traffic.
	conn = newIdleDeadlineConn(conn, r.upstreamReadIdle())
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(strings.NewReader(string(body)))
	out.ContentLength = int64(len(body))
	out.Header.Set("Host", host)
	out.RequestURI = ""
	if err := out.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), out)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Close the conn when the body is closed.
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// roundTripStreaming is the passthrough round-trip: it dials the upstream and
// writes the request — INCLUDING its body — straight to the wire via req.Write
// (which io.Copy's req.Body through, no io.ReadAll), then returns the response
// whose body streams off the same conn. It differs from roundTrip in that NO
// body is buffered: the /v1/messages path needs the request bytes for the match
// key, but a verbatim passthrough captures nothing, so both bodies stay
// streamed. The upstream conn carries the inactivity read deadline so a hung
// upstream can't block the response read forever.
func (r *recorder) roundTripStreaming(host string, req *http.Request) (*http.Response, error) {
	conn, err := r.upstreamDial(host)
	if err != nil {
		return nil, err
	}
	conn = newIdleDeadlineConn(conn, r.upstreamReadIdle())
	// Write the request verbatim, streaming its body straight to the wire.
	req.Host = host
	req.Header.Set("Host", host)
	req.RequestURI = ""
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// dialUpstreamTLS is the production dialer: a real crypto/tls.Dial to the
// upstream host on :443 with WebPKI defaults. In production both seam fields are
// zero, so the dial target is host:443 and the system trust store validates the
// certificate — byte-identical to the original one-liner. The offline test suite
// sets tlsDialAddr/tlsRootCAs to point the SAME tls.Dial at an in-process TLS
// upstream on an ephemeral 127.0.0.1 port whose synthetic cert is anchored by an
// injected root pool, so the gzip/refuse-partial branches are exercised end-to-end
// through this real dial path with zero egress (see record_test.go).
func (r *recorder) dialUpstreamTLS(host string) (net.Conn, error) {
	addr := host + ":443"
	if r.tlsDialAddr != "" {
		addr = r.tlsDialAddr
	}
	// ServerName stays the upstream host so SNI/cert-name verification is the
	// real production check; the in-process cert is minted for that same name.
	return tls.Dial("tcp", addr, &tls.Config{ServerName: host, RootCAs: r.tlsRootCAs, MinVersion: tls.VersionTLS13})
}

// forwardPlain proxies a plaintext HTTP request (non-CONNECT). CC's Anthropic
// traffic never uses this path; it exists so the proxy is well-behaved.
func (r *recorder) forwardPlain(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "ds-capture: plaintext proxying not supported (HTTPS via CONNECT only)", http.StatusBadGateway)
}

// connClosingBody closes the underlying conn when the body is closed.
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	_ = b.conn.Close()
	return err
}

// idleDeadlineConn wraps an upstream net.Conn and arms a fresh read deadline
// before every Read, so a HUNG upstream (one that stops sending bytes) is bounded
// by `idle` instead of blocking forever. Because the deadline is re-armed on each
// Read — not set once for the whole stream — it is an INACTIVITY timeout: a long
// but live SSE turn keeps making progress and is never truncated, while an
// upstream that goes silent fails after `idle`. A non-positive idle disables the
// deadline (the conn behaves exactly as before). It bounds the upstream READ leg
// only; writes are unchanged.
type idleDeadlineConn struct {
	net.Conn
	idle time.Duration
}

func newIdleDeadlineConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	return &idleDeadlineConn{Conn: c, idle: idle}
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	// Re-arm before each read so the deadline measures INACTIVITY, not total
	// stream duration. SetReadDeadline errors are non-fatal here (e.g. an already
	// closed conn) — the Read below will surface the real failure.
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

// leafFor returns a cached or freshly minted leaf certificate for host.
func (r *recorder) leafFor(host string) (*tls.Certificate, error) {
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

// ---------------------------------------------------------------------- //
// TLS material                                                            //
// ---------------------------------------------------------------------- //

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ds-capture egress-gateway CA (synthetic)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func mintLeaf(host string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: nil}, nil
}

func writeCertPEM(path string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ---------------------------------------------------------------------- //
// HTTP helpers                                                            //
// ---------------------------------------------------------------------- //

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func parseJSONBody(b []byte) map[string]any {
	if len(b) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}

func flattenHeader(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func writeResponse(conn net.Conn, status int, headers http.Header, body []byte) {
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Header.Del("Transfer-Encoding")
	_ = resp.Write(conn)
}

func writeGatewayError(conn net.Conn, msg string) {
	body := []byte(msg)
	h := http.Header{}
	h.Set("Content-Type", "text/plain")
	writeResponse(conn, http.StatusBadGateway, h, body)
}
