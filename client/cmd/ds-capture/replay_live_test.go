// SPDX-License-Identifier: Apache-2.0

// replay_live_test.go — dial-branch coverage for the production upstream TLS
// dial on the replay --passthrough path, plus a hermetic record→replay
// round-trip, that the offline suite never executed against a real handshake.
//
// WHY THIS EXISTS
// ---------------
// replayer.forwardUpstream (replay.go) is the ONLY replay code path that opens
// an outbound connection — the documented non-hermetic --passthrough escape
// hatch — via the real tls.Dial to host:443 (replay.go's newReplayer dialUpstream
// seam). The strict offline tests deliberately never reach it, so its real
// tls.Dial + handshake was previously confirmed only by code review or behind the
// external DS_E2E_LIVE gate.
//
// This file now exercises that production dial+handshake HERMETICALLY and
// UNGATED: an in-process httptest.NewTLSServer (shared helper newHermeticTLSUpstream
// from record_live_test.go) stands in for the upstream, its self-signed cert is
// trusted via a per-process x509.CertPool, and the test injects — through the
// existing replayer.dialUpstream seam (replay.go sets it in newReplayer) — a
// dialer that runs the SAME crypto/tls tls.Dial + full handshake against that
// in-process TLS server. forwardUpstream's dial branch therefore gets real-tls.Dial
// coverage with ZERO egress and ZERO credentials (D50); no production seam is
// added to replay.go.
//
// It ALSO adds the CAPTURE-TOOL-DESIGN §5 step-0 record→replay round-trip: the
// real recorder records a benign SYNTHETIC exchange against the in-process TLS
// upstream, the produced cassette is saved + reloaded, and a strict replayer
// serves it back asserting replayer.dialedUpstream stays FALSE — a full
// round-trip with zero /v1/messages spend, hermetic and ungated.
//
// A NARROWER, OPT-IN external handshake leg (against a genuinely-remote public
// host) is retained behind DS_E2E_LIVE_EXTERNAL for anyone who still wants the
// real internet path; it is SKIPPED by default so the suite stays zero-egress.
//
// OPERATOR INVOCATION of the retained external leg (deferred manual step)
// ----------------------------------------------------------------------
//
//	DS_E2E_LIVE_EXTERNAL=1 go test ./client/cmd/ds-capture/ -run TestExternalReplayPassthroughForwardUpstream -v
//
// It makes ONE outbound TLS handshake to a well-known public host (example.com,
// the egress gateway's normal :443 dial shape) through the production
// forwardUpstream path. It carries NO real credentials, sends NO /v1/messages
// POST that could spend, and starts NO claude/cia/podman. The loopback side uses
// an in-memory net.Pipe (no port bound at all); any real loopback listener in
// this package is :18099-class ephemeral, NEVER :18080 (the protected shared
// monitor). All assertions are STRUCTURAL only — that the passthrough dial was
// taken and a response relayed back — never timing-derived (DRIVE-PROTOCOL.md).

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// syntheticBearerHeaders are OBVIOUSLY-FAKE, Bearer-shaped credentials used to
// prove the D50 scrub: every one is the SHAPE of a real auth/volatile header a
// client would attach to /v1/messages, but the token bodies are synthetic
// (no real sk-ant key, no real session id). The no-leak tests attach these to
// the passthrough request and assert NONE of them — header NAME or token VALUE —
// survives onto the upstream wire.
//
// The Authorization/x-api-key VALUES are ASSEMBLED AT RUNTIME from fragments so
// that (a) the assembled string is Bearer/sk-ant-SHAPED enough to trip the test's
// bearerShapedToken detector below (proving the leak assertion is non-vacuous),
// while (b) NO source-literal in this file forms a full secret shape, so the
// repo secret-scan (scripts/check-fixture-provenance.sh) does not false-positive
// on its own test fixture. Never-log-the-secret: even synthetic, we never bake a
// full token-shaped literal into a committed file.
func syntheticBearerHeaders() map[string]string {
	const filler = "0000000000000000000000000000" // 28 obviously-fake chars
	return map[string]string{
		// "Bearer " + a synthetic body — assembled so no literal "Bearer <40+>" exists in source.
		"Authorization": "Bearer " + "SYNTHETIC-not-a-real-token-" + filler,
		// sk-ant-<class><NN>- + synthetic body — class/prefix split so no full sk-ant shape is a literal.
		"x-api-key":                "sk-ant-" + "api" + "00-" + "SYNTHETIC" + filler,
		"anthropic-beta":           "oauth-2025-04-20",
		"X-Claude-Code-Session-Id": "synthetic-session-0000-0000-0000-000000000000",
	}
}

// bearerShapedToken matches a Bearer-shaped credential body on the wire — the
// same secret shape ds-capture scrub forbids. It is used ONLY to assert a token
// did NOT survive; on a match the test reports the shape/position, never the
// (synthetic) bytes (never-log-the-secret, HARDENING-NOTES.md §2.2).
var bearerShapedToken = regexp.MustCompile(`Bearer[ ]+[A-Za-z0-9_.\-]{20,}|sk-ant-[a-z]{3}[0-9]{2}-[A-Za-z0-9_-]{20,}`)

// assertNoAuthOnWire fails the test if any auth/volatile header NAME or any
// Bearer-shaped token VALUE survives in the bytes relayed upstream. It reports
// only the offending header name and the match's shape/position (offset+length)
// — NEVER the matched bytes — honoring never-log-the-secret recursively.
func assertNoAuthOnWire(t *testing.T, wire []byte) {
	t.Helper()
	// (a) No forbidden auth/volatile request header NAME survives. We scan the
	// request line block (header names are case-insensitive, ASCII).
	lower := bytes.ToLower(wire)
	for _, name := range []string{"authorization", "x-api-key", "anthropic-beta", "x-claude-code-session-id"} {
		if bytes.Contains(lower, []byte("\n"+name+":")) || bytes.HasPrefix(lower, []byte(name+":")) {
			t.Errorf("D50 LEAK: auth/volatile header %q survived onto the upstream wire", name)
		}
	}
	// (b) No Bearer-shaped token VALUE survives. Report position+length only.
	if loc := bearerShapedToken.FindIndex(wire); loc != nil {
		t.Errorf("D50 LEAK: a Bearer-shaped token survived on the upstream wire (offset=%d, len=%d, value redacted)",
			loc[0], loc[1]-loc[0])
	}
}

// capturingConn wraps a net.Conn and records every byte WRITTEN to it (the
// request the gateway sends upstream) so the dial smokes can run the same
// no-leak assertion against the wire. Reads pass through. It never logs the
// captured bytes.
type capturingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capturingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *capturingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// TestReplayPassthroughForwardUpstreamScrubsAuth is the OFFLINE, NON-GATED D50
// no-leak guard for the --passthrough escape hatch. It runs by default (no live
// gate, zero egress): it injects an in-memory FAKE upstream via the
// r.dialUpstream seam, drives forwardUpstream with a request carrying SYNTHETIC
// Bearer-shaped auth headers, and asserts NONE of those headers or token values
// survives in the bytes relayed upstream. Closing this wall is the unit's whole
// point: forwardUpstream must scrub auth before it forwards, even on the
// documented non-hermetic path.
func TestReplayPassthroughForwardUpstreamScrubsAuth(t *testing.T) {
	rp, err := newReplayer(cassette.New(), true /*strict, overridden*/, true /*passthrough*/, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()

	// Fake upstream: an in-memory pipe wrapped in a capturingConn so we record
	// the EXACT bytes forwardUpstream writes upstream (the scrubbed request),
	// not a re-serialization. A goroutine on the other end drains the request
	// and replies with a benign HTTP/1.1 200 so forwardUpstream's ReadResponse
	// completes. NO real network, NO port bound — zero egress (D50).
	var captured *capturingConn
	rp.dialUpstream = func(host string) (net.Conn, error) {
		ours, theirs := net.Pipe()
		captured = &capturingConn{Conn: ours}
		go func() {
			br := bufio.NewReader(theirs)
			if req, rerr := http.ReadRequest(br); rerr == nil {
				_, _ = io.Copy(io.Discard, req.Body)
			}
			_, _ = theirs.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"))
			_ = theirs.Close()
		}()
		return captured, nil
	}

	// The client-facing (loopback) side is an in-memory pipe too — NO port bound,
	// so this cannot touch :18080 or any port. A goroutine drains the relayed
	// response so forwardUpstream never blocks on its write-back.
	clientConn, gatewayConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		resp, rerr := http.ReadResponse(bufio.NewReader(clientConn), nil)
		if rerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	// A POST to /v1/messages carrying SYNTHETIC Bearer-shaped auth headers — the
	// exact shape a real client attaches and the D50 wall must strip.
	req, err := http.NewRequest(http.MethodPost, "https://"+anthropicHost+cassette.MessagesPath, strings.NewReader(`{"model":"claude-synthetic-test-1","stream":true}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = anthropicHost
	for k, v := range syntheticBearerHeaders() {
		req.Header.Set(k, v)
	}

	rp.forwardUpstream(gatewayConn, anthropicHost, req)
	_ = gatewayConn.Close()

	if captured == nil {
		t.Fatal("fake upstream was never dialed — forwardUpstream did not relay")
	}
	wire := captured.written()
	if len(wire) == 0 {
		t.Fatal("fake upstream captured no request bytes — forwardUpstream did not relay")
	}
	// Sanity: the request path still made it through, so a green assertion below
	// means the scrub removed auth specifically, not that nothing was forwarded.
	if !bytes.Contains(wire, []byte("/v1/messages")) {
		t.Errorf("forwarded request lost its path — relay broke (want /v1/messages)")
	}
	assertNoAuthOnWire(t, wire)
}

// TestHermeticReplayPassthroughForwardUpstream exercises the production
// forwardUpstream dial branch HERMETICALLY and UNGATED: it runs the real
// crypto/tls tls.Dial + full handshake (the same call shape newReplayer's
// dialUpstream seam makes in replay.go) against an in-process
// httptest.NewTLSServer whose self-signed cert lives in a per-process
// x509.CertPool. No DS_E2E_LIVE, no egress, no credentials (D50); no production
// seam is added to replay.go — the override rides the existing
// replayer.dialUpstream field.
//
// It drives a real --passthrough replayer's forwardUpstream against the
// in-process TLS upstream and asserts STRUCTURALLY that (a) the dial branch ran
// (dialedUpstream==true), (b) the real handshake completed, (c) NO synthetic
// auth header/token survived onto the wire (the D50 scrub, proven against a real
// tls.Dial), and (d) a response was relayed back — never anything
// timing-derived.
func TestHermeticReplayPassthroughForwardUpstream(t *testing.T) {
	up := newHermeticTLSUpstream(t)

	// A passthrough replayer is the only configuration whose dispatcher would
	// reach forwardUpstream; constructing it the same way cmdReplay does keeps
	// the smoke faithful to the production wiring. No port is bound here (the
	// loopback side is an in-memory net.Pipe).
	rp, err := newReplayer(cassette.New(), true /*strict, overridden*/, true /*passthrough*/, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	if rp.strict {
		t.Fatal("passthrough must override strict before forwardUpstream is reachable")
	}
	if rp.dialedUpstream {
		t.Fatal("dialedUpstream must start false")
	}

	// Override the dialUpstream seam from the TEST side with a dialer that runs
	// the real tls.Dial + handshake against the in-process TLS upstream, wrapped
	// in a capturingConn so the same D50 no-leak assertion runs against the bytes
	// forwardUpstream actually writes on a real TLS conn.
	hermeticDial := up.dialer()
	var captured *capturingConn
	var captureMu sync.Mutex
	rp.dialUpstream = func(host string) (net.Conn, error) {
		c, derr := hermeticDial(host)
		if derr != nil {
			return nil, derr
		}
		captureMu.Lock()
		captured = &capturingConn{Conn: c}
		cc := captured
		captureMu.Unlock()
		return cc, nil
	}

	// The loopback (client-facing) side of forwardUpstream is an in-memory pipe —
	// NO port is bound, so this cannot collide with :18080 or any port. A
	// goroutine drains whatever the relay writes back so forwardUpstream never
	// blocks on the write.
	clientConn, gatewayConn := net.Pipe()
	defer clientConn.Close()
	defer gatewayConn.Close()

	relayed := make(chan *http.Response, 1)
	relayErr := make(chan error, 1)
	go func() {
		resp, rerr := http.ReadResponse(bufio.NewReader(clientConn), nil)
		if rerr != nil {
			relayErr <- rerr
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		relayed <- resp
	}()

	// A benign GET — NEVER a /v1/messages POST that could spend. forwardUpstream
	// dials the in-process upstream over real TLS, completing the handshake on the
	// production path. Synthetic Bearer-shaped auth headers make the no-leak
	// assertion non-vacuous against the real wire: forwardUpstream must strip them.
	req, err := http.NewRequest(http.MethodGet, "https://"+up.serverName+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = up.serverName
	for k, v := range syntheticBearerHeaders() {
		req.Header.Set(k, v)
	}

	rp.forwardUpstream(gatewayConn, up.serverName, req)
	_ = gatewayConn.Close()

	// (a) The upstream dial branch was taken — the previously un-exercised
	// production dial ran (hermetically).
	rp.mu.Lock()
	dialed := rp.dialedUpstream
	rp.mu.Unlock()
	if !dialed {
		t.Fatal("forwardUpstream did not record an upstream dial — the production dial branch was not exercised")
	}

	// (b) The real TLS handshake completed on the production dial path.
	captureMu.Lock()
	cc := captured
	captureMu.Unlock()
	if cc == nil {
		t.Fatal("upstream dial was not captured — cannot assert the handshake/no-leak wall")
	}
	if tlsConn, ok := cc.Conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if !state.HandshakeComplete {
			t.Error("TLS handshake did not complete on the production passthrough dial path")
		}
		if state.Version < tls.VersionTLS12 {
			t.Errorf("negotiated TLS version %#x is below the TLS 1.2 floor", state.Version)
		}
	} else {
		t.Fatalf("captured upstream conn is %T, want *tls.Conn (the production dial shape)", cc.Conn)
	}

	// (c) D50: no auth/volatile header or Bearer-shaped token survived onto the
	// real TLS wire — the same wall the offline test asserts, proven here against
	// the production tls.Dial.
	assertNoAuthOnWire(t, cc.written())

	// (d) A response was relayed back over the loopback conn.
	select {
	case err := <-relayErr:
		t.Fatalf("no response relayed from the hermetic passthrough dial: %v", err)
	case resp := <-relayed:
		if resp.StatusCode == 0 {
			t.Error("relayed response carried no status code")
		}
		if resp.ProtoMajor != 1 {
			t.Errorf("relayed response not HTTP/1.x: proto major %d", resp.ProtoMajor)
		}
	}
}

// TestHermeticRecordReplayRoundTrip is the CAPTURE-TOOL-DESIGN.md §5 step-0
// round-trip, run HERMETICALLY and UNGATED: the REAL recorder records a benign
// SYNTHETIC /v1/messages exchange against the in-process TLS upstream (driving
// recorder.upstreamDial — defaulted to the production dial — overridden to the
// real tls.Dial against the httptest server), the produced cassette is saved to
// disk and reloaded, and a STRICT replayer serves it back. It asserts the replay
// is served FROM THE CASSETTE with replayer.dialedUpstream == FALSE — a full
// record→replay round-trip with zero /v1/messages spend and zero egress (D50).
func TestHermeticRecordReplayRoundTrip(t *testing.T) {
	up := newHermeticTLSUpstreamSSE(t)

	// --- RECORD leg: real recorder + real proxy, hermetic TLS upstream ---------
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	// Override the production dial seam with the real tls.Dial against the
	// in-process TLS upstream (no production seam added to record.go).
	rec.upstreamDial = up.dialer()
	rsrv, raddr, err := rec.listen("127.0.0.1", 0) // :0 ephemeral, never :18080
	if err != nil {
		t.Fatalf("recorder listen: %v", err)
	}
	go func() { _ = rsrv.Serve(rec.ln) }()

	reqBody := `{"model":"claude-synthetic-test-1","system":"synthetic system","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	client := proxyClient(t, raddr, rec.caCertPath)
	req, _ := http.NewRequest(http.MethodPost, "https://"+anthropicHost+cassette.MessagesPath, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Synthetic auth headers a real CC client would carry — the recorder strips
	// these before the cassette. Values are obviously-synthetic.
	req.Header.Set("Authorization", "Bearer synthetic-fake-token")
	req.Header.Set("x-api-key", "synthetic-fake-key")

	resp, err := client.Do(req)
	if err != nil {
		_ = rsrv.Close()
		rec.cleanup()
		t.Fatalf("record request through hermetic TLS upstream: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(gotBody) != roundTripSSE {
		t.Errorf("recorded client SSE mismatch:\n got=%q\nwant=%q", gotBody, roundTripSSE)
	}

	// The recorder must have teed exactly one complete turn into the cassette.
	rec.mu.Lock()
	n := rec.cassette.Len()
	rec.mu.Unlock()
	if n != 1 {
		_ = rsrv.Close()
		rec.cleanup()
		t.Fatalf("expected 1 recorded interaction, got %d", n)
	}

	// Persist the cassette to disk (real Save) and tear the recorder down.
	cassettePath := filepath.Join(t.TempDir(), "roundtrip-synthetic.json")
	if err := rec.cassette.Save(cassettePath); err != nil {
		_ = rsrv.Close()
		rec.cleanup()
		t.Fatalf("save cassette: %v", err)
	}
	_ = rsrv.Close()
	rec.cleanup()

	// --- REPLAY leg: reload from disk, strict, assert no dial -------------------
	cas, err := cassette.Load(cassettePath)
	if err != nil {
		t.Fatalf("reload cassette: %v", err)
	}
	rp, err := newReplayer(cas, true /*strict*/, false /*passthrough*/, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	psrv, paddr, err := rp.listen("127.0.0.1", 0) // :0 ephemeral, never :18080
	if err != nil {
		t.Fatalf("replayer listen: %v", err)
	}
	go func() { _ = psrv.Serve(rp.ln) }()
	defer psrv.Close()

	rclient := proxyClient(t, paddr, rp.caCertPath)
	rreq, _ := http.NewRequest(http.MethodPost, "https://"+anthropicHost+cassette.MessagesPath, strings.NewReader(reqBody))
	rresp, err := rclient.Do(rreq)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	rbody, _ := io.ReadAll(rresp.Body)
	_ = rresp.Body.Close()

	// The replay was served FROM THE CASSETTE: same synthetic SSE, 200, and —
	// the core round-trip assertion — the strict replayer NEVER dialed upstream.
	if rresp.StatusCode != http.StatusOK {
		t.Errorf("round-trip replay status: got %d want 200", rresp.StatusCode)
	}
	if string(rbody) != roundTripSSE {
		t.Errorf("round-trip replayed SSE mismatch:\n got=%q\nwant=%q", rbody, roundTripSSE)
	}
	rp.mu.Lock()
	dialed := rp.dialedUpstream
	rp.mu.Unlock()
	if dialed {
		t.Fatal("round-trip replay dialed upstream — the hermetic guarantee (dialedUpstream==false) was broken")
	}
}

// TestExternalReplayPassthroughForwardUpstream exercises the REAL
// replayer.forwardUpstream production path (replay.go: tls.Dial to host:443, the
// --passthrough escape hatch) against a GENUINELY-EXTERNAL public TLS host. It
// is the retained, narrower opt-in leg — SKIPPED unless DS_E2E_LIVE_EXTERNAL=1 —
// so the default suite stays hermetic (zero-egress, cred-free, D50). The
// hermetic passthrough test above already covers this dial branch zero-egress in
// the ungated run; this leg only adds genuine-internet reachability for an
// operator who explicitly asks for it.
//
// Under the gate it drives a passthrough replayer's forwardUpstream against a
// well-known public TLS host (NOT api.anthropic.com, NO /v1/messages POST) and
// asserts STRUCTURALLY that (a) the replayer recorded that it dialed upstream,
// (b) no synthetic auth survived onto the real wire, and (c) a real upstream
// response was relayed back — never anything timing-derived.
func TestExternalReplayPassthroughForwardUpstream(t *testing.T) {
	if os.Getenv("DS_E2E_LIVE_EXTERNAL") != "1" {
		t.Skip("external passthrough-forward handshake is DS_E2E_LIVE_EXTERNAL-gated (deferred manual step; the hermetic passthrough test covers this path zero-egress in the default run — D50)")
	}

	rp, err := newReplayer(cassette.New(), true /*strict, overridden*/, true /*passthrough*/, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	if rp.strict {
		t.Fatal("passthrough must override strict before forwardUpstream is reachable")
	}
	if rp.dialedUpstream {
		t.Fatal("dialedUpstream must start false")
	}

	// Wrap the production upstream dial so the same D50 no-leak assertion runs
	// against the REAL external wire: capturingConn tees every byte the gateway
	// writes upstream (the scrubbed request) without altering the dial itself.
	realDial := rp.dialUpstream
	var captured *capturingConn
	rp.dialUpstream = func(host string) (net.Conn, error) {
		c, derr := realDial(host)
		if derr != nil {
			return nil, derr
		}
		captured = &capturingConn{Conn: c}
		return captured, nil
	}

	clientConn, gatewayConn := net.Pipe()
	defer clientConn.Close()
	defer gatewayConn.Close()

	relayed := make(chan *http.Response, 1)
	relayErr := make(chan error, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
		if err != nil {
			relayErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		relayed <- resp
	}()

	req, err := http.NewRequest(http.MethodGet, "https://"+externalDialHost+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = externalDialHost
	for k, v := range syntheticBearerHeaders() {
		req.Header.Set(k, v)
	}

	rp.forwardUpstream(gatewayConn, externalDialHost, req)
	_ = gatewayConn.Close()

	rp.mu.Lock()
	dialed := rp.dialedUpstream
	rp.mu.Unlock()
	if !dialed {
		t.Fatal("forwardUpstream did not record an upstream dial — the production dial branch was not exercised")
	}

	if captured == nil {
		t.Fatal("upstream dial was not captured — cannot assert the no-leak wall on the live wire")
	}
	assertNoAuthOnWire(t, captured.written())

	select {
	case err := <-relayErr:
		t.Fatalf("no response relayed from the live passthrough dial: %v", err)
	case resp := <-relayed:
		if resp.StatusCode == 0 {
			t.Error("relayed response carried no status code")
		}
		if resp.ProtoMajor != 1 {
			t.Errorf("relayed response not HTTP/1.x: proto major %d", resp.ProtoMajor)
		}
	}
}
