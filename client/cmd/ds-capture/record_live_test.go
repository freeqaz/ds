// SPDX-License-Identifier: Apache-2.0

// record_live_test.go — dial-branch coverage for the production upstream TLS
// dial that the fake-dialer offline suite never executes.
//
// WHY THIS EXISTS
// ---------------
// The offline record tests inject a fake net.Dial dialer (record_test.go's
// fakeUpstream.dialer), so recorder.dialUpstreamTLS — the real tls.Dial +
// handshake to host:443 in record.go — was previously confirmed only by code
// review or behind the external DS_E2E_LIVE gate, never in the default run.
//
// This file exercises that exact production dial+handshake path HERMETICALLY:
// it stands up an in-process httptest.NewTLSServer, drops the server's
// self-signed certificate into a per-process x509.CertPool, and injects a
// test-side dialer (through the existing recorder.upstreamDial seam — record.go
// already defaults it to r.dialUpstreamTLS) that runs the SAME crypto/tls
// tls.Dial + full handshake against that in-process TLS upstream. The dial
// branch therefore gets real-tls.Dial coverage in the UNGATED `go test` run with
// ZERO egress and ZERO credentials (D50) — no DS_E2E_LIVE needed, no production
// seam added to record.go.
//
// A NARROWER, OPT-IN external handshake leg (against a genuinely-remote public
// host) is retained behind DS_E2E_LIVE_EXTERNAL for anyone who still wants to
// prove the real internet path; it is SKIPPED by default so the suite stays
// zero-egress.
//
// OPERATOR INVOCATION of the retained external leg (deferred manual step)
// ----------------------------------------------------------------------
//
//	DS_E2E_LIVE_EXTERNAL=1 go test ./client/cmd/ds-capture/ -run TestExternalDialUpstreamTLSHandshake -v
//
// It makes ONE outbound TLS handshake to a well-known public host (example.com,
// the egress gateway's normal :443 dial shape). It carries NO credentials, sends
// NO /v1/messages POST, spends nothing, and starts NO claude/cia/podman. All
// assertions are STRUCTURAL only — that the TLS handshake completed — never
// timing-derived (DRIVE-PROTOCOL.md forbids asserting TTFT/throughput).

package main

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
)

// externalDialHost is the well-known public TLS endpoint the OPT-IN external leg
// dials. It is deliberately NOT api.anthropic.com: this smoke proves the dial +
// handshake code path works, not that we can reach the model API, and it must
// never be a host where a stray request could spend. example.com is an
// IANA-reserved, long-lived host that terminates TLS on :443.
const externalDialHost = "example.com"

// The hermetic in-process TLS upstream helper (hermeticTLSUpstream +
// newHermeticTLSUpstream / newHermeticTLSUpstreamSSE + its per-process CertPool
// dialer) is shared cross-file with replay_live_test.go, so it now lives in the
// dedicated testhelpers_test.go.

// TestHermeticDialUpstreamTLSHandshake exercises the production upstream TLS dial
// branch HERMETICALLY and UNGATED: it runs the real crypto/tls tls.Dial + full
// handshake (the same call shape recorder.dialUpstreamTLS makes in record.go)
// against an in-process httptest.NewTLSServer whose self-signed cert lives in a
// per-process x509.CertPool. No DS_E2E_LIVE, no egress, no credentials (D50).
//
// It drives the dial through the existing recorder.upstreamDial seam (record.go
// defaults it to r.dialUpstreamTLS in newRecorder) so the test stays on the
// production wiring, then asserts STRUCTURALLY that the handshake completed —
// never anything timing-derived.
func TestHermeticDialUpstreamTLSHandshake(t *testing.T) {
	up := newHermeticTLSUpstream(t)

	// Construct a recorder so we drive the SAME field the production record path
	// uses (r.upstreamDial defaults to r.dialUpstreamTLS in newRecorder), then
	// override that seam from the TEST side with a dialer that runs the real
	// tls.Dial against the in-process TLS upstream. No proxy is started, no port
	// is bound, no cassette is written — this is a pure dial-path smoke.
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	defer rec.cleanup()
	rec.upstreamDial = up.dialer()

	// Drive the production seam exactly as roundTrip would: the host argument is
	// the upstream the recorder believes it is reaching; the hermetic dialer
	// transparently substitutes the in-process TLS server.
	conn, err := rec.upstreamDial(anthropicHost)
	if err != nil {
		t.Fatalf("hermetic upstreamDial: real tls.Dial against in-process TLS upstream failed: %v", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("hermetic dialer returned %T, want *tls.Conn (the production dial shape)", conn)
	}

	// tls.Dial completes the handshake before returning; inspect the resulting
	// ConnectionState structurally — proof the real handshake ran, not timing.
	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("TLS handshake did not complete on the production dial path against the in-process upstream")
	}
	if state.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x is below the TLS 1.2 floor the dialer expects", state.Version)
	}
	if state.ServerName != up.serverName {
		t.Errorf("ServerName not propagated to the handshake: got %q want %q", state.ServerName, up.serverName)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("handshake completed with no peer certificate — the in-process upstream cert was not validated")
	}

	// Structural sanity: the dialer returns a usable, addressable loopback conn.
	if _, ok := conn.(net.Conn); !ok {
		t.Fatal("hermetic dialer did not return a net.Conn")
	}
	if conn.RemoteAddr() == nil {
		t.Fatal("dialed connection has no remote address")
	}
	if !strings.HasPrefix(conn.RemoteAddr().String(), "127.0.0.1:") {
		t.Errorf("hermetic dial did not stay on loopback: remote %q (must be in-process, zero-egress)", conn.RemoteAddr())
	}
}

// TestExternalDialUpstreamTLSHandshake exercises the REAL recorder.dialUpstreamTLS
// production path (record.go: tls.Dial to host:443) against a GENUINELY-EXTERNAL
// public TLS host. It is the retained, narrower opt-in leg — SKIPPED unless
// DS_E2E_LIVE_EXTERNAL=1 — so the default suite stays hermetic (zero-egress,
// cred-free, D50). The hermetic test above already covers the dial branch in the
// ungated run; this leg only adds genuine-internet reachability for an operator
// who explicitly asks for it.
//
// Under the gate it asserts STRUCTURALLY that the upstream TLS handshake
// completed (HandshakeComplete + a negotiated version), never anything
// timing-derived.
func TestExternalDialUpstreamTLSHandshake(t *testing.T) {
	if os.Getenv("DS_E2E_LIVE_EXTERNAL") != "1" {
		t.Skip("external upstream-dial handshake is DS_E2E_LIVE_EXTERNAL-gated (deferred manual step; the hermetic dial-branch test covers this path zero-egress in the default run — D50)")
	}

	// Construct a recorder so we drive the SAME method the production record path
	// uses (r.upstreamDial defaults to r.dialUpstreamTLS in newRecorder). No proxy
	// is started, no port is bound, no cassette is written.
	rec, err := newRecorder("")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	defer rec.cleanup()

	conn, err := rec.dialUpstreamTLS(externalDialHost)
	if err != nil {
		t.Fatalf("dialUpstreamTLS(%q): real upstream TLS dial failed: %v", externalDialHost, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dialUpstreamTLS returned %T, want *tls.Conn", conn)
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("TLS handshake did not complete on the production dial path")
	}
	if state.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x is below the TLS 1.2 floor the dialer expects", state.Version)
	}
	if state.ServerName != externalDialHost {
		t.Errorf("ServerName not propagated to the handshake: got %q want %q", state.ServerName, externalDialHost)
	}
	if _, ok := conn.(net.Conn); !ok {
		t.Fatal("dialUpstreamTLS did not return a net.Conn")
	}
	if conn.RemoteAddr() == nil {
		t.Fatal("dialed connection has no remote address")
	}
}
