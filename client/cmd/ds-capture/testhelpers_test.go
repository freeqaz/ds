// SPDX-License-Identifier: Apache-2.0

// testhelpers_test.go — the shared hermetic in-process TLS upstream helper used
// by the ds-capture *_live_test.go legs.
//
// WHY THIS EXISTS
// ---------------
// The hermeticTLSUpstream helper (an in-process httptest.NewTLSServer plus the
// per-process x509.CertPool dialer that trusts its self-signed cert) is consumed
// cross-file: both record_live_test.go and replay_live_test.go stand one up to
// drive the production crypto/tls tls.Dial + handshake path HERMETICALLY (zero
// egress, zero credentials — D50). Defining it inside one *_live_test.go created
// an implicit *_test.go file-ordering coupling between the record and replay
// legs. Lifting it here lets each *_live_test.go stay focused on its own
// assertions while the shared upstream lives in one dedicated place.
//
// This file is a pure test fixture: stdlib only (httptest / crypto/tls /
// crypto/x509), offline, ephemeral loopback ports (NEVER :18080), synthetic
// payloads only, and it never logs a secret. No live claude/cia/podman/network
// is involved.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hermeticTLSUpstream is an in-process httptest.NewTLSServer standing in for the
// real upstream so the production tls.Dial + handshake path runs HERMETICALLY.
// It mints its own self-signed cert; dialer() hands back a test-side dialer that
// trusts that cert via a per-process x509.CertPool and dials the server's real
// loopback address over crypto/tls — the identical production handshake, with
// zero egress (D50). No live claude/cia/podman/network is involved.
//
// serverName is the SNI the dialer presents — taken from the in-process cert's
// own SAN so the handshake validates against the per-process pool. It is a
// synthetic httptest cert name (NOT api.anthropic.com, NOT a routable host we
// reach), so nothing about this fixture implies a real endpoint or any egress.
type hermeticTLSUpstream struct {
	srv        *httptest.Server
	pool       *x509.CertPool
	addr       string
	serverName string
}

// certServerName returns a DNS SAN the in-process cert is valid for, so the
// dialer's ServerName validates against the per-process pool. httptest mints its
// cert with at least one DNS SAN; falling back to the CommonName keeps this
// robust if the SAN list is ever empty.
func certServerName(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.CommonName
}

// newHermeticTLSUpstream stands up the in-process TLS server and builds the
// per-process trust pool from its leaf certificate. The handler replies with a
// benign, synthetic HTTP/1.1 200 for any request — enough for a dial+handshake
// (and an optional round-trip read) without any /v1/messages spend.
func newHermeticTLSUpstream(t *testing.T) *hermeticTLSUpstream {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok-synthetic")
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &hermeticTLSUpstream{
		srv:        srv,
		pool:       pool,
		addr:       strings.TrimPrefix(srv.URL, "https://"),
		serverName: certServerName(srv.Certificate()),
	}
}

// dialer returns an upstreamDial that drives the SAME crypto/tls tls.Dial + full
// handshake the production dialUpstreamTLS uses, but pointed at the in-process
// httptest TLS server and trusting only the per-process pool. The requested host
// is ignored (the in-process upstream stands in for any host); ServerName is the
// minted cert's name so the handshake validates against the pool. This is the
// production dial path exercised hermetically — no production seam is added; the
// override rides the existing recorder.upstreamDial / replayer.dialUpstream field.
func (h *hermeticTLSUpstream) dialer() func(string) (net.Conn, error) {
	return func(_ string) (net.Conn, error) {
		return tls.Dial("tcp", h.addr, &tls.Config{
			RootCAs:    h.pool,
			ServerName: h.serverName,
			MinVersion: tls.VersionTLS12,
		})
	}
}

// roundTripSSE is the benign, synthetic /v1/messages SSE turn the hermetic
// record→replay round-trip records and replays. It is a COMPLETE turn (carries a
// terminal message_stop) so recordMessages persists it; values are obviously
// synthetic (no real ids/models/text/costs).
const roundTripSSE = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_SYNTHETIC_RT\",\"model\":\"claude-synthetic-test-1\",\"role\":\"assistant\"}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"round-trip synthetic text\"}}\n\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

// newHermeticTLSUpstreamSSE is the SSE-emitting variant of the hermetic in-process
// TLS upstream used by the record→replay round-trip: it replies to a
// /v1/messages POST with the complete synthetic SSE turn (roundTripSSE) over
// text/event-stream so the real recorder tees a full turn into the cassette. Its
// dialer() runs the SAME real tls.Dial + handshake against the in-process server
// trusted via a per-process x509.CertPool — zero egress (D50). No live
// claude/cia/podman/network is involved.
func newHermeticTLSUpstreamSSE(t *testing.T) *hermeticTLSUpstream {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, roundTripSSE)
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &hermeticTLSUpstream{
		srv:        srv,
		pool:       pool,
		addr:       strings.TrimPrefix(srv.URL, "https://"),
		serverName: certServerName(srv.Certificate()),
	}
}
