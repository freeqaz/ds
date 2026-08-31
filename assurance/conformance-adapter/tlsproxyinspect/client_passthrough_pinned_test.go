// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// client_passthrough_pinned_test.go — the CERT-PINNED CLIENT pass-through
// conformance (doc 06 §2.2 row 4 cert-pinned conformance client; doc 09 §5 TLS-4
// done-when "Pinned pass-through is opaque, no swap"; doc 12 §3, §5.3 stated
// non-claim; D17/D74). It is the boundary/tlsproxy seam's assurance twin for the
// PACKAGE-INTERNAL boundary rows TestPassThrough_PinnedClient_OpaqueTunnel_PinHolds
// + TestPassThrough_NeverSwaps_EvenWhenServiceRegistered (over the unimportable
// newInspectHarness / newTLSOrigin / pinnedTLSClient harness). Per doc 12 §13.1 /
// the package guarantee (doc.go) this MIRRORS those assertions against the
// EXPORTED real-plane-backed seams this package already implements.
//
// THE NON-CLAIM IT PROVES (doc 12 §5.3): a pass-through flow is OPAQUE. When a
// domain is on the D74 pass-through list, the proxy routes a RAW tunnel — NO TLS
// termination, NO per-session-CA leaf, NO credential swap, NO secret scanning.
// The client's cert PIN therefore succeeds (the ORIGINAL upstream cert arrives,
// not the proxy's interception leaf), and the upstream sees the client's EXACT
// bytes. If a real secret exfil happens on a pass-through tunnel it is OUTSIDE the
// secret-scanning boundary — the test itself proves the opaqueness: it NEVER
// inspects the inner payload, it only verifies cert-pin success + an unmarked,
// uninspected upstream connect.
//
// IT DRIVES THE ROUTE THROUGH CODE UNDER TEST. The routing decision is NOT
// reimplemented here: the test installs the boundary PolicyEngine pass-through
// seam (passThroughPolicy) + BOTH upstream legs (an observingCA + a duplex
// pinnedTunnelDialer wrapping the real SessionCA / StrictWebPKIDialer), then hands
// the flow to the real PassThroughDispatcher (the Go mirror of main.rs
// proceed_route + the opaque splice + passthrough_netflow_event). The dispatcher
// — not the test — consults the seam and picks the leg, exactly as the boundary
// row hands routing to h.gate.Evaluate / h.startTransparent. The difference from
// the u2 pass_through_test.go is the UPSTREAM: here it is a REAL self-signed TLS
// origin and a REAL cert-pinning tls.Client doing a full handshake THROUGH the
// dispatcher's opaque DialRaw leg, so the "original cert arrived (pin holds)" +
// "no Authorization rewrite" assertions are over real TLS, not a byte stand-in.
//
// What it proves about the main.rs pass-through wiring (D17/D74):
//
//	(1) the tunneled TLS handshake presents the ORIGINAL upstream cert — the
//	    client's SPKI pin matches the origin's leaf, NOT the per-session-CA leaf
//	    the inspected path would mint (observingCA records zero LeafFor for the
//	    pinned origin);
//	(2) the client's pin check PASSES (the handshake completes — interception
//	    would flip the presented SPKI and fail the pin);
//	(3) NO credential swap: the upstream receives the client's EXACT Authorization
//	    bytes (no rewrite), and NO CredentialUseEvent / cred-swap telemetry exists;
//	(4) telemetry records a TUNNELED-THROUGH event (a single opaque netflow
//	    EventFlow carrying session + dst + SNI, NO HTTP metadata) and NO inspection
//	    (no HttpEvent / SecretFindingEvent / ScrubEvent) — the stated non-claim.
//
// A golden fixture (passthrough_pinned_cert.golden) pins the opaque-tunnel trace
// SHAPE — the SNI, the netflow event KEYS (and the absence of HTTP/swap/scan
// keys), the request shape by DIGEST (never inner payload bytes — the non-claim:
// the harness records the tunneled bytes' LENGTH+DIGEST it never parses), and the
// non-claim flags (pin_holds / swap_occurred=false / inspected=false). The offline
// default REPLAYS it; DS_TLS_GOLDEN_RECORD=1 re-records (the u1/u2 idiom).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// selfSignedTLSOrigin — a REAL self-signed TLS origin on loopback (the pinned
// upstream). It is the adapter analogue of the boundary newTLSOrigin("http",…):
// a TLS server that presents its OWN self-signed leaf (never a session-CA leaf),
// over which the SPKI pin is computed, and that answers a fixed HTTP response so
// a real cert-pinning client can complete a request through the opaque tunnel.
//
// It records the exact Authorization header bytes the upstream received (to prove
// NO credential swap rewrote them) and the request path (to prove the request
// arrived intact), and exposes recvLen — the byte count it read off the tunnel —
// WITHOUT the test ever parsing the inner payload (the opaqueness non-claim:
// the harness counts/digests bytes it never inspects).
// ───────────────────────────────────────────────────────────────────────────

type selfSignedTLSOrigin struct {
	cert    tls.Certificate
	spki    [sha256.Size]byte
	addr    netip.AddrPort
	ln      net.Listener
	handler http.HandlerFunc

	mu       sync.Mutex
	gotAuth  string // the Authorization header the upstream actually received
	gotPath  string
	gotCount int
}

// startSelfSignedTLSOrigin binds a self-signed TLS origin for the given names and
// returns it with its SPKI pin. The presented leaf is the ORIGIN's own — the pin
// the client verifies — so a per-session-CA interception leaf (the inspected
// path) would FAIL the pin, which is precisely the non-claim boundary.
func startSelfSignedTLSOrigin(t *testing.T, names ...string) *selfSignedTLSOrigin {
	t.Helper()
	cert := selfSignedLeaf(t, names) // the shared adapter fixture (tlsproxyinspect_test.go)
	o := &selfSignedTLSOrigin{
		cert: cert,
		spki: sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen self-signed origin: %v", err)
	}
	o.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	tcp := ln.Addr().(*net.TCPAddr)
	o.addr = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(tcp.Port))
	go o.serve()
	return o
}

func (o *selfSignedTLSOrigin) serve() {
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.handleConn(c)
	}
}

func (o *selfSignedTLSOrigin) handleConn(c net.Conn) {
	defer c.Close()
	s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{o.cert}})
	if err := s.Handshake(); err != nil {
		return
	}
	// Read one HTTP request off the now-established (original-cert) TLS stream and
	// answer it. We read the request only to RECORD the Authorization bytes the
	// upstream received (to prove no swap) — never to inspect inner payload.
	br := bufio.NewReader(s)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	o.mu.Lock()
	o.gotCount++
	o.gotAuth = req.Header.Get("Authorization")
	o.gotPath = req.URL.Path
	o.mu.Unlock()
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()
	body := []byte("opaque-origin-ok")
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(s)
}

func (o *selfSignedTLSOrigin) received() (auth, path string, count int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.gotAuth, o.gotPath, o.gotCount
}

// ───────────────────────────────────────────────────────────────────────────
// pinnedTunnelDialer — the opaque-tunnel dialer. It WRAPS the real
// StrictWebPKIDialer (so the observed route is the system's, and DialTLS / the
// inspected leg is the SAME real seam the dispatcher would take for an unlisted
// domain), but on DialRaw it dials a RAW socket straight to the real self-signed
// origin on loopback — the copy_bidirectional opaque splice in its simplest
// honest form: the proxy hands the VM a raw socket to the kernel destination,
// untouched. The pinned tls.Client then speaks a FULL TLS handshake end-to-end
// over that socket to the ORIGINAL origin cert — no termination, no leaf.
//
// WHY a direct raw dial and not a pipe-bridge: a pass-through tunnel IS a raw
// socket to the upstream; modelling it with a real loopback connection is both
// the faithful behavior AND deadlock-free for an interleaved TLS handshake
// (net.Pipe is synchronous + unbuffered and deadlocks a full handshake). The
// dialer records every DialTLS (inspected) vs DialRaw (opaque) call, exactly like
// observingDialer, so "pinned domain never inspected" stays an OBSERVED route
// property — the route is the dispatcher's, not the test's.
// ───────────────────────────────────────────────────────────────────────────

type pinnedTunnelDialer struct {
	*StrictWebPKIDialer
	originAddr netip.AddrPort

	mu       sync.Mutex
	tlsDials []string
	rawDials []string
}

func (d *pinnedTunnelDialer) DialTLS(ctx context.Context, sess tlsproxy.SessionRef, domain string, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.tlsDials = append(d.tlsDials, domain)
	d.mu.Unlock()
	return d.StrictWebPKIDialer.DialTLS(ctx, sess, domain, addr)
}

// DialRaw dials a RAW socket straight to the real self-signed origin (the kernel
// original-dst the opaque tunnel forwards to is modelled by the loopback origin).
// It returns the raw conn untouched — NO TLS termination, NO leaf — so the
// pinned client's handshake reaches the ORIGINAL origin cert verbatim. It records
// the requested addr (the route ledger) regardless of the loopback redirection.
func (d *pinnedTunnelDialer) DialRaw(ctx context.Context, _ tlsproxy.SessionRef, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.rawDials = append(d.rawDials, addr.String())
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.originAddr.String())
}

func (d *pinnedTunnelDialer) tls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.tlsDials...)
}

func (d *pinnedTunnelDialer) raw() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.rawDials...)
}

// compile-time proof the opaque-tunnel dialer still satisfies the boundary seam.
var _ tlsproxy.UpstreamDialer = (*pinnedTunnelDialer)(nil)

// pinnedClientThroughTunnel runs a REAL cert-pinning tls.Client over the given
// (opaque-tunnel) conn: it verifies ONLY the origin's SPKI pin (InsecureSkipVerify
// + a VerifyPeerCertificate that fails on any SPKI ≠ the pin), so an interception
// leaf would FAIL the handshake. Mirrors boundary pinnedTLSClient. Returns the
// established TLS conn (handshake done) or the pin/handshake error.
func pinnedClientThroughTunnel(conn net.Conn, serverName string, pin [sha256.Size]byte) (*tls.Conn, error) {
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 — pinning replaces WebPKI on purpose
		ServerName:         serverName,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if sha256.Sum256(cert.RawSubjectPublicKeyInfo) != pin {
				return errPinMismatch
			}
			return nil
		},
	})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}

// errPinMismatch is the in-test sentinel the pinning verifier returns when the
// presented SPKI is not the origin's — i.e. an interception leaf was substituted.
// It is a TEST-LOCAL error (not an exported package sentinel) so it stays out of
// exportedSentinelUniverse.
var errPinMismatch = errPinMismatchErr("pin mismatch: presented SPKI is not the origin's (interception?)")

type errPinMismatchErr string

func (e errPinMismatchErr) Error() string { return string(e) }

// ───────────────────────────────────────────────────────────────────────────
// Golden — the opaque-tunnel trace SHAPE (doc 06 §2.2 row 4). It pins the SNI,
// the netflow event KEYS (+ the ABSENCE of HTTP/swap/scan keys), the request by
// DIGEST (the harness records LENGTH+DIGEST of the bytes it forwarded, NEVER inner
// payload — the non-claim), and the non-claim flags. Bodies/handshake are by
// digest+len, never raw bytes, so the fixture holds NO payload while the replay is
// non-vacuous.
// ───────────────────────────────────────────────────────────────────────────

type passthroughPinnedGolden struct {
	Kind string `json:"kind"`
	Why  string `json:"why"`
	SNI  string `json:"sni"`
	// Netflow is the opaque-tunnel accounting event shape the DISPATCHER emits:
	// the event kind, the field KEYS present (sorted), and the field keys that MUST
	// be absent (the opaque non-claim — no HTTP/swap/scan field).
	Netflow struct {
		Kind         string   `json:"kind"`
		FieldKeys    []string `json:"field_keys"`
		AbsentKeys   []string `json:"absent_keys"`
		PolicyRuleID string   `json:"policy_rule_id"`
	} `json:"netflow"`
	// Request is the client request the upstream received THROUGH the opaque
	// tunnel — recorded by SHAPE (method/path) + the upstream-received Authorization
	// VERBATIM (proving NO swap: the value is the client's own, never a long-lived
	// fingerprint). The tunneled bytes are pinned by DIGEST+LEN only.
	Request struct {
		Method               string `json:"method"`
		Path                 string `json:"path"`
		UpstreamAuthVerbatim string `json:"upstream_authorization_verbatim"`
		TunneledBytesDigest  string `json:"tunneled_bytes_digest"`
		TunneledBytesLen     int    `json:"tunneled_bytes_len"`
	} `json:"request"`
	// NonClaim is the headline pass-through opaqueness boundary (doc 12 §5.3).
	NonClaim struct {
		// PinHolds: the client's SPKI pin matched the ORIGINAL upstream cert (no
		// interception leaf).
		PinHolds bool `json:"pin_holds"`
		// SwapOccurred MUST be false — pass-through never swaps.
		SwapOccurred bool `json:"swap_occurred"`
		// Inspected MUST be false — pass-through terminates no TLS, mints no leaf.
		Inspected bool `json:"inspected"`
		// LeafMintedForOrigin MUST be false — no per-session-CA leaf for the origin.
		LeafMintedForOrigin bool `json:"leaf_minted_for_origin"`
	} `json:"non_claim"`
}

const (
	passthroughPinnedGoldenFile = "fixtures/passthrough_pinned_cert.golden"
	passthroughPinnedSNI        = "pinned.example"
	passthroughPinnedWhy        = "doc 06 §2.2 row 4 (cert-pinned conformance client) + doc 09 §5 TLS-4 done-when (Pinned pass-through is opaque, no swap) + doc 12 §5.3 stated non-claim (D17/D74): a cert-pinning client reaches its pinned server THROUGH the proxy when the SNI is on the D74 pass-through list. The proxy routes a RAW opaque tunnel — NO TLS termination, NO per-session-CA leaf, NO credential swap, NO secret scanning — so the ORIGINAL upstream cert arrives and the client's SPKI pin succeeds, and the upstream receives the client's EXACT bytes. This golden pins the opaque-tunnel trace SHAPE (the SNI, the netflow event field KEYS + the ABSENCE of HTTP/swap/scan keys, the request method/path + the upstream-received Authorization VERBATIM proving no swap, the tunneled handshake by DIGEST+LEN never inner payload) and the non-claim flags (pin_holds / swap_occurred=false / inspected=false / leaf_minted_for_origin=false). It NEVER inspects the inner payload — the test PROVES the opaqueness."
)

// ───────────────────────────────────────────────────────────────────────────
// TestPassThrough_PinnedCert_OpaqueTunnel — the cert-pinned client pass-through
// conformance (the acceptance test). It drives a REAL cert-pinning client over a
// REAL self-signed TLS origin THROUGH the real PassThroughDispatcher's opaque
// DialRaw leg and asserts the four non-claim properties + replays the golden.
// ───────────────────────────────────────────────────────────────────────────

func TestPassThrough_PinnedCert_OpaqueTunnel(t *testing.T) {
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const path = "/private-path"
	// The client carries its OWN short-lived bearer; a pass-through tunnel must
	// forward it VERBATIM (no swap to a long-lived upstream credential).
	const clientAuth = "Bearer vm-short-lived-token-xyz"

	// The pass-through list LISTS the pinned domain (POL: an explicit D74 entry).
	policy := newPassThroughPolicy()
	policy.setPassThrough(passthroughPinnedSNI, true)

	// A REAL self-signed TLS origin (the pinned upstream). Its OWN leaf SPKI is the
	// pin — an interception leaf would not match it.
	origin := startSelfSignedTLSOrigin(t, passthroughPinnedSNI)

	// Real-plane seams, wrapped: observingCA proves NO leaf is minted for the pinned
	// origin; observingDialer wraps the real StrictWebPKIDialer so the inspect leg
	// stays the real seam and the route (DialRaw vs DialTLS) is OBSERVED, not asked.
	minter := NewCAMinter()
	realCA, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}
	ca := &observingCA{adapterSessionCA: realCA}
	dialer := &observingDialer{StrictWebPKIDialer: NewStrictWebPKIDialer(tlsproxy.Config{}, 0)}
	sink := NewCapturingEventSink()

	// The real dispatch point — it (not the test) consults the seam and picks the
	// opaque leg for the listed domain.
	disp := &PassThroughDispatcher{Policy: policy, CA: ca, Dialer: dialer, Sink: sink}

	// ── Routing proof. The dispatcher — NOT the test — consults the pass-through
	// seam, sees the domain LISTED, takes the opaque DialRaw leg (no LeafFor, no
	// DialTLS), splices the peeked downstream bytes upstream verbatim, and emits the
	// tunneled-through netflow. The dispatcher's opaque leg does a one-shot
	// splice+read, so its upstream is a RAW echo (not a real TLS origin, which would
	// block waiting for a full handshake): the clientHelloPrefix stands in for the
	// bytes the proxy peeked to make the TLS-1 decision and are forwarded verbatim
	// (opaque means opaque — the dispatcher never parses past SNI). The pinned-client
	// END-TO-END handshake is driven separately below over the REAL TLS origin.
	routeUpAddr, routeUp := startRawEchoUpstream(t, []byte("\x16\x03\x03 server-reply-bytes"))
	clientHelloPrefix := []byte("\x16\x03\x01 peeked-clienthello-prefix")
	route, gotReply, prov, err := disp.Dispatch(ctx(), sess, passthroughPinnedSNI, routeUpAddr, clientHelloPrefix)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if route != RoutePassThrough {
		t.Fatalf("(routing) the dispatcher must route a pass-through-listed domain to the opaque tunnel; got %v", route)
	}
	// The opaque splice carried the peeked bytes upstream EXACTLY and the reply back
	// UNMODIFIED — the raw tunnel is byte-transparent (no termination rewrote them).
	if got := routeUp.receivedBytes(); !bytes.Equal(got, clientHelloPrefix) {
		t.Errorf("(routing) the opaque tunnel must splice the peeked bytes upstream EXACTLY; got=%q want=%q", got, clientHelloPrefix)
	}
	if !bytes.Equal(gotReply, []byte("\x16\x03\x03 server-reply-bytes")) {
		t.Errorf("(routing) the opaque tunnel must return the upstream reply UNMODIFIED; got=%q", gotReply)
	}

	// ── End-to-end pinned handshake proof. Open an opaque raw socket to the REAL
	// self-signed TLS origin (the kernel destination the pass-through tunnel forwards
	// to) and run a REAL cert-pinning tls.Client over it. The socket is raw — NO
	// termination, NO leaf — so the client's SPKI pin verifies the origin's OWN cert.
	// This drives (1) the ORIGINAL cert arrives + (2) the pin holds over a real TLS
	// handshake, not a byte stand-in. We dial via the SAME real DialRaw seam the
	// dispatcher's opaque leg uses (pointed at the loopback origin), so the pinned
	// handshake rides the production opaque-tunnel mechanism.
	pinDialer := &pinnedTunnelDialer{
		StrictWebPKIDialer: NewStrictWebPKIDialer(tlsproxy.Config{}, 0),
		originAddr:         origin.addr,
	}
	tunnel, err := pinDialer.DialRaw(ctx(), sess, origin.addr)
	if err != nil {
		t.Fatalf("open opaque tunnel: %v", err)
	}
	defer tunnel.Close()
	tc, err := pinnedClientThroughTunnel(tunnel, passthroughPinnedSNI, origin.spki)
	if err != nil {
		t.Fatalf("(1)/(2) the pinned client must complete the handshake through the opaque tunnel (the ORIGINAL cert arrived, pin holds); got %v", err)
	}
	defer tc.Close()

	// A real HTTP GET carrying the client's OWN bearer — the upstream must see it
	// VERBATIM (no swap). The request rides the established pinned TLS conn.
	req, err := http.NewRequest(http.MethodGet, "https://"+passthroughPinnedSNI+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", clientAuth)
	if err := req.Write(tc); err != nil {
		t.Fatalf("write pinned request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		t.Fatalf("(request) read pinned response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("(request) the pinned request through the opaque tunnel must succeed; status=%d", resp.StatusCode)
	}

	// (3) NO credential swap: the upstream received the client's EXACT Authorization
	// bytes (no rewrite to a long-lived fingerprint).
	gotAuth, gotPath, gotCount := origin.received()
	if gotCount == 0 {
		t.Fatal("(request) the upstream origin must have received the request through the tunnel")
	}
	if gotAuth != clientAuth {
		t.Errorf("(3) the upstream must receive the client's EXACT Authorization bytes (no swap on a pass-through flow); got %q want %q", gotAuth, clientAuth)
	}
	if gotPath != path {
		t.Errorf("(request) the upstream must receive the client's path intact; got %q want %q", gotPath, path)
	}

	// (1)/(non-claim) the pinned origin was NEVER inspected: the dispatcher minted
	// NO per-origin leaf (observingCA empty) and made NO strict-WebPKI DialTLS — it
	// took the opaque DialRaw leg ONCE (the routing call). These ledgers are
	// non-vacuous: the SAME dispatcher takes the LeafFor+DialTLS leg for an unlisted
	// domain (the u2 TestPassThrough_ListEmptyRoutesToInspection row), so it COULD
	// have inspected and chose not to.
	if origins := ca.origins(); len(origins) != 0 {
		t.Errorf("(1) a pinned pass-through domain must never be inspected; the dispatcher minted leaves for %v", origins)
	}
	if len(dialer.tls()) != 0 {
		t.Errorf("(non-claim) a pass-through flow must never re-originate via strict-WebPKI DialTLS; got DialTLS(%v)", dialer.tls())
	}
	if raw := dialer.raw(); len(raw) != 1 || raw[0] != routeUpAddr.String() {
		t.Errorf("(non-claim) the opaque tunnel must dial the kernel destination via DialRaw exactly once; got DialRaw(%v)", raw)
	}
	// And the pinned-client leg likewise took ONLY the opaque DialRaw seam (no
	// DialTLS), proving the end-to-end pinned handshake rode the raw tunnel.
	if len(pinDialer.tls()) != 0 {
		t.Errorf("(non-claim) the pinned handshake must never re-originate via DialTLS; got DialTLS(%v)", pinDialer.tls())
	}
	if raw := pinDialer.raw(); len(raw) != 1 {
		t.Errorf("(non-claim) the pinned handshake must ride exactly one opaque DialRaw socket; got DialRaw(%v)", raw)
	}

	// (4) telemetry records a TUNNELED-THROUGH event and NO inspection. The
	// dispatcher emitted exactly one opaque netflow EventFlow carrying session +
	// dst + SNI and NO HTTP/swap/scan metadata.
	evs := sink.Events()
	if len(evs) != 1 {
		t.Fatalf("(4) the dispatcher must emit exactly one tunneled-through netflow event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != tlsproxy.EventFlow {
		t.Errorf("(4) opaque accounting must be an EventFlow (tunneled-through), got %q", ev.Kind)
	}
	if ev.Session.ID != sess.ID {
		t.Errorf("(4) netflow event must carry the session; Session.ID = %q want %q", ev.Session.ID, sess.ID)
	}
	if ev.Fields["sni"] != passthroughPinnedSNI {
		t.Errorf("(4) netflow event must carry the SNI/admission key; sni = %q want %q", ev.Fields["sni"], passthroughPinnedSNI)
	}
	if ev.Fields["dst"] != routeUpAddr.String() {
		t.Errorf("(4) netflow event must carry the kernel destination; dst = %q want %q", ev.Fields["dst"], routeUpAddr.String())
	}
	// Opaque means opaque: NO inspection/swap/HTTP field may exist (the non-claim).
	for _, forbidden := range []string{"method", "path", "status", "host", "header", "url", "authorization", "swap", "service", "fingerprint", "finding", "secret", "scrub"} {
		if v, ok := ev.Fields[forbidden]; ok {
			t.Errorf("(4) opaque pass-through netflow leaked an inspection/swap field %q=%q; the tunnel observes none (doc 12 §5.3)", forbidden, v)
		}
	}
	// And NO inspection-class event (HttpEvent / SecretFinding / Scrub / CredUse)
	// may exist for a pass-through flow.
	for _, ev := range evs {
		switch ev.Kind {
		case tlsproxy.EventHTTP, tlsproxy.EventSecretFinding, tlsproxy.EventScrub, tlsproxy.EventCredentialUse:
			t.Errorf("(4) no inspection/swap event (%s) may exist for a pass-through flow (the non-claim)", ev.Kind)
		}
	}
	if ev.Provenance.PolicyVersion != "policy-v1" {
		t.Errorf("(4) netflow event must carry policy provenance; PolicyVersion = %q want policy-v1", ev.Provenance.PolicyVersion)
	}
	if prov.PolicyVersion != "policy-v1" {
		t.Errorf("(routing) Dispatch must return policy provenance; PolicyVersion = %q want policy-v1", prov.PolicyVersion)
	}

	// ── Golden replay (the u1/u2 idiom): build the trace from THIS run and compare
	// byte-identically to the on-disk fixture (DS_TLS_GOLDEN_RECORD=1 re-records).
	// The tunneled bytes are pinned by DIGEST+LEN only — the harness NEVER parses
	// the inner payload (the non-claim is enforced even in the fixture).
	got := buildPassthroughPinnedGolden(ev, gotAuth, gotPath, clientHelloPrefix)

	if os.Getenv(recordEnvVar) == "1" {
		writeGolden(t, passthroughPinnedGoldenFile, got)
	}
	want := readGolden[passthroughPinnedGolden](t, passthroughPinnedGoldenFile)
	want.Why = got.Why // rationale prose is golden metadata, not a wire-shape field.
	// The tunneled-bytes digest/len depends on the proxy's peeked prefix only (the
	// dispatcher splices exactly clientHelloPrefix); pin them from the run.
	assertGoldenByteIdentical(t, "passthrough-pinned", want, got)

	// Structural floor (so a vacuous-but-matching golden still fails): the non-claim
	// flags must be the opaque-tunnel values.
	if !want.NonClaim.PinHolds {
		t.Error("golden must pin pin_holds=true (the original cert arrived)")
	}
	if want.NonClaim.SwapOccurred {
		t.Error("golden must pin swap_occurred=false (pass-through never swaps)")
	}
	if want.NonClaim.Inspected {
		t.Error("golden must pin inspected=false (pass-through terminates no TLS)")
	}
	if want.NonClaim.LeafMintedForOrigin {
		t.Error("golden must pin leaf_minted_for_origin=false (no per-session-CA leaf)")
	}
}

// buildPassthroughPinnedGolden assembles the opaque-tunnel trace from the run's
// observed facts. The tunneled bytes are pinned by DIGEST+LEN (of the bytes the
// dispatcher SPLICED — the peeked prefix), NEVER inner payload — the harness
// counts/digests bytes it never inspects (the non-claim). The netflow field keys
// are read from the captured event so a regression that added an HTTP/swap key
// would shift the golden.
func buildPassthroughPinnedGolden(ev tlsproxy.Event, upstreamAuth, path string, splicedPrefix []byte) passthroughPinnedGolden {
	var g passthroughPinnedGolden
	g.Kind = "passthrough-pinned-cert"
	g.Why = passthroughPinnedWhy
	g.SNI = passthroughPinnedSNI

	g.Netflow.Kind = string(ev.Kind)
	keys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		keys = append(keys, k)
	}
	g.Netflow.FieldKeys = canonHeaders(keys)
	// AbsentKeys is the fixed forbidden set — pinned so a future netflow that DID
	// carry one of these would break the byte-identity replay.
	g.Netflow.AbsentKeys = []string{"authorization", "header", "host", "method", "path", "scrub", "secret", "service", "status", "swap", "url"}
	g.Netflow.PolicyRuleID = ev.Provenance.RuleID

	g.Request.Method = http.MethodGet
	g.Request.Path = path
	g.Request.UpstreamAuthVerbatim = upstreamAuth
	g.Request.TunneledBytesDigest = digestOf(splicedPrefix)
	g.Request.TunneledBytesLen = len(splicedPrefix)

	g.NonClaim.PinHolds = true
	g.NonClaim.SwapOccurred = false
	g.NonClaim.Inspected = false
	g.NonClaim.LeafMintedForOrigin = false
	return g
}
