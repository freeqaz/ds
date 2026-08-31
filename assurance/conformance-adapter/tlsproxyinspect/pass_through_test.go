// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// pass_through_test.go — the TLS-4 pass-through (opaque-tunnel) conformance
// assertion (doc 09 §5 TLS-4 done-when; doc 06 §3 (c) pass-through assertion;
// D17/D74). It is the boundary/tlsproxy seam's assurance twin for the
// TestPassThrough_* rows in boundary/tlsproxy/tlsproxy_inspect_test.go, which are
// PACKAGE-INTERNAL test funcs over an unimportable harness (newInspectHarness,
// newTLSOrigin, pinnedTLSClient, recordingUpstream). Per doc 12 §13.1 / the
// package guarantee (doc.go) this MIRRORS those assertions against the EXPORTED
// real-plane-backed seams this package already implements.
//
// IT DRIVES THE ROUTE THROUGH CODE UNDER TEST. The routing decision is NOT
// reimplemented in this file: the test installs the boundary PolicyEngine
// pass-through seam (passThroughPolicy) and BOTH upstream legs (an observingCA +
// observingDialer wrapping the real SessionCA / StrictWebPKIDialer), then hands
// the flow to the real PassThroughDispatcher (the Go mirror of main.rs
// proceed_route + the opaque splice + passthrough_netflow_event). The dispatcher
// — not the test — consults the seam and picks the leg, exactly as the boundary
// rows hand routing to h.gate.Evaluate / h.startTransparent and observe which leg
// the PROXY chose. The test then OBSERVES, via the wrapping recorders, which seam
// methods the dispatcher actually invoked. Because the same dispatch code can
// take EITHER leg, the "never inspected" / "list-empty inspects" / "no HTTP
// metadata" assertions are genuine routing PROPERTIES, not tautologies over a
// test-local mirror.
//
// What it proves about the main.rs wiring (u2 opaque forwarding + netflow; u1/u3
// the pass-through admission decision):
//
//	(a) the downstream ClientHello reaches the upstream EXACTLY — byte-identical,
//	    no TLS-3 interception, no leaf-cert substitution (it is a raw splice);
//	(b) the upstream's response reaches the downstream UNMODIFIED;
//	(c) the netflow EventFlow the DISPATCHER emits carries the SESSION + the
//	    DESTINATION (the SNI/admission key + the kernel dst) and NO HTTP-level
//	    metadata — opaque-tunnel accounting built in code-under-test (doc 12
//	    §3/§5/§10);
//	(d) a pass-through domain NEVER enters the TLS-3 path — the DISPATCHER mints no
//	    per-origin leaf for it and never calls the strict-WebPKI DialTLS leg
//	    (observed via the wrapping recorders, NOT asserted of test code);
//	(e) the LIST-EMPTY case (D74 baseline) routes to INSPECTION — handing an
//	    UNLISTED admitted domain to the SAME dispatcher takes the inspect leg
//	    (LeafFor + DialTLS, never DialRaw), proving the positive predicate / safe
//	    fall-through u3 hardened. The dispatcher CHOSE inspect; the test did not.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// Pass-through routing model — the boundary `PolicyEngine.PassThrough` seam.
//
// The pass-through list is POLICY, not code (doc 09 §5 TLS-4; the list ships
// EMPTY in the D64 baseline, D74). passThroughPolicy is the minimal real-plane
// model of that seam, mirroring boundary's fakePolicyEngine.PassThrough +
// setPassThrough: empty by default, a listed domain returns true with
// provenance. It satisfies the full boundary PolicyEngine interface so the real
// PassThroughDispatcher can consult it; the non-pass-through methods are unused
// by the dispatcher (admission is enforced UPSTREAM) and are inert stubs.
// ───────────────────────────────────────────────────────────────────────────

type passThroughPolicy struct {
	mu          sync.Mutex
	version     string
	passthrough map[string]bool
}

func newPassThroughPolicy() *passThroughPolicy {
	return &passThroughPolicy{version: "policy-v1", passthrough: map[string]bool{}}
}

// setPassThrough lists (on=true) or unlists a domain — POL-4 hot-reload of the
// policy snapshot (doc 12 §3; the list is §6 policy, not code).
func (p *passThroughPolicy) setPassThrough(domain string, on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if on {
		p.passthrough[domain] = true
	} else {
		delete(p.passthrough, domain)
	}
}

// PassThrough satisfies the boundary PolicyEngine.PassThrough seam: it returns
// whether the domain is on the pass-through list plus its provenance. Mirrors
// boundary fakePolicyEngine.PassThrough (the load-bearing "passthrough:" rule id
// + policy layer/version).
func (p *passThroughPolicy) PassThrough(_ context.Context, _ tlsproxy.SessionRef, domain string) (bool, tlsproxy.Provenance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.passthrough[domain], tlsproxy.Provenance{
		RuleID:        "passthrough:" + domain,
		PolicyLayer:   "system",
		PolicyVersion: p.version,
	}, nil
}

// The remaining PolicyEngine methods are not consulted by the pass-through
// dispatcher (SNI + admission are enforced UPSTREAM of it — the boundary
// TestPassThrough_StillSNIAndAdmissionEnforced row covers the refusal path at
// the TLS-1 gate). They exist only so passThroughPolicy satisfies the seam shape
// the dispatcher's Policy field requires.
func (p *passThroughPolicy) EvaluateConnect(context.Context, tlsproxy.SessionRef, string) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{}, nil
}

func (p *passThroughPolicy) EvaluateHTTP(context.Context, tlsproxy.SessionRef, tlsproxy.RequestMeta) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{}, nil
}

func (p *passThroughPolicy) MatchSwapService(context.Context, string) (tlsproxy.ServiceRule, bool, error) {
	return tlsproxy.ServiceRule{}, false, nil
}

// compile-time proof the policy model satisfies the boundary seam the dispatcher
// consults.
var _ tlsproxy.PolicyEngine = (*passThroughPolicy)(nil)

// ───────────────────────────────────────────────────────────────────────────
// TLS-3-path observers — prove a pass-through domain NEVER reaches the inspected
// plane (no leaf minted, no strict-WebPKI re-origination dialed) and, dually,
// that an unlisted domain DOES (the (e) inspect fall-through). They WRAP the real
// SessionCA / StrictWebPKIDialer the dispatcher drives and record which method
// the DISPATCHER invoked — so the route observed is the system's, not the test's.
//
// observingCA records every origin LeafFor is asked to mint; observingDialer
// records every (domain) DialTLS (inspected re-origination) vs (addr) DialRaw
// (opaque tunnel).
// ───────────────────────────────────────────────────────────────────────────

type observingCA struct {
	*adapterSessionCA
	mu          sync.Mutex
	leafOrigins []string
}

func (o *observingCA) LeafFor(ctx context.Context, origin string) (tls.Certificate, error) {
	o.mu.Lock()
	o.leafOrigins = append(o.leafOrigins, origin)
	o.mu.Unlock()
	return o.adapterSessionCA.LeafFor(ctx, origin)
}

func (o *observingCA) origins() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.leafOrigins...)
}

type observingDialer struct {
	*StrictWebPKIDialer
	mu       sync.Mutex
	tlsDials []string // domains given to DialTLS (the inspected re-origination leg)
	rawDials []string // addrs given to DialRaw (the opaque-tunnel leg)
}

func (o *observingDialer) DialTLS(ctx context.Context, sess tlsproxy.SessionRef, domain string, addr netip.AddrPort) (net.Conn, error) {
	o.mu.Lock()
	o.tlsDials = append(o.tlsDials, domain)
	o.mu.Unlock()
	return o.StrictWebPKIDialer.DialTLS(ctx, sess, domain, addr)
}

func (o *observingDialer) DialRaw(ctx context.Context, sess tlsproxy.SessionRef, addr netip.AddrPort) (net.Conn, error) {
	o.mu.Lock()
	o.rawDials = append(o.rawDials, addr.String())
	o.mu.Unlock()
	return o.StrictWebPKIDialer.DialRaw(ctx, sess, addr)
}

func (o *observingDialer) tls() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.tlsDials...)
}

func (o *observingDialer) raw() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.rawDials...)
}

// compile-time proof the observers still satisfy the boundary seams they wrap.
var (
	_ tlsproxy.SessionCA      = (*observingCA)(nil)
	_ tlsproxy.UpstreamDialer = (*observingDialer)(nil)
)

// ───────────────────────────────────────────────────────────────────────────
// rawEchoUpstream — a faked OPAQUE upstream (the "upstreamReceives" pattern).
//
// It records every byte the dispatcher splices toward it (so we can assert the
// downstream ClientHello reached the upstream EXACTLY — no termination/leaf
// substitution) and echoes a fixed response BACK (so we can assert the upstream's
// bytes reach the downstream UNMODIFIED). It speaks NO TLS — a pass-through tunnel
// is opaque, the origin's own handshake/payload pass through verbatim. It closes
// after replying so the dispatcher's read drains to EOF. Mirrors the boundary
// recordingUpstream/tlsOrigin over the adapter's loopback-listener idiom.
// ───────────────────────────────────────────────────────────────────────────

type rawEchoUpstream struct {
	received *lockedBuffer
	reply    []byte
}

func startRawEchoUpstream(t *testing.T, reply []byte) (netip.AddrPort, *rawEchoUpstream) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	up := &rawEchoUpstream{received: &lockedBuffer{}, reply: reply}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the spliced client bytes (the downstream ClientHello +
				// whatever follows) and record them verbatim, then reply and close
				// so the dispatcher's reply read sees EOF.
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = up.received.Write(buf[:n])
				}
				_, _ = c.Write(up.reply)
			}(c)
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(tcp.Port)), up
}

func (u *rawEchoUpstream) receivedBytes() []byte { return u.received.bytes() }

// startInspectUpstream serves a real TLS listener whose cert chains to the given
// session's interception CA — the upstream the INSPECT leg's strict-WebPKI
// DialTLS validates against. It exists so the (e) fall-through exercises the
// inspected leg END TO END (the dispatcher mints a leaf AND completes a real
// re-origination handshake) rather than failing the dial.
func startInspectUpstream(t *testing.T, ca *adapterSessionCA, domain string) netip.AddrPort {
	t.Helper()
	leaf, err := ca.LeafFor(ctx(), domain)
	if err != nil {
		t.Fatalf("mint upstream leaf: %v", err)
	}
	addr, _ := startTLSListener(t, leaf)
	return addr
}

// ───────────────────────────────────────────────────────────────────────────
// TestPassThrough — the doc 06 §3 (c) pass-through assertion (doc 09 §5 TLS-4
// done-when). It drives the real PassThroughDispatcher over a LISTED domain and
// asserts the dispatcher chose the opaque leg: (a) verbatim ClientHello upstream,
// (b) unmodified downstream response, (c) opaque netflow accounting (emitted BY
// the dispatcher), and (d) the inspected plane was never touched (observed via
// the wrapping recorders, not asserted of the test).
// ───────────────────────────────────────────────────────────────────────────

func TestPassThrough(t *testing.T) {
	const domain = "pinned.example"
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	// A representative downstream ClientHello prefix (the bytes the proxy peeked
	// off the VM to make the TLS-1 decision; on the opaque branch they are
	// replayed upstream verbatim). Opaque means opaque: the dispatcher never
	// parses past SNI here, so any byte string stands in for "the VM's handshake".
	clientHello := []byte("\x16\x03\x01\x00\x2a CLIENTHELLO-pinned.example-bytes")
	upstreamReply := []byte("\x16\x03\x03\x00\x10 SERVERHELLO+payload-from-origin")

	// The pass-through list LISTS the domain (POL: an explicit entry; the D74
	// baseline is empty, exercised by the (e) subtest).
	policy := newPassThroughPolicy()
	policy.setPassThrough(domain, true)

	// Real-plane seams, wrapped in observers so we can prove the inspected plane
	// is never touched for the listed domain.
	minter := NewCAMinter()
	realCA, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}
	ca := &observingCA{adapterSessionCA: realCA}
	dialer := &observingDialer{StrictWebPKIDialer: NewStrictWebPKIDialer(tlsproxy.Config{}, 0)}
	sink := NewCapturingEventSink()

	// The real dispatch point — the Go mirror of main.rs proceed_route + opaque
	// splice + passthrough_netflow_event. It — not the test — consults the seam
	// and picks the leg.
	disp := &PassThroughDispatcher{Policy: policy, CA: ca, Dialer: dialer, Sink: sink}

	upAddr, upstream := startRawEchoUpstream(t, upstreamReply)

	// Hand the admitted flow to the DISPATCHER: it must consult the pass-through
	// seam, see the domain LISTED, take the opaque DialRaw leg, splice the
	// ClientHello upstream verbatim, read the reply, and account the netflow.
	r, gotReply, _, err := disp.Dispatch(ctx(), sess, domain, upAddr, clientHello)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if r != RoutePassThrough {
		t.Fatalf("the dispatcher must route a pass-through-listed domain to the opaque tunnel; got %v", r)
	}

	// (a) the downstream ClientHello reached the upstream EXACTLY — byte-identical,
	// no leaf-cert substitution, no TLS-3 interception rewrote the handshake.
	if got := upstream.receivedBytes(); !bytes.Equal(got, clientHello) {
		t.Errorf("(a) upstream must receive the downstream ClientHello EXACTLY (opaque tunnel);\n got=%q\nwant=%q", got, clientHello)
	}

	// (b) the upstream's response reached the downstream UNMODIFIED.
	if !bytes.Equal(gotReply, upstreamReply) {
		t.Errorf("(b) downstream must receive the upstream response UNMODIFIED;\n got=%q\nwant=%q", gotReply, upstreamReply)
	}

	// (c) the netflow event the DISPATCHER emitted carries SESSION + DESTINATION,
	// not HTTP metadata. The event is built by the production-shaped
	// passThroughNetflowEvent in code-under-test, so a regression that leaked an
	// HTTP field into the pass-through accounting would surface HERE.
	evs := sink.Events()
	if len(evs) != 1 {
		t.Fatalf("(c) the dispatcher must emit exactly one netflow event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != tlsproxy.EventFlow {
		t.Errorf("(c) opaque accounting must be an EventFlow, got %q", ev.Kind)
	}
	if ev.Session.ID != sess.ID {
		t.Errorf("(c) netflow event must carry the session; Session.ID = %q, want %q", ev.Session.ID, sess.ID)
	}
	if ev.Fields["sni"] != domain {
		t.Errorf("(c) netflow event must carry the destination NAME (the admission/SNI key); sni = %q, want %q", ev.Fields["sni"], domain)
	}
	if ev.Fields["dst"] != upAddr.String() {
		t.Errorf("(c) netflow event must carry the destination address; dst = %q, want %q", ev.Fields["dst"], upAddr.String())
	}
	// Opaque means opaque: NO HTTP-level field may exist on a pass-through flow.
	for _, httpField := range []string{"method", "path", "status", "host", "header", "url"} {
		if v, ok := ev.Fields[httpField]; ok {
			t.Errorf("(c) opaque pass-through netflow leaked HTTP-level metadata %q=%q; the tunnel observes none", httpField, v)
		}
	}
	if ev.Provenance.PolicyVersion != "policy-v1" {
		t.Errorf("(c) netflow event must carry policy provenance; PolicyVersion = %q, want policy-v1", ev.Provenance.PolicyVersion)
	}

	// (d) the domain NEVER entered the TLS-3 path: the DISPATCHER minted no
	// per-origin leaf for it (observingCA saw no LeafFor) and never called the
	// strict-WebPKI DialTLS leg (observingDialer saw no DialTLS) — it dialed the
	// kernel destination opaquely via DialRaw exactly once. These ledgers are
	// non-vacuous: the SAME dispatcher takes the DialTLS+LeafFor leg for an
	// unlisted domain (the (e) test), so the system COULD have inspected and
	// chose not to.
	if origins := ca.origins(); len(origins) != 0 {
		t.Errorf("(d) a pass-through domain must never be inspected; the dispatcher minted leaves for %v", origins)
	}
	if len(dialer.tls()) != 0 {
		t.Errorf("(d) a pass-through flow must never re-originate via strict-WebPKI DialTLS; got DialTLS(%v)", dialer.tls())
	}
	if raw := dialer.raw(); len(raw) != 1 || raw[0] != upAddr.String() {
		t.Errorf("(d) the opaque tunnel must dial the kernel destination via DialRaw exactly once; got %v", raw)
	}
}

// TestPassThrough_ListEmptyRoutesToInspection pins the (e) done-when: the D74
// baseline pass-through list is EMPTY, so handing an admitted domain NOT on the
// list to the SAME PassThroughDispatcher takes the INSPECT-eligible leg (the
// positive predicate u3 hardened) — it never defaults to pass-through. The route
// is the DISPATCHER's: it consults the seam, sees the domain unlisted, mints a
// per-origin leaf (LeafFor) and re-originates upstream (DialTLS), never DialRaw.
// Mirrors boundary TestNonListedDomain_AlwaysInspected at the dispatch layer and
// the Rust acquire_passthrough_list_ships_empty_d74 +
// proceed_route_inspects_armed_non_passthrough_and_opaques_otherwise unit rows.
func TestPassThrough_ListEmptyRoutesToInspection(t *testing.T) {
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	policy := newPassThroughPolicy() // EMPTY by default (D74 baseline)

	minter := NewCAMinter()
	realCA, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}

	for _, domain := range []string{"ordinary.example", "api.example", "anything.example"} {
		// Fresh observers per domain so each ledger reflects exactly one dispatch.
		ca := &observingCA{adapterSessionCA: realCA}
		dialer := &observingDialer{StrictWebPKIDialer: NewStrictWebPKIDialer(inspectRootsConfig(t, realCA), 0)}
		sink := NewCapturingEventSink()
		disp := &PassThroughDispatcher{Policy: policy, CA: ca, Dialer: dialer, Sink: sink}

		// A real inspected upstream whose cert chains to the session CA, so the
		// dispatcher's strict-WebPKI re-origination DialTLS completes end-to-end.
		upAddr := startInspectUpstream(t, realCA, domain)

		r, _, _, err := disp.Dispatch(ctx(), sess, domain, upAddr, nil)
		if err != nil {
			t.Fatalf("Dispatch(%q): %v", domain, err)
		}
		if r != RouteInspect {
			t.Errorf("empty pass-through list: the dispatcher must route %q to Inspect (D74 baseline inspects every admitted domain), got %v", domain, r)
		}
		// The dispatcher took the INSPECT leg: it minted the per-origin leaf and
		// re-originated via strict-WebPKI DialTLS, and NEVER opened the opaque tunnel.
		if origins := ca.origins(); len(origins) != 1 || origins[0] != domain {
			t.Errorf("inspect leg must mint exactly the per-origin leaf for %q; LeafFor calls = %v", domain, origins)
		}
		if tlsd := dialer.tls(); len(tlsd) != 1 || tlsd[0] != domain {
			t.Errorf("inspect leg must re-originate %q via DialTLS exactly once; DialTLS calls = %v", domain, tlsd)
		}
		if raw := dialer.raw(); len(raw) != 0 {
			t.Errorf("an unlisted (inspected) domain must NEVER open the opaque DialRaw tunnel; got DialRaw(%v)", raw)
		}
		// No netflow EventFlow is emitted on the inspect leg (that accounting is
		// the opaque-tunnel path's; the inspected path emits HTTP events elsewhere).
		if evs := sink.Events(); len(evs) != 0 {
			t.Errorf("inspect leg must not emit the opaque-tunnel netflow event; got %d events", len(evs))
		}
	}

	// And a single explicit listing flips ONLY that domain to pass-through — the
	// list is policy (POL-4), the predicate stays positive. The unlisted domain
	// still inspects.
	policy.setPassThrough("api.example", true)

	listedCA := &observingCA{adapterSessionCA: realCA}
	listedDialer := &observingDialer{StrictWebPKIDialer: NewStrictWebPKIDialer(tlsproxy.Config{}, 0)}
	listedSink := NewCapturingEventSink()
	listedDisp := &PassThroughDispatcher{Policy: policy, CA: listedCA, Dialer: listedDialer, Sink: listedSink}
	listedAddr, _ := startRawEchoUpstream(t, []byte("opaque-reply"))
	if r, _, _, err := listedDisp.Dispatch(ctx(), sess, "api.example", listedAddr, []byte("client-bytes")); err != nil || r != RoutePassThrough {
		t.Errorf("a listed domain must flip to PassThrough, got route=%v err=%v", r, err)
	}
	if len(listedDialer.raw()) != 1 || len(listedDialer.tls()) != 0 {
		t.Errorf("the listed domain must take the opaque DialRaw leg, not DialTLS; raw=%v tls=%v", listedDialer.raw(), listedDialer.tls())
	}

	unlistedCA := &observingCA{adapterSessionCA: realCA}
	unlistedDialer := &observingDialer{StrictWebPKIDialer: NewStrictWebPKIDialer(inspectRootsConfig(t, realCA), 0)}
	unlistedDisp := &PassThroughDispatcher{Policy: policy, CA: unlistedCA, Dialer: unlistedDialer, Sink: NewCapturingEventSink()}
	unlistedAddr := startInspectUpstream(t, realCA, "ordinary.example")
	if r, _, _, err := unlistedDisp.Dispatch(ctx(), sess, "ordinary.example", unlistedAddr, nil); err != nil || r != RouteInspect {
		t.Errorf("an unlisted domain must stay Inspect even after another is listed, got route=%v err=%v", r, err)
	}
}

// inspectRootsConfig builds an UpstreamDialer Config whose roots trust ONLY the
// session CA, so the inspect leg's strict-WebPKI DialTLS validates the
// session-CA-chained upstream the (e) test serves. (The pass-through leg ignores
// roots — it terminates no TLS.)
func inspectRootsConfig(t *testing.T, ca *adapterSessionCA) tlsproxy.Config {
	t.Helper()
	pemBytes, err := ca.CertPool()
	if err != nil {
		t.Fatalf("CertPool: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("append session CA PEM to roots")
	}
	return tlsproxy.Config{UpstreamRoots: roots}
}
