// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// netflowadapter_test.go — the conformance assertions for proxy-side netflow
// telemetry with admitting-DNS-name attribution (doc 09 §7 LOG-1..LOG-3; doc 12
// §3/§5/§10; D17/D74). It drives SCRIPTED sessions through the real
// tlsproxyinspect PassThroughDispatcher via the Driver and proves the four
// acceptance properties over the COLLECTED flowlog stream:
//
//	(1) every FlowRecord and HttpEvent carries the admitting domain (SNI join);
//	(2) inspected flows emit BOTH a FlowRecord (L3/4) AND an HttpEvent (HTTP);
//	(3) passthrough flows emit ONLY a FlowRecord (no HTTP metadata);
//	(4) cardinality: exactly one FlowRecord per connection, never per request.
//
// The routes are the DISPATCHER's (it consults the boundary pass-through seam and
// picks the leg); the test OBSERVES the route map + the collected stream. The
// attribution + collection seams are the adapter's REAL implementations of the
// boundary/flowlog contract.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/tlsproxyinspect"
	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

var bg = context.Background()

// t0 is the deterministic harness epoch — never time.Now() in assertions.
var t0 = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

func mkRef(id string) flowlog.SessionRef {
	return flowlog.SessionRef{SessionID: id, HostID: "host-1", Iface: "dstap-" + id}
}

// ───────────────────────────────────────────────────────────────────────────
// Pass-through policy model — the boundary/tlsproxy PolicyEngine.PassThrough
// seam the dispatcher consults (empty by default per D74; a listed domain takes
// the opaque tunnel). Mirrors the tlsproxyinspect passThroughPolicy shape.
// ───────────────────────────────────────────────────────────────────────────

type passPolicy struct{ listed map[string]bool }

func newPassPolicy(listed ...string) *passPolicy {
	m := map[string]bool{}
	for _, d := range listed {
		m[d] = true
	}
	return &passPolicy{listed: m}
}

func (p *passPolicy) PassThrough(_ context.Context, _ tlsproxy.SessionRef, domain string) (bool, tlsproxy.Provenance, error) {
	return p.listed[domain], tlsproxy.Provenance{RuleID: "passthrough:" + domain, PolicyLayer: "system", PolicyVersion: "policy-v1"}, nil
}
func (p *passPolicy) EvaluateConnect(context.Context, tlsproxy.SessionRef, string) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{}, nil
}
func (p *passPolicy) EvaluateHTTP(context.Context, tlsproxy.SessionRef, tlsproxy.RequestMeta) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{}, nil
}
func (p *passPolicy) MatchSwapService(context.Context, string) (tlsproxy.ServiceRule, bool, error) {
	return tlsproxy.ServiceRule{}, false, nil
}

var _ tlsproxy.PolicyEngine = (*passPolicy)(nil)

// ───────────────────────────────────────────────────────────────────────────
// Loopback upstreams — the real targets the dispatcher dials.
//
// rawEchoUpstream serves an OPAQUE TCP echo (the pass-through leg dials it via
// DialRaw, splices the ClientHello verbatim, reads the reply). inspectUpstream
// serves a real TLS listener whose leaf chains to the session CA (the inspected
// leg dials it via strict-WebPKI DialTLS and completes a handshake). Mirrors the
// tlsproxyinspect harness idiom.
// ───────────────────────────────────────────────────────────────────────────

func startRawEchoUpstream(t *testing.T, host string, reply []byte) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write(reply)
			}(c)
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(tcp.Port))
}

func startInspectUpstream(t *testing.T, host string, leaf tls.Certificate) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{leaf}})
				if s.Handshake() != nil {
					return
				}
				_, _ = io.Copy(io.Discard, s)
			}(c)
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(tcp.Port))
}

// inspectRootsConfig builds an UpstreamDialer Config trusting ONLY the session
// CA, so the inspect leg's strict-WebPKI DialTLS validates the session-CA-chained
// upstream. Mirrors the tlsproxyinspect helper.
func inspectRootsConfig(t *testing.T, minter *tlsproxyinspect.AdapterCAMinter, sess flowlog.SessionRef) tlsproxy.Config {
	t.Helper()
	pool, err := minter.PoolFor(tlsproxy.SessionRef{ID: sess.SessionID})
	if err != nil {
		t.Fatalf("PoolFor(%s): %v", sess.SessionID, err)
	}
	return tlsproxy.Config{UpstreamRoots: pool}
}

// leafFor mints the per-origin leaf for the session/domain so the inspect upstream
// can serve a cert the dispatcher's strict-WebPKI DialTLS validates.
func leafFor(t *testing.T, minter *tlsproxyinspect.AdapterCAMinter, sess flowlog.SessionRef, domain string) tls.Certificate {
	t.Helper()
	ca, err := minter.MintSessionCA(bg, tlsproxy.SessionRef{ID: sess.SessionID})
	if err != nil {
		t.Fatalf("MintSessionCA: %v", err)
	}
	leaf, err := ca.LeafFor(bg, domain)
	if err != nil {
		t.Fatalf("LeafFor(%s): %v", domain, err)
	}
	return leaf
}

// ───────────────────────────────────────────────────────────────────────────
// Stream helpers — count/inspect the collected flowlog events.
// ───────────────────────────────────────────────────────────────────────────

func flowsFor(evs []flowlog.Event, session string) []flowlog.FlowRecord {
	var out []flowlog.FlowRecord
	for _, ev := range evs {
		if fr, ok := ev.(flowlog.FlowRecord); ok && fr.Session.SessionID == session {
			out = append(out, fr)
		}
	}
	return out
}

func httpsFor(evs []flowlog.Event, session string) []flowlog.HttpEvent {
	var out []flowlog.HttpEvent
	for _, ev := range evs {
		if he, ok := ev.(flowlog.HttpEvent); ok && he.Session.SessionID == session {
			out = append(out, he)
		}
	}
	return out
}

// ───────────────────────────────────────────────────────────────────────────
// TestNetflow_InspectedAndPassthrough_Attribution — the headline conformance
// run. One session opens TWO connections: an UNLISTED domain (inspected leg, one
// HTTP request) and a LISTED domain (opaque pass-through leg). It asserts:
//
//	(1) both flows carry the admitting domain (SNI join via the AdmissionIndex);
//	(2) the inspected flow emits BOTH a FlowRecord and an HttpEvent;
//	(3) the passthrough flow emits ONLY a FlowRecord (no HttpEvent / HTTP fields);
//	(4) exactly one FlowRecord per connection (two connections -> two FlowRecords).
// ───────────────────────────────────────────────────────────────────────────

func TestNetflow_InspectedAndPassthrough_Attribution(t *testing.T) {
	const (
		inspectedDomain = "registry.npmjs.org"
		passDomain      = "pinned.example"
	)
	sess := mkRef("sess-a")
	minter := tlsproxyinspect.NewCAMinter()

	// The pass-through list LISTS only the opaque domain (D74 baseline empty +
	// one explicit entry). The inspected domain is unlisted -> inspect leg.
	policy := newPassPolicy(passDomain)

	// The inspected upstream serves a session-CA-chained leaf so the dispatcher's
	// strict-WebPKI DialTLS completes; the opaque upstream is a raw echo.
	// Distinct loopback IPs so each domain's DNS-2 admission joins unambiguously
	// (real upstream IPs differ per domain; the AdmissionIndex keys on the IP).
	inspectAddr := startInspectUpstream(t, "127.0.0.1", leafFor(t, minter, sess, inspectedDomain))
	passAddr := startRawEchoUpstream(t, "127.0.0.2", []byte("opaque-reply"))

	dialer := tlsproxyinspect.NewStrictWebPKIDialer(inspectRootsConfig(t, minter, sess), 0)
	drv := NewDriver(DriverDeps{Policy: policy, CAMinter: minter, Dialer: dialer}, 64<<20)

	// Prime the admitting-domain join: DNS-2 admitted each domain's upstream IP
	// (loopback here) for this session, valid across the flow window.
	inspectIP := inspectAddr.Addr()
	passIP := passAddr.Addr()
	mustObserve(t, drv, dnsEvent(sess, inspectedDomain, inspectIP, t0))
	mustObserve(t, drv, dnsEvent(sess, passDomain, passIP, t0))

	sessions := []ScriptedSession{{
		Ref:    sess,
		CtMark: 0xA001,
		Conns: []ScriptedConn{
			{
				Domain:      inspectedDomain,
				Dst:         inspectAddr,
				ClientHello: nil,
				Requests:    []ScriptedRequest{{Method: "GET", Path: "/pkg", Status: 200}},
				Start:       t0.Add(time.Second),
				BytesOut:    4096,
				BytesIn:     1 << 20,
			},
			{
				Domain:      passDomain,
				Dst:         passAddr,
				ClientHello: []byte("\x16\x03\x01 CLIENTHELLO-pinned"),
				// A request IS scripted on the opaque connection on purpose: the
				// system must NOT lift it into an HttpEvent because the route is
				// PassThrough (the opaque tunnel observes no HTTP). This makes
				// property (3) NON-VACUOUS — the no-leak assertion below fails iff
				// the RouteInspect guard (netflowadapter.go) that suppresses HTTP
				// emission on the opaque leg regresses. (A vacuous Requests:nil here
				// would pass even if HttpEvents were emitted on every leg.)
				Requests: []ScriptedRequest{{Method: "GET", Path: "/leak", Status: 200}},
				Start:    t0.Add(2 * time.Second),
				BytesOut: 512,
				BytesIn:  2048,
			},
		},
	}}

	routes, err := drv.Run(bg, sessions)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The DISPATCHER chose the legs (the test did not): unlisted -> Inspect,
	// listed -> PassThrough.
	if got := routes[sess.SessionID+"|"+inspectedDomain]; got != tlsproxyinspect.RouteInspect {
		t.Fatalf("the dispatcher must route the unlisted domain %q to Inspect, got %v", inspectedDomain, got)
	}
	if got := routes[sess.SessionID+"|"+passDomain]; got != tlsproxyinspect.RoutePassThrough {
		t.Fatalf("the dispatcher must route the listed domain %q to PassThrough, got %v", passDomain, got)
	}

	evs := drv.CollectedEvents()
	flows := flowsFor(evs, sess.SessionID)
	https := httpsFor(evs, sess.SessionID)

	// (4) cardinality: two connections -> exactly two FlowRecords (one per
	// connection), never one-per-request.
	if len(flows) != 2 {
		t.Fatalf("(4) cardinality: two connections must emit exactly two FlowRecords (one per connection), got %d", len(flows))
	}

	// Map flows by admitting domain for per-leg assertions.
	byDomain := map[string]flowlog.FlowRecord{}
	for _, fr := range flows {
		byDomain[fr.AdmittingDomain] = fr
	}

	// (1) both flows carry the admitting domain joined from the SNI.
	insFlow, ok := byDomain[inspectedDomain]
	if !ok {
		t.Fatalf("(1) the inspected flow must carry AdmittingDomain=%q; flows=%+v", inspectedDomain, flows)
	}
	passFlow, ok := byDomain[passDomain]
	if !ok {
		t.Fatalf("(1) the pass-through flow must carry AdmittingDomain=%q; flows=%+v", passDomain, flows)
	}
	// The join is byte-for-byte the SNI domain, attributed to the right session.
	if insFlow.Session.SessionID != sess.SessionID || passFlow.Session.SessionID != sess.SessionID {
		t.Errorf("(1) both flows must attribute to the originating session %q; got %q/%q", sess.SessionID, insFlow.Session.SessionID, passFlow.Session.SessionID)
	}
	if insFlow.CtMark != 0xA001 || passFlow.CtMark != 0xA001 {
		t.Errorf("(1) both flows must carry the session ct mark 0xA001; got %#x/%#x", insFlow.CtMark, passFlow.CtMark)
	}

	// (2) the inspected flow emits BOTH a FlowRecord (above) AND an HttpEvent.
	if len(https) != 1 {
		t.Fatalf("(2) the inspected connection (one request) must emit exactly one HttpEvent, got %d", len(https))
	}
	he := https[0]
	if he.Host != inspectedDomain {
		t.Errorf("(2) the HttpEvent must carry the admitting domain join Host=%q, got %q", inspectedDomain, he.Host)
	}
	if he.Method != "GET" || he.Path != "/pkg" || he.Status != 200 {
		t.Errorf("(2) the HttpEvent must carry the HTTP metadata; got %s %s %d", he.Method, he.Path, he.Status)
	}
	if he.Decision.PolicyVersion == "" {
		t.Errorf("(2) the HttpEvent must carry policy provenance (POL-3); got empty PolicyVersion")
	}

	// (3) the pass-through flow emits ONLY a FlowRecord — no HttpEvent names the
	// pass-through domain (opaque tunnel observes no HTTP). The flowlog.HttpEvent
	// type structurally cannot carry a header/body value (LOG-5), and here the
	// opaque leg emits NO HttpEvent at all.
	for _, h := range https {
		if h.Host == passDomain {
			t.Errorf("(3) a pass-through (opaque) connection must emit NO HttpEvent; leaked %+v", h)
		}
	}
	// And the pass-through FlowRecord itself carries connection-level metadata, not
	// HTTP — it has no HTTP fields by construction (FlowRecord has none), and its
	// byte counts are the connection's, not a request's.
	if passFlow.BytesOut != 512 || passFlow.BytesIn != 2048 {
		t.Errorf("(3) the pass-through FlowRecord must carry connection-level bytes (out=512,in=2048); got out=%d in=%d", passFlow.BytesOut, passFlow.BytesIn)
	}
}

// TestNetflow_OneFlowPerConnection_NotPerRequest pins the cardinality property
// (4) sharply: ONE inspected connection carrying THREE HTTP requests must emit
// exactly ONE FlowRecord and THREE HttpEvents — never three FlowRecords. The
// connection is the netflow unit (LOG-1), the request is the HTTP-telemetry unit.
func TestNetflow_OneFlowPerConnection_NotPerRequest(t *testing.T) {
	const domain = "api.github.com"
	sess := mkRef("sess-multi")
	minter := tlsproxyinspect.NewCAMinter()
	policy := newPassPolicy() // empty -> the domain inspects (D74 baseline)

	addr := startInspectUpstream(t, "127.0.0.1", leafFor(t, minter, sess, domain))
	dialer := tlsproxyinspect.NewStrictWebPKIDialer(inspectRootsConfig(t, minter, sess), 0)
	drv := NewDriver(DriverDeps{Policy: policy, CAMinter: minter, Dialer: dialer}, 64<<20)
	mustObserve(t, drv, dnsEvent(sess, domain, addr.Addr(), t0))

	reqs := []ScriptedRequest{
		{Method: "GET", Path: "/a", Status: 200},
		{Method: "POST", Path: "/b", Status: 201},
		{Method: "GET", Path: "/c", Status: 404},
	}
	sessions := []ScriptedSession{{
		Ref:    sess,
		CtMark: 0xC003,
		Conns: []ScriptedConn{{
			Domain: domain, Dst: addr, Requests: reqs,
			Start: t0.Add(time.Second), BytesOut: 8192, BytesIn: 1 << 20,
		}},
	}}

	if _, err := drv.Run(bg, sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}

	evs := drv.CollectedEvents()
	flows := flowsFor(evs, sess.SessionID)
	https := httpsFor(evs, sess.SessionID)

	if len(flows) != 1 {
		t.Fatalf("(4) ONE connection with %d requests must emit exactly one FlowRecord (not one-per-request), got %d", len(reqs), len(flows))
	}
	if len(https) != len(reqs) {
		t.Fatalf("(4) %d requests must emit %d HttpEvents, got %d", len(reqs), len(reqs), len(https))
	}
	// The single FlowRecord carries the admitting domain; every HttpEvent does too.
	if flows[0].AdmittingDomain != domain {
		t.Errorf("(1) the single FlowRecord must carry AdmittingDomain=%q, got %q", domain, flows[0].AdmittingDomain)
	}
	for _, he := range https {
		if he.Host != domain {
			t.Errorf("(1) every HttpEvent must carry the admitting domain Host=%q, got %q", domain, he.Host)
		}
	}
}

// TestNetflow_UnattributedFlow_NeverGuessed proves the LOG-2 attribution gate:
// a flow whose ct mark + iifname do not resolve to a registered session is
// surfaced via ErrUnattributed, never joined to a guessed session. The driver
// surfaces it from Run; the Attributor returns the boundary sentinel.
func TestNetflow_UnattributedFlow_NeverGuessed(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	if err := reg.RegisterSession(bg, refA, 0xA001, refA.Iface); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}

	// A mark on the WRONG iface (disagreement) must NOT coin-flip a session.
	bad := flowlog.ConntrackFlow{
		CtMark: 0xA001, Iif: "dstap-ghost",
		Dst:   netip.MustParseAddrPort("104.16.0.5:443"),
		Start: t0, End: t0.Add(time.Second),
	}
	rec, err := attr.Attribute(bg, bad)
	if err == nil {
		t.Fatalf("a mark/iface disagreement must return ErrUnattributed, got nil with rec=%+v", rec)
	}
	if rec != (flowlog.FlowRecord{}) {
		t.Errorf("no FlowRecord may be produced for an unattributable flow, got %+v", rec)
	}
}

// TestNetflow_AdmissionWindow_NoCrossSessionJoin proves the LOG-2 admitting-
// domain join is per-session and time-windowed: two sessions sharing a CDN IP
// each join to their OWN admitting domain, and a flow starting post-expiry gets
// no domain (flagged for reconciliation), never a fabricated one.
func TestNetflow_AdmissionWindow_NoCrossSessionJoin(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	refB := mkRef("sess-b")
	if err := reg.RegisterSession(bg, refA, 0xA001, refA.Iface); err != nil {
		t.Fatalf("register A: %v", err)
	}
	if err := reg.RegisterSession(bg, refB, 0xB002, refB.Iface); err != nil {
		t.Fatalf("register B: %v", err)
	}

	shared := netip.MustParseAddr("151.101.1.1")
	if err := idx.ObserveDns(bg, dnsEventWindow(refA, "alloweda.example", shared, t0, t0.Add(5*time.Minute))); err != nil {
		t.Fatalf("observe A: %v", err)
	}
	if err := idx.ObserveDns(bg, dnsEventWindow(refB, "allowedb.example", shared, t0, t0.Add(5*time.Minute))); err != nil {
		t.Fatalf("observe B: %v", err)
	}

	sharedDst := netip.AddrPortFrom(shared, 443)
	recA, err := attr.Attribute(bg, flowlog.ConntrackFlow{CtMark: 0xA001, Iif: refA.Iface, Dst: sharedDst, Start: t0.Add(time.Second), End: t0.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("attribute A: %v", err)
	}
	recB, err := attr.Attribute(bg, flowlog.ConntrackFlow{CtMark: 0xB002, Iif: refB.Iface, Dst: sharedDst, Start: t0.Add(time.Second), End: t0.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("attribute B: %v", err)
	}
	if recA.AdmittingDomain != "alloweda.example" {
		t.Errorf("A's flow over the shared CDN IP joined %q, want alloweda.example (never B's)", recA.AdmittingDomain)
	}
	if recB.AdmittingDomain != "allowedb.example" {
		t.Errorf("B's flow over the shared CDN IP joined %q, want allowedb.example (never A's)", recB.AdmittingDomain)
	}

	// A flow starting AFTER the admission window: no fabricated domain.
	recLate, err := attr.Attribute(bg, flowlog.ConntrackFlow{CtMark: 0xA001, Iif: refA.Iface, Dst: sharedDst, Start: t0.Add(10 * time.Minute), End: t0.Add(10 * time.Minute).Add(time.Second)})
	if err != nil {
		t.Fatalf("attribute late: %v", err)
	}
	if recLate.AdmittingDomain != "" {
		t.Errorf("a post-expiry flow must get NO admitting domain (flagged for reconciliation), got %q", recLate.AdmittingDomain)
	}
}

// TestNetflow_ShipThroughRouterToSink_Queryable proves the LOG-3 collect ->
// spool -> ship -> sink path is queryable off-box: the driver collects a scripted
// session's flows, the shipper drains the spool through the router into the sink,
// and the sink's Query returns the session's complete story. It also pins the D19
// tier routing: TierOnPrem routes customer-side.
func TestNetflow_ShipThroughRouterToSink_Queryable(t *testing.T) {
	const domain = "registry.npmjs.org"
	sess := mkRef("sess-ship")
	minter := tlsproxyinspect.NewCAMinter()
	policy := newPassPolicy()
	addr := startInspectUpstream(t, "127.0.0.1", leafFor(t, minter, sess, domain))
	dialer := tlsproxyinspect.NewStrictWebPKIDialer(inspectRootsConfig(t, minter, sess), 0)
	drv := NewDriver(DriverDeps{Policy: policy, CAMinter: minter, Dialer: dialer}, 64<<20)
	mustObserve(t, drv, dnsEvent(sess, domain, addr.Addr(), t0))

	sessions := []ScriptedSession{{
		Ref: sess, CtMark: 0xD004,
		Conns: []ScriptedConn{{
			Domain: domain, Dst: addr,
			Requests: []ScriptedRequest{{Method: "GET", Path: "/", Status: 200}},
			Start:    t0.Add(time.Second), BytesOut: 1024, BytesIn: 4096,
		}},
	}}
	if _, err := drv.Run(bg, sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Ship customer-side under TierOnPrem (D19): the router routes everything to
	// the customer sink regardless of the configured default.
	const customer flowlog.SinkID = "customer"
	const vendor flowlog.SinkID = "vendor"
	sink := NewSink()
	router := NewRouter(flowlog.RouterConfig{Default: vendor, CustomerSide: customer})
	sinks := map[flowlog.SinkID]flowlog.Sink{customer: sink, vendor: NewSink()}
	shipper := NewShipper(drv.Spool, router, sinks, flowlog.TierOnPrem)

	if err := shipper.Ship(bg); err != nil {
		t.Fatalf("Ship: %v", err)
	}

	// The session's complete story is queryable off-box from the customer sink.
	story, err := sink.Query(bg, flowlog.StoryQuery{SessionID: sess.SessionID, Window: flowlog.Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	flows := flowsFor(story, sess.SessionID)
	https := httpsFor(story, sess.SessionID)
	if len(flows) != 1 {
		t.Errorf("the shipped story must hold the one connection FlowRecord, got %d", len(flows))
	}
	if len(https) != 1 {
		t.Errorf("the shipped story must hold the one request HttpEvent, got %d", len(https))
	}
	if len(flows) == 1 && flows[0].AdmittingDomain != domain {
		t.Errorf("the shipped FlowRecord must carry the admitting domain %q, got %q", domain, flows[0].AdmittingDomain)
	}

	// The vendor sink got NOTHING under TierOnPrem (everything routed customer-side).
	vendorStory, err := sinks[vendor].Query(bg, flowlog.StoryQuery{SessionID: sess.SessionID})
	if err != nil {
		t.Fatalf("Query vendor: %v", err)
	}
	if len(vendorStory) != 0 {
		t.Errorf("D19: under TierOnPrem NO event may reach the vendor sink, got %d", len(vendorStory))
	}
}

// TestNetflow_RouterUnroutableTier proves an unconfigured tier errors rather than
// falling through to the vendor sink (the boundary ErrUnroutableTier contract).
func TestNetflow_RouterUnroutableTier(t *testing.T) {
	r := NewRouter(flowlog.RouterConfig{Default: "vendor"}) // no CustomerSide configured
	if _, err := r.Route(flowlog.FlowRecord{}, flowlog.TierOnPrem); err == nil {
		t.Errorf("TierOnPrem with no customer-side sink configured must return ErrUnroutableTier, got nil")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// fixtures
// ───────────────────────────────────────────────────────────────────────────

func dnsEvent(ref flowlog.SessionRef, name string, ip netip.Addr, at time.Time) flowlog.DnsEvent {
	return dnsEventWindow(ref, name, ip, at, at.Add(time.Hour))
}

func dnsEventWindow(ref flowlog.SessionRef, name string, ip netip.Addr, from, until time.Time) flowlog.DnsEvent {
	return flowlog.DnsEvent{
		Session: ref, QueryName: name,
		AdmittedIPs: []netip.Addr{ip},
		TTL:         until.Sub(from), ExpiresAt: until,
		Decision: flowlog.PolicyDecision{
			Session: ref, Verdict: flowlog.VerdictAllow,
			RuleID: "DNS-2.admit", PolicyLayer: "session", PolicyVersion: "policy-v1",
			Resource: name, At: from,
		},
	}
}

func mustObserve(t *testing.T, drv *Driver, ev flowlog.DnsEvent) {
	t.Helper()
	if err := drv.ObserveDns(bg, ev); err != nil {
		t.Fatalf("ObserveDns(%s): %v", ev.QueryName, err)
	}
}
