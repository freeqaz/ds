package nft

// Test doubles and shared fixtures for the nft suite. Per CONVENTIONS.md
// these live in a _test.go file so they ship with the tests, not the stubs.
// (The spec sketches FakeClock in a `nfttest` helper package; conventions
// place test doubles in _test.go files, which is what we do here.)

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// FakeClock is the deterministic time source: expiry/grace/dormancy tests
// Advance() it instead of sleeping (doc 06 §3 (a)-suite budget).
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{now: start} }

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// --- Shared fixtures ---

const (
	hostUplinkIface = "uplink0"
	clampMin        = 60 * time.Second
	clampMax        = 15 * time.Minute
	graceMargin     = 30 * time.Second
)

var (
	hostIP       = netip.MustParseAddr("192.0.2.10")
	dnsGateAddr  = netip.MustParseAddrPort("192.0.2.10:10053")
	tlsProxyAddr = netip.MustParseAddrPort("192.0.2.10:10443")

	sessA = SessionSpec{ID: "alpha", Iface: "dstap-alpha", VLANID: 101, VMAddr: netip.MustParseAddr("10.77.101.2"), CtMark: 0xA10A}
	sessB = SessionSpec{ID: "bravo", Iface: "dstap-bravo", VLANID: 102, VMAddr: netip.MustParseAddr("10.77.102.2"), CtMark: 0xB20B}
	sessC = SessionSpec{ID: "charlie", Iface: "dstap-charlie", VLANID: 103, VMAddr: netip.MustParseAddr("10.77.103.2"), CtMark: 0xC30C}
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
func ipa(s string) netip.Addr    { return netip.MustParseAddr(s) }

// srcOf is the legitimate (unforged) source for a session's VM.
func srcOf(s SessionSpec) netip.AddrPort { return netip.AddrPortFrom(s.VMAddr, 40000) }

// vmPkt builds a packet from the session's interface with its legit source.
func vmPkt(s SessionSpec, dst string, proto Proto, st CtState) Packet {
	return Packet{InIface: s.Iface, Src: srcOf(s), Dst: ap(dst), Proto: proto, CtState: st}
}

// --- Harness ---

type harness struct {
	tb     testing.TB
	ctx    context.Context
	clk    *FakeClock
	cfg    BootstrapConfig
	mgr    RulesetManager
	eval   PacketEvaluator
	flows  FlowSimulator
	writer AllowSetWriter
	reader AllowSetReader
	events FlowEventSource
}

// newHarness wires the seams via New() and bootstraps the default ruleset
// (Stage-1 direct mode, 60s/15m clamp, 30s grace). Against the stub this
// fails RED at Bootstrap — that is the designed baseline.
func newHarness(tb testing.TB) *harness {
	tb.Helper()
	clk := NewFakeClock(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC))
	mgr, eval, flows, writer, reader, events := New(clk)
	h := &harness{
		tb:  tb,
		ctx: context.Background(),
		clk: clk,
		cfg: BootstrapConfig{
			HostUplinkIface: hostUplinkIface,
			DNSGateAddr:     dnsGateAddr,
			TLSProxyAddr:    tlsProxyAddr,
			EgressMode:      EgressStage1Direct,
			TTLClampMin:     clampMin,
			TTLClampMax:     clampMax,
			Grace:           graceMargin,
		},
		mgr:    mgr,
		eval:   eval,
		flows:  flows,
		writer: writer,
		reader: reader,
		events: events,
	}
	if err := h.mgr.Bootstrap(h.ctx, h.cfg); err != nil {
		tb.Fatalf("Bootstrap: %v", err)
	}
	return h
}

func (h *harness) attach(spec SessionSpec) {
	h.tb.Helper()
	if err := h.mgr.AttachSession(h.ctx, spec); err != nil {
		h.tb.Fatalf("AttachSession(%s): %v", spec.ID, err)
	}
}

func (h *harness) detach(id SessionID) {
	h.tb.Helper()
	if err := h.mgr.DetachSession(h.ctx, id); err != nil {
		h.tb.Fatalf("DetachSession(%s): %v", id, err)
	}
}

// admit inserts IPv4 addresses for the session as the authorized dnsgate
// principal.
func (h *harness) admit(id SessionID, ttl time.Duration, addrs ...string) {
	h.tb.Helper()
	var as []netip.Addr
	for _, a := range addrs {
		as = append(as, ipa(a))
	}
	if err := h.writer.Admit(h.ctx, PrincipalDNSGate, id, FamilyIPv4, as, ttl); err != nil {
		h.tb.Fatalf("Admit(%s, %v): %v", id, addrs, err)
	}
}

func (h *harness) mustEval(p Packet) Decision {
	h.tb.Helper()
	d, err := h.eval.Evaluate(h.ctx, p)
	if err != nil {
		h.tb.Fatalf("Evaluate(%+v): %v", p, err)
	}
	return d
}

func (h *harness) entries(id SessionID, fam Family) []AllowEntry {
	h.tb.Helper()
	es, err := h.reader.Entries(h.ctx, id, fam)
	if err != nil {
		h.tb.Fatalf("Entries(%s): %v", id, err)
	}
	return es
}

func (h *harness) snapshot() RulesetSnapshot {
	h.tb.Helper()
	s, err := h.mgr.Snapshot(h.ctx)
	if err != nil {
		h.tb.Fatalf("Snapshot: %v", err)
	}
	if s == nil {
		h.tb.Fatalf("Snapshot returned nil snapshot without error")
	}
	return s
}

func (h *harness) setMode(m EgressMode) {
	h.tb.Helper()
	if err := h.mgr.SetEgressMode(h.ctx, m); err != nil {
		h.tb.Fatalf("SetEgressMode(%v): %v", m, err)
	}
}

func (h *harness) openFlow(p Packet) (FlowID, Decision) {
	h.tb.Helper()
	id, d, err := h.flows.OpenFlow(h.ctx, p)
	if err != nil {
		h.tb.Fatalf("OpenFlow(%+v): %v", p, err)
	}
	return id, d
}

// drainEvents collects the recorded event stream (the seam contract: the
// channel delivers everything recorded so far, then closes). The real-time
// timeout is only a hang guard, never an expiry mechanism.
func drainEvents(tb testing.TB, src FlowEventSource) []FlowEvent {
	tb.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := src.Events(ctx)
	if err != nil {
		tb.Fatalf("Events: %v", err)
	}
	var out []FlowEvent
	guard := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-guard:
			tb.Fatalf("timed out draining %d events", len(out))
		}
	}
}

// --- Assertion helpers ---

// requireDrop asserts the documented default-deny outcome: drop + log with
// rule provenance (NFT-1 "drop + log"; POL-3 provenance). Strict enough that
// a zero-value Decision cannot satisfy it.
func requireDrop(tb testing.TB, d Decision, desc string) {
	tb.Helper()
	if d.Verdict != VerdictDrop {
		tb.Errorf("%s: verdict = %v, want drop", desc, d.Verdict)
	}
	if !d.Logged {
		tb.Errorf("%s: drop must be logged (nflog), Logged = false", desc)
	}
	if d.RuleID == "" {
		tb.Errorf("%s: drop must carry a non-empty RuleID (provenance)", desc)
	}
}

// requireAccepted asserts an accepting verdict (direct or return path).
func requireAccepted(tb testing.TB, d Decision, desc string) {
	tb.Helper()
	if d.Verdict != VerdictAcceptDirect && d.Verdict != VerdictAcceptReturn {
		tb.Errorf("%s: verdict = %v, want accept-direct or accept-return", desc, d.Verdict)
	}
}

// requireRedirect asserts a redirect verdict with its full attribution
// contract: target listener, preserved original dst, session, ct mark.
func requireRedirect(tb testing.TB, d Decision, want Verdict, target netip.AddrPort, origDst netip.AddrPort, sess SessionSpec, desc string) {
	tb.Helper()
	if d.Verdict != want {
		tb.Errorf("%s: verdict = %v, want %v", desc, d.Verdict, want)
	}
	if d.RedirectTarget != target {
		tb.Errorf("%s: RedirectTarget = %v, want %v", desc, d.RedirectTarget, target)
	}
	if d.OriginalDst != origDst {
		tb.Errorf("%s: OriginalDst = %v, want %v (preserved)", desc, d.OriginalDst, origDst)
	}
	if d.Session != sess.ID {
		tb.Errorf("%s: Session = %q, want %q", desc, d.Session, sess.ID)
	}
	if d.CtMark != sess.CtMark {
		tb.Errorf("%s: CtMark = %#x, want %#x", desc, d.CtMark, sess.CtMark)
	}
}

// findEntry returns the entry for addr, or false.
func findEntry(es []AllowEntry, a netip.Addr) (AllowEntry, bool) {
	for _, e := range es {
		if e.Addr == a {
			return e, true
		}
	}
	return AllowEntry{}, false
}
