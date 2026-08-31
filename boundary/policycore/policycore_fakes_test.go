package policycore

// Test doubles and helpers for the policycore TDD harness: a fake clock,
// request builders, a programmable SnapshotSource, recording
// SnapshotConsumers, a recording Stage-0 AskRouter, and fake service shapes
// (ds-dnsgate / ds-tlsproxy) for the e2e lifecycle test. These ship with the
// tests, never with the stubs.

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

// Shared deterministic fixtures.
var (
	sessS1 = SessionRef{Session: "S1", Host: "H1", Org: "O1"}
	sessS2 = SessionRef{Session: "S2", Host: "H2", Org: "O2"}

	// testT0 is the fake-clock epoch. Tests advance from here; nothing ever
	// sleeps to make time pass.
	testT0 = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	testIP = netip.MustParseAddr("203.0.113.10")
)

// fakeClock is the injectable deterministic clock: Evaluate takes `now`
// explicitly, so the clock just owns the current instant and advances on
// demand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// --- request builders ---

func dnsReq(sess SessionRef, domain string) Request {
	return Request{Session: sess, Kind: KindDNSResolve, Scope: ScopeVM, Domain: domain, Protocol: "udp", DstPort: 53}
}

func sniReq(sess SessionRef, domain string) Request {
	return Request{Session: sess, Kind: KindTLSSNI, Scope: ScopeVM, Domain: domain, Protocol: "tcp", DstPort: 443}
}

func httpReq(sess SessionRef, domain, method, path string) Request {
	return Request{Session: sess, Kind: KindHTTPRequest, Scope: ScopeVM, Domain: domain, Protocol: "tcp", DstPort: 443, HTTPMethod: method, HTTPPath: path}
}

func l4Req(sess SessionRef, domain string, ip netip.Addr, port uint16, proto string) Request {
	return Request{Session: sess, Kind: KindL4Direct, Scope: ScopeVM, Domain: domain, DstIP: ip, DstPort: port, Protocol: proto}
}

// zeroScope strips the request scope: a zero-value scope must be denied,
// never defaulted to the permissive scope (POL-2.c).
func zeroScope(r Request) Request {
	r.Scope = ""
	return r
}

// --- must* helpers (Fatalf on stub errors => RED by construction) ---

func mustCompose(t *testing.T, layers ...LayeredPolicy) *Snapshot {
	t.Helper()
	snap, err := Compose(layers...)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if snap == nil {
		t.Fatalf("Compose returned a nil snapshot without error")
	}
	return snap
}

func mustBaseline(t *testing.T) *Policy {
	t.Helper()
	p, err := DefaultBaseline()
	if err != nil {
		t.Fatalf("DefaultBaseline: %v", err)
	}
	if p == nil {
		t.Fatalf("DefaultBaseline returned a nil policy without error")
	}
	return p
}

func mustEvaluate(t *testing.T, eval Evaluator, snap *Snapshot, req Request, now time.Time) Decision {
	t.Helper()
	dec, err := eval.Evaluate(snap, req, now)
	if err != nil {
		t.Fatalf("Evaluate(%s %q): %v", req.Kind, req.Domain, err)
	}
	return dec
}

func validLayer(l Layer) bool {
	return l == LayerSystem || l == LayerOrg || l == LayerSession
}

// assertFullProvenance asserts the POL-3 invariant on a decision: non-empty
// rule id, a defined layer, and the policy version of the snapshot that
// decided.
func assertFullProvenance(t *testing.T, dec Decision, snap *Snapshot) {
	t.Helper()
	if dec.Provenance.RuleID == "" {
		t.Errorf("decision carries empty Provenance.RuleID (action %q)", dec.Action)
	}
	if !validLayer(dec.Provenance.Layer) {
		t.Errorf("decision carries undefined Provenance.Layer %q", dec.Provenance.Layer)
	}
	if snap != nil && dec.Provenance.PolicyVersion != snap.PolicyVersion {
		t.Errorf("decision Provenance.PolicyVersion = %q, want snapshot's %q",
			dec.Provenance.PolicyVersion, snap.PolicyVersion)
	}
}

// blockRuleID finds the block rule covering domain in a policy pack.
func blockRuleID(t *testing.T, p *Policy, domain string) string {
	t.Helper()
	for _, b := range p.Block {
		if b.Domain == domain {
			return b.ID
		}
	}
	t.Fatalf("policy pack %q has no block rule for %q", p.Name, domain)
	return ""
}

// gateUpstreamRuleID finds the gate-upstream-scoped allow rule covering an
// upstream resolver IP in a policy pack (POL-2.c provenance pinning).
func gateUpstreamRuleID(t *testing.T, p *Policy, ip string) string {
	t.Helper()
	for _, a := range p.Allow {
		if a.Scope == ScopeGateUpstream && a.Domain == ip {
			return a.ID
		}
	}
	t.Fatalf("policy pack %q has no gate-upstream allow rule for %q", p.Name, ip)
	return ""
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// --- programmable SnapshotSource ---

// fakeSource is a programmable control-plane policy stream. It records every
// Subscribe call (and its fromSeq), replays preloaded history on subscribe,
// and fans live pushes out to all subscribers.
type fakeSource struct {
	mu            sync.Mutex
	history       []*Snapshot
	subs          []chan *Snapshot
	subscribeFrom []uint64
}

func newFakeSource() *fakeSource { return &fakeSource{} }

func (s *fakeSource) Subscribe(ctx context.Context, fromSeq uint64) (<-chan *Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribeFrom = append(s.subscribeFrom, fromSeq)
	ch := make(chan *Snapshot, 1024)
	for _, snap := range s.history {
		if snap.Seq >= fromSeq {
			ch <- snap
		}
	}
	s.subs = append(s.subs, ch)
	return ch, nil
}

// Push appends to history and delivers to every live subscriber.
func (s *fakeSource) Push(snap *Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append(s.history, snap)
	for _, ch := range s.subs {
		select {
		case ch <- snap:
		default:
		}
	}
}

// Preload appends to history without notifying subscribers — the "host was
// offline while the source advanced" shape for catch-up tests.
func (s *fakeSource) Preload(snaps ...*Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append(s.history, snaps...)
}

func (s *fakeSource) SubscribeCalls() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.subscribeFrom...)
}

// --- recording SnapshotConsumer ---

// recordingConsumer is a service-shaped fake (dnsgate / tlsproxy) that
// records every Reload, optionally slowed to provoke skew windows.
type recordingConsumer struct {
	name        string
	reloadDelay time.Duration

	mu      sync.Mutex
	cur     *Snapshot
	reloads []uint64

	reloaded chan uint64
}

func newRecordingConsumer(name string, delay time.Duration) *recordingConsumer {
	return &recordingConsumer{name: name, reloadDelay: delay, reloaded: make(chan uint64, 4096)}
}

func (c *recordingConsumer) Reload(snap *Snapshot) error {
	if c.reloadDelay > 0 {
		time.Sleep(c.reloadDelay) // artificial slowness, not expiry timing
	}
	c.mu.Lock()
	c.cur = snap
	c.reloads = append(c.reloads, snap.Seq)
	c.mu.Unlock()
	select {
	case c.reloaded <- snap.Seq:
	default:
	}
	return nil
}

func (c *recordingConsumer) CurrentVersion() (string, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		return "", 0
	}
	return c.cur.PolicyVersion, c.cur.Seq
}

func (c *recordingConsumer) snapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *recordingConsumer) reloadSeqs() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.reloads...)
}

// waitForReload blocks until the consumer has reloaded a snapshot with
// Seq >= seq, the subscriber's Run goroutine exits early (stub => RED fast),
// or a liveness timeout elapses.
func waitForReload(t *testing.T, c *recordingConsumer, seq uint64, runErr <-chan error) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-c.reloaded:
			if got >= seq {
				return
			}
		case err := <-runErr:
			t.Fatalf("HostSubscriber.Run exited before consumer %q reached seq %d: %v", c.name, seq, err)
		case <-deadline:
			t.Fatalf("timed out waiting for consumer %q to reload seq %d", c.name, seq)
		}
	}
}

// --- recording Stage-0 ask router (the fake orchestrator/client wrapper) ---

type recordingAskRouter struct {
	mu   sync.Mutex
	reqs []AskUserRequest
}

func (r *recordingAskRouter) RouteAsk(_ context.Context, req AskUserRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return nil
}

func (r *recordingAskRouter) recorded() []AskUserRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AskUserRequest(nil), r.reqs...)
}

// --- fake service shapes for the e2e lifecycle test (POL-2.g) ---

// fakeDNSGate is the ds-dnsgate-shaped harness stub: every resolution is one
// Evaluate call through the shared engine.
type fakeDNSGate struct {
	eval Evaluator
	snap *Snapshot
}

func (g *fakeDNSGate) Resolve(sess SessionRef, domain string, now time.Time) (Decision, error) {
	return g.eval.Evaluate(g.snap, dnsReq(sess, domain), now)
}

// fakeTLSProxy is the ds-tlsproxy-shaped harness stub: every SNI-checked
// connect is one Evaluate call through the same shared engine.
type fakeTLSProxy struct {
	eval Evaluator
	snap *Snapshot
}

func (p *fakeTLSProxy) ConnectSNI(sess SessionRef, domain string, now time.Time) (Decision, error) {
	return p.eval.Evaluate(p.snap, sniReq(sess, domain), now)
}
