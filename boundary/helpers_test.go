package boundary

// Test rig: fake clock, rig topology constants, and shared helpers for the
// assurance suite. Fakes live here, compiled only with the tests
// (CONVENTIONS.md "fakes in _test.go").

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"
)

// --- rig topology (the harness defines the test host's addressing) ---------

var (
	// hostGatewayAddr is the boundary gateway's own address on the agent
	// segment — must never be admitted (DNS-4 rule 2) nor reachable (C9-21).
	hostGatewayAddr = netip.MustParseAddr("10.99.0.1")
	// evilAddr is a non-allowlisted public destination (TEST-NET-3).
	evilAddr = netip.MustParseAddr("203.0.113.66")
	// sharedCDNAddr is a public IP shared by many domains (C9-12/13/14).
	sharedCDNAddr = netip.MustParseAddr("203.0.113.80")
	// rotatedAddrA / rotatedAddrB model CDN rotation (C9-8).
	rotatedAddrA = netip.MustParseAddr("203.0.113.10")
	rotatedAddrB = netip.MustParseAddr("203.0.113.11")
)

// --- fake clock -------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// installFakeClock installs a fake clock for the test and restores the real
// clock afterwards.
func installFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	fc := newFakeClock()
	SetClock(fc)
	t.Cleanup(func() { SetClock(nil) })
	return fc
}

// --- harness ----------------------------------------------------------------

// harness bundles the boundary under test with the rig control seams.
type harness struct {
	b     Boundary
	clock *fakeClock
	dns   UpstreamDNSControl
	http  UpstreamHTTPControl
	store SecretStoreControl
	fault FaultInjector
}

// newHarness builds the black box under test (the REAL boundary — the §9/§8
// suites are the spec the real data plane must satisfy) plus rig seams.
func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := installFakeClock(t)
	b, done := NewRealBoundary(t)
	t.Cleanup(done)
	return &harness{
		b:     b,
		clock: clock,
		dns:   NewUpstreamDNSControl(t),
		http:  NewUpstreamHTTPControl(t),
		store: NewSecretStoreControl(t),
		fault: NewFaultInjector(t),
	}
}

// newSession creates a baseline-posture session or fails RED.
func (h *harness) newSession(t *testing.T) Session {
	t.Helper()
	sess, err := h.b.CreateSession(context.Background(), CreateSessionRequest{
		Posture:  PostureStandard,
		Identity: IdentityRef{ID: "test-identity-" + t.Name()},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}

// setUpstreamA programs the rig's upstream resolver: name -> A records.
func (h *harness) setUpstreamA(t *testing.T, name string, ttl time.Duration, addrs ...netip.Addr) {
	t.Helper()
	recs := make([]DNSRecord, 0, len(addrs))
	for _, a := range addrs {
		recs = append(recs, DNSRecord{Name: name, Type: DNSTypeA, Addr: a, TTL: ttl})
	}
	if err := h.dns.SetAnswers(context.Background(), name, recs); err != nil {
		t.Fatalf("UpstreamDNSControl.SetAnswers(%s): %v", name, err)
	}
}

// resolveOK resolves name from inside the session and requires a gated
// NOERROR answer served by ds-dnsgate, returning the answered addresses.
func (h *harness) resolveOK(t *testing.T, s SessionRef, name string) (DNSResponse, []netip.Addr) {
	t.Helper()
	resp, err := h.b.VM(s).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS(%s): %v", name, err)
	}
	if resp.Rcode != RcodeNoError {
		t.Fatalf("ResolveDNS(%s) rcode = %s, want NOERROR", name, resp.Rcode)
	}
	if len(resp.Answers) == 0 {
		t.Fatalf("ResolveDNS(%s): no answers", name)
	}
	if resp.ServedBy != ServedByDNSGate {
		t.Fatalf("ResolveDNS(%s) ServedBy = %q, want %q", name, resp.ServedBy, ServedByDNSGate)
	}
	var addrs []netip.Addr
	for _, rec := range resp.Answers {
		if rec.Addr.IsValid() {
			addrs = append(addrs, rec.Addr)
		}
	}
	return resp, addrs
}

// --- goroutine-safe variants (load tests assert on the test goroutine; a
// t.Fatalf from a spawned goroutine is undefined behavior, so these return
// errors instead) ---------------------------------------------------------

// trySetUpstreamA is the goroutine-safe variant of setUpstreamA.
func (h *harness) trySetUpstreamA(name string, ttl time.Duration, addrs ...netip.Addr) error {
	recs := make([]DNSRecord, 0, len(addrs))
	for _, a := range addrs {
		recs = append(recs, DNSRecord{Name: name, Type: DNSTypeA, Addr: a, TTL: ttl})
	}
	if err := h.dns.SetAnswers(context.Background(), name, recs); err != nil {
		return fmt.Errorf("UpstreamDNSControl.SetAnswers(%s): %w", name, err)
	}
	return nil
}

// tryResolve is the goroutine-safe variant of resolveOK: same gated-NOERROR
// requirements, returned as an error.
func (h *harness) tryResolve(s SessionRef, name string) ([]netip.Addr, error) {
	resp, err := h.b.VM(s).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		return nil, fmt.Errorf("ResolveDNS(%s): %w", name, err)
	}
	if resp.Rcode != RcodeNoError {
		return nil, fmt.Errorf("ResolveDNS(%s) rcode = %s, want NOERROR", name, resp.Rcode)
	}
	if len(resp.Answers) == 0 {
		return nil, fmt.Errorf("ResolveDNS(%s): no answers", name)
	}
	if resp.ServedBy != ServedByDNSGate {
		return nil, fmt.Errorf("ResolveDNS(%s) ServedBy = %q, want %q", name, resp.ServedBy, ServedByDNSGate)
	}
	var addrs []netip.Addr
	for _, rec := range resp.Answers {
		if rec.Addr.IsValid() {
			addrs = append(addrs, rec.Addr)
		}
	}
	return addrs, nil
}

// tryAllowSet is the goroutine-safe variant of allowSet.
func (h *harness) tryAllowSet(s SessionRef) ([]AllowSetEntry, error) {
	entries, err := h.b.Inspect().AllowSet(context.Background(), s, IPv4)
	if err != nil {
		return nil, fmt.Errorf("AllowSet: %w", err)
	}
	return entries, nil
}

// allowSet reads the session's IPv4 allow-set or fails RED.
func (h *harness) allowSet(t *testing.T, s SessionRef) []AllowSetEntry {
	t.Helper()
	entries, err := h.b.Inspect().AllowSet(context.Background(), s, IPv4)
	if err != nil {
		t.Fatalf("AllowSet: %v", err)
	}
	return entries
}

// admissionMap reads the session's DNS-2b admission map or fails RED.
func (h *harness) admissionMap(t *testing.T, s SessionRef) []AdmissionEntry {
	t.Helper()
	entries, err := h.b.Inspect().AdmissionMap(context.Background(), s)
	if err != nil {
		t.Fatalf("AdmissionMap: %v", err)
	}
	return entries
}

// events reads the session's event bundle or fails RED.
func (h *harness) events(t *testing.T, s SessionRef) EventBundle {
	t.Helper()
	ev, err := h.b.Inspect().Events(context.Background(), s)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	return ev
}

// --- assertion helpers --------------------------------------------------------

func allowSetContains(entries []AllowSetEntry, addr netip.Addr) bool {
	for _, e := range entries {
		if e.Addr == addr {
			return true
		}
	}
	return false
}

func admissionFor(entries []AdmissionEntry, domain string) (AdmissionEntry, bool) {
	for _, e := range entries {
		if e.Domain == domain {
			return e, true
		}
	}
	return AdmissionEntry{}, false
}

func admissionHasAddr(e AdmissionEntry, addr netip.Addr) bool {
	for _, a := range e.Addrs {
		if a == addr {
			return true
		}
	}
	return false
}

// requireDenyDecision asserts a deny PolicyDecision for resource exists and
// carries full POL-3 provenance, returning it.
func requireDenyDecision(t *testing.T, ev EventBundle, resource string) PolicyDecision {
	t.Helper()
	for _, d := range ev.Decisions {
		if d.Decision == "deny" && d.Resource == resource {
			requireProvenance(t, d.Rule, "deny decision for "+resource)
			return d
		}
	}
	t.Fatalf("no deny PolicyDecision recorded for %q (decisions: %d)", resource, len(ev.Decisions))
	return PolicyDecision{}
}

func requireProvenance(t *testing.T, r RuleRef, what string) {
	t.Helper()
	if r.RuleID == "" || r.Layer == "" || r.PolicyVersion == "" {
		t.Fatalf("%s missing POL-3 provenance: rule=%q layer=%q version=%q", what, r.RuleID, r.Layer, r.PolicyVersion)
	}
}

// needleForms returns the canary encodings the credential-isolation tests
// must scan for: raw, base64, hex, url-encoded (CONVENTIONS).
func needleForms(needle string) map[string][]byte {
	return map[string][]byte{
		"raw":    []byte(needle),
		"base64": []byte(base64.StdEncoding.EncodeToString([]byte(needle))),
		"hex":    []byte(hex.EncodeToString([]byte(needle))),
		"url":    []byte(url.QueryEscape(needle)),
	}
}

// realGitHubToken is the high-entropy long-lived canary seeded into the
// secret store (outside the boundary) — must NEVER appear inside the VM.
const realGitHubToken = "ghp_REAL5ecr3tCanary9fK2xWqLm8vNpQ4jT7yZb0aHdEuRcSgVi"

// percentile returns the p-th percentile of sorted durations (p in [0,100]).
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}

// sortDurations sorts in place (ascending).
func sortDurations(d []time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
}

// runBufGate drives the Stage-0 buf freeze gate (S0-5). RED until the proto
// package and buf pipeline exist.
func runBufGate(t *testing.T) error {
	t.Helper()
	return BufGate(context.Background())
}
