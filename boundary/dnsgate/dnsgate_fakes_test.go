package dnsgate

// Test doubles and helpers for the dnsgate executable spec. Everything here
// is compiled only with the tests (CONVENTIONS.md file-naming rule): recording
// fakes, programmable stores, a fake clock, and DNS packet helpers.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	sess1 = SessionRef{ID: "s1", Interface: "dstap-s1"}
	sess2 = SessionRef{ID: "s2", Interface: "dstap-s2"}
)

func allowDec(rule string) Decision {
	return Decision{Verdict: VerdictAllow, RuleID: rule, PolicyLayer: "system", PolicyVersion: "v0.3"}
}

func denyDec(rule string) Decision {
	return Decision{Verdict: VerdictDeny, RuleID: rule, PolicyLayer: "system", PolicyVersion: "v0.3"}
}

func askDec(rule string) Decision {
	return Decision{Verdict: VerdictAsk, RuleID: rule, PolicyLayer: "org", PolicyVersion: "v0.3"}
}

func mkAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mkPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// defaultTTLPolicy is the strawman clamp from doc 09 §4 DNS-1 / NFT-3.
func defaultTTLPolicy() TTLPolicy {
	return TTLPolicy{Floor: 60 * time.Second, Ceiling: 900 * time.Second, Grace: 45 * time.Second}
}

// defaultScrubConfig: the host/boundary ranges for the test deployment.
// 0.0.0.0/8 and 255.255.255.255/32 are listed as host/boundary ranges so the
// DNS-4.a table judges them ReasonHostRange4.
func defaultScrubConfig() ScrubConfig {
	return ScrubConfig{
		HostRanges4: []netip.Prefix{
			mkPrefix("198.51.100.0/24"),
			mkPrefix("0.0.0.0/8"),
			mkPrefix("255.255.255.255/32"),
		},
		HostAddrs6: []netip.Addr{mkAddr("2001:db8::5")},
	}
}

func defaultConfig() PlannerConfig {
	return PlannerConfig{
		TTL:     defaultTTLPolicy(),
		Scrub:   defaultScrubConfig(),
		Posture: Posture{StripAAAA: true, SuppressHTTPSSVCB: true},
	}
}

// defaultResolvers is the D64 default upstream resolver set (doc 09 §6 POL-2
// resolver rows): the only endpoints the gate's own upstream queries may use.
func defaultResolvers() []netip.AddrPort {
	return []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:53"),
	}
}

// ---------------------------------------------------------------------------
// fake clock — deterministic time, never time.Sleep for expiry.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// fake policy evaluator — programmable verdicts + ordered call log.
// ---------------------------------------------------------------------------

type policyCall struct {
	Sess   SessionRef
	Domain string
}

type fakePolicy struct {
	mu         sync.Mutex
	global     map[string]Decision // domain → decision
	sessScoped map[string]Decision // sessID|domain → decision (session-scoped grants)
	defaultDec Decision
	calls      []policyCall
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{
		global:     map[string]Decision{},
		sessScoped: map[string]Decision{},
		defaultDec: denyDec("baseline/default-deny"),
	}
}

func (p *fakePolicy) set(domain string, d Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.global[domain] = d
}

// setForSession models an approval grant: a session-scoped TTL'd allow on the
// policy stream (doc 09 §8 Stage-0 ask-user seam).
func (p *fakePolicy) setForSession(sess SessionRef, domain string, d Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessScoped[sess.ID+"|"+domain] = d
}

func (p *fakePolicy) EvaluateDomain(ctx context.Context, sess SessionRef, domain string) (Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, policyCall{Sess: sess, Domain: domain})
	if d, ok := p.sessScoped[sess.ID+"|"+domain]; ok {
		return d, nil
	}
	if d, ok := p.global[domain]; ok {
		return d, nil
	}
	return p.defaultDec, nil
}

func (p *fakePolicy) callLog() []policyCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]policyCall, len(p.calls))
	copy(out, p.calls)
	return out
}

// ---------------------------------------------------------------------------
// fake upstream — scripted chains, rebind flips, call log.
// ---------------------------------------------------------------------------

type resolveCall struct {
	Resolver netip.AddrPort
	Name     string
	Qtype    RRType
}

type fakeUpstream struct {
	mu      sync.Mutex
	scripts map[string][]ResolutionChain // "name|qtype" or "name|*" → sequence (last repeats)
	served  map[string]int
	calls   []resolveCall
	failAll bool // arm to prove zero upstream resolution on deny/ask paths
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{scripts: map[string][]ResolutionChain{}, served: map[string]int{}}
}

// script registers chains for a name regardless of qtype; successive Resolve
// calls walk the sequence (rebind flips); the last chain repeats.
func (u *fakeUpstream) script(name string, chains ...ResolutionChain) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.scripts[name+"|*"] = chains
}

// scriptQ registers chains for an exact (name, qtype) pair.
func (u *fakeUpstream) scriptQ(name string, qtype RRType, chains ...ResolutionChain) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.scripts[fmt.Sprintf("%s|%d", name, qtype)] = chains
}

func (u *fakeUpstream) Resolve(ctx context.Context, resolver netip.AddrPort, name string, qtype RRType) (ResolutionChain, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, resolveCall{Resolver: resolver, Name: name, Qtype: qtype})
	if u.failAll {
		return ResolutionChain{}, fmt.Errorf("fakeUpstream: Resolve(%q) called but upstream was armed to fail the test", name)
	}
	for _, key := range []string{fmt.Sprintf("%s|%d", name, qtype), name + "|*"} {
		if seq, ok := u.scripts[key]; ok && len(seq) > 0 {
			i := u.served[key]
			if i >= len(seq) {
				i = len(seq) - 1
			}
			u.served[key]++
			return seq[i], nil
		}
	}
	return ResolutionChain{}, fmt.Errorf("fakeUpstream: no script for %q qtype %d", name, qtype)
}

func (u *fakeUpstream) callLog() []resolveCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]resolveCall, len(u.calls))
	copy(out, u.calls)
	return out
}

// aChain builds a link-free chain of terminal A records.
func aChain(name string, ttl uint32, addrs ...string) ResolutionChain {
	c := ResolutionChain{QueryName: name}
	for _, a := range addrs {
		c.Terminal = append(c.Terminal, AddrRecord{Addr: mkAddr(a), TTL: ttl})
	}
	return c
}

// ---------------------------------------------------------------------------
// fake admission store — behaving in-memory reference used as the Responder's
// collaborator. (The DNS-2b *contract* tests run against NewAdmissionStore's
// seam instead, so they stay RED against the stub.)
// ---------------------------------------------------------------------------

type storedAdmission struct {
	Addrs     []netip.Addr
	ExpiresAt time.Time
	Decision  Decision
}

type admitRecord struct {
	Tx  AdmissionTx
	At  time.Time
	Seq int
}

type fakeAdmissions struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]map[string]storedAdmission // sessID → domain → admission
	addrs   map[string]map[netip.Addr]time.Time   // sessID → addr → latest expiry
	admits  []admitRecord
	seq     int

	failDomains map[string]error // domain → injected Admit error

	armed   bool
	entered chan struct{}
	release chan struct{}
}

func newFakeAdmissions(now func() time.Time) *fakeAdmissions {
	return &fakeAdmissions{
		now:         now,
		entries:     map[string]map[string]storedAdmission{},
		addrs:       map[string]map[netip.Addr]time.Time{},
		failDomains: map[string]error{},
	}
}

// failDomain injects an Admit error for one domain (DNS-2.b).
func (s *fakeAdmissions) failDomain(domain string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failDomains[domain] = err
}

// arm makes the next Admit signal `entered` and block until `release` is
// closed — the insert-then-answer ordering probe (DNS-2.a / DNS-5.b).
func (s *fakeAdmissions) arm() (entered <-chan struct{}, release chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = true
	s.entered = make(chan struct{}, 1)
	s.release = make(chan struct{})
	return s.entered, s.release
}

func (s *fakeAdmissions) Admit(ctx context.Context, tx AdmissionTx) error {
	s.mu.Lock()
	if s.armed {
		s.armed = false
		entered, release := s.entered, s.release
		s.mu.Unlock()
		entered <- struct{}{}
		<-release
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	if err, ok := s.failDomains[tx.Domain]; ok {
		return err // atomic: nothing written
	}
	exp := s.now().Add(tx.Timeout)
	if s.entries[tx.Session.ID] == nil {
		s.entries[tx.Session.ID] = map[string]storedAdmission{}
	}
	addrs := make([]netip.Addr, len(tx.Addrs))
	copy(addrs, tx.Addrs)
	s.entries[tx.Session.ID][tx.Domain] = storedAdmission{Addrs: addrs, ExpiresAt: exp, Decision: tx.Decision}
	if s.addrs[tx.Session.ID] == nil {
		s.addrs[tx.Session.ID] = map[netip.Addr]time.Time{}
	}
	for _, a := range tx.Addrs {
		if cur, ok := s.addrs[tx.Session.ID][a]; !ok || exp.After(cur) {
			s.addrs[tx.Session.ID][a] = exp
		}
	}
	s.seq++
	s.admits = append(s.admits, admitRecord{Tx: tx, At: s.now(), Seq: s.seq})
	return nil
}

func (s *fakeAdmissions) Lookup(ctx context.Context, sess SessionRef, domain string, addr netip.Addr) (Admission, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ent, ok := s.entries[sess.ID][domain]
	if !ok || !s.now().Before(ent.ExpiresAt) {
		return Admission{}, false, nil
	}
	for _, a := range ent.Addrs {
		if a == addr {
			return Admission{Domain: domain, Addrs: ent.Addrs, ExpiresAt: ent.ExpiresAt}, true, nil
		}
	}
	return Admission{}, false, nil
}

func (s *fakeAdmissions) ContainsAddr(ctx context.Context, sess SessionRef, addr netip.Addr) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.addrs[sess.ID][addr]
	return ok && s.now().Before(exp), nil
}

func (s *fakeAdmissions) FlushSession(ctx context.Context, sess SessionRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, sess.ID)
	delete(s.addrs, sess.ID)
	return nil
}

func (s *fakeAdmissions) admitLog() []admitRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]admitRecord, len(s.admits))
	copy(out, s.admits)
	return out
}

// snapshot serializes the live store contents deterministically so tests can
// assert "bit-identical before/after" (DNS-3.f, DNS-2.b).
func (s *fakeAdmissions) snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lines []string
	for sid, doms := range s.entries {
		for d, ent := range doms {
			as := make([]string, 0, len(ent.Addrs))
			for _, a := range ent.Addrs {
				as = append(as, a.String())
			}
			sort.Strings(as)
			lines = append(lines, fmt.Sprintf("entry %s %s %s exp=%s", sid, d, strings.Join(as, ","), ent.ExpiresAt.UTC()))
		}
	}
	for sid, m := range s.addrs {
		for a, exp := range m {
			lines = append(lines, fmt.Sprintf("addr %s %s exp=%s", sid, a, exp.UTC()))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// fake ask-user notifier and event sink — recording.
// ---------------------------------------------------------------------------

type fakeNotifier struct {
	mu    sync.Mutex
	reqs  []AskUserRequest
	block chan struct{} // if non-nil, Notify blocks until closed
	err   error
}

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{} }

func (n *fakeNotifier) Notify(ctx context.Context, req AskUserRequest) error {
	n.mu.Lock()
	n.reqs = append(n.reqs, req)
	block, err := n.block, n.err
	n.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	return err
}

func (n *fakeNotifier) requests() []AskUserRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]AskUserRequest, len(n.reqs))
	copy(out, n.reqs)
	return out
}

type fakeEvents struct {
	mu        sync.Mutex
	dns       []DNSEvent
	decisions []PolicyDecisionEvent
}

func newFakeEvents() *fakeEvents { return &fakeEvents{} }

func (e *fakeEvents) EmitDNS(ctx context.Context, ev DNSEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dns = append(e.dns, ev)
	return nil
}

func (e *fakeEvents) EmitPolicyDecision(ctx context.Context, ev PolicyDecisionEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.decisions = append(e.decisions, ev)
	return nil
}

func (e *fakeEvents) dnsEvents() []DNSEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]DNSEvent, len(e.dns))
	copy(out, e.dns)
	return out
}

func (e *fakeEvents) decisionEvents() []PolicyDecisionEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]PolicyDecisionEvent, len(e.decisions))
	copy(out, e.decisions)
	return out
}

// ---------------------------------------------------------------------------
// env — one fully-faked Responder per test.
// ---------------------------------------------------------------------------

type env struct {
	t         *testing.T
	clock     *fakeClock
	policy    *fakePolicy
	upstream  *fakeUpstream
	store     *fakeAdmissions
	notifier  *fakeNotifier
	events    *fakeEvents
	cfg       PlannerConfig
	resolvers []netip.AddrPort
	resp      Responder
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:         t,
		clock:     newFakeClock(),
		policy:    newFakePolicy(),
		upstream:  newFakeUpstream(),
		notifier:  newFakeNotifier(),
		events:    newFakeEvents(),
		cfg:       defaultConfig(),
		resolvers: defaultResolvers(),
	}
	e.store = newFakeAdmissions(e.clock.Now)
	r, err := New(Deps{
		Policy:     e.policy,
		Upstream:   e.upstream,
		Resolvers:  e.resolvers,
		Admissions: e.store,
		AskUser:    e.notifier,
		Events:     e.events,
		Config:     e.cfg,
		Now:        e.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r == nil {
		t.Fatal("New returned a nil Responder (stubs must be non-nil)")
	}
	e.resp = r
	return e
}

// mustServe requires a successful Serve — RED against the stub, which errors.
func (e *env) mustServe(q Query) Answer {
	e.t.Helper()
	ans, err := e.resp.Serve(context.Background(), q)
	if err != nil {
		e.t.Fatalf("Serve(%s %d %s) error: %v", q.Name, q.Type, q.Proto, err)
	}
	return ans
}

// isConfiguredResolver reports whether rp is one of the policy-configured
// D64 upstream resolver endpoints wired into Deps.Resolvers (DNS-5.d).
func (e *env) isConfiguredResolver(rp netip.AddrPort) bool {
	for _, r := range e.resolvers {
		if r == rp {
			return true
		}
	}
	return false
}

func (e *env) containsAddr(sess SessionRef, addr netip.Addr) bool {
	e.t.Helper()
	ok, err := e.store.ContainsAddr(context.Background(), sess, addr)
	if err != nil {
		e.t.Fatalf("ContainsAddr(%s, %s): %v", sess.ID, addr, err)
	}
	return ok
}

func (e *env) lookup(sess SessionRef, domain string, addr netip.Addr) (Admission, bool) {
	e.t.Helper()
	adm, ok, err := e.store.Lookup(context.Background(), sess, domain, addr)
	if err != nil {
		e.t.Fatalf("Lookup(%s, %s, %s): %v", sess.ID, domain, addr, err)
	}
	return adm, ok
}

type serveResult struct {
	ans Answer
	err error
}

func serveAsync(r Responder, q Query) <-chan serveResult {
	ch := make(chan serveResult, 1)
	go func() {
		ans, err := r.Serve(context.Background(), q)
		ch <- serveResult{ans, err}
	}()
	return ch
}

// assertInsertThenAnswer proves the DNS-2.a ordering: Admit completes before
// the answer is released, and at the instant Serve returns every answered
// addr is already in the allow-set.
func (e *env) assertInsertThenAnswer(q Query) Answer {
	e.t.Helper()
	entered, release := e.store.arm()
	ch := serveAsync(e.resp, q)
	select {
	case <-entered:
	case r := <-ch:
		e.t.Fatalf("Serve returned (rcode=%d err=%v) without ever calling Admit — insert-then-answer violated", r.ans.RCode, r.err)
		return Answer{}
	case <-time.After(2 * time.Second):
		e.t.Fatal("Admit was never called within 2s — insert-then-answer cannot hold")
		return Answer{}
	}
	// Admit is blocked: the answer must not be released.
	select {
	case r := <-ch:
		e.t.Fatalf("Serve returned while Admit was still blocked (rcode=%d err=%v) — answer released before insert", r.ans.RCode, r.err)
		return Answer{}
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case r := <-ch:
		if r.err != nil {
			e.t.Fatalf("Serve after Admit release: %v", r.err)
		}
		for _, a := range addrRecords(r.ans) {
			if !e.containsAddr(q.Session, a.Addr) {
				e.t.Errorf("answered addr %s not in allow-set at the instant Serve returned", a.Addr)
			}
		}
		return r.ans
	case <-time.After(2 * time.Second):
		e.t.Fatal("Serve did not return after Admit was released")
		return Answer{}
	}
}

// ---------------------------------------------------------------------------
// answer inspection helpers.
// ---------------------------------------------------------------------------

func allSections(ans Answer) []RR {
	out := make([]RR, 0, len(ans.Answers)+len(ans.Authority)+len(ans.Additionals))
	out = append(out, ans.Answers...)
	out = append(out, ans.Authority...)
	out = append(out, ans.Additionals...)
	return out
}

// addrRecords returns every A/AAAA record across all sections.
func addrRecords(ans Answer) []RR {
	var out []RR
	for _, rr := range allSections(ans) {
		if rr.Type == TypeA || rr.Type == TypeAAAA {
			out = append(out, rr)
		}
	}
	return out
}

func recordsOfType(ans Answer, t RRType) []RR {
	var out []RR
	for _, rr := range allSections(ans) {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

func answerAddrSet(ans Answer) map[netip.Addr]bool {
	set := map[netip.Addr]bool{}
	for _, rr := range addrRecords(ans) {
		set[rr.Addr] = true
	}
	return set
}

// ---------------------------------------------------------------------------
// raw DNS packet helpers (DNS-5.a hardening surface).
// ---------------------------------------------------------------------------

// dnsQueryPacket builds a minimal well-formed DNS query packet.
func dnsQueryPacket(id uint16, name string, qtype RRType) []byte {
	b := []byte{
		byte(id >> 8), byte(id),
		0x01, 0x00, // RD set
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00)
	b = append(b, byte(uint16(qtype)>>8), byte(qtype), 0x00, 0x01)
	return b
}

// rawRCode extracts the RCODE from a raw DNS response header.
func rawRCode(resp []byte) RCode { return RCode(resp[3] & 0x0F) }

// rawID extracts the transaction ID from a raw DNS response header.
func rawID(resp []byte) uint16 { return uint16(resp[0])<<8 | uint16(resp[1]) }

// rawQR reports whether the QR (response) bit is set.
func rawQR(resp []byte) bool { return resp[2]&0x80 != 0 }
