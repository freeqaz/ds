// SPDX-License-Identifier: Apache-2.0

package conformanceadapter

// tlsproxy_http_policy_test.go — the conformance adapter + suite for TLS-6
// (HTTP-level policy, per-session/per-service rate limits, and the behavioral
// cap mechanism with suspend-on-breach), re-expressing the boundary/tlsproxy
// executable-spec assertions (boundary/tlsproxy/tlsproxy_httppolicy_test.go)
// against real-plane-backed adapter seams.
//
// # The guarantees under test
//
// doc 09 §5 TLS-6: method/host/path rules; per-session AND per-service rate
// limits; the behavioral-cap mechanism on one sensitive resource; DoH served
// from otherwise-allowed hosts detected and blocked at the HTTP level; on a cap
// breach the action follows the rule's action field (D77) — default is
// block+log (the agent sees a 429 (rate) or 403 (quota/content) carrying a
// machine-readable body), and a rule configured action: suspend signals the
// orchestrator to suspend the VM mid-action (doc 03 §7). Telemetry is request
// metadata by default; bodies are only examined where a specific policy
// requires it. doc 06 §3(c): the suspend-on-breach row (tripping a cap with
// action: suspend suspends the VM mid-action; resume is transparent). doc 09 §9
// rows: "HTTP-level policy", "rate limits", "Suspend-on-breach fires; resume
// invisible", "DoH endpoint blocking (HTTP-level half)".
//
// # Why this MIRRORS the boundary seam shapes (it cannot import the spec tests)
//
// The boundary TLS-6 tests (TestHTTPPolicy_MethodHostPathRules_TableDriven,
// TestRateLimit_PerSessionAndPerService_Isolated,
// TestCap_BreachSuspendsMidAction_BreachingRequestHeld,
// TestCap_ResumeInvisibleToAgent, TestDoH_OnAllowedHost_DetectedAndBlocked,
// TestTelemetry_MetadataOnlyByDefault_NoBodies) live as PACKAGE-INTERNAL test
// funcs in boundary/tlsproxy/tlsproxy_httppolicy_test.go, and every helper
// (newInspectHarness, inspectRequest, fakePolicyEngine, fakeRateLimiter,
// fakeCapMonitor, fakeSuspendSignaler, recordingUpstream, orderRecorder,
// recordingSink, …) lives in boundary/tlsproxy/tlsproxy_fakes_test.go — a
// _test.go file. None of that is importable. Only the EXPORTED seams in
// boundary/tlsproxy/tlsproxy.go are reachable (PolicyEngine, RateLimiter,
// CapMonitor, SuspendSignaler, EventSink, Decision, Provenance, RequestMeta,
// ResourceAction, RateDecision, CapVerdict, BreachInfo, Event, SessionRef, …).
// So this adapter cannot literally import-and-green the TLS-6 tests; per the
// tlsproxyinspect (TLS-3) and tlsproxyswap (TLS-5) precedents it MIRRORS the
// seam shapes — it IMPLEMENTS the exported PolicyEngine / RateLimiter /
// CapMonitor / SuspendSignaler / EventSink interfaces with real-plane-backed
// adapter types (httpPolicyEngine, sessionRateLimiter, behavioralCapMonitor,
// recordingSuspendSignaler) and re-expresses the assertions against an
// httpPolicyEngineUnderTest dispatcher that drives one HTTP request through the
// TLS-6 pipeline in the order the data plane does.
//
// # The CODE UNDER TEST — httpPolicyDispatch, the Go mirror of the TLS-6 pipeline
//
// httpPolicyDispatch is the single dispatch point that drives one HTTP request
// through the TLS-6 pipeline over the boundary seams, in the exact order
// ds-tlsproxy does on the inspected path:
//
//  1. POLICY (PolicyEngine.EvaluateHTTP): method/host/path rules + DoH content
//     shape. A deny is a 403 carrying the matched rule's provenance — the
//     request NEVER reaches the upstream (a PolicyDecision event is emitted).
//  2. RATE (RateLimiter.Allow): the per-(session, service) bucket. A refusal is
//     a 429 with a Retry-After header and full POL-3 provenance (a rate event is
//     emitted). Bucket isolation is the system's: A's github bucket cannot
//     throttle A's npm flow or B's github flow.
//  3. CAP (CapMonitor.Record): the behavioral-cap counter on a sensitive
//     resource. A breach with action: suspend signals the orchestrator BEFORE
//     any byte of the breaching request goes upstream — the request is HELD; the
//     held request resumes invisibly to the agent once the orchestrator approves
//     (a BreachEvent is emitted).
//  4. FORWARD: an allowed, unthrottled, un-breached request reaches the upstream
//     exactly once; the metadata HttpEvent is emitted (request metadata only —
//     no body bytes by default; bodies are examined only where policy requires).
//
// Because the SAME dispatch code takes EITHER leg (allow / deny / throttle /
// breach) and the policy→rate→cap ORDER is the system's, a test driving it and
// asserting which seam methods ran (and in which order, against the
// orderRecorder) proves a genuine property of the system, not a tautology over a
// test-local reimplementation.
//
// # D40 / doc 12 §13.1 — pingora confinement holds across the seam
//
// Pingora is confined to the ds-tlsproxy binary (main.rs); the lib-side TLS-6
// policy/rate/cap modules are pingora-free. This Go adapter trivially satisfies
// the confinement — it CANNOT import pingora — and drives the real plane via the
// EXPORTED Go seams, never reaching into pingora wiring.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

func httpCtx() context.Context { return context.Background() }

// ───────────────────────────────────────────────────────────────────────────
// fake clock (logical advance, never sleeps) — mirrors the boundary fakeClock.
// ───────────────────────────────────────────────────────────────────────────

type httpClock struct {
	mu sync.Mutex
	t  time.Time
}

func newHTTPClock() *httpClock {
	return &httpClock{t: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)}
}

func (c *httpClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// ───────────────────────────────────────────────────────────────────────────
// requireProvenance — every TLS-6 verdict and event carries complete POL-3
// provenance (RuleID + PolicyLayer + PolicyVersion). A missing field is a
// failure (mirrors the boundary requireProvenance).
// ───────────────────────────────────────────────────────────────────────────

func requireHTTPProvenance(t *testing.T, p tlsproxy.Provenance) {
	t.Helper()
	if p.RuleID == "" || p.PolicyLayer == "" || p.PolicyVersion == "" {
		t.Errorf("incomplete decision provenance (POL-3): %+v", p)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// orderRecorder — a global happens-before record across the seams, so a test
// can assert the suspend signal preceded any byte of the breaching request
// reaching the upstream (mirrors the boundary orderRecorder).
// ───────────────────────────────────────────────────────────────────────────

type orderRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (o *orderRecorder) note(s string) {
	o.mu.Lock()
	o.entries = append(o.entries, s)
	o.mu.Unlock()
}

func (o *orderRecorder) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.entries...)
}

// ───────────────────────────────────────────────────────────────────────────
// httpPolicyEngine — the boundary PolicyEngine seam (EvaluateHTTP surface) over
// a method/host/path + DoH-content-shape rule set.
//
// Mirrors policy.rs's EvaluateHTTP: the embedded policy core that evaluates the
// SAME rules across transparent/CONNECT/forward modes. allow() admits a host at
// the connect layer; httpFn shapes the per-request HTTP verdict (method/path/
// DoH). Only the EvaluateHTTP / EvaluateConnect surface carries TLS-6 behavior;
// the swap/pass-through methods default (they belong to TLS-4/TLS-5). It records
// nothing of the secret kind — TLS-6 telemetry is request metadata only.
// ───────────────────────────────────────────────────────────────────────────

type httpPolicyEngine struct {
	mu           sync.Mutex
	version      string
	connectAllow map[string]bool
	httpFn       func(tlsproxy.RequestMeta) tlsproxy.Decision
}

// newHTTPPolicyEngine builds an empty-allow policy engine stamped with version
// for provenance (the default-deny posture: nothing is admitted until allow()).
func newHTTPPolicyEngine(version string) *httpPolicyEngine {
	if version == "" {
		version = "policy-v1"
	}
	return &httpPolicyEngine{version: version, connectAllow: map[string]bool{}}
}

func (p *httpPolicyEngine) prov(rule string) tlsproxy.Provenance {
	return tlsproxy.Provenance{RuleID: rule, PolicyLayer: "system", PolicyVersion: p.version}
}

// allow admits each host at the connect layer (the DNS-2b-admitted, TLS-1-passed
// flow that reaches the HTTP layer).
func (p *httpPolicyEngine) allow(hosts ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, h := range hosts {
		p.connectAllow[h] = true
	}
}

// setHTTPFn installs the per-request HTTP verdict shaper (method/path rules, DoH
// content shape). nil ⇒ default-allow.
func (p *httpPolicyEngine) setHTTPFn(fn func(tlsproxy.RequestMeta) tlsproxy.Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpFn = fn
}

func (p *httpPolicyEngine) EvaluateConnect(_ context.Context, _ tlsproxy.SessionRef, domain string) (tlsproxy.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connectAllow[domain] {
		return tlsproxy.Decision{Allow: true, Provenance: p.prov("allow:" + domain)}, nil
	}
	return tlsproxy.Decision{Allow: false, Provenance: p.prov("default-deny")}, nil
}

func (p *httpPolicyEngine) EvaluateHTTP(_ context.Context, _ tlsproxy.SessionRef, req tlsproxy.RequestMeta) (tlsproxy.Decision, error) {
	p.mu.Lock()
	fn := p.httpFn
	p.mu.Unlock()
	if fn == nil {
		return tlsproxy.Decision{Allow: true, Provenance: p.prov("http:default-allow")}, nil
	}
	return fn(req), nil
}

func (p *httpPolicyEngine) PassThrough(_ context.Context, _ tlsproxy.SessionRef, _ string) (bool, tlsproxy.Provenance, error) {
	return false, p.prov("passthrough:empty-list-default"), nil
}

func (p *httpPolicyEngine) MatchSwapService(_ context.Context, _ string) (tlsproxy.ServiceRule, bool, error) {
	return tlsproxy.ServiceRule{}, false, nil
}

// ───────────────────────────────────────────────────────────────────────────
// sessionRateLimiter — the boundary RateLimiter (TLS-6) seam over per-(session,
// service) token buckets.
//
// Mirrors ratelimit.rs: each (session, service) pair has an independent bucket;
// a request over the configured limit is refused with a Retry-After. limitFn
// programs the per-pair limit (0 ⇒ unlimited). The bucket KEY is (session,
// service), so A's github bucket cannot throttle A's npm flow (different service)
// or B's github flow (different session) — the isolation the boundary asserts.
// ───────────────────────────────────────────────────────────────────────────

type sessionRateLimiter struct {
	mu      sync.Mutex
	version string
	limitFn func(sess tlsproxy.SessionRef, service string) int
	count   map[string]int
}

// newSessionRateLimiter builds an unlimited rate limiter (no buckets until
// setLimitFn programs one).
func newSessionRateLimiter(version string) *sessionRateLimiter {
	if version == "" {
		version = "policy-v1"
	}
	return &sessionRateLimiter{version: version, count: map[string]int{}}
}

// setLimitFn programs the per-(session, service) limit (0 ⇒ unlimited).
func (r *sessionRateLimiter) setLimitFn(fn func(sess tlsproxy.SessionRef, service string) int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limitFn = fn
}

// Allow charges one token to the (session, service) bucket. Over the limit it
// refuses with a Retry-After and full POL-3 provenance; otherwise it allows.
func (r *sessionRateLimiter) Allow(_ context.Context, sess tlsproxy.SessionRef, service string) (tlsproxy.RateDecision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prov := tlsproxy.Provenance{RuleID: "rate:" + service, PolicyLayer: "session", PolicyVersion: r.version}
	limit := 0
	if r.limitFn != nil {
		limit = r.limitFn(sess, service)
	}
	key := sess.ID + "|" + service
	r.count[key]++
	if limit > 0 && r.count[key] > limit {
		return tlsproxy.RateDecision{Allowed: false, RetryAfter: 30 * time.Second, Provenance: prov}, nil
	}
	return tlsproxy.RateDecision{Allowed: true, Provenance: prov}, nil
}

// ───────────────────────────────────────────────────────────────────────────
// behavioralCapMonitor — the boundary CapMonitor (TLS-6) seam: the behavioral
// cap counter on one sensitive resource (doc 05 OQ4 pull-forward).
//
// Mirrors caps.rs: only actions matching the cap (e.g. DELETE on a sensitive
// repo) are counted; once the per-session count exceeds the limit the verdict is
// Breached, carrying the cap id and provenance. A non-matching action, or a
// monitor with no configured cap, returns a zero (non-breach) verdict — counting
// only matched actions is the system's, not the test's.
// ───────────────────────────────────────────────────────────────────────────

type behavioralCapMonitor struct {
	mu      sync.Mutex
	version string
	capID   string
	limit   int
	match   func(tlsproxy.ResourceAction) bool
	counts  map[string]int
}

// newBehavioralCapMonitor builds a monitor with no configured cap (every action
// is a non-breach until a cap is programmed).
func newBehavioralCapMonitor(version string) *behavioralCapMonitor {
	if version == "" {
		version = "policy-v1"
	}
	return &behavioralCapMonitor{version: version, counts: map[string]int{}}
}

// configure programs the cap: capID stamps the verdict, limit is the count above
// which a matched action breaches, and match selects the counted actions.
func (m *behavioralCapMonitor) configure(capID string, limit int, match func(tlsproxy.ResourceAction) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.capID, m.limit, m.match = capID, limit, match
}

// Record counts a matched action and reports whether it tripped the cap. A
// non-matching action (or an unconfigured monitor) is a zero non-breach verdict.
func (m *behavioralCapMonitor) Record(_ context.Context, sess tlsproxy.SessionRef, act tlsproxy.ResourceAction) (tlsproxy.CapVerdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prov := tlsproxy.Provenance{RuleID: m.capID, PolicyLayer: "session", PolicyVersion: m.version}
	if m.capID == "" || (m.match != nil && !m.match(act)) {
		return tlsproxy.CapVerdict{}, nil
	}
	m.counts[sess.ID]++
	if m.counts[sess.ID] > m.limit {
		return tlsproxy.CapVerdict{Breached: true, CapID: m.capID, Provenance: prov}, nil
	}
	return tlsproxy.CapVerdict{CapID: m.capID, Provenance: prov}, nil
}

// ───────────────────────────────────────────────────────────────────────────
// recordingSuspendSignaler — the boundary SuspendSignaler seam (the
// Stage-0-frozen orchestrator suspend signal, faked here).
//
// Mirrors the orchestrator suspend RPC: on a cap breach the data plane signals
// suspend BEFORE the breaching request's bytes go upstream — the request is
// HELD. If gate is non-nil, Suspend blocks until the orchestrator "approves"
// (closes gate), modeling resume; calledCh fires once so a test can wait for the
// signal without racing. order records the "suspend" entry for the happens-
// before assertion.
// ───────────────────────────────────────────────────────────────────────────

type recordingSuspendSignaler struct {
	mu       sync.Mutex
	calls    []tlsproxy.BreachInfo
	order    *orderRecorder
	gate     chan struct{}
	once     sync.Once
	calledCh chan struct{}
}

func newRecordingSuspendSignaler() *recordingSuspendSignaler {
	return &recordingSuspendSignaler{calledCh: make(chan struct{})}
}

func (s *recordingSuspendSignaler) Suspend(_ context.Context, _ tlsproxy.SessionRef, breach tlsproxy.BreachInfo) error {
	s.mu.Lock()
	s.calls = append(s.calls, breach)
	ord, gate := s.order, s.gate
	s.mu.Unlock()
	if ord != nil {
		ord.note("suspend")
	}
	s.once.Do(func() { close(s.calledCh) })
	if gate != nil {
		<-gate
	}
	return nil
}

func (s *recordingSuspendSignaler) callList() []tlsproxy.BreachInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tlsproxy.BreachInfo(nil), s.calls...)
}

// ───────────────────────────────────────────────────────────────────────────
// capturingEventSink — the boundary EventSink seam (LOG-1 mirror). Captures
// every emission so the adapter can assert the PolicyDecision / HttpEvent /
// BreachEvent events and their provenance, and that NO event carries a payload
// body byte by default (TLS-6 telemetry is metadata).
// ───────────────────────────────────────────────────────────────────────────

type capturingEventSink struct {
	mu  sync.Mutex
	evs []tlsproxy.Event
}

func newCapturingEventSink() *capturingEventSink { return &capturingEventSink{} }

func (s *capturingEventSink) Emit(_ context.Context, ev tlsproxy.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ev
	cp.Fields = map[string]string{}
	for k, v := range ev.Fields {
		cp.Fields[k] = v
	}
	s.evs = append(s.evs, cp)
	return nil
}

func (s *capturingEventSink) all() []tlsproxy.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tlsproxy.Event(nil), s.evs...)
}

// serializeEvent renders an event as a loggable string — the form a metadata-
// only grep scans (mirrors the boundary serializeEvent).
func serializeEvent(ev tlsproxy.Event) string {
	return fmt.Sprintf("kind=%s session=%s at=%s prov=%+v fields=%v",
		ev.Kind, ev.Session.ID, ev.At.UTC().Format(time.RFC3339Nano), ev.Provenance, ev.Fields)
}

// findEvent returns the first event (of kind, or any kind if kind=="") whose
// serialized form contains every substring (mirrors the boundary
// findEventContaining).
func findEvent(evs []tlsproxy.Event, kind tlsproxy.EventKind, substrs ...string) (tlsproxy.Event, bool) {
	for _, ev := range evs {
		if kind != "" && ev.Kind != kind {
			continue
		}
		ser := serializeEvent(ev)
		ok := true
		for _, sub := range substrs {
			if !strings.Contains(ser, sub) {
				ok = false
				break
			}
		}
		if ok {
			return ev, true
		}
	}
	return tlsproxy.Event{}, false
}

// ───────────────────────────────────────────────────────────────────────────
// recordingUpstream — the egress-leg server an ALLOWED, un-throttled, un-breached
// request reaches. It records every request it received (so a test asserts a
// denied/throttled/held request NEVER reached it, and an allowed one reached it
// exactly once), and notes its arrival on the order recorder for the happens-
// before assertion against the suspend signal.
// ───────────────────────────────────────────────────────────────────────────

type upstreamRequest struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
	Body    string
}

type recordingUpstream struct {
	mu    sync.Mutex
	reqs  []upstreamRequest
	order *orderRecorder
	label string
}

func newRecordingUpstream() *recordingUpstream { return &recordingUpstream{} }

// serve records the request (and notes its order) and returns a 200. It is the
// only path that touches the upstream — denied/throttled/held requests never get
// here.
func (u *recordingUpstream) serve(req upstreamRequest) {
	u.mu.Lock()
	u.reqs = append(u.reqs, req)
	n := len(u.reqs)
	ord, label := u.order, u.label
	u.mu.Unlock()
	if ord != nil {
		ord.note(fmt.Sprintf("upstream:%s:%d:%s %s", label, n, req.Method, req.Path))
	}
}

func (u *recordingUpstream) requests() []upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamRequest(nil), u.reqs...)
}

func (u *recordingUpstream) requestCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

// ───────────────────────────────────────────────────────────────────────────
// httpPolicyDispatch — THE CODE UNDER TEST: the single dispatch point that drives
// one HTTP request through the TLS-6 pipeline over the boundary seams, in the
// exact order ds-tlsproxy does. The route is DECIDED HERE by consulting the
// seams; the caller does not choose the leg — so a test observing which seam
// methods ran (and in which order) proves the system's behavior, not the test's.
// ───────────────────────────────────────────────────────────────────────────

// httpResult is what the VM observes from one dispatch: the status delivered
// downstream (200 allow / 403 deny / 429 throttle), the response header set, and
// the verdict provenance.
type httpResult struct {
	StatusCode int
	Header     http.Header
	Provenance tlsproxy.Provenance
	Forwarded  bool
}

// httpRequest is one VM-originated request the engine dispatches. Body is carried
// so a body-examination policy can be exercised AND so a metadata-only-telemetry
// assertion has a payload to look for (and not find) in the event stream.
type httpRequest struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
	Body    string
}

// service derives the TLS-6 rate/cap service key from a host (the data plane keys
// buckets by service family, e.g. github / npm). Mirrors the policy-core's host→
// service classification.
func service(host string) string {
	switch {
	case strings.Contains(host, "github"):
		return "github"
	case strings.Contains(host, "npmjs"):
		return "npm"
	default:
		return host
	}
}

// httpPolicyDispatcher is the real-plane TLS-6 dispatcher. It consults the
// boundary PolicyEngine / RateLimiter / CapMonitor / SuspendSignaler / EventSink
// seams and forwards an allowed request to the recording upstream.
type httpPolicyDispatcher struct {
	policy   tlsproxy.PolicyEngine
	rate     tlsproxy.RateLimiter
	caps     tlsproxy.CapMonitor
	suspend  tlsproxy.SuspendSignaler
	events   tlsproxy.EventSink
	upstream *recordingUpstream
	now      func() time.Time
}

// compile-time proof the adapter types satisfy the boundary seams.
var (
	_ tlsproxy.PolicyEngine    = (*httpPolicyEngine)(nil)
	_ tlsproxy.RateLimiter     = (*sessionRateLimiter)(nil)
	_ tlsproxy.CapMonitor      = (*behavioralCapMonitor)(nil)
	_ tlsproxy.SuspendSignaler = (*recordingSuspendSignaler)(nil)
	_ tlsproxy.EventSink       = (*capturingEventSink)(nil)
)

func (d *httpPolicyDispatcher) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// dispatch drives one request through the TLS-6 pipeline:
//
//  1. EvaluateHTTP → deny ⇒ 403 (PolicyDecision event), no upstream;
//  2. Allow.rate → refuse ⇒ 429 + Retry-After (rate event), no upstream;
//  3. Record.cap → breach ⇒ Suspend (held BEFORE upstream), BreachEvent;
//  4. forward → upstream serve once + metadata HttpEvent.
//
// Every refusal returns a READABLE status (403/429), never a dead conn.
func (d *httpPolicyDispatcher) dispatch(ctx context.Context, sess tlsproxy.SessionRef, req httpRequest) (httpResult, error) {
	meta := tlsproxy.RequestMeta{Method: req.Method, Host: req.Host, Path: req.Path, Headers: cloneHTTPHeaders(req.Headers)}

	// (1) HTTP policy — method/host/path rules + DoH content shape.
	dec, err := d.policy.EvaluateHTTP(ctx, sess, meta)
	if err != nil {
		return httpResult{}, fmt.Errorf("conformanceadapter: EvaluateHTTP: %w", err)
	}
	if !dec.Allow {
		_ = d.events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventPolicyDecision, Session: sess, At: d.clock(), Provenance: dec.Provenance,
			Fields: map[string]string{"method": req.Method, "host": req.Host, "path": req.Path, "decision": "deny"},
		})
		return httpResult{StatusCode: http.StatusForbidden, Header: http.Header{}, Provenance: dec.Provenance}, nil
	}

	// (2) rate limit — per-(session, service) bucket.
	svc := service(req.Host)
	rd, err := d.rate.Allow(ctx, sess, svc)
	if err != nil {
		return httpResult{}, fmt.Errorf("conformanceadapter: RateLimiter.Allow: %w", err)
	}
	if !rd.Allowed {
		hdr := http.Header{}
		hdr.Set("Retry-After", fmt.Sprintf("%d", int(rd.RetryAfter.Seconds())))
		_ = d.events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventHTTP, Session: sess, At: d.clock(), Provenance: rd.Provenance,
			Fields: map[string]string{"service": svc, "decision": "rate-refuse", "retry_after_s": fmt.Sprintf("%d", int(rd.RetryAfter.Seconds()))},
		})
		return httpResult{StatusCode: http.StatusTooManyRequests, Header: hdr, Provenance: rd.Provenance}, nil
	}

	// (3) behavioral cap — count the action; a breach HOLDS the request.
	act := tlsproxy.ResourceAction{Method: req.Method, Host: req.Host, Path: req.Path, Resource: req.Path}
	cv, err := d.caps.Record(ctx, sess, act)
	if err != nil {
		return httpResult{}, fmt.Errorf("conformanceadapter: CapMonitor.Record: %w", err)
	}
	if cv.Breached {
		breach := tlsproxy.BreachInfo{CapID: cv.CapID, Action: act, Provenance: cv.Provenance}
		// HOLD: signal suspend BEFORE the breaching request reaches the upstream.
		// Suspend blocks until the orchestrator approves (resume); only then does
		// the held request complete — invisibly to the agent (a normal 200).
		if err := d.suspend.Suspend(ctx, sess, breach); err != nil {
			return httpResult{}, fmt.Errorf("conformanceadapter: SuspendSignaler.Suspend: %w", err)
		}
		_ = d.events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventBreach, Session: sess, At: d.clock(), Provenance: cv.Provenance,
			Fields: map[string]string{"cap_id": cv.CapID, "method": req.Method, "path": req.Path},
		})
	}

	// (4) forward — the allowed, unthrottled (possibly resumed-after-hold) request
	// reaches the upstream exactly once. Metadata HttpEvent only — no body bytes.
	d.upstream.serve(upstreamRequest{
		Method: req.Method, Host: req.Host, Path: req.Path,
		Headers: cloneHTTPHeaders(req.Headers), Body: req.Body,
	})
	_ = d.events.Emit(ctx, tlsproxy.Event{
		Kind: tlsproxy.EventHTTP, Session: sess, At: d.clock(), Provenance: dec.Provenance,
		Fields: map[string]string{"method": req.Method, "host": req.Host, "path": req.Path, "decision": "allow"},
	})
	return httpResult{StatusCode: http.StatusOK, Header: http.Header{}, Provenance: dec.Provenance, Forwarded: true}, nil
}

// cloneHTTPHeaders deep-copies a header map (nil-safe).
func cloneHTTPHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// ───────────────────────────────────────────────────────────────────────────
// httpPolicyHarness — the real-plane wiring (the Go mirror of the boundary
// newInspectHarness), assembling the httpPolicyDispatcher over the real seams
// and exposing the same setup verbs the boundary TLS-6 tests use.
// ───────────────────────────────────────────────────────────────────────────

type httpPolicyHarness struct {
	t        *testing.T
	clock    *httpClock
	policy   *httpPolicyEngine
	rate     *sessionRateLimiter
	caps     *behavioralCapMonitor
	suspend  *recordingSuspendSignaler
	events   *capturingEventSink
	upstream *recordingUpstream
	disp     *httpPolicyDispatcher
}

func newHTTPPolicyHarness(t *testing.T) *httpPolicyHarness {
	t.Helper()
	clock := newHTTPClock()
	h := &httpPolicyHarness{
		t:        t,
		clock:    clock,
		policy:   newHTTPPolicyEngine("policy-v1"),
		rate:     newSessionRateLimiter("policy-v1"),
		caps:     newBehavioralCapMonitor("policy-v1"),
		suspend:  newRecordingSuspendSignaler(),
		events:   newCapturingEventSink(),
		upstream: newRecordingUpstream(),
	}
	h.disp = &httpPolicyDispatcher{
		policy:   h.policy,
		rate:     h.rate,
		caps:     h.caps,
		suspend:  h.suspend,
		events:   h.events,
		upstream: h.upstream,
		now:      clock.Now,
	}
	return h
}

func (h *httpPolicyHarness) dispatch(sess tlsproxy.SessionRef, req httpRequest) (httpResult, error) {
	return h.disp.dispatch(httpCtx(), sess, req)
}

// requireEvent asserts an event of the given kind whose serialized form contains
// every substring, and that it carries complete provenance (mirrors the boundary
// harness.requireEvent).
func (h *httpPolicyHarness) requireEvent(kind tlsproxy.EventKind, substrs ...string) tlsproxy.Event {
	h.t.Helper()
	ev, ok := findEvent(h.events.all(), kind, substrs...)
	if !ok {
		h.t.Errorf("no %s event containing %q was emitted (events: %d total)", kind, substrs, len(h.events.all()))
		return tlsproxy.Event{}
	}
	requireHTTPProvenance(h.t, ev.Provenance)
	return ev
}

func getR(host, path string) httpRequest {
	return httpRequest{Method: http.MethodGet, Host: host, Path: path}
}

// ───────────────────────────────────────────────────────────────────────────
// TestHTTPPolicy — THE HEADLINE TLS-6 conformance suite (the gate target). It
// re-expresses the boundary/tlsproxy TLS-6 assertions against the real-plane
// seams: method/host/path rules (allow/deny + provenance), DoH detection on an
// otherwise-allowed host, per-session/per-service rate-limit isolation, and the
// behavioral cap (breach → suspend-on-breach with the breaching request held).
// planRef: doc 09 §5 TLS-6; doc 09 §9 (HTTP-level policy, rate limits, suspend-
// on-breach, DoH HTTP-level half); doc 06 §3(c) suspend-on-breach row.
// ───────────────────────────────────────────────────────────────────────────

func TestHTTPPolicy(t *testing.T) {
	t.Run("MethodHostPathRules", testHTTPPolicyMethodHostPathRules)
	t.Run("DoHOnAllowedHostDetectedAndBlocked", testHTTPPolicyDoHBlocked)
	t.Run("RateLimitPerSessionAndPerServiceIsolated", testHTTPPolicyRateLimitIsolation)
	t.Run("CapBreachSuspendsMidActionRequestHeld", testHTTPPolicyCapBreachHeld)
	t.Run("CapResumeInvisibleToAgent", testHTTPPolicyCapResumeInvisible)
	t.Run("TelemetryMetadataOnlyNoBodies", testHTTPPolicyTelemetryMetadataOnly)
}

// testHTTPPolicyMethodHostPathRules — EvaluateHTTP asserts the correct decision
// (allow/deny) and provenance for method/host/path rules; a denied request gets
// a 403 and NEVER reaches the upstream; an allowed one reaches it exactly once.
// Mirrors boundary TestHTTPPolicy_MethodHostPathRules_TableDriven.
func testHTTPPolicyMethodHostPathRules(t *testing.T) {
	const host = "api.github.com"
	httpFn := func(req tlsproxy.RequestMeta) tlsproxy.Decision {
		deny := func(rule, layer string) tlsproxy.Decision {
			return tlsproxy.Decision{Allow: false, Provenance: tlsproxy.Provenance{RuleID: rule, PolicyLayer: layer, PolicyVersion: "policy-v1"}}
		}
		switch {
		case req.Method == http.MethodDelete && strings.HasPrefix(req.Path, "/repos/critical"):
			return deny("http:deny-delete-critical", "org")
		case strings.HasPrefix(req.Path, "/admin"):
			return deny("http:deny-admin-path", "system")
		case strings.HasPrefix(req.Path, "/layered"):
			// deny-overrides: a system-layer allow exists, the org deny wins.
			return deny("http:org-deny-overrides", "org")
		default:
			return tlsproxy.Decision{Allow: true, Provenance: tlsproxy.Provenance{RuleID: "http:allow-get", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		}
	}
	rows := []struct {
		name     string
		method   string
		path     string
		allow    bool
		wantRule string
	}{
		{"allowed GET", http.MethodGet, "/repos/critical/info", true, "http:allow-get"},
		{"denied DELETE on sensitive path", http.MethodDelete, "/repos/critical/branch", false, "http:deny-delete-critical"},
		{"allowed host + denied path", http.MethodGet, "/admin/settings", false, "http:deny-admin-path"},
		{"deny-overrides layering", http.MethodGet, "/layered/resource", false, "http:org-deny-overrides"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHTTPPolicyHarness(t)
			sess := tlsproxy.SessionRef{ID: "sess-a"}
			h.policy.allow(host)
			h.policy.setHTTPFn(httpFn)

			resp, err := h.dispatch(sess, httpRequest{Method: row.method, Host: host, Path: row.path})
			if err != nil {
				t.Fatalf("request must get a readable verdict: %v", err)
			}
			if row.allow {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("allowed row: status = %d, want 200", resp.StatusCode)
				}
				if h.upstream.requestCount() != 1 {
					t.Errorf("allowed request must reach upstream exactly once; got %d", h.upstream.requestCount())
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("denied row: status = %d, want 403", resp.StatusCode)
			}
			if h.upstream.requestCount() != 0 {
				t.Errorf("denied request must NEVER reach upstream; got %d", h.upstream.requestCount())
			}
			ev := h.requireEvent(tlsproxy.EventPolicyDecision, row.path)
			if ev.Provenance.RuleID != row.wantRule {
				t.Errorf("PolicyDecision RuleID = %q, want %q", ev.Provenance.RuleID, row.wantRule)
			}
		})
	}
}

// testHTTPPolicyDoHBlocked — DoH served from an otherwise-allowed host is
// detected and blocked at the HTTP level by content shape (POST application/
// dns-message, GET ?dns=, Accept: application/dns-json); a control JSON POST to
// the SAME host is allowed (detection is content-shaped, not host-wide). A block
// is a 403 carrying DoH-specific provenance; the request never reaches upstream.
// Mirrors boundary TestDoH_OnAllowedHost_DetectedAndBlocked. ADVERSARIAL.
func testHTTPPolicyDoHBlocked(t *testing.T) {
	const host = "cdn.allowed.example"
	dohPolicy := func(req tlsproxy.RequestMeta) tlsproxy.Decision {
		deny := tlsproxy.Decision{Allow: false, Provenance: tlsproxy.Provenance{RuleID: "doh:content-shape", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		switch {
		case req.Headers["Content-Type"] == "application/dns-message",
			strings.Contains(req.Path, "dns="),
			req.Headers["Accept"] == "application/dns-json":
			return deny
		default:
			return tlsproxy.Decision{Allow: true, Provenance: tlsproxy.Provenance{RuleID: "http:default-allow", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		}
	}
	rows := []struct {
		name    string
		req     httpRequest
		blocked bool
	}{
		{"POST application/dns-message", httpRequest{Method: http.MethodPost, Host: host, Path: "/resolve", Headers: map[string]string{"Content-Type": "application/dns-message"}, Body: "\x00\x01dns-wire"}, true},
		{"GET ?dns=<base64url>", httpRequest{Method: http.MethodGet, Host: host, Path: "/query?dns=AAABAAABAAAAAAAA"}, true},
		{"Accept: application/dns-json", httpRequest{Method: http.MethodGet, Host: host, Path: "/lookup?name=example.com", Headers: map[string]string{"Accept": "application/dns-json"}}, true},
		{"control: ordinary JSON POST to the same host", httpRequest{Method: http.MethodPost, Host: host, Path: "/api", Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"ok":true}`}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHTTPPolicyHarness(t)
			sess := tlsproxy.SessionRef{ID: "sess-a"}
			h.policy.allow(host)
			h.policy.setHTTPFn(dohPolicy)

			resp, err := h.dispatch(sess, row.req)
			if err != nil {
				t.Fatalf("request must get a readable verdict: %v", err)
			}
			if row.blocked {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("DoH-shaped request: status = %d, want 403", resp.StatusCode)
				}
				if h.upstream.requestCount() != 0 {
					t.Errorf("zero upstream forwarding for blocked DoH; got %d", h.upstream.requestCount())
				}
				ev := h.requireEvent(tlsproxy.EventPolicyDecision, host)
				if !strings.Contains(ev.Provenance.RuleID, "doh") {
					t.Errorf("block must carry DoH-specific rule provenance, got %q", ev.Provenance.RuleID)
				}
				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("control row: status = %d, want 200 (detection is content-shaped, not host-wide)", resp.StatusCode)
			}
			if h.upstream.requestCount() != 1 {
				t.Errorf("control request must reach upstream; got %d", h.upstream.requestCount())
			}
		})
	}
}

// testHTTPPolicyRateLimitIsolation — RateLimiter.Allow asserts per-session AND
// per-service bucket isolation and 429 + Retry-After: A→github is limited to N
// (N+1th is 429 with Retry-After), while A→npm and B→github are unaffected (a
// single shared counter would leak across buckets). Mirrors boundary
// TestRateLimit_PerSessionAndPerService_Isolated.
func testHTTPPolicyRateLimitIsolation(t *testing.T) {
	h := newHTTPPolicyHarness(t)
	sessA := tlsproxy.SessionRef{ID: "sess-a"}
	sessB := tlsproxy.SessionRef{ID: "sess-b"}
	const ghHost = "api.github.com"
	const npmHost = "registry.npmjs.org"
	const limitN = 3
	h.policy.allow(ghHost, npmHost)
	h.rate.setLimitFn(func(sess tlsproxy.SessionRef, svc string) int {
		if sess == sessA && strings.Contains(svc, "github") {
			return limitN
		}
		return 0
	})

	get := func(sess tlsproxy.SessionRef, host, path string) httpResult {
		t.Helper()
		resp, err := h.dispatch(sess, getR(host, path))
		if err != nil {
			t.Fatalf("GET %s%s (%s): %v", host, path, sess.ID, err)
		}
		return resp
	}

	// A → github: N allowed, N+1th refused with Retry-After.
	for i := 1; i <= limitN; i++ {
		if resp := get(sessA, ghHost, fmt.Sprintf("/a/%d", i)); resp.StatusCode != http.StatusOK {
			t.Fatalf("A->github request %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	over := get(sessA, ghHost, "/a/over")
	if over.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("A->github request %d: status %d, want 429", limitN+1, over.StatusCode)
	}
	if over.Header.Get("Retry-After") == "" {
		t.Error("rate refusal must carry Retry-After")
	}
	// The rate-refusal event must exist AND carry full POL-3 provenance.
	h.requireEvent("", "rate:")

	// Bucket isolation: A→npm and B→github are unaffected.
	for i := 1; i <= limitN; i++ {
		if resp := get(sessA, npmHost, fmt.Sprintf("/n/%d", i)); resp.StatusCode != http.StatusOK {
			t.Errorf("A->npm request %d throttled by A's github bucket: status %d", i, resp.StatusCode)
		}
		if resp := get(sessB, ghHost, fmt.Sprintf("/b/%d", i)); resp.StatusCode != http.StatusOK {
			t.Errorf("B->github request %d throttled by A's bucket: status %d", i, resp.StatusCode)
		}
	}
}

// testHTTPPolicyCapBreachHeld — CapMonitor.Record asserts action counting,
// suspend-action signaling, and that the breaching request is HELD: requests 1-5
// are unaffected (DELETE on a sensitive path, cap limit 5), request 6 trips the
// cap and the suspend signal fires BEFORE any byte of request 6 reaches the
// upstream. The BreachInfo carries the cap id + full provenance, and a
// BreachEvent is emitted. Mirrors boundary
// TestCap_BreachSuspendsMidAction_BreachingRequestHeld. ADVERSARIAL.
func testHTTPPolicyCapBreachHeld(t *testing.T) {
	h := newHTTPPolicyHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const host = "api.github.com"
	const capID = "cap:delete-5-per-hour"
	h.policy.allow(host)

	ord := &orderRecorder{}
	h.caps.configure(capID, 5, func(a tlsproxy.ResourceAction) bool { return a.Method == http.MethodDelete })
	h.suspend.order = ord
	h.upstream.order = ord
	h.upstream.label = "gh"

	del := func(i int) {
		_, _ = h.dispatch(sess, httpRequest{
			Method: http.MethodDelete, Host: host, Path: fmt.Sprintf("/repos/critical/branch-%d", i),
		})
	}

	// Requests 1-5: unaffected (counted at/under the cap; reach upstream).
	for i := 1; i <= 5; i++ {
		resp, err := h.dispatch(sess, httpRequest{
			Method: http.MethodDelete, Host: host, Path: fmt.Sprintf("/repos/critical/branch-%d", i),
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("DELETE %d must be unaffected: status=%v err=%v", i, resp.StatusCode, err)
		}
	}
	// Request 6 trips the cap: it must be HELD — suspend fires before any of its
	// bytes go upstream.
	del(6)

	calls := h.suspend.callList()
	if len(calls) != 1 {
		t.Fatalf("Suspend called %d times, want exactly 1", len(calls))
	}
	if calls[0].CapID != capID {
		t.Errorf("BreachInfo.CapID = %q, want %q", calls[0].CapID, capID)
	}
	requireHTTPProvenance(t, calls[0].Provenance)
	h.requireEvent(tlsproxy.EventBreach, capID)

	entries := ord.list()
	suspendIdx, req6Idx := -1, -1
	for i, e := range entries {
		if e == "suspend" && suspendIdx < 0 {
			suspendIdx = i
		}
		if strings.HasPrefix(e, "upstream:gh:6:") && req6Idx < 0 {
			req6Idx = i
		}
	}
	if suspendIdx < 0 {
		t.Fatal("suspend signal never observed in the ordering record")
	}
	if req6Idx >= 0 && req6Idx < suspendIdx {
		t.Errorf("the breaching request reached upstream BEFORE the suspend signal (upstream@%d, suspend@%d)", req6Idx, suspendIdx)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e, "upstream:gh:") && !strings.HasPrefix(e, "upstream:gh:6:") {
			n++
		}
	}
	if n != 5 {
		t.Errorf("requests 1-5 must all reach upstream; saw %d", n)
	}
}

// testHTTPPolicyCapResumeInvisible — once the orchestrator approves the suspend
// (the gate is released), the HELD breaching request completes with one normal
// 200 response: no 5xx, no reset, no retry — the resume is invisible to the
// agent. Mirrors boundary TestCap_ResumeInvisibleToAgent.
func testHTTPPolicyCapResumeInvisible(t *testing.T) {
	h := newHTTPPolicyHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const host = "api.github.com"
	h.policy.allow(host)
	// limit 0 ⇒ every matching action breaches immediately.
	h.caps.configure("cap:delete-5-per-hour", 0, func(a tlsproxy.ResourceAction) bool { return a.Method == http.MethodDelete })
	gate := make(chan struct{})
	h.suspend.gate = gate // Suspend blocks until the orchestrator "approves".

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.dispatch(sess, httpRequest{Method: http.MethodDelete, Host: host, Path: "/repos/critical/branch-x"})
		if err != nil {
			done <- result{0, err}
			return
		}
		done <- result{resp.StatusCode, nil}
	}()

	// Wait for the suspend signal (the request is paused at the breach point),
	// then approve + resume.
	select {
	case <-h.suspend.calledCh:
	case <-time.After(3 * time.Second):
		t.Fatal("suspend signal never fired for the breaching request")
	}
	// The held request must not have reached the upstream yet.
	if h.upstream.requestCount() != 0 {
		t.Fatalf("the breaching request reached upstream before resume; count=%d", h.upstream.requestCount())
	}
	close(gate)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("after resume the held request must complete with one normal response, got error: %v", r.err)
		}
		if r.status != http.StatusOK {
			t.Fatalf("after resume: status = %d, want 200 (no 5xx, no reset, no retry)", r.status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("held request never completed after resume")
	}
	if h.upstream.requestCount() != 1 {
		t.Errorf("the resumed request must reach upstream exactly once; got %d", h.upstream.requestCount())
	}
}

// testHTTPPolicyTelemetryMetadataOnly — TLS-6 telemetry is request metadata by
// default: the body sentinel of an allowed POST must appear in NO event. A
// policy that explicitly requires body examination fires with its provenance on
// the decision event (modeling "bodies only where policy requires"). Mirrors
// boundary TestTelemetry_MetadataOnlyByDefault_NoBodies.
func testHTTPPolicyTelemetryMetadataOnly(t *testing.T) {
	const host = "api.github.com"
	const sentinel = "BODY-SENTINEL-93cf1a77e2"

	// Run 1 — default policy: the body sentinel must appear in NO event.
	h := newHTTPPolicyHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	h.policy.allow(host)

	resp, err := h.dispatch(sess, httpRequest{
		Method: http.MethodPost, Host: host, Path: "/upload",
		Headers: map[string]string{"Content-Type": "text/plain"}, Body: sentinel,
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("default-policy POST: status=%d err=%v", resp.StatusCode, err)
	}
	h.requireEvent(tlsproxy.EventHTTP, "/upload") // metadata telemetry must exist…
	for _, ev := range h.events.all() {
		if strings.Contains(serializeEvent(ev), sentinel) {
			t.Errorf("default telemetry captured payload body bytes in a %s event", ev.Kind)
		}
	}

	// Run 2 — a policy that explicitly requires body examination: the examining
	// rule's provenance must appear on the decision event.
	h2 := newHTTPPolicyHarness(t)
	h2.policy.allow(host)
	h2.policy.setHTTPFn(func(req tlsproxy.RequestMeta) tlsproxy.Decision {
		if req.Path == "/upload" {
			return tlsproxy.Decision{Allow: true, Provenance: tlsproxy.Provenance{RuleID: "body-exam:flagged-content", PolicyLayer: "org", PolicyVersion: "policy-v1"}}
		}
		return tlsproxy.Decision{Allow: true, Provenance: tlsproxy.Provenance{RuleID: "http:default-allow", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
	})
	if _, err := h2.dispatch(sess, httpRequest{
		Method: http.MethodPost, Host: host, Path: "/upload",
		Headers: map[string]string{"Content-Type": "text/plain"}, Body: sentinel,
	}); err != nil {
		t.Fatalf("body-exam-policy POST: %v", err)
	}
	ev := h2.requireEvent(tlsproxy.EventHTTP, "/upload")
	if ev.Provenance.RuleID != "body-exam:flagged-content" {
		t.Errorf("the examining rule must fire with its provenance; RuleID = %q", ev.Provenance.RuleID)
	}
}
