package tlsproxy

// TLS-6 — HTTP-level policy, rate limits, behavioral caps + suspend-on-breach,
// DoH-on-allowed-host detection, and metadata-only telemetry (doc 09 §5 TLS-6).

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// planRef: doc 09 §5 TLS-6 (method/host/path rules)
func TestHTTPPolicy_MethodHostPathRules_TableDriven(t *testing.T) {
	const host = "api.github.com"
	httpFn := func(req RequestMeta) Decision {
		deny := func(rule, layer string) Decision {
			return Decision{Allow: false, Provenance: Provenance{RuleID: rule, PolicyLayer: layer, PolicyVersion: "policy-v1"}}
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
			return Decision{Allow: true, Provenance: Provenance{RuleID: "http:allow-get", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
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
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			h.policy.allow(host)
			h.policy.httpFn = httpFn
			h.admit(sess, host, time.Hour, ip("140.82.1.1"))
			up := &recordingUpstream{}
			h.dialer.tlsFn = up.dialTLS

			resp, _, err := h.inspectRequest(sess, host, ap("140.82.1.1:443"),
				newReq(t, row.method, "https://"+host+row.path, nil, ""))
			if err != nil {
				t.Fatalf("request must get a readable verdict: %v", err)
			}
			if row.allow {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("allowed row: status = %d, want 200", resp.StatusCode)
				}
				if up.requestCount() != 1 {
					t.Errorf("allowed request must reach upstream exactly once; got %d", up.requestCount())
				}
			} else {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("denied row: status = %d, want 403", resp.StatusCode)
				}
				if up.requestCount() != 0 {
					t.Errorf("denied request must NEVER reach upstream; got %d", up.requestCount())
				}
				ev := h.requireEvent(EventPolicyDecision, row.path)
				if ev.Provenance.RuleID != row.wantRule {
					t.Errorf("PolicyDecision RuleID = %q, want %q", ev.Provenance.RuleID, row.wantRule)
				}
			}
		})
	}
}

// planRef: doc 09 §5 TLS-6 (per-session and per-service rate limits)
func TestRateLimit_PerSessionAndPerService_Isolated(t *testing.T) {
	h := newInspectHarness(t)
	sessA := SessionRef{ID: "sess-a"}
	sessB := SessionRef{ID: "sess-b"}
	const ghHost = "api.github.com"
	const npmHost = "registry.npmjs.org"
	const limitN = 3
	h.policy.allow(ghHost, npmHost)
	for _, s := range []SessionRef{sessA, sessB} {
		h.admit(s, ghHost, time.Hour, ip("140.82.1.1"))
		h.admit(s, npmHost, time.Hour, ip("104.16.0.1"))
	}
	h.rate.limitFn = func(sess SessionRef, service string) int {
		if sess == sessA && strings.Contains(service, "github") {
			return limitN
		}
		return 0
	}
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	// Per-host original destinations matching the DNS-2b admissions above: a
	// single hard-coded origDst would make every A->npm flow refusable by a
	// CORRECT proxy (104.16.0.1 is npm's admission, 140.82.1.1 is github's).
	dstFor := map[string]netip.AddrPort{
		ghHost:  ap("140.82.1.1:443"),
		npmHost: ap("104.16.0.1:443"),
	}
	get := func(sess SessionRef, host, path string) *http.Response {
		t.Helper()
		resp, _, err := h.inspectRequest(sess, host, dstFor[host],
			newReq(t, http.MethodGet, "https://"+host+path, nil, ""))
		if err != nil {
			t.Fatalf("GET %s%s (%s): %v", host, path, sess.ID, err)
		}
		return resp
	}

	// A -> github: N allowed, N+1th refused with RetryAfter.
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

	// Bucket isolation: A->npm and B->github are unaffected.
	for i := 1; i <= limitN; i++ {
		if resp := get(sessA, npmHost, fmt.Sprintf("/n/%d", i)); resp.StatusCode != http.StatusOK {
			t.Errorf("A->npm request %d throttled by A's github bucket: status %d", i, resp.StatusCode)
		}
		if resp := get(sessB, ghHost, fmt.Sprintf("/b/%d", i)); resp.StatusCode != http.StatusOK {
			t.Errorf("B->github request %d throttled by A's bucket: status %d", i, resp.StatusCode)
		}
	}
}

// planRef: doc 09 §5 TLS-6 Done-when; §9 row "Suspend-on-breach fires";
// doc 06 §3(c) suspend row (5-deletions/hour cap). ADVERSARIAL.
func TestCap_BreachSuspendsMidAction_BreachingRequestHeld(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const host = "api.github.com"
	const capID = "cap:delete-5-per-hour"
	h.policy.allow(host)
	h.admit(sess, host, time.Hour, ip("140.82.1.1"))

	ord := &orderRecorder{}
	h.caps.capID = capID
	h.caps.limit = 5
	h.caps.match = func(a ResourceAction) bool { return a.Method == http.MethodDelete }
	h.suspend.order = ord
	up := &recordingUpstream{order: ord, label: "gh"}
	h.dialer.tlsFn = up.dialTLS

	// Requests 1-5: unaffected.
	for i := 1; i <= 5; i++ {
		resp, _, err := h.inspectRequest(sess, host, ap("140.82.1.1:443"),
			newReq(t, http.MethodDelete, fmt.Sprintf("https://%s/repos/critical/branch-%d", host, i), nil, ""))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("DELETE %d must be unaffected: status=%v err=%v", i, resp, err)
		}
	}
	// Request 6 trips the cap: it must be HELD — suspend fires before any of
	// its bytes go upstream. (The response may or may not complete here.)
	_, _, _ = h.inspectRequest(sess, host, ap("140.82.1.1:443"),
		newReq(t, http.MethodDelete, "https://"+host+"/repos/critical/branch-6", nil, ""))

	calls := h.suspend.callList()
	if len(calls) != 1 {
		t.Fatalf("Suspend called %d times, want exactly 1", len(calls))
	}
	if calls[0].CapID != capID {
		t.Errorf("BreachInfo.CapID = %q, want %q", calls[0].CapID, capID)
	}
	requireProvenance(t, calls[0].Provenance)
	h.requireEvent(EventBreach, capID)

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
	if n := 0; true {
		for _, e := range entries {
			if strings.HasPrefix(e, "upstream:gh:") && !strings.HasPrefix(e, "upstream:gh:6:") {
				n++
			}
		}
		if n != 5 {
			t.Errorf("requests 1-5 must all reach upstream; saw %d", n)
		}
	}
}

// planRef: doc 09 §5 TLS-6 Done-when (resume is invisible to the agent); §9
// suspend row second half; doc 03 §7.
func TestCap_ResumeInvisibleToAgent(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const host = "api.github.com"
	h.policy.allow(host)
	h.admit(sess, host, time.Hour, ip("140.82.1.1"))
	h.caps.capID = "cap:delete-5-per-hour"
	h.caps.limit = 0 // every matching action breaches immediately
	h.caps.match = func(a ResourceAction) bool { return a.Method == http.MethodDelete }
	gate := make(chan struct{})
	h.suspend.gate = gate // Suspend blocks until the orchestrator "approves"
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, _, err := h.inspectRequest(sess, host, ap("140.82.1.1:443"),
			newReq(t, http.MethodDelete, "https://"+host+"/repos/critical/branch-x", nil, ""))
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
	case <-time.After(ioTimeout):
		t.Fatal("suspend signal never fired for the breaching request")
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
	case <-time.After(ioTimeout):
		t.Fatal("held request never completed after resume")
	}
}

// planRef: doc 09 §5 TLS-6 (DoH on otherwise-allowed hosts detected/blocked
// at HTTP level); §9 row "DoH endpoint blocking (HTTP-level half)"; NFT-4
// layering. ADVERSARIAL.
func TestDoH_OnAllowedHost_DetectedAndBlocked(t *testing.T) {
	const host = "cdn.allowed.example"
	dohPolicy := func(req RequestMeta) Decision {
		deny := Decision{Allow: false, Provenance: Provenance{RuleID: "doh:content-shape", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		switch {
		case req.Headers["Content-Type"] == "application/dns-message",
			strings.Contains(req.Path, "dns="),
			req.Headers["Accept"] == "application/dns-json":
			return deny
		default:
			return Decision{Allow: true, Provenance: Provenance{RuleID: "http:default-allow", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		}
	}
	rows := []struct {
		name    string
		req     func(t *testing.T) *http.Request
		blocked bool
	}{
		{"POST application/dns-message", func(t *testing.T) *http.Request {
			return newReq(t, http.MethodPost, "https://"+host+"/resolve",
				map[string]string{"Content-Type": "application/dns-message"}, "\x00\x01dns-wire")
		}, true},
		{"GET ?dns=<base64url>", func(t *testing.T) *http.Request {
			return newReq(t, http.MethodGet, "https://"+host+"/query?dns=AAABAAABAAAAAAAA", nil, "")
		}, true},
		{"Accept: application/dns-json", func(t *testing.T) *http.Request {
			return newReq(t, http.MethodGet, "https://"+host+"/lookup?name=example.com",
				map[string]string{"Accept": "application/dns-json"}, "")
		}, true},
		{"control: ordinary JSON POST to the same host", func(t *testing.T) *http.Request {
			return newReq(t, http.MethodPost, "https://"+host+"/api",
				map[string]string{"Content-Type": "application/json"}, `{"ok":true}`)
		}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			h.policy.allow(host)
			h.policy.httpFn = dohPolicy
			h.admit(sess, host, time.Hour, ip("151.101.1.1"))
			up := &recordingUpstream{}
			h.dialer.tlsFn = up.dialTLS

			resp, _, err := h.inspectRequest(sess, host, ap("151.101.1.1:443"), row.req(t))
			if err != nil {
				t.Fatalf("request must get a readable verdict: %v", err)
			}
			if row.blocked {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("DoH-shaped request: status = %d, want 403", resp.StatusCode)
				}
				if up.requestCount() != 0 {
					t.Errorf("zero upstream forwarding for blocked DoH; got %d", up.requestCount())
				}
				ev := h.requireEvent(EventPolicyDecision, host)
				if !strings.Contains(ev.Provenance.RuleID, "doh") {
					t.Errorf("block must carry DoH-specific rule provenance, got %q", ev.Provenance.RuleID)
				}
			} else {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("control row: status = %d, want 200 (detection is content-shaped, not host-wide)", resp.StatusCode)
				}
				if up.requestCount() != 1 {
					t.Errorf("control request must reach upstream; got %d", up.requestCount())
				}
			}
		})
	}
}

// planRef: doc 09 §5 TLS-6 (telemetry is request metadata by default; bodies
// only where policy requires). Body examination is modeled at the decision
// level: the structural guarantee under test is that DEFAULT telemetry never
// contains payload bytes.
func TestTelemetry_MetadataOnlyByDefault_NoBodies(t *testing.T) {
	const host = "api.github.com"
	const sentinel = "BODY-SENTINEL-93cf1a77e2"

	// Run 1 — default policy: the body sentinel must appear in NO event.
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow(host)
	h.admit(sess, host, time.Hour, ip("140.82.1.1"))
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	resp, _, err := h.inspectRequest(sess, host, ap("140.82.1.1:443"),
		newReq(t, http.MethodPost, "https://"+host+"/upload",
			map[string]string{"Content-Type": "text/plain"}, sentinel))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("default-policy POST: status=%v err=%v", resp, err)
	}
	h.requireEvent(EventHTTP, "/upload") // metadata telemetry must exist…
	if ev, found := findEventContaining(h.events.all(), "", sentinel); found {
		t.Errorf("default telemetry captured payload body bytes in a %s event", ev.Kind)
	}

	// Run 2 — a policy that explicitly requires body examination: the
	// examining rule's provenance must appear on the decision event.
	h2 := newInspectHarness(t)
	h2.policy.allow(host)
	h2.admit(sess, host, time.Hour, ip("140.82.1.1"))
	h2.policy.httpFn = func(req RequestMeta) Decision {
		if req.Path == "/upload" {
			return Decision{Allow: true, Provenance: Provenance{RuleID: "body-exam:flagged-content", PolicyLayer: "org", PolicyVersion: "policy-v1"}}
		}
		return Decision{Allow: true, Provenance: Provenance{RuleID: "http:default-allow", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
	}
	up2 := &recordingUpstream{}
	h2.dialer.tlsFn = up2.dialTLS
	if _, _, err := h2.inspectRequest(sess, host, ap("140.82.1.1:443"),
		newReq(t, http.MethodPost, "https://"+host+"/upload",
			map[string]string{"Content-Type": "text/plain"}, sentinel)); err != nil {
		t.Fatalf("body-exam-policy POST: %v", err)
	}
	ev := h2.requireEvent(EventPolicyDecision, "/upload")
	if ev.Provenance.RuleID != "body-exam:flagged-content" {
		t.Errorf("the examining rule must fire with its provenance; RuleID = %q", ev.Provenance.RuleID)
	}
}
