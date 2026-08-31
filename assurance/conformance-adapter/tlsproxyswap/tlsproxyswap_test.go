// SPDX-License-Identifier: Apache-2.0

package tlsproxyswap

// tlsproxyswap_test.go — the conformance suite for the TLS-5 credential swap
// (D8), re-expressing the boundary/tlsproxy/tlsproxy_swap_test.go assertions
// against the real-plane-backed adapter seams (AdapterSwapEngine + collaborators).
// THE HEADLINE is TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep: zero
// long-lived credential bytes on ANY VM surface (response, env, disk, CoW delta)
// or in ANY event/log path after a swap. See doc.go for why this MIRRORS the
// boundary seam shapes (the swap tests + helpers are package-internal _test.go,
// not importable) rather than importing them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

func ctx() context.Context { return context.Background() }

// ───────────────────────────────────────────────────────────────────────────
// fake clock (logical advance, never sleeps) — mirrors the boundary fakeClock.
// ───────────────────────────────────────────────────────────────────────────

type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)}
}
func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// ───────────────────────────────────────────────────────────────────────────
// canary + leak helpers — mirror the boundary newCanary / requireNoCanary /
// requireZeroLeaks / encForms. A canary is a high-entropy hex needle usable as a
// leak target on any surface.
// ───────────────────────────────────────────────────────────────────────────

func newCanary(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, (n+1)/2)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("canary entropy: %v", err)
	}
	return []byte(hex.EncodeToString(raw))[:n]
}

// requireNoCanary asserts zero occurrences of the needle, in every encoded form,
// in hay.
func requireNoCanary(t *testing.T, hay, needle []byte, where string) {
	t.Helper()
	for form, enc := range EncodedForms(needle) {
		if bytes.Contains(hay, enc) {
			t.Errorf("%v: credential canary leaked (%s form) in %s", ErrCredentialLeaked, form, where)
		}
	}
}

// requireZeroLeaks runs the probe for every encoded form of the needle and
// asserts zero hits on every VM surface.
func requireZeroLeaks(t *testing.T, probe *AdapterLeakProbe, sess tlsproxy.SessionRef, needle []byte) {
	t.Helper()
	for form, enc := range EncodedForms(needle) {
		hits, err := probe.Search(ctx(), sess, enc)
		if err != nil {
			t.Fatalf("LeakProbe.Search(%s): %v", form, err)
		}
		for _, h := range hits {
			t.Errorf("%v: canary leaked (%s form) on VM surface %s at offset %d (%s)",
				ErrCredentialLeaked, form, h.Surface, h.Offset, h.Context)
		}
	}
}

func requireProvenance(t *testing.T, p tlsproxy.Provenance) {
	t.Helper()
	if p.RuleID == "" || p.PolicyLayer == "" || p.PolicyVersion == "" {
		t.Errorf("incomplete decision provenance (POL-3): %+v", p)
	}
}

// findEvent returns the first event (of kind, or any kind if kind=="") whose
// serialized form contains every substring.
func findEvent(evs []tlsproxy.Event, kind tlsproxy.EventKind, substrs ...string) (tlsproxy.Event, bool) {
	for _, ev := range evs {
		if kind != "" && ev.Kind != kind {
			continue
		}
		ser := string(serializeEvent(ev))
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
// swapHarness — the real-plane wiring (the Go mirror of the boundary
// newInspectHarness/setupSwap), assembling the AdapterSwapEngine over the real
// seams and exposing the same setup verbs the boundary swap tests use.
// ───────────────────────────────────────────────────────────────────────────

type swapHarness struct {
	t        *testing.T
	clock    *fakeClock
	policy   *AdapterPolicyEngine
	identity *AdapterIdentityValidator
	secrets  *AdapterSecretStore
	scrubber *AdapterScrubber
	events   *CapturingEventSink
	probe    *AdapterLeakProbe
	upstream *Upstream
	engine   *AdapterSwapEngine
}

func newSwapHarness(t *testing.T) *swapHarness {
	t.Helper()
	clock := newFakeClock()
	h := &swapHarness{
		t:        t,
		clock:    clock,
		policy:   NewPolicyEngine("policy-v1"),
		identity: NewIdentityValidator(clock.Now),
		secrets:  NewSecretStore(),
		scrubber: NewScrubber(),
		events:   NewCapturingEventSink(),
		probe:    NewLeakProbe(),
		upstream: NewUpstream(),
	}
	h.engine = &AdapterSwapEngine{
		Policy:   h.policy,
		Identity: h.identity,
		Secrets:  h.secrets,
		Scrubber: h.scrubber,
		Events:   h.events,
		Probe:    h.probe,
		Upstream: h.upstream,
		Now:      clock.Now,
	}
	return h
}

// setupSwap programs the full TLS-5 swap chain for one service and returns a
// valid short-lived credential for sess (mirrors the boundary setupSwap). Both
// credentials are registered with the scrubber (scrub BOTH on the VM-bound leg).
func (h *swapHarness) setupSwap(sess tlsproxy.SessionRef, service string, hosts []string, longLived []byte) tlsproxy.Credential {
	h.policy.Register(tlsproxy.ServiceRule{Service: service, Hosts: hosts, CredLocation: "header:Authorization"})
	short := h.identity.Mint(sess, service, time.Hour)
	h.secrets.Program(service, longLived)
	h.scrubber.Guard(longLived)
	h.scrubber.Guard([]byte(short.Value))
	return short
}

// dispatch drives one request through the engine.
func (h *swapHarness) dispatch(sess tlsproxy.SessionRef, req HTTPRequest) (SwapResult, error) {
	return h.engine.Dispatch(ctx(), sess, req)
}

func bearer(c tlsproxy.Credential) string { return "Bearer " + string(c.Value) }

func getReq(host, path string, headers map[string]string) HTTPRequest {
	return HTTPRequest{Method: "GET", Host: host, Path: path, Headers: headers}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5.1 — the swap itself: the upstream gets the long-lived credential, the VM
// never does (boundary TestSwap_GitHubToken_UpstreamGetsLongLived_VMNeverDoes).
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_GitHubToken_UpstreamGetsLongLived_VMNeverDoes(t *testing.T) {
	h := newSwapHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	short := h.setupSwap(sess, "github", []string{"api.github.com", "github.com"}, longLived)
	h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
		return UpstreamResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"login":"agent"}`)}
	})

	res, err := h.dispatch(sess, getReq("api.github.com", "/user", map[string]string{"Authorization": bearer(short)}))
	if err != nil {
		t.Fatalf("swapped request: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if !res.Swapped {
		t.Fatal("the request must have been swapped")
	}

	reqs := h.upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(reqs))
	}
	gotAuth := reqs[0].Headers["Authorization"]
	if !strings.Contains(gotAuth, string(longLived)) {
		t.Errorf("upstream Authorization must carry the long-lived credential; got %q", gotAuth)
	}
	if strings.Contains(gotAuth, string(short.Value)) {
		t.Errorf("the short-lived credential must not reach the upstream; got %q", gotAuth)
	}

	// The VM-side response never carries the long-lived value.
	requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "downstream response")
	h.probe.SnapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)

	ev, ok := findEvent(h.events.Events(), tlsproxy.EventCredentialUse, "github")
	if !ok {
		t.Fatal("a CredentialUseEvent for github must be emitted (LOG-5)")
	}
	if ev.Session != sess {
		t.Errorf("CredentialUseEvent session = %q, want %q", ev.Session.ID, sess.ID)
	}
	requireProvenance(t, ev.Provenance)
	if _, found := findEvent([]tlsproxy.Event{ev}, tlsproxy.EventCredentialUse, "fp-long-github"); !found {
		t.Error("CredentialUseEvent must carry the credential fingerprint fp-long-github")
	}
	requireNoCanary(t, serializeEvent(ev), longLived, "CredentialUseEvent")
}

// ───────────────────────────────────────────────────────────────────────────
// THE HEADLINE — the all-surfaces canary grep (boundary
// TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep). Every scenario tries to
// smuggle the canary onto a VM surface; the grep asserts zero hits.
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep(t *testing.T) {
	h := newSwapHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	short := h.setupSwap(sess, "github", []string{"api.github.com", "github.com"}, longLived)
	auth := map[string]string{"Authorization": bearer(short)}

	// 1 — happy-path swap: the positive leg (keeps the test RED against a
	// do-nothing stub that moves no bytes and trivially "leaks" nothing).
	t.Run("happy path swap", func(t *testing.T) {
		h.upstream.SetHandler(func(UpstreamRequest) UpstreamResponse {
			return UpstreamResponse{Status: 200, Body: []byte(`{"login":"agent"}`)}
		})
		res, err := h.dispatch(sess, getReq("api.github.com", "/user", auth))
		if err != nil || res.Status != 200 {
			t.Fatalf("happy path: status=%d err=%v", res.Status, err)
		}
		reqs := h.upstream.Requests()
		if len(reqs) == 0 || !strings.Contains(reqs[len(reqs)-1].Headers["Authorization"], string(longLived)) {
			t.Fatal("swap must have substituted the long-lived credential upstream")
		}
	})

	// 2 — upstream 401/500 echoing the swapped header in body and headers.
	t.Run("upstream error pages echo the credential", func(t *testing.T) {
		for _, status := range []int{401, 500} {
			h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
				a := req.Headers["Authorization"]
				return UpstreamResponse{Status: status, Headers: map[string]string{"X-Debug-Auth": a},
					Body: []byte(fmt.Sprintf(`{"error":"bad token","got":%q}`, a))}
			})
			res, err := h.dispatch(sess, getReq("api.github.com", "/user", auth))
			if err != nil {
				t.Fatalf("a readable (scrubbed) response is required, got transport failure: %v", err)
			}
			requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "echoed error page")
		}
	})

	// 3 — 3xx redirect chain carrying the credential in Location.
	t.Run("redirect chain", func(t *testing.T) {
		h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
			return UpstreamResponse{Status: 302, Headers: map[string]string{"Location": "https://api.github.com/login?token=" + req.Headers["Authorization"]}}
		})
		res, err := h.dispatch(sess, getReq("api.github.com", "/user", auth))
		if err != nil {
			t.Fatalf("redirect response must be delivered (scrubbed): %v", err)
		}
		requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "redirect Location")
	})

	// 4 — TRACE-style reflection of the full request.
	t.Run("TRACE-style reflection", func(t *testing.T) {
		h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
			var b bytes.Buffer
			fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.Path)
			for k, v := range req.Headers {
				fmt.Fprintf(&b, "%s: %s\r\n", k, v)
			}
			return UpstreamResponse{Status: 200, Headers: map[string]string{"Content-Type": "message/http"}, Body: b.Bytes()}
		})
		res, err := h.dispatch(sess, HTTPRequest{Method: "TRACE", Host: "api.github.com", Path: "/anything", Headers: auth})
		if err != nil {
			t.Fatalf("reflected response must be delivered (scrubbed): %v", err)
		}
		requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "TRACE reflection")
	})

	// 5 — oversized response with the canary echoed in the middle of a large body.
	t.Run("oversized response, canary embedded", func(t *testing.T) {
		h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
			pad := bytes.Repeat([]byte("A"), 64*1024)
			auth := []byte(req.Headers["Authorization"])
			full := append(append(append([]byte{}, pad...), auth...), pad...)
			return UpstreamResponse{Status: 200, Body: full}
		})
		res, err := h.dispatch(sess, getReq("api.github.com", "/big", auth))
		if err != nil {
			t.Fatalf("oversized response must be delivered (scrubbed): %v", err)
		}
		requireNoCanary(t, res.Body, longLived, "oversized body")
	})

	// 6 — proxy-generated error page (upstream dial fails mid-swap).
	t.Run("proxy-generated error page", func(t *testing.T) {
		h.upstream.FailDial(fmt.Errorf("upstream unreachable (injected)"))
		res, err := h.dispatch(sess, getReq("api.github.com", "/user", auth))
		if err != nil {
			t.Fatalf("the proxy must answer with its own error page, not a dead conn: %v", err)
		}
		if res.Status != 502 {
			t.Errorf("proxy error page status = %d, want 502", res.Status)
		}
		requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "proxy error page")
		h.upstream.FailDial(nil)
	})

	// 7 — the session survives a failed swap: the NEXT request still swaps.
	t.Run("session survives a failed swap", func(t *testing.T) {
		h.upstream.SetHandler(func(UpstreamRequest) UpstreamResponse {
			return UpstreamResponse{Status: 200, Body: []byte("ok")}
		})
		res, err := h.dispatch(sess, getReq("api.github.com", "/after-abort", auth))
		if err != nil || res.Status != 200 {
			t.Fatalf("the session must survive an aborted swap: status=%d err=%v", res.Status, err)
		}
	})

	// 8 — malformed upstream response embedding the canary in the body.
	t.Run("malformed upstream response", func(t *testing.T) {
		h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
			return UpstreamResponse{Status: 200, Body: []byte("NOT-HTTP-GARBAGE " + req.Headers["Authorization"])}
		})
		res, err := h.dispatch(sess, getReq("api.github.com", "/user", auth))
		if err != nil {
			t.Fatalf("malformed response must be delivered (scrubbed): %v", err)
		}
		requireNoCanary(t, res.Body, longLived, "malformed upstream body")
	})

	// THE GREP — zero canary occurrences (raw/base64/hex/url-encoded) on every VM
	// surface and in every event/log path.
	h.probe.SnapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)
	requireZeroLeaks(t, h.probe, sess, []byte(short.Value))
	requireNoCanary(t, serializeEvents(h.events.Events()), longLived, "captured events (long-lived)")
	requireNoCanary(t, serializeEvents(h.events.Events()), []byte(short.Value), "captured events (short-lived)")
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 — upstream echoes the credential: scrubbed or blocked, never delivered
// (boundary TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked).
// Encoded forms — including base64 — ARE in scope for the scrubber.
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked(t *testing.T) {
	rows := []struct {
		name    string
		handler func(longLived []byte) func(UpstreamRequest) UpstreamResponse
		encoded func([]byte) []byte
	}{
		{
			name: "echoed in response body",
			handler: func([]byte) func(UpstreamRequest) UpstreamResponse {
				return func(req UpstreamRequest) UpstreamResponse {
					return UpstreamResponse{Status: 200, Body: []byte(fmt.Sprintf(`{"headers":{"Authorization":%q}}`, req.Headers["Authorization"]))}
				}
			},
			encoded: func(c []byte) []byte { return c },
		},
		{
			name: "echoed in a response header",
			handler: func([]byte) func(UpstreamRequest) UpstreamResponse {
				return func(req UpstreamRequest) UpstreamResponse {
					return UpstreamResponse{Status: 200, Headers: map[string]string{"X-Echo-Auth": req.Headers["Authorization"]}, Body: []byte("ok")}
				}
			},
			encoded: func(c []byte) []byte { return c },
		},
		{
			name: "base64 of the credential (encoded forms in scope)",
			handler: func(longLived []byte) func(UpstreamRequest) UpstreamResponse {
				return func(req UpstreamRequest) UpstreamResponse {
					// Encode the BARE credential bytes (base64 of "Bearer "+cred would
					// phase-shift past base64(cred), hiding the staged leak).
					auth := []byte(req.Headers["Authorization"])
					echoed := auth
					if idx := bytes.Index(auth, longLived); idx >= 0 {
						echoed = auth[idx : idx+len(longLived)]
					}
					return UpstreamResponse{Status: 200, Body: []byte(fmt.Sprintf(`{"auth_b64":%q}`, base64.StdEncoding.EncodeToString(echoed)))}
				}
			},
			encoded: func(c []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(c)) },
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newSwapHarness(t)
			sess := tlsproxy.SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			short := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			h.upstream.SetHandler(row.handler(longLived))
			mark := len(h.events.Events())

			res, err := h.dispatch(sess, getReq("api.github.com", "/user", map[string]string{"Authorization": bearer(short)}))
			if err != nil {
				t.Fatalf("a readable scrubbed response is required: %v", err)
			}
			delivered := dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body)
			if bytes.Contains(delivered, row.encoded(longLived)) {
				t.Error("the echoed long-lived credential reached the VM in a readable response")
			}
			requireNoCanary(t, delivered, longLived, "delivered response")

			if _, ok := findEvent(h.events.Events()[mark:], tlsproxy.EventScrub); !ok {
				t.Error("a ScrubEvent must be emitted when an upstream echoes the credential")
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 — cross-session short-lived cred is rejected with NO secret-store fetch
// (boundary TestSwap_CrossSessionShortLivedCred_RejectedNoFetch).
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_CrossSessionShortLivedCred_RejectedNoFetch(t *testing.T) {
	h := newSwapHarness(t)
	sessA := tlsproxy.SessionRef{ID: "sess-a"}
	sessB := tlsproxy.SessionRef{ID: "sess-b"}
	longLived := newCanary(t, 64)
	shortA := h.setupSwap(sessA, "github", []string{"api.github.com"}, longLived)

	// Session B replays A's short-lived credential.
	res, err := h.dispatch(sessB, getReq("api.github.com", "/user", map[string]string{"Authorization": bearer(shortA)}))
	if err != nil {
		t.Fatalf("the refusal must be a readable 401/403, not a dead conn: %v", err)
	}
	if res.Status != 401 && res.Status != 403 {
		t.Fatalf("status = %d, want 401 or 403: A's credential must not swap on B", res.Status)
	}
	if n := h.secrets.FetchCount(); n != 0 {
		t.Errorf("SecretStore.FetchLongLived must NEVER be called on identity mismatch; calls=%d", n)
	}
	for _, r := range h.upstream.Requests() {
		if strings.Contains(r.Headers["Authorization"], string(longLived)) {
			t.Error("no swapped request may reach the upstream for a cross-session credential")
		}
	}
	ev, ok := findEvent(h.events.Events(), "", "identity mismatch")
	if !ok {
		t.Fatal("a deny event mentioning the identity mismatch must be emitted")
	}
	requireNoCanary(t, serializeEvent(ev), longLived, "identity-mismatch event (long-lived)")
	requireNoCanary(t, serializeEvent(ev), []byte(shortA.Value), "identity-mismatch event (short-lived)")
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 — invalid short-lived creds rejected with NO fetch (boundary
// TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven).
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven(t *testing.T) {
	rows := []struct {
		name string
		auth func(h *swapHarness, sess tlsproxy.SessionRef) string
	}{
		{"expired credential", func(h *swapHarness, sess tlsproxy.SessionRef) string {
			c := h.identity.Mint(sess, "github", time.Minute)
			h.clock.Advance(2 * time.Minute) // now expired under the fake clock
			return bearer(c)
		}},
		{"tampered signature", func(h *swapHarness, sess tlsproxy.SessionRef) string {
			c := h.identity.Mint(sess, "github", time.Hour)
			return bearer(tlsproxy.Credential{Value: tlsproxy.Secret(string(c.Value) + "-tampered")})
		}},
		{"random garbage token", func(*swapHarness, tlsproxy.SessionRef) string {
			return "Bearer garbage-aaaabbbbccccdddd"
		}},
		{"empty Authorization value", func(*swapHarness, tlsproxy.SessionRef) string {
			return ""
		}},
		{"credential minted for a different session", func(h *swapHarness, _ tlsproxy.SessionRef) string {
			other := h.identity.Mint(tlsproxy.SessionRef{ID: "sess-other"}, "github", time.Hour)
			return bearer(other)
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newSwapHarness(t)
			sess := tlsproxy.SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			_ = h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			fetchBefore := h.secrets.FetchCount()
			auth := row.auth(h, sess)

			res, err := h.dispatch(sess, getReq("api.github.com", "/user", map[string]string{"Authorization": auth}))
			if err != nil {
				t.Fatalf("the refusal must be a readable 4xx, not a dead conn: %v", err)
			}
			// An empty/absent credential is a no-swap (forward untouched) — the upstream
			// answers 200; a present-but-invalid credential is a 4xx deny. Either way
			// the secret store is NOT fetched and the long-lived credential never swaps.
			if auth != "" {
				if res.Status < 400 || res.Status > 499 {
					t.Fatalf("status = %d, want a 4xx refusal for a present invalid credential", res.Status)
				}
			}
			if n := h.secrets.FetchCount(); n != fetchBefore {
				t.Errorf("no secret-store fetch for an invalid credential; calls grew by %d", n-fetchBefore)
			}
			for _, r := range h.upstream.Requests() {
				if strings.Contains(r.Headers["Authorization"], string(longLived)) {
					t.Error("the long-lived credential must never be swapped in for an invalid cred")
				}
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 — no registry match (or credential in a non-registered location): the
// request is forwarded UNTOUCHED, validator + secret store never consulted
// (boundary TestSwap_NoRegistryMatch_RequestUntouched).
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_NoRegistryMatch_RequestUntouched(t *testing.T) {
	rows := []struct {
		name   string
		host   string
		header map[string]string
	}{
		{"allowed non-registry host with Authorization", "plain.example",
			map[string]string{"Authorization": "Bearer user-supplied-token-123"}},
		{"registry host, credential in a non-registered location (cookie)", "api.github.com",
			map[string]string{"Cookie": "session=user-cookie-credential-456"}},
		{"registry host, no credential present", "api.github.com", nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newSwapHarness(t)
			sess := tlsproxy.SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			_ = h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			h.upstream.SetHandler(func(UpstreamRequest) UpstreamResponse {
				return UpstreamResponse{Status: 200, Body: []byte("ok")}
			})

			res, err := h.dispatch(sess, getReq(row.host, "/data", row.header))
			if err != nil || res.Status != 200 {
				t.Fatalf("non-swap request must pass through: status=%d err=%v", res.Status, err)
			}
			if res.Swapped {
				t.Error("a non-registry / non-located request must NOT be swapped")
			}
			reqs := h.upstream.Requests()
			if len(reqs) != 1 {
				t.Fatalf("upstream saw %d requests, want 1", len(reqs))
			}
			for k, v := range row.header {
				if got := reqs[0].Headers[k]; got != v {
					t.Errorf("header %s must arrive upstream byte-identical: got %q want %q", k, got, v)
				}
			}
			if _, ok := row.header["Authorization"]; !ok {
				if got := reqs[0].Headers["Authorization"]; got != "" {
					t.Errorf("no Authorization may be fabricated; upstream got %q", got)
				}
			}
			if n := h.identity.CallCount(); n != 0 {
				t.Errorf("IdentityValidator must not be called without a registry+location match; calls=%d", n)
			}
			if n := h.secrets.FetchCount(); n != 0 {
				t.Errorf("SecretStore must not be called without a registry+location match; calls=%d", n)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 — every log path scrubbed, fingerprint only (boundary
// TestSwap_EveryLogPathScrubbed_FingerprintOnly + LOG-5).
// ───────────────────────────────────────────────────────────────────────────

func TestSwap_EveryLogPathScrubbed_FingerprintOnly(t *testing.T) {
	h := newSwapHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	short := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
	authHdr := map[string]string{"Authorization": bearer(short)}

	// Path 1 — swap success.
	h.upstream.SetHandler(func(UpstreamRequest) UpstreamResponse { return UpstreamResponse{Status: 200, Body: []byte("ok")} })
	if _, err := h.dispatch(sess, getReq("api.github.com", "/user", authHdr)); err != nil {
		t.Fatalf("swap success path: %v", err)
	}
	// Path 2 — swap failure (forged cred).
	_, _ = h.dispatch(sess, getReq("api.github.com", "/user", map[string]string{"Authorization": "Bearer forged-cred-zzz"}))
	// Path 3 — upstream error after swap.
	h.upstream.FailDial(fmt.Errorf("upstream connect refused (injected)"))
	_, _ = h.dispatch(sess, getReq("api.github.com", "/user", authHdr))
	h.upstream.FailDial(nil)
	// Path 4 — scrubber hit (upstream echoes the swapped credential).
	h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
		return UpstreamResponse{Status: 200, Body: []byte("echo:" + req.Headers["Authorization"])}
	})
	_, _ = h.dispatch(sess, getReq("api.github.com", "/user", authHdr))

	evs := h.events.Events()
	if len(evs) == 0 {
		t.Fatal("the driven paths must emit telemetry; zero events captured")
	}
	ser := serializeEvents(evs)
	requireNoCanary(t, ser, longLived, "captured events (long-lived)")
	requireNoCanary(t, ser, []byte(short.Value), "captured events (short-lived)")

	ev, ok := findEvent(evs, tlsproxy.EventCredentialUse, "github")
	if !ok {
		t.Fatal("a CredentialUseEvent must be emitted on the swap-success path")
	}
	if ev.Fields["fingerprint"] != "fp-long-github" {
		t.Errorf("CredentialUseEvent must carry the expected fingerprint fp-long-github; fields=%v", ev.Fields)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-5 e2e — a GitHub push works with ONLY a short-lived credential in the VM
// (boundary TestE2E_GitHubPushWithOnlyShortLivedCredInVM).
// ───────────────────────────────────────────────────────────────────────────

func TestE2E_GitHubPushWithOnlyShortLivedCredInVM(t *testing.T) {
	h := newSwapHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	short := h.setupSwap(sess, "github", []string{"github.com", "api.github.com"}, longLived)

	const unpackOK = "000eunpack ok\n0000"
	// The fake GitHub accepts ONLY the long-lived canary on git-receive-pack.
	h.upstream.SetHandler(func(req UpstreamRequest) UpstreamResponse {
		if !strings.HasSuffix(req.Path, "/git-receive-pack") {
			return UpstreamResponse{Status: 404}
		}
		if !strings.Contains(req.Headers["Authorization"], string(longLived)) {
			return UpstreamResponse{Status: 401}
		}
		return UpstreamResponse{Status: 200, Body: []byte(unpackOK)}
	})

	// git push over HTTPS: the inspected inner request carries the short-lived
	// credential — the only credential the VM holds.
	res, err := h.dispatch(sess, HTTPRequest{
		Method: "POST", Host: "github.com", Path: "/org/repo.git/git-receive-pack",
		Headers: map[string]string{"Authorization": bearer(short)},
	})
	if err != nil {
		t.Fatalf("git push round trip: %v", err)
	}
	if res.Status != 200 || string(res.Body) != unpackOK {
		t.Fatalf("push must succeed via the swapped credential: status=%d body=%q", res.Status, res.Body)
	}

	// No long-lived credential on any VM surface.
	h.probe.SnapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)
	requireNoCanary(t, serializeEvents(h.events.Events()), longLived, "captured events")

	// LOG-5: which session used the GitHub key, when, for what request.
	ev, ok := findEvent(h.events.Events(), tlsproxy.EventCredentialUse, "github", "git-receive-pack")
	if !ok {
		t.Fatal("a CredentialUseEvent must attribute the git-receive-pack swap to the session (LOG-5)")
	}
	if ev.Session != sess {
		t.Errorf("credential-use attribution: session = %q, want %q", ev.Session.ID, sess.ID)
	}
	if !ev.At.Equal(h.clock.Now()) {
		t.Errorf("credential-use timestamp must come from the injected clock: got %v want %v", ev.At, h.clock.Now())
	}
}

// ───────────────────────────────────────────────────────────────────────────
// DOUBLE-FIRE (D132) — the SWAP side of the TLS-5/TLS-7 ordering invariant.
//
// planRef: doc 12 §13.3 / §5.3 (D132 — TLS-5/TLS-7 filter ordering FROZEN:
// scan-before-swap on the inspected path); doc 04 §6 D132; doc 12 §13.6 OQ2
// (closed). It re-expresses the boundary row boundary/tlsproxy/tlsproxy_scan_-
// test.go: TestSwap_TLS5_InjectedAuthHeader_NeverScannedAfterSubstitution against
// the REAL swap engine (AdapterSwapEngine).
//
// THE CORE OQ2 REQUIREMENT: the TLS-5 credential swap and the TLS-7 scan do not
// double-fire on the same Authorization header. The scan ALWAYS runs BEFORE the
// swap (D132), so the scan reads the AGENT-PRESENTED bytes, and the long-lived
// credential the swap substitutes onto the UPSTREAM-bound request is NEVER on the
// bytes the scan saw.
//
// This SWAP-side mirror drives the real engine and proves the byte-provenance the
// invariant rests on:
//
//   (a) a canary that LOOKS LIKE a valid credential is planted as the long-lived
//       secret the swap fetches and injects;
//   (b) the engine substitutes it onto the UPSTREAM request's Authorization header
//       (the post-swap surface) — NEVER onto the agent-presented request;
//   (c) the TLS-7 scan, which by D132 reads the AGENT-PRESENTED (pre-swap) bytes,
//       does NOT see the injected long-lived credential — so the swap and the scan
//       never double-fire on the shared header.
//
// scanAgentPresentedBytes models the TLS-7 scan reading the request the AGENT
// presented (pre-swap) — the bytes D132 guarantees the scan sees. It looks for the
// injected long-lived credential and reports whether it would have matched it (the
// double-fire condition).
// ───────────────────────────────────────────────────────────────────────────

// scanAgentPresentedBytes is the conformance stand-in for the TLS-7 scan reading
// the agent-presented request (pre-swap). It returns true iff the long-lived
// credential is present on those bytes — i.e. iff the scan WOULD double-fire on the
// swap-injected credential. By D132 (scan-before-swap) it must always return false.
func scanAgentPresentedBytes(req HTTPRequest, longLived []byte) bool {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.Path, req.Host)
	for k, v := range req.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	return bytes.Contains(b.Bytes(), longLived)
}

func TestSwap_TLS5InjectedAuthHeader_NeverScannedAfterSubstitution(t *testing.T) {
	h := newSwapHarness(t)
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	// (a) The long-lived credential the swap fetches + injects is a canary that
	// looks like valid credential text — were the scan to run on the post-swap
	// header, it would flag exactly this value.
	longLived := newCanary(t, 64)
	short := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)

	// The AGENT-PRESENTED request: it carries ONLY the short-lived credential. This
	// is the request the TLS-7 scan reads (pre-swap, D132).
	agentReq := getReq("api.github.com", "/user", map[string]string{"Authorization": bearer(short)})

	// (c.1) BEFORE dispatch: the scan over the agent-presented bytes must not see the
	// injected long-lived credential — it is not there yet, and never will be on this
	// surface.
	if scanAgentPresentedBytes(agentReq, longLived) {
		t.Fatal("the swap-injected long-lived credential must NOT be on the agent-presented bytes the scan reads (D132 scan-before-swap)")
	}

	res, err := h.dispatch(sess, agentReq)
	if err != nil {
		t.Fatalf("swapped request: %v", err)
	}
	if !res.Swapped || res.Status != 200 {
		t.Fatalf("the request must swap and succeed: swapped=%v status=%d", res.Swapped, res.Status)
	}

	// (b) The engine substituted the long-lived credential onto the UPSTREAM-bound
	// request — the post-swap surface, never the agent-presented one.
	reqs := h.upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(reqs))
	}
	upstreamAuth := reqs[len(reqs)-1].Headers["Authorization"]
	if !strings.Contains(upstreamAuth, string(longLived)) {
		t.Fatalf("the swap must inject the long-lived credential onto the UPSTREAM header; got %q", upstreamAuth)
	}
	if strings.Contains(upstreamAuth, string(short.Value)) {
		t.Errorf("the short-lived credential must not reach the upstream after the swap; got %q", upstreamAuth)
	}

	// (c.2) AFTER dispatch: dispatch must NOT have mutated the agent-presented
	// request's Authorization header (the swap substitutes IN A CLONE onto the
	// upstream leg — the agent-presented bytes the scan read are untouched). So a
	// re-scan of the agent-presented request still does not see the injected
	// credential: the scan and the swap never double-fire on the shared header.
	if got := agentReq.Headers["Authorization"]; got != bearer(short) {
		t.Errorf("dispatch must not mutate the agent-presented Authorization header (scan reads it pre-swap); got %q want %q", got, bearer(short))
	}
	if scanAgentPresentedBytes(agentReq, longLived) {
		t.Fatal("double-fire: the injected long-lived credential appeared on the agent-presented bytes after dispatch (D132 violated)")
	}

	// (c.3) The DUAL keeping (c) honest: the scan IS capable of catching the
	// long-lived credential — were it ever on the agent-presented bytes (it is not,
	// by D132), the scan would flag it. We prove capability by scanning a request
	// that DOES carry it.
	postSwapReq := getReq("api.github.com", "/user", map[string]string{"Authorization": "Bearer " + string(longLived)})
	if !scanAgentPresentedBytes(postSwapReq, longLived) {
		t.Fatal("the scan stand-in must be CAPABLE of matching the long-lived credential (proving (c) is not vacuous)")
	}

	// And the headline holds: the long-lived credential never reached any VM surface.
	requireNoCanary(t, dumpResponse(&tlsproxy.ResponseMeta{Status: res.Status, Headers: res.Headers}, res.Body), longLived, "downstream response")
	h.probe.SnapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)
}

// ───────────────────────────────────────────────────────────────────────────
// Sentinel-universe completeness (mirrors tlsproxyinspect): the Err* convention
// is load-bearing; these AST tests keep the universe honest.
// ───────────────────────────────────────────────────────────────────────────

// exportedSentinelUniverse is the authoritative set of this package's exported
// reject-cause sentinels. Every `Err* = errors.New(...)` var in a non-_test.go
// file must appear here, and every name here must exist in source.
var exportedSentinelUniverse = map[string]error{
	"ErrNoSwapRule":        ErrNoSwapRule,
	"ErrIdentityRejected":  ErrIdentityRejected,
	"ErrSecretUnavailable": ErrSecretUnavailable,
	"ErrCredentialLeaked":  ErrCredentialLeaked,
}

func nonTestGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, n)
	}
	return files
}

// TestExportedSentinelUniverseComplete reconciles exportedSentinelUniverse
// against source by parsing the `Err* = errors.New(...)` var specs.
func TestExportedSentinelUniverseComplete(t *testing.T) {
	found := map[string]bool{}
	for _, file := range nonTestGoFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !name.IsExported() || !strings.HasPrefix(name.Name, "Err") {
						continue
					}
					if i >= len(vs.Values) || !isErrorsNew(vs.Values[i]) {
						continue
					}
					found[name.Name] = true
					if _, ok := exportedSentinelUniverse[name.Name]; !ok {
						t.Errorf("exported sentinel %s (errors.New) in %s is missing from exportedSentinelUniverse", name.Name, file)
					}
				}
			}
		}
	}
	for name := range exportedSentinelUniverse {
		if !found[name] {
			t.Errorf("exportedSentinelUniverse names %s, but no `%s = errors.New(...)` var was found in source", name, name)
		}
	}
}

// TestExportedErrorVarsCoveredByUniverse is the naming-agnostic backstop: it
// flags ANY exported error-constructing var (errors.New or fmt.Errorf) missing
// from the universe, so a sentinel that BROKE the Err* convention cannot slip
// past the by-name scan.
func TestExportedErrorVarsCoveredByUniverse(t *testing.T) {
	for _, file := range nonTestGoFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !name.IsExported() || i >= len(vs.Values) {
						continue
					}
					if !isErrorConstructor(vs.Values[i]) {
						continue
					}
					if _, ok := exportedSentinelUniverse[name.Name]; !ok {
						t.Errorf("exported error-constructing var %s in %s is missing from exportedSentinelUniverse (sentinel convention: name it Err* and add it)", name.Name, file)
					}
				}
			}
		}
	}
}

// isErrorsNew reports whether expr is an `errors.New(...)` call.
func isErrorsNew(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}

// isErrorConstructor reports whether expr is an `errors.New(...)` or
// `fmt.Errorf(...)` call — the naming-agnostic backstop's recognizer.
func isErrorConstructor(expr ast.Expr) bool {
	if isErrorsNew(expr) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "fmt" && sel.Sel.Name == "Errorf"
}

// ───────────────────────────────────────────────────────────────────────────
// Live half env-gate (mirrors tlsproxyinspect live_test.go): DEFERRED MANUAL,
// gated behind DS_TLS5_LIVE=1, SKIPPED BY DEFAULT so `go test ./...` is green
// offline and in CI.
// ───────────────────────────────────────────────────────────────────────────

func requireLive(t *testing.T) {
	t.Helper()
	if !LiveEnabled() {
		t.Skipf("live TLS-5 conformance is a deferred manual pass; set %s=1 to run a git push through a running ds-tlsproxy at %s (default skip)",
			LiveEnvVar, LiveTargetFromEnv().TLSProxyAddr)
	}
}

// liveCase is one documented over-the-wire row.
type liveCase struct {
	Name   string
	Runner string
	Want   string
	Why    string
}

func liveCases() []liveCase {
	return []liveCase{
		{
			Name:   "5-git-push-to-real-github-only-shortlived-in-vm",
			Runner: "git-push-credential-swap",
			Want:   "git push over HTTPS to real GitHub succeeds through the egress gateway; the VM held only a short-lived credential; zero long-lived bytes on any VM surface",
			Why:    "doc 09 §5 TLS-5 done-when: push to GitHub works end to end; doc 06 §3(c): long-lived credential never enters the VM",
		},
	}
}

type liveRunner func(t *testing.T, c liveCase, target LiveTarget)

// notYetWired is the placeholder body for every runner. It fails loudly so a
// half-configured live run can never look like a pass (HONEST STATUS).
func notYetWired(t *testing.T, c liveCase, target LiveTarget) {
	t.Helper()
	t.Fatalf("live runner %q (case %q) is a DEFERRED MANUAL step: wire it against a running ds-tlsproxy at %s "+
		"(no live git push to real GitHub from CI). Expected: %s. Why: %s",
		c.Runner, c.Name, target.TLSProxyAddr, c.Want, c.Why)
}

func liveRunners() map[string]liveRunner {
	return map[string]liveRunner{
		"git-push-credential-swap": notYetWired,
	}
}

// TestLive_SwapConformance drives every over-the-wire TLS-5 row under
// DS_TLS5_LIVE=1. Skipped by default.
func TestLive_SwapConformance(t *testing.T) {
	requireLive(t)
	target := LiveTargetFromEnv()
	runners := liveRunners()
	for _, c := range liveCases() {
		t.Run(c.Name, func(t *testing.T) {
			run, ok := runners[c.Runner]
			if !ok {
				t.Fatalf("live case %q names runner %q with no implementation registered", c.Name, c.Runner)
			}
			run(t, c, target)
		})
	}
}

// TestLiveGateDefaultsOff is a guard that ALWAYS runs: it asserts the gate is
// named DS_TLS5_LIVE and is disabled by default. It never touches the network.
func TestLiveGateDefaultsOff(t *testing.T) {
	if LiveEnvVar != "DS_TLS5_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_TLS5_LIVE", LiveEnvVar)
	}
	switch os.Getenv(LiveEnvVar) {
	case "":
		if LiveEnabled() {
			t.Error("DS_TLS5_LIVE unset but LiveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !LiveEnabled() {
			t.Error("DS_TLS5_LIVE=1 but LiveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveRunnerCoverage asserts every live case names a registered runner and no
// registered runner is orphaned. Runs WITHOUT the live gate.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	named := map[string]bool{}
	for _, c := range liveCases() {
		if c.Runner == "" {
			t.Errorf("live case %q names no runner", c.Name)
			continue
		}
		named[c.Runner] = true
		if _, ok := runners[c.Runner]; !ok {
			t.Errorf("live case %q names runner %q with no registered implementation", c.Name, c.Runner)
		}
	}
	for name := range runners {
		if !named[name] {
			t.Errorf("registered runner %q is not referenced by any live case", name)
		}
	}
}
