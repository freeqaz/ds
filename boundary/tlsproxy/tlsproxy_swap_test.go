package tlsproxy

// TLS-5 — the credential swap (D8): the long-lived credential never enters
// the VM. THE HEADLINE is TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// planRef: doc 09 §5 TLS-5 (swap rules in service registry; substitute
// upstream); doc 05 M1 first service.
func TestSwap_GitHubToken_UpstreamGetsLongLived_VMNeverDoes(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	up, short := h.setupSwap(sess, "github", []string{"api.github.com", "github.com"}, longLived)

	resp, body, err := h.inspectRequest(sess, "api.github.com", ap("140.82.1.1:443"),
		newReq(t, http.MethodGet, "https://api.github.com/user",
			map[string]string{"Authorization": bearer(short)}, ""))
	if err != nil {
		t.Fatalf("swapped request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	reqs := up.requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(reqs))
	}
	gotAuth := reqs[0].Header.Get("Authorization")
	if !strings.Contains(gotAuth, string(longLived)) {
		t.Errorf("upstream Authorization must carry the long-lived credential; got %q", gotAuth)
	}
	if strings.Contains(gotAuth, string(short.Value)) {
		t.Errorf("the short-lived credential must not reach the upstream; got %q", gotAuth)
	}

	// The VM-side connection never carries the long-lived value.
	requireNoCanary(t, dumpResponse(resp, body), longLived, "downstream response")
	requireZeroLeaks(t, h.probe, sess, longLived)

	ev := h.requireEvent(EventCredentialUse, "github")
	if ev.Session != sess {
		t.Errorf("CredentialUseEvent session = %q, want %q", ev.Session.ID, sess.ID)
	}
	if _, found := findEventContaining([]Event{ev}, EventCredentialUse, "fp-long-github"); !found {
		t.Error("CredentialUseEvent must carry the credential fingerprint")
	}
	requireNoCanary(t, serializeEvent(ev), longLived, "CredentialUseEvent")
}

// planRef: doc 09 §5 TLS-5 Done-when; §9 row "Long-lived credential never
// enters the VM"; doc 06 §3(c) credential-swap row — THE HEADLINE.
// ADVERSARIAL: every scenario tries to smuggle the canary onto a VM surface.
func TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	_, short := h.setupSwap(sess, "github", []string{"api.github.com", "github.com"}, longLived)
	authHdr := map[string]string{"Authorization": bearer(short)}
	dst := ap("140.82.1.1:443")

	// 1 — happy-path swap: the positive leg that keeps this test RED against
	// a do-nothing stub (a stub that moves no bytes trivially "leaks" nothing).
	t.Run("happy path swap", func(t *testing.T) {
		up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"login":"agent"}`)
		}}
		h.dialer.tlsFn = up.dialTLS
		resp, _, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, ""))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("happy path: status=%v err=%v", resp, err)
		}
		if reqs := up.requests(); len(reqs) != 1 || !strings.Contains(reqs[0].Header.Get("Authorization"), string(longLived)) {
			t.Fatal("swap must have substituted the long-lived credential upstream")
		}
	})

	// 2 — upstream 401/500 echoing the swapped header in body and headers.
	t.Run("upstream error pages echo the credential", func(t *testing.T) {
		for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
			up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Debug-Auth", r.Header.Get("Authorization"))
				w.WriteHeader(status)
				fmt.Fprintf(w, `{"error":"bad token","got":%q}`, r.Header.Get("Authorization"))
			}}
			h.dialer.tlsFn = up.dialTLS
			if _, _, err := h.inspectRequest(sess, "api.github.com", dst,
				newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, "")); err != nil {
				t.Fatalf("a readable (scrubbed) response or clean error is required, got transport failure: %v", err)
			}
		}
	})

	// 3 — 3xx redirect chain carrying the credential in Location.
	t.Run("redirect chain", func(t *testing.T) {
		up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://api.github.com/login?token="+r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusFound)
		}}
		h.dialer.tlsFn = up.dialTLS
		if _, _, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, "")); err != nil {
			t.Fatalf("redirect response must be delivered (scrubbed): %v", err)
		}
	})

	// 4 — TRACE-style reflection of the full request.
	t.Run("TRACE-style reflection", func(t *testing.T) {
		up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "message/http")
			fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", r.Method, r.URL.Path)
			r.Header.Write(w)
		}}
		h.dialer.tlsFn = up.dialTLS
		if _, _, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, "TRACE", "https://api.github.com/anything", authHdr, "")); err != nil {
			t.Fatalf("reflected response must be delivered (scrubbed): %v", err)
		}
	})

	// 5 — oversized response with the canary straddling buffer boundaries.
	t.Run("oversized response, canary across chunk boundary", func(t *testing.T) {
		pad := bytes.Repeat([]byte("A"), 64*1024)
		full := append(append(append([]byte{}, pad...), longLived...), pad...)
		cut := len(pad) + 32 // mid-canary
		up := &rawResponder{script: func(_ *http.Request, _ []byte, w io.Writer) {
			fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(full))
			w.Write(full[:cut])
			w.Write(full[cut:])
		}}
		h.dialer.tlsFn = up.dialTLS
		if _, _, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, http.MethodGet, "https://api.github.com/big", authHdr, "")); err != nil {
			t.Fatalf("oversized response must be delivered (scrubbed): %v", err)
		}
	})

	// 6 — proxy-generated error page (upstream dial fails mid-swap).
	t.Run("proxy-generated error page", func(t *testing.T) {
		h.dialer.tlsFn = func(string, netip.AddrPort) (net.Conn, error) {
			return nil, fmt.Errorf("upstream unreachable (injected)")
		}
		resp, body, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, ""))
		if err != nil {
			t.Fatalf("the proxy must answer with its own error page, not a dead conn: %v", err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("proxy error page status = %d, want 502", resp.StatusCode)
		}
		// Whatever error page the proxy generates is a VM surface.
		h.probe.addBytes(SurfaceDownstreamBytes, dumpResponse(resp, body))
	})

	// 7 — connection abort mid-swap: the abort must not leak, and must not
	// wedge the session's swap state for the next request.
	t.Run("abort mid-swap", func(t *testing.T) {
		up := &recordingUpstream{}
		h.dialer.tlsFn = up.dialTLS
		conn, _ := h.startTransparent(sess, dst)
		tc, err := h.sessionTLSClient(conn, sess, "api.github.com")
		if err == nil {
			fmt.Fprintf(tc, "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: %s\r\n", bearer(short))
		}
		conn.Close() // abort before the request completes
		resp, _, err := h.inspectRequest(sess, "api.github.com", dst,
			newReq(t, http.MethodGet, "https://api.github.com/after-abort", authHdr, ""))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("the session must survive an aborted swap: status=%v err=%v", resp, err)
		}
	})

	// 8 — malformed upstream response embedding the canary.
	t.Run("malformed upstream response", func(t *testing.T) {
		up := &rawResponder{script: func(_ *http.Request, _ []byte, w io.Writer) {
			fmt.Fprintf(w, "NOT-HTTP-GARBAGE %s\r\n", longLived)
		}}
		h.dialer.tlsFn = up.dialTLS
		conn, _ := h.startTransparent(sess, dst)
		defer conn.Close()
		tc, err := h.sessionTLSClient(conn, sess, "api.github.com")
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if err := newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, "").Write(tc); err != nil {
			t.Fatalf("write request: %v", err)
		}
		raw, _ := io.ReadAll(tc) // whatever the proxy forwarded is VM-observable
		h.probe.addBytes(SurfaceDownstreamBytes, raw)
		requireNoCanary(t, raw, longLived, "raw downstream bytes after malformed upstream response")
	})

	// THE GREP — zero canary occurrences (raw/base64/hex/url-encoded) on
	// every VM-observable surface and in every event/log/error string.
	h.probe.snapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)
	requireNoCanary(t, serializeEvents(h.events.all()), longLived, "captured events")
}

// planRef: doc 09 §5 TLS-5 Done-when ("not in any readable response");
// ResponseScrubber seam. ADVERSARIAL.
// Contract decision (documented here): encoded forms of the credential —
// including base64 — ARE in scope for the scrubber; row (d) asserts it.
func TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked(t *testing.T) {
	type echoRow struct {
		name    string
		upFor   func(h *harness, longLived []byte) // installs the echoing upstream
		encoded func([]byte) []byte                // form the canary takes downstream
	}
	rows := []echoRow{
		{
			name: "echoed in response body",
			upFor: func(h *harness, _ []byte) {
				up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"headers":{"Authorization":%q}}`, r.Header.Get("Authorization"))
				}}
				h.dialer.tlsFn = up.dialTLS
			},
			encoded: func(c []byte) []byte { return c },
		},
		{
			name: "echoed in a response header",
			upFor: func(h *harness, _ []byte) {
				up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
					io.WriteString(w, "ok")
				}}
				h.dialer.tlsFn = up.dialTLS
			},
			encoded: func(c []byte) []byte { return c },
		},
		{
			name: "split across two body chunks straddling a buffer boundary",
			upFor: func(h *harness, longLived []byte) {
				up := &rawResponder{script: func(r *http.Request, _ []byte, w io.Writer) {
					echo := []byte(r.Header.Get("Authorization"))
					pad := bytes.Repeat([]byte("B"), 4096)
					body := append(append(append([]byte{}, pad...), echo...), pad...)
					cut := len(pad) + len(echo)/2
					io.WriteString(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
					fmt.Fprintf(w, "%x\r\n", cut)
					w.Write(body[:cut])
					io.WriteString(w, "\r\n")
					fmt.Fprintf(w, "%x\r\n", len(body)-cut)
					w.Write(body[cut:])
					io.WriteString(w, "\r\n0\r\n\r\n")
				}}
				h.dialer.tlsFn = up.dialTLS
			},
			encoded: func(c []byte) []byte { return c },
		},
		{
			name: "base64 of the credential (encoded forms in scope)",
			upFor: func(h *harness, longLived []byte) {
				up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
					// Encode the BARE credential bytes at canonical 3-byte
					// alignment: base64("Bearer "+cred) does NOT contain
					// base64(cred) (group phase shift), so encoding the whole
					// header value would make the staged leak invisible to
					// the assertion below and let a scrubber that ignores
					// encoded forms pass this row.
					auth := []byte(r.Header.Get("Authorization"))
					echoed := auth
					if idx := bytes.Index(auth, longLived); idx >= 0 {
						echoed = auth[idx : idx+len(longLived)]
					}
					fmt.Fprintf(w, `{"auth_b64":%q}`, base64.StdEncoding.EncodeToString(echoed))
				}}
				h.dialer.tlsFn = up.dialTLS
			},
			encoded: func(c []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(c)) },
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			_, short := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			row.upFor(h, longLived)
			mark := h.events.snapshot()

			resp, body, err := h.inspectRequest(sess, "api.github.com", ap("140.82.1.1:443"),
				newReq(t, http.MethodGet, "https://api.github.com/user",
					map[string]string{"Authorization": bearer(short)}, ""))
			// Scrubbed delivery or whole-response block are both acceptable;
			// a delivered canary is not.
			if err == nil {
				delivered := dumpResponse(resp, body)
				if bytes.Contains(delivered, row.encoded(longLived)) {
					t.Error("the echoed long-lived credential reached the VM in a readable response")
				}
				requireNoCanary(t, delivered, longLived, "delivered response")
			}
			if _, ok := findEventContaining(h.events.since(mark), EventScrub); !ok {
				t.Error("a ScrubHit/security event must be emitted when an upstream echoes the credential")
			}
		})
	}
}

// planRef: doc 09 §5 TLS-5 (validate the presented short-lived credential
// against the session identity, D22). ADVERSARIAL.
func TestSwap_CrossSessionShortLivedCred_RejectedNoFetch(t *testing.T) {
	h := newInspectHarness(t)
	sessA := SessionRef{ID: "sess-a"}
	sessB := SessionRef{ID: "sess-b"}
	longLived := newCanary(t, 64)
	up, shortA := h.setupSwap(sessA, "github", []string{"api.github.com"}, longLived)
	// Session B is also admitted/allowed for the host; it replays A's cred.
	h.admit(sessB, "api.github.com", time.Hour, ip("140.82.1.1"))

	resp, _, err := h.inspectRequest(sessB, "api.github.com", ap("140.82.1.1:443"),
		newReq(t, http.MethodGet, "https://api.github.com/user",
			map[string]string{"Authorization": bearer(shortA)}, ""))
	if err != nil {
		t.Fatalf("the refusal must be a readable 401/403, not a dead conn: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403: A's credential must not swap on B", resp.StatusCode)
	}
	if n := h.secrets.fetchCount(); n != 0 {
		t.Errorf("SecretStore.FetchLongLived must NEVER be called on identity mismatch; calls=%d", n)
	}
	for _, r := range up.requests() {
		if strings.Contains(r.Header.Get("Authorization"), string(longLived)) {
			t.Error("no swapped request may reach the upstream for a cross-session credential")
		}
	}
	ev := h.requireEvent("", "identity mismatch")
	ser := serializeEvent(ev)
	requireNoCanary(t, ser, longLived, "identity-mismatch event")
	requireNoCanary(t, ser, []byte(shortA.Value), "identity-mismatch event (short-lived)")
}

// planRef: doc 09 §5 TLS-5 (sidecar validation seam D22). ADVERSARIAL.
func TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven(t *testing.T) {
	rows := []struct {
		name string
		auth func(h *harness, sess SessionRef) string // returns the Authorization value
	}{
		{"expired credential", func(h *harness, sess SessionRef) string {
			c := h.identity.mint(sess, "github", time.Minute)
			h.clock.Advance(2 * time.Minute) // now expired under the fake clock
			return bearer(c)
		}},
		{"tampered signature", func(h *harness, sess SessionRef) string {
			c := h.identity.mint(sess, "github", time.Hour)
			return bearer(Credential{Value: Secret(string(c.Value) + "-tampered"), Fingerprint: c.Fingerprint})
		}},
		{"random garbage token", func(*harness, SessionRef) string {
			return "Bearer garbage-aaaabbbbccccdddd"
		}},
		{"empty Authorization value", func(*harness, SessionRef) string {
			return ""
		}},
		{"credential minted for a different service", func(h *harness, sess SessionRef) string {
			other := h.identity.mint(SessionRef{ID: "sess-other"}, "npm", time.Hour)
			return bearer(other)
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			up, _ := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			auth := row.auth(h, sess)
			mark := h.events.snapshot()

			resp, _, err := h.inspectRequest(sess, "api.github.com", ap("140.82.1.1:443"),
				newReq(t, http.MethodGet, "https://api.github.com/user",
					map[string]string{"Authorization": auth}, ""))
			if err != nil {
				t.Fatalf("the refusal must be a readable 4xx, not a dead conn: %v", err)
			}
			if resp.StatusCode < 400 || resp.StatusCode > 499 {
				t.Fatalf("status = %d, want a 4xx refusal", resp.StatusCode)
			}
			if n := h.secrets.fetchCount(); n != 0 {
				t.Errorf("no secret-store fetch for an invalid credential; calls=%d", n)
			}
			for _, r := range up.requests() {
				got := r.Header.Get("Authorization")
				if got != auth {
					t.Errorf("the proxy must never fabricate an Authorization header upstream; got %q want %q", got, auth)
				}
				if strings.Contains(got, string(longLived)) {
					t.Error("the long-lived credential must never be swapped in for an invalid cred")
				}
			}
			if ev, ok := findEventContaining(h.events.since(mark), EventPolicyDecision); ok {
				requireProvenance(t, ev.Provenance)
			} else if ev, ok := findEventContaining(h.events.since(mark), EventError); ok {
				requireProvenance(t, ev.Provenance)
			} else {
				t.Error("a deny event with provenance must be emitted")
			}
		})
	}
}

// planRef: doc 09 §5 TLS-5 (swap rules live in the service registry).
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
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			longLived := newCanary(t, 64)
			up, _ := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
			h.policy.allow(row.host)
			h.admit(sess, row.host, time.Hour, ip("140.82.1.1"))

			resp, _, err := h.inspectRequest(sess, row.host, ap("140.82.1.1:443"),
				newReq(t, http.MethodGet, "https://"+row.host+"/data", row.header, ""))
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("non-swap request must pass through: status=%v err=%v", resp, err)
			}
			reqs := up.requests()
			if len(reqs) != 1 {
				t.Fatalf("upstream saw %d requests, want 1", len(reqs))
			}
			for k, v := range row.header {
				if got := reqs[0].Header.Get(k); got != v {
					t.Errorf("header %s must arrive upstream byte-identical: got %q want %q", k, got, v)
				}
			}
			if got := reqs[0].Header.Get("Authorization"); row.header["Authorization"] == "" && got != "" {
				t.Errorf("no Authorization may be fabricated; upstream got %q", got)
			}
			if n := h.identity.callCount(); n != 0 {
				t.Errorf("IdentityValidator must not be called without a registry+location match; calls=%d", n)
			}
			if n := h.secrets.fetchCount(); n != 0 {
				t.Errorf("SecretStore must not be called without a registry+location match; calls=%d", n)
			}
		})
	}
}

// planRef: doc 09 §5 TLS-5 (scrub BOTH credentials from every log path) +
// LOG-5 (fingerprint, never the credential). ADVERSARIAL.
func TestSwap_EveryLogPathScrubbed_FingerprintOnly(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	up, short := h.setupSwap(sess, "github", []string{"api.github.com"}, longLived)
	shortCanary := []byte(short.Value)
	authHdr := map[string]string{"Authorization": bearer(short)}
	dst := ap("140.82.1.1:443")

	// Path 1 — swap success.
	h.dialer.tlsFn = up.dialTLS
	if _, _, err := h.inspectRequest(sess, "api.github.com", dst,
		newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, "")); err != nil {
		t.Fatalf("swap success path: %v", err)
	}
	// Path 2 — swap failure (forged cred).
	_, _, _ = h.inspectRequest(sess, "api.github.com", dst,
		newReq(t, http.MethodGet, "https://api.github.com/user",
			map[string]string{"Authorization": "Bearer forged-cred-zzz"}, ""))
	// Path 3 — policy deny with the credential attached.
	h.policy.httpFn = func(req RequestMeta) Decision {
		if req.Path == "/denied" {
			return Decision{Allow: false, Provenance: Provenance{RuleID: "http:deny-path", PolicyLayer: "org", PolicyVersion: "policy-v1"}}
		}
		return Decision{Allow: true, Provenance: Provenance{RuleID: "http:default-allow", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
	}
	_, _, _ = h.inspectRequest(sess, "api.github.com", dst,
		newReq(t, http.MethodGet, "https://api.github.com/denied", authHdr, ""))
	h.policy.httpFn = nil
	// Path 4 — upstream error after swap.
	h.dialer.tlsFn = func(string, netip.AddrPort) (net.Conn, error) {
		return nil, fmt.Errorf("upstream connect refused (injected)")
	}
	_, _, _ = h.inspectRequest(sess, "api.github.com", dst,
		newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, ""))
	// Path 5 — scrubber hit (upstream echoes the swapped credential).
	echo := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo:%s", r.Header.Get("Authorization"))
	}}
	h.dialer.tlsFn = echo.dialTLS
	_, _, _ = h.inspectRequest(sess, "api.github.com", dst,
		newReq(t, http.MethodGet, "https://api.github.com/user", authHdr, ""))

	evs := h.events.all()
	if len(evs) == 0 {
		t.Fatal("the five driven paths must emit telemetry; zero events captured")
	}
	ser := serializeEvents(evs)
	requireNoCanary(t, ser, longLived, "captured events (long-lived)")
	requireNoCanary(t, ser, shortCanary, "captured events (short-lived)")

	ev := h.requireEvent(EventCredentialUse, "github")
	foundFP := false
	for _, v := range ev.Fields {
		if v == "fp-long-github" {
			foundFP = true
		}
	}
	if !foundFP {
		t.Errorf("CredentialUseEvent must carry the expected fingerprint fp-long-github; fields=%v", ev.Fields)
	}
}

// planRef: doc 09 §5 TLS-5 Done-when (push to GitHub works end to end) + §1
// credentialed half (Stage 3). e2e-lifecycle.
func TestE2E_GitHubPushWithOnlyShortLivedCredInVM(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	_, short := h.setupSwap(sess, "github", []string{"github.com", "api.github.com"}, longLived)

	const unpackOK = "000eunpack ok\n0000"
	github := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The fake GitHub accepts ONLY the long-lived canary.
		if !strings.Contains(r.Header.Get("Authorization"), string(longLived)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, unpackOK)
	}}
	h.dialer.tlsFn = github.dialTLS

	// git push over HTTPS through the explicit path: CONNECT, then the
	// inspected inner TLS (session CA), then receive-pack with the
	// short-lived credential — the only credential the VM holds.
	conn, _ := h.startCONNECT(sess)
	defer conn.Close()
	code, err := connectThrough(conn, "github.com:443")
	if err != nil || code != http.StatusOK {
		t.Fatalf("CONNECT github.com:443: code=%d err=%v", code, err)
	}
	tc, err := h.sessionTLSClient(conn, sess, "github.com")
	if err != nil {
		t.Fatalf("inner inspected TLS: %v", err)
	}
	resp, body, err := roundTrip(tc, newReq(t, http.MethodPost, "https://github.com/org/repo.git/git-receive-pack",
		map[string]string{"Authorization": bearer(short)}, "PACK-push-bytes"))
	if err != nil {
		t.Fatalf("git push round trip: %v", err)
	}
	h.probe.addBytes(SurfaceDownstreamBytes, dumpResponse(resp, body))
	if resp.StatusCode != http.StatusOK || string(body) != unpackOK {
		t.Fatalf("push must succeed via the swapped credential: status=%d body=%q", resp.StatusCode, body)
	}

	// No long-lived credential on any VM surface.
	h.probe.snapshotEnv()
	requireZeroLeaks(t, h.probe, sess, longLived)
	requireNoCanary(t, serializeEvents(h.events.all()), longLived, "captured events")

	// LOG-5: which session used the GitHub key, when, for what request.
	ev := h.requireEvent(EventCredentialUse, "github", "git-receive-pack")
	if ev.Session != sess {
		t.Errorf("credential-use attribution: session = %q, want %q", ev.Session.ID, sess.ID)
	}
	if !ev.At.Equal(h.clock.Now()) {
		t.Errorf("credential-use timestamp must come from the injected clock: got %v want %v", ev.At, h.clock.Now())
	}
}
