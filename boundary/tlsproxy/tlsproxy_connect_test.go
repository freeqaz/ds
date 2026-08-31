package tlsproxy

// TLS-2 — explicit proxy modes: HTTP CONNECT + plain-HTTP forward
// (doc 09 §5 TLS-2). Both modes evaluate the identical policy-core rules.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// planRef: doc 09 §5 TLS-2 Done-when (explicit path with per-request telemetry)
func TestCONNECT_AllowedDomain_TunnelPlusTelemetry(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))

	origin := newTLSOrigin(t, "echo", "github.com")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startCONNECT(sess)
	defer conn.Close()
	code, err := connectThrough(conn, "github.com:443")
	if err != nil {
		t.Fatalf("CONNECT github.com:443: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", code)
	}

	// Inner TLS to the fake upstream works through the tunnel.
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "github.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("inner TLS through established CONNECT tunnel: %v", err)
	}
	payload := []byte("connect-tunnel-probe")
	if _, err := tc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tc, echo); err != nil {
		t.Fatalf("tunnel echo read: %v", err)
	}

	// The upstream address must come from the DNS-2b admission for the
	// domain — never from the proxy's own resolver or any client-influenced
	// value. (The recorder accepted any address; pin it here.)
	if !h.dialer.dialedAddr(ap("140.82.1.1:443")) {
		t.Error("CONNECT upstream must be dialed at the admitted 140.82.1.1:443 (DNS-2b admission for github.com)")
	}
	for _, a := range h.dialer.dialedAddrs() {
		if a != ap("140.82.1.1:443") {
			t.Errorf("unexpected upstream dial to %v; the only legal upstream is the admitted 140.82.1.1:443", a)
		}
	}

	h.requireEvent(EventHTTP, "CONNECT", "github.com")
	h.requireEvent(EventPolicyDecision, "github.com")
}

// planRef: doc 09 §5 TLS-2 (both modes evaluate the identical policy-core
// rules) + POL-3 ("why was this blocked" has a one-line answer)
func TestCONNECT_DeniedDomain_RefusedWithProvenance(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.deny("blocked-domain.example")

	conn, _ := h.startCONNECT(sess)
	defer conn.Close()
	code, err := connectThrough(conn, "blocked-domain.example:443")
	if err != nil {
		t.Fatalf("CONNECT to denied domain must get an HTTP refusal, not a dead conn: %v", err)
	}
	if code != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want 403", code)
	}
	if n := h.dialer.dialCount(); n != 0 {
		t.Errorf("no upstream dial for a denied domain; got %d", n)
	}
	ev := h.requireEvent(EventPolicyDecision, "blocked-domain.example")
	if !strings.Contains(ev.Provenance.RuleID, "blocklist") {
		t.Errorf("deny provenance RuleID = %q, want the blocklist rule", ev.Provenance.RuleID)
	}
}

// planRef: doc 09 §5 TLS-2 × TLS-1 SNI rule (transparent-path rules must hold
// inside explicit tunnels). ADVERSARIAL.
func TestCONNECT_InnerSNIMismatchesAuthority_Refused(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))
	origin := newTLSOrigin(t, "echo", "github.com")
	h.dialer.rawFn = origin.dialRaw

	// Control first: matching inner SNI works (this makes the test RED
	// against the stub instead of trivially satisfied by a dead conn).
	ctrl, _ := h.startCONNECT(sess)
	defer ctrl.Close()
	if code, err := connectThrough(ctrl, "github.com:443"); err != nil || code != http.StatusOK {
		t.Fatalf("control CONNECT: code=%d err=%v", code, err)
	}
	ctrlTLS := tls.Client(ctrl, &tls.Config{RootCAs: origin.pool, ServerName: "github.com"})
	if err := ctrlTLS.Handshake(); err != nil {
		t.Fatalf("control inner handshake must succeed: %v", err)
	}
	dialsAfterControl := h.dialer.dialCount()

	// Bypass attempt: declare the allowed authority, handshake a different inner SNI.
	conn, _ := h.startCONNECT(sess)
	defer conn.Close()
	if code, err := connectThrough(conn, "github.com:443"); err != nil || code != http.StatusOK {
		t.Fatalf("mismatched-SNI CONNECT setup: code=%d err=%v", code, err)
	}
	evil := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "exfil.evil.com"})
	if err := evil.Handshake(); err == nil {
		t.Error("tunnel must be torn down at the mismatched inner ClientHello; handshake succeeded")
	}
	if n := h.dialer.dialCount(); n != dialsAfterControl {
		t.Errorf("no upstream bytes for the mismatched inner SNI; dials went %d -> %d", dialsAfterControl, n)
	}
	h.requireEvent(EventPolicyDecision, "exfil.evil.com")
}

// planRef: doc 09 §5 TLS-2 Done-when (both modes evaluate identical
// policy-core rules). Parity is asserted at domain granularity here;
// method/path-level parity across all three modes is asserted by
// TestPolicyParity_MethodPathRules_AllThreeModes below.
func TestPolicyParity_TransparentCONNECTForward_TableDriven(t *testing.T) {
	ctx := context.Background()
	rows := []struct {
		domain string
		allow  bool
	}{
		{"github.com", true},
		{"api.github.com", true},
		{"blocked-domain.example", false},
	}
	for _, row := range rows {
		t.Run(row.domain, func(t *testing.T) {
			h := newHarness(t)
			sess := SessionRef{ID: "sess-a"}
			if row.allow {
				h.policy.allow(row.domain)
			} else {
				h.policy.deny(row.domain)
			}
			h.admit(sess, row.domain, time.Minute, ip("140.82.1.1"))

			origin := newTLSOrigin(t, "echo", row.domain)
			up := &recordingUpstream{}
			h.dialer.rawFn = func(addr netip.AddrPort) (net.Conn, error) {
				if addr.Port() == 80 {
					return up.dial()
				}
				return origin.dialRaw(addr)
			}

			// Mode 1 — transparent (gate verdict).
			dec, err := h.gate.Evaluate(ctx, sess, ClientHello{SNI: row.domain}, ap("140.82.1.1:443"))
			if err != nil {
				t.Fatalf("transparent Evaluate: %v", err)
			}
			allowedT := dec.Action != ActionRefuse && dec.Action != ActionUnknown
			ruleT := dec.Provenance.RuleID

			// Mode 2 — explicit CONNECT.
			mark := h.events.snapshot()
			cconn, _ := h.startCONNECT(sess)
			defer cconn.Close()
			code, err := connectThrough(cconn, row.domain+":443")
			if err != nil {
				t.Fatalf("CONNECT: %v", err)
			}
			allowedC := code == http.StatusOK
			evC, okC := findEventContaining(h.events.since(mark), EventPolicyDecision, row.domain)
			if !okC {
				t.Fatal("CONNECT mode must emit a PolicyDecision event")
			}
			ruleC := evC.Provenance.RuleID

			// Mode 3 — plain-HTTP forward.
			mark = h.events.snapshot()
			fconn, _ := h.startForward(sess)
			defer fconn.Close()
			resp, _, err := roundTrip(fconn, newReq(t, http.MethodGet, "http://"+row.domain+"/", nil, ""))
			if err != nil {
				t.Fatalf("forward GET: %v", err)
			}
			// Strict per-side statuses: a forward path that is broken for
			// allowed domains (e.g. always 502) must NOT count as "agreeing"
			// on the allow side. The fake upstream answers 200 "ok".
			if row.allow && resp.StatusCode != http.StatusOK {
				t.Errorf("forward allow row: status = %d, want 200 from the fake upstream", resp.StatusCode)
			}
			if !row.allow && resp.StatusCode != http.StatusForbidden {
				t.Errorf("forward deny row: status = %d, want 403", resp.StatusCode)
			}
			allowedF := resp.StatusCode == http.StatusOK
			evF, okF := findEventContaining(h.events.since(mark), EventPolicyDecision, row.domain)
			if !okF {
				t.Fatal("forward mode must emit a PolicyDecision event")
			}
			ruleF := evF.Provenance.RuleID

			if allowedT != row.allow || allowedC != row.allow || allowedF != row.allow {
				t.Errorf("verdict disagreement for %s: transparent=%v connect=%v forward=%v want=%v",
					row.domain, allowedT, allowedC, allowedF, row.allow)
			}
			if ruleT != ruleC || ruleC != ruleF {
				t.Errorf("RuleID disagreement across modes: transparent=%q connect=%q forward=%q", ruleT, ruleC, ruleF)
			}
		})
	}
}

// planRef: doc 09 §5 TLS-2 Done-when (npm install and git clone via explicit
// path; push with hand-supplied short-lived test cred pending TLS-5).
// Conformance clients are modeled with stdlib request sequences over real
// CONNECT tunnels; the real npm/git binaries run on the scheduled (d) rig.
func TestCONNECT_Conformance_NpmInstallGitClone(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("registry.npmjs.org", "github.com")
	h.admit(sess, "registry.npmjs.org", time.Minute, ip("104.16.0.1"))
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))

	const (
		metaJSON  = `{"name":"left-pad","dist-tags":{"latest":"1.3.0"}}`
		tarball   = "TARBALL-BYTES-left-pad-1.3.0"
		refsAdv   = "001e# service=git-upload-pack\n0000"
		packData  = "PACK-data-for-clone"
		shortCred = "hand-supplied-short-lived-test-cred"
		unpackOK  = "000eunpack ok\n0000"
	)

	registry := newTLSOrigin(t, "http", "registry.npmjs.org")
	registry.handler = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/left-pad":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, metaJSON)
		case "/left-pad/-/left-pad-1.3.0.tgz":
			io.WriteString(w, tarball)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	github := newTLSOrigin(t, "http", "github.com")
	github.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/info/refs"):
			io.WriteString(w, refsAdv)
		case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
			io.WriteString(w, packData)
		case strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
			if r.Header.Get("Authorization") != "Bearer "+shortCred {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			io.WriteString(w, unpackOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	h.dialer.rawFn = func(addr netip.AddrPort) (net.Conn, error) {
		if addr.Addr() == ip("104.16.0.1") {
			return registry.dialRaw(addr)
		}
		return github.dialRaw(addr)
	}

	openTunnel := func(authority string, origin *tlsOrigin) *tls.Conn {
		t.Helper()
		conn, _ := h.startCONNECT(sess)
		t.Cleanup(func() { conn.Close() })
		code, err := connectThrough(conn, authority)
		if err != nil || code != http.StatusOK {
			t.Fatalf("CONNECT %s: code=%d err=%v", authority, code, err)
		}
		name, _, _ := strings.Cut(authority, ":")
		tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: name})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("inner TLS %s: %v", authority, err)
		}
		return tc
	}

	// npm install: metadata then tarball over one tunnel.
	npm := openTunnel("registry.npmjs.org:443", registry)
	resp, body, err := roundTrip(npm, newReq(t, http.MethodGet, "https://registry.npmjs.org/left-pad", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != metaJSON {
		t.Fatalf("npm metadata: status=%v body=%q err=%v", resp, body, err)
	}
	resp, body, err = roundTrip(npm, newReq(t, http.MethodGet, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != tarball {
		t.Fatalf("npm tarball: status=%v body=%q err=%v", resp, body, err)
	}

	// git clone: refs advertisement + upload-pack.
	git := openTunnel("github.com:443", github)
	resp, body, err = roundTrip(git, newReq(t, http.MethodGet, "https://github.com/org/repo.git/info/refs?service=git-upload-pack", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != refsAdv {
		t.Fatalf("git info/refs: status=%v body=%q err=%v", resp, body, err)
	}
	resp, body, err = roundTrip(git, newReq(t, http.MethodPost, "https://github.com/org/repo.git/git-upload-pack", nil, "0009want\n0000"))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != packData {
		t.Fatalf("git upload-pack: status=%v body=%q err=%v", resp, body, err)
	}

	// git push with the hand-supplied short-lived test credential (TLS-5 pending).
	push := openTunnel("github.com:443", github)
	resp, body, err = roundTrip(push, newReq(t, http.MethodPost, "https://github.com/org/repo.git/git-receive-pack",
		map[string]string{"Authorization": "Bearer " + shortCred}, "PACK-push-bytes"))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != unpackOK {
		t.Fatalf("git push: status=%v body=%q err=%v", resp, body, err)
	}

	// Per-request telemetry on the explicit path: one HttpEvent per CONNECT.
	if evs := h.events.byKind(EventHTTP); len(evs) < 3 {
		t.Errorf("expected >=3 HttpEvents (one per CONNECT tunnel), got %d", len(evs))
	}
	h.requireEvent(EventHTTP, "registry.npmjs.org")
	h.requireEvent(EventHTTP, "github.com")
}

// planRef: doc 09 §5 TLS-2.d (table of (domain, method, path, expected
// verdict) rows, each row driven through ALL THREE modes). ADVERSARIAL: a
// mode that skips HTTP-level rules is an open side door for the same request.
func TestPolicyParity_MethodPathRules_AllThreeModes(t *testing.T) {
	const host = "api.github.com"
	httpFn := func(req RequestMeta) Decision {
		deny := func(rule string) Decision {
			return Decision{Allow: false, Provenance: Provenance{RuleID: rule, PolicyLayer: "org", PolicyVersion: "policy-v1"}}
		}
		switch {
		case req.Method == http.MethodDelete && strings.HasPrefix(req.Path, "/repos/critical"):
			return deny("http:deny-delete-critical")
		case strings.HasPrefix(req.Path, "/admin"):
			return deny("http:deny-admin-path")
		default:
			return Decision{Allow: true, Provenance: Provenance{RuleID: "http:allow-default", PolicyLayer: "system", PolicyVersion: "policy-v1"}}
		}
	}
	rows := []struct {
		name     string
		method   string
		path     string
		allow    bool
		wantRule string
	}{
		{"allowed GET on guarded prefix", http.MethodGet, "/repos/critical/info", true, "http:allow-default"},
		{"denied DELETE on guarded prefix", http.MethodDelete, "/repos/critical/branch", false, "http:deny-delete-critical"},
		{"denied admin path", http.MethodGet, "/admin/keys", false, "http:deny-admin-path"},
		{"allowed POST", http.MethodPost, "/repos/other/issues", true, "http:allow-default"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, mode := range []string{"transparent", "connect", "forward"} {
				h := newInspectHarness(t)
				sess := SessionRef{ID: "sess-a"}
				h.policy.allow(host)
				h.policy.httpFn = httpFn
				h.admit(sess, host, time.Hour, ip("140.82.1.1"))
				up := &recordingUpstream{}
				h.dialer.tlsFn = up.dialTLS
				h.dialer.rawFn = up.dialRaw
				mark := h.events.snapshot()

				var resp *http.Response
				var err error
				switch mode {
				case "transparent":
					resp, _, err = h.inspectRequest(sess, host, ap("140.82.1.1:443"),
						newReq(t, row.method, "https://"+host+row.path, nil, ""))
				case "connect":
					conn, _ := h.startCONNECT(sess)
					defer conn.Close()
					code, cerr := connectThrough(conn, host+":443")
					if cerr != nil || code != http.StatusOK {
						t.Fatalf("connect mode: CONNECT %s: code=%d err=%v", host, code, cerr)
					}
					tc, herr := h.sessionTLSClient(conn, sess, host)
					if herr != nil {
						t.Fatalf("connect mode: inner inspected TLS: %v", herr)
					}
					resp, _, err = roundTrip(tc, newReq(t, row.method, "https://"+host+row.path, nil, ""))
				case "forward":
					fconn, _ := h.startForward(sess)
					defer fconn.Close()
					resp, _, err = roundTrip(fconn, newReq(t, row.method, "http://"+host+row.path, nil, ""))
				}
				if err != nil {
					t.Fatalf("%s mode must yield a readable verdict for %s %s: %v", mode, row.method, row.path, err)
				}

				wantStatus, wantUpstream := http.StatusForbidden, 0
				if row.allow {
					wantStatus, wantUpstream = http.StatusOK, 1
				}
				if resp.StatusCode != wantStatus {
					t.Errorf("%s mode: %s %s status = %d, want %d", mode, row.method, row.path, resp.StatusCode, wantStatus)
				}
				if up.requestCount() != wantUpstream {
					t.Errorf("%s mode: upstream saw %d requests, want %d", mode, up.requestCount(), wantUpstream)
				}
				ev, ok := findEventContaining(h.events.since(mark), EventPolicyDecision, row.path)
				if !ok {
					t.Errorf("%s mode must emit a PolicyDecision event for %s", mode, row.path)
					continue
				}
				requireProvenance(t, ev.Provenance)
				// EXACT rule parity: every mode must fire the identical rule.
				if ev.Provenance.RuleID != row.wantRule {
					t.Errorf("%s mode RuleID = %q, want %q (identical policy-core rules in every mode)", mode, ev.Provenance.RuleID, row.wantRule)
				}
			}
		})
	}
}

// planRef: doc 09 §5 TLS-2.e (Proxy.ServeHTTPForward conformance sequence
// with per-request HttpEvent telemetry on the forward path). Conformance
// clients are modeled with stdlib request sequences per the conventions'
// seam-first rule; the real npm binary runs on the scheduled (d) rig.
func TestForward_Conformance_NpmSequence_PerRequestTelemetry(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("registry.npmjs.org")
	h.admit(sess, "registry.npmjs.org", time.Minute, ip("104.16.0.1"))

	const (
		metaJSON = `{"name":"left-pad","dist-tags":{"latest":"1.3.0"}}`
		tarball  = "TARBALL-BYTES-left-pad-1.3.0"
	)
	up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/left-pad":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, metaJSON)
		case "/left-pad/-/left-pad-1.3.0.tgz":
			io.WriteString(w, tarball)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}}
	h.dialer.rawFn = func(addr netip.AddrPort) (net.Conn, error) {
		if addr.Addr() != ip("104.16.0.1") {
			return nil, fmt.Errorf("unexpected forward upstream %v: the upstream address must come from the DNS-2b admission", addr)
		}
		return up.dial()
	}

	// npm-install-shaped sequence: metadata then tarball over ONE forward conn.
	conn, _ := h.startForward(sess)
	defer conn.Close()
	resp, body, err := roundTrip(conn, newReq(t, http.MethodGet, "http://registry.npmjs.org/left-pad", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != metaJSON {
		t.Fatalf("forward npm metadata: status=%v body=%q err=%v", resp, body, err)
	}
	resp, body, err = roundTrip(conn, newReq(t, http.MethodGet, "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != tarball {
		t.Fatalf("forward npm tarball: status=%v body=%q err=%v", resp, body, err)
	}
	if got := up.requestCount(); got != 2 {
		t.Errorf("upstream saw %d requests, want 2", got)
	}

	// Per-request HttpEvent on the forward path, each provenance-complete and
	// attributed to the session.
	ev1 := h.requireEvent(EventHTTP, "registry.npmjs.org", "/left-pad")
	ev2 := h.requireEvent(EventHTTP, "registry.npmjs.org", "/left-pad/-/left-pad-1.3.0.tgz")
	for _, ev := range []Event{ev1, ev2} {
		if ev.Session != sess {
			t.Errorf("forward HttpEvent attributed to %q, want %q", ev.Session.ID, sess.ID)
		}
	}
	if evs := h.events.byKind(EventHTTP); len(evs) < 2 {
		t.Errorf("expected one HttpEvent per forward request (>=2), got %d", len(evs))
	}
}

// planRef: doc 09 §5 TLS-1.k / TLS-2.e real-binary conformance halves. The
// seam-driven halves run in TestTunnel_Conformance_CurlAndGitHTTPS_PassClean,
// TestCONNECT_Conformance_NpmInstallGitClone and
// TestForward_Conformance_NpmSequence_PerRequestTelemetry; this records the
// rig obligation as an executable, skipped test rather than a comment.
func TestConformance_RealCurlGitNpmBinaries_ScheduledRig(t *testing.T) {
	t.Skip("requires the scheduled (d) conformance rig: real curl/git/npm binaries inside a session VM, " +
		"the boundary's transparent/CONNECT/forward ingress, the session interception CA installed in the " +
		"VM trust store, and live golden-trace capture — not expressible against the in-process seams")
}

// planRef: doc 09 §5 TLS-2 × TLS-1 edge rule 2 (IP-literal refused by
// default, mode-consistent). ADVERSARIAL.
func TestCONNECT_IPLiteralAuthority_Refused(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1")) // the IP sits in an allow-set

	conn, _ := h.startCONNECT(sess)
	defer conn.Close()
	code, err := connectThrough(conn, "140.82.1.1:443")
	if err != nil {
		t.Fatalf("CONNECT to IP literal must get an HTTP refusal: %v", err)
	}
	if code != http.StatusForbidden {
		t.Fatalf("CONNECT 140.82.1.1:443 status = %d, want 403: bare-IP CONNECT bypasses domain policy", code)
	}
	if n := h.dialer.dialCount(); n != 0 {
		t.Errorf("no upstream dial for an IP-literal authority; got %d", n)
	}
}
