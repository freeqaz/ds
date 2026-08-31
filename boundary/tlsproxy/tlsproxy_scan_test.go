package tlsproxy

// TLS-7 — the inbound secret-scanning gate on the inspected path
// (doc 09 §5 TLS-7; rules/response ownership stays OQ8 — scanner pluggable).

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

const seededToken = "ghp_0123456789abcdef0123456789abcdef0123"

// planRef: doc 09 §5 TLS-7 Done-when (seeded token entering on the inspected
// path is detected; configured hook fires) — the doc 02 §6 hand-fed-token
// scenario.
func TestSecretScan_SeededLongLivedTokenInbound_HookFires(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const host = "paste.example"
	h.policy.allow(host)
	h.admit(sess, host, time.Hour, ip("198.51.100.20"))
	up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("here is the token you asked me to paste: " + seededToken + "\n"))
	}}
	h.dialer.tlsFn = up.dialTLS

	resp, _, err := h.inspectRequest(sess, host, ap("198.51.100.20:443"),
		newReq(t, http.MethodGet, "https://"+host+"/snippet", nil, ""))
	if err != nil {
		t.Fatalf("inspected fetch: %v", err)
	}
	// Default configured mode is alert-on-finding: delivery proceeds.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (alert mode delivers)", resp.StatusCode)
	}

	findings := h.hook.list()
	if len(findings) == 0 {
		t.Fatal("the configured hook must fire for a seeded long-lived token entering the VM")
	}
	f := findings[0]
	if f.Kind == "" {
		t.Error("Finding.Kind must classify the secret (e.g. github-token)")
	}
	if f.Fingerprint == "" {
		t.Error("Finding.Fingerprint must be set")
	}
	if f.Where == "" {
		t.Error("Finding.Where must locate the secret (e.g. body)")
	}
	for _, f := range findings {
		if strings.Contains(f.Kind+f.Fingerprint+f.Where, seededToken) {
			t.Error("a Finding must carry a fingerprint, NEVER the token value")
		}
	}
}

// planRef: doc 09 §5 TLS-7 (rules ownership OQ8 — the gate must not be noise)
func TestSecretScan_NearMissContent_NoFalseTrigger(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	sc := NewSecretScanner(Config{Now: clock.Now})
	sess := SessionRef{ID: "sess-a"}
	rows := []struct {
		name string
		body string
	}{
		{"README documenting the token FORMAT", "GitHub tokens look like ghp_ followed by 36 alphanumerics, e.g. ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
		{"random base64 blob", "payload=QmFzZTY0IGJsb2JzIGFyZSBub3Qgc2VjcmV0cyBidXQgbG9vayBlbnRyb3BpYyE9PQ=="},
		{"UUIDs", "request-id: 1f2e3d4c-5b6a-7980-1122-334455667788, trace: 99887766-5544-3322-1100-aabbccddeeff"},
		{"truncated token prefix", "the prefix ghp_abc alone is not a credential"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			findings, err := sc.ScanInbound(ctx, sess, ResponseMeta{Status: 200, Headers: map[string]string{"Content-Type": "text/plain"}}, []byte(row.body))
			if err != nil {
				t.Fatalf("ScanInbound must scan near-miss content cleanly: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("near-miss content fired %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

// planRef: doc 09 §5 TLS-7 (the gate exists on the inspected path only —
// doc 05 §7 HTTP-level-visibility dependency). This test is the living
// documentation of the guarantee's boundary: pass-through tunnels are
// OUTSIDE the secret-scan promise.
func TestSecretScan_PassThroughNotScanned_GuaranteeBoundaryDocumented(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "pinned.example"
	h.policy.allow(domain)
	h.policy.setPassThrough(domain, true)
	h.admit(sess, domain, time.Hour, ip("203.0.113.5"))
	origin := newTLSOrigin(t, "http", domain)
	origin.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("opaque delivery: " + seededToken))
	}
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("203.0.113.5:443"))
	defer conn.Close()
	tc, err := pinnedTLSClient(conn, domain, origin.spki)
	if err != nil {
		t.Fatalf("pass-through tunnel: %v", err)
	}
	resp, body, err := roundTrip(tc, newReq(t, http.MethodGet, "https://"+domain+"/secret", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("opaque fetch: status=%v err=%v", resp, err)
	}
	// The token reaches the VM — documented, by design, for listed domains.
	if !strings.Contains(string(body), seededToken) {
		t.Fatalf("opaque tunnel must deliver the origin bytes untouched; body=%q", body)
	}
	if n := h.scanner.callCount(); n != 0 {
		t.Errorf("ScanInbound must never be invoked for an opaque pass-through flow; calls=%d", n)
	}
	if findings := h.hook.list(); len(findings) != 0 {
		t.Errorf("no findings may fire for pass-through flows; got %d", len(findings))
	}
}
