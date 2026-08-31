package tlsproxy

// TLS-1 — the SNI-checked tunnel (doc 09 §5 TLS-1, DNS-2b admission map).
// Tests assert the documented outcome and run RED against the stubs.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// rawClientHello builds a minimal TLS ClientHello record with the given SNI
// (server_name omitted when sni == "") and, when ech, an
// encrypted_client_hello (0xfe0d) extension — enough for the proxy's SNI/ECH
// peek on the transparent path.
func rawClientHello(sni string, ech bool) []byte {
	be16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	var ext bytes.Buffer
	if sni != "" {
		host := []byte(sni)
		ext.Write([]byte{0x00, 0x00}) // extension type: server_name
		ext.Write(be16(len(host) + 5))
		ext.Write(be16(len(host) + 3))
		ext.WriteByte(0x00) // name_type: host_name
		ext.Write(be16(len(host)))
		ext.Write(host)
	}
	if ech {
		payload := []byte{0x00, 0x01, 0x02, 0x03}
		ext.Write([]byte{0xfe, 0x0d}) // extension type: encrypted_client_hello
		ext.Write(be16(len(payload)))
		ext.Write(payload)
	}
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})             // legacy_version TLS 1.2
	body.Write(make([]byte, 32))               // random (deterministic zeros)
	body.WriteByte(0)                          // session_id length
	body.Write([]byte{0x00, 0x02, 0x13, 0x01}) // cipher_suites: TLS_AES_128_GCM_SHA256
	body.Write([]byte{0x01, 0x00})             // compression: null
	body.Write(be16(ext.Len()))
	body.Write(ext.Bytes())
	var hs bytes.Buffer
	hs.WriteByte(0x01) // handshake type: client_hello
	hs.Write([]byte{0x00, byte(body.Len() >> 8), byte(body.Len())})
	hs.Write(body.Bytes())
	rec := []byte{0x16, 0x03, 0x01, byte(hs.Len() >> 8), byte(hs.Len())}
	return append(rec, hs.Bytes()...)
}

// requireProxyRefusesHello drives Proxy.ServeTransparentTLS with a raw
// ClientHello and asserts the load-bearing half of a TLS-1 refusal: the
// downstream connection is torn down (no tunnel), ZERO upstream dials occur,
// and a provenance-complete PolicyDecision deny event is emitted.
func requireProxyRefusesHello(t *testing.T, h *harness, sess SessionRef, origDst netip.AddrPort, rawHello []byte, eventSubstrs ...string) {
	t.Helper()
	mark := h.events.snapshot()
	dialsBefore := h.dialer.dialCount()
	conn, errc := h.startTransparent(sess, origDst)
	defer conn.Close()
	_, _ = conn.Write(rawHello) // the proxy may legally close before reading it all
	_, _ = io.Copy(io.Discard, conn)
	select {
	case <-errc:
	case <-time.After(ioTimeout):
		t.Fatal("ServeTransparentTLS never returned for a refused ClientHello")
	}
	if n := h.dialer.dialCount(); n != dialsBefore {
		t.Errorf("refused ClientHello caused %d upstream dial(s); the no-tunnel half requires zero", n-dialsBefore)
	}
	ev, ok := findEventContaining(h.events.since(mark), EventPolicyDecision, eventSubstrs...)
	if !ok {
		t.Errorf("proxy-path refusal must emit a PolicyDecision deny event (containing %q)", eventSubstrs)
		return
	}
	requireProvenance(t, ev.Provenance)
}

// planRef: doc 09 §5 TLS-1 Done-when (conformance clients pass cleanly)
func TestTunnel_AllowedDomainAdmittedIP_TunnelsOpaque(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", 60*time.Second, ip("140.82.1.1"))

	dec, err := h.gate.Evaluate(ctx, sess, ClientHello{SNI: "github.com"}, ap("140.82.1.1:443"))
	if err != nil {
		t.Fatalf("TunnelGate.Evaluate: %v", err)
	}
	if dec.Action != ActionTunnelOpaque {
		t.Fatalf("Action = %v, want TunnelOpaque", dec.Action)
	}
	if dec.Upstream != ap("140.82.1.1:443") {
		t.Fatalf("Upstream = %v, want 140.82.1.1:443", dec.Upstream)
	}
	requireProvenance(t, dec.Provenance)

	// Byte path: payload flows both ways unmodified through the opaque tunnel.
	origin := newTLSOrigin(t, "echo", "github.com")
	h.dialer.rawFn = origin.dialRaw
	conn, _ := h.startTransparent(sess, ap("140.82.1.1:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "github.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("end-to-end TLS handshake through the opaque tunnel: %v", err)
	}
	payload := []byte("ping-payload-7d1f")
	if _, err := tc.Write(payload); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tc, echo); err != nil {
		t.Fatalf("read echo through tunnel: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("payload modified in opaque tunnel: got %q want %q", echo, payload)
	}
	h.requireEvent(EventFlow, "github.com")
}

// planRef: doc 09 §5 TLS-1 Done-when (non-matching SNI refused) + §4 DNS-2b
// Done-when; doc 03 OQ1 shared-CDN hole. ADVERSARIAL.
func TestTunnel_MismatchedSNI_SharedCDNIP_Refused(t *testing.T) {
	ctx := context.Background()
	rows := []struct {
		name    string
		admitIP string // if non-empty, evil domain is admitted — for a DIFFERENT IP
	}{
		{name: "SNI domain not admitted anywhere"},
		{name: "SNI domain admitted for a different IP", admitIP: "9.9.9.9"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			sess := SessionRef{ID: "sess-a"}
			h.policy.allow("allowed-a.com")
			h.admit(sess, "allowed-a.com", time.Minute, ip("151.101.1.1"))
			if row.admitIP != "" {
				// Even policy-allowed: the per-domain admission must still gate.
				h.policy.allow("evil-behind-cdn.com")
				h.admit(sess, "evil-behind-cdn.com", time.Minute, ip(row.admitIP))
			}

			dec, err := h.gate.Evaluate(ctx, sess, ClientHello{SNI: "evil-behind-cdn.com"}, ap("151.101.1.1:443"))
			if err != nil {
				t.Fatalf("Evaluate must refuse cleanly, got error: %v", err)
			}
			if dec.Action != ActionRefuse {
				t.Fatalf("Action = %v, want Refuse: an IP admitted for domain A must not admit domain B's SNI", dec.Action)
			}
			if dec.Reason == "" {
				t.Error("refusal must carry a Reason")
			}
			requireProvenance(t, dec.Provenance)
			if n := h.dialer.dialCount(); n != 0 {
				t.Errorf("zero upstream bytes expected; got %d upstream dials", n)
			}
			h.requireEvent(EventPolicyDecision, "evil-behind-cdn.com")
		})
	}
}

// planRef: doc 09 §5 TLS-1 edge rule 1; §9 row "ECH can't hide a non-admitted
// domain behind an admitted IP". ADVERSARIAL — the strongest bypass shape:
// outer SNI and origDst are BOTH admitted.
func TestTunnel_ECHClientHello_Refused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("allowed-cdn-name.com")
	h.admit(sess, "allowed-cdn-name.com", time.Minute, ip("151.101.1.1"))

	hello := ClientHello{SNI: "allowed-cdn-name.com", HasECH: true}
	dec, err := h.gate.Evaluate(ctx, sess, hello, ap("151.101.1.1:443"))
	if err != nil {
		t.Fatalf("Evaluate must refuse cleanly, got error: %v", err)
	}
	if dec.Action != ActionRefuse {
		t.Fatalf("Action = %v, want Refuse: ECH must be refused even with admitted outer SNI + IP", dec.Action)
	}
	if dec.Reason == "" {
		t.Error("ECH refusal must carry a documented Reason")
	}
	if n := h.dialer.dialCount(); n != 0 {
		t.Errorf("no upstream dial allowed for an ECH ClientHello; got %d", n)
	}

	// Proxy-path half (TLS-1.c fn = Proxy.ServeTransparentTLS): the PROXY
	// itself must honor the ECH refusal — connection torn down, zero tunneled
	// upstream bytes, deny event — not just the gate seam.
	requireProxyRefusesHello(t, h, sess, ap("151.101.1.1:443"),
		rawClientHello("allowed-cdn-name.com", true), "allowed-cdn-name.com")
}

// planRef: doc 09 §5 TLS-1 edge rule 1 (GREASE indistinguishable, refused,
// documented+tested). ADVERSARIAL.
func TestTunnel_GREASEECH_Refused_DocumentedBehavior(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))

	// GREASE ECH is indistinguishable from real ECH by design: same flag.
	grease := ClientHello{SNI: "github.com", HasECH: true, Raw: []byte{0xfe, 0x0d, 0x0a, 0x0a}}
	real_ := ClientHello{SNI: "github.com", HasECH: true}

	decG, errG := h.gate.Evaluate(ctx, sess, grease, ap("140.82.1.1:443"))
	if errG != nil {
		t.Fatalf("Evaluate(GREASE) must refuse cleanly, got error: %v", errG)
	}
	decR, errR := h.gate.Evaluate(ctx, sess, real_, ap("140.82.1.1:443"))
	if errR != nil {
		t.Fatalf("Evaluate(real ECH) must refuse cleanly, got error: %v", errR)
	}
	if decG.Action != ActionRefuse {
		t.Fatalf("GREASE ECH Action = %v, want Refuse", decG.Action)
	}
	if decG.Reason == "" {
		t.Error("GREASE refusal must carry the distinct documented Reason")
	}
	if decG.Action != decR.Action || decG.Reason != decR.Reason {
		t.Errorf("GREASE must behave identically to real ECH: grease=(%v,%q) real=(%v,%q)",
			decG.Action, decG.Reason, decR.Action, decR.Reason)
	}
}

// planRef: doc 09 §5 TLS-1 edge rule 2. ADVERSARIAL — admitted-IP status
// alone never admits a flow.
func TestTunnel_AbsentSNI_Refused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))

	dec, err := h.gate.Evaluate(ctx, sess, ClientHello{SNI: ""}, ap("140.82.1.1:443"))
	if err != nil {
		t.Fatalf("Evaluate must refuse cleanly, got error: %v", err)
	}
	if dec.Action != ActionRefuse {
		t.Fatalf("Action = %v, want Refuse: absent SNI means no domain-level policy check is possible", dec.Action)
	}
	if dec.Reason == "" {
		t.Error("absent-SNI refusal must carry a Reason")
	}

	// Proxy-path half: an SNI-less ClientHello to an admitted IP must yield
	// no tunnel and no upstream dial at the proxy itself.
	requireProxyRefusesHello(t, h, sess, ap("140.82.1.1:443"), rawClientHello("", false))
}

// planRef: doc 09 §5 TLS-1 edge rule 2 (absent-SNI / IP-literal refused by
// default). ADVERSARIAL.
func TestTunnel_IPLiteralSNI_Refused(t *testing.T) {
	ctx := context.Background()
	rows := []struct {
		name, sni, origDst string
	}{
		{"IPv4 literal", "140.82.1.1", "140.82.1.1:443"},
		{"IPv6 literal bracketed", "[2606:50c0::1]", "[2606:50c0::1]:443"},
		{"IPv6 literal bare", "2606:50c0::1", "[2606:50c0::1]:443"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			sess := SessionRef{ID: "sess-a"}
			h.policy.allow("github.com")
			h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"), ip("2606:50c0::1"))

			dec, err := h.gate.Evaluate(ctx, sess, ClientHello{SNI: row.sni}, ap(row.origDst))
			if err != nil {
				t.Fatalf("Evaluate must refuse cleanly, got error: %v", err)
			}
			if dec.Action != ActionRefuse {
				t.Fatalf("Action = %v, want Refuse: an IP literal in SNI cannot substitute for a policy-evaluated domain", dec.Action)
			}

			// Proxy-path half: the same IP-literal SNI must yield no tunnel
			// and no upstream dial at the proxy itself.
			requireProxyRefusesHello(t, h, sess, ap(row.origDst), rawClientHello(row.sni, false))
		})
	}
}

// planRef: doc 09 §5 TLS-1 Done-when (resolve-once client survives set
// expiry); OQ3 resolve-once clients.
func TestTunnel_LapsedAdmission_SameIP_ReAdmitted(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("api.anthropic.com")
	// Admission already expired: Expiry in the past.
	h.admit(sess, "api.anthropic.com", -time.Second, ip("104.18.0.5"))
	h.programReAdmit("api.anthropic.com", ip("104.18.0.5"))

	origin := newTLSOrigin(t, "echo", "api.anthropic.com")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("104.18.0.5:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "api.anthropic.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("resolve-once client must be re-admitted, not refused; handshake: %v", err)
	}
	if n := h.readmit.callsFor("api.anthropic.com"); n != 1 {
		t.Errorf("ReAdmit called %d times, want exactly 1", n)
	}
	if !h.dialer.dialedAddr(ap("104.18.0.5:443")) {
		t.Error("connection must proceed to the re-admitted address 104.18.0.5:443")
	}
	// A fresh admission must have been recorded in the DNS-2b map.
	a, ok, err := h.adm.Lookup(context.Background(), sess, "api.anthropic.com")
	if err != nil || !ok {
		t.Fatalf("fresh admission missing after re-admit: ok=%v err=%v", ok, err)
	}
	if !a.Expiry.After(h.clock.Now()) {
		t.Errorf("re-admission must record a live expiry; got %v at now=%v", a.Expiry, h.clock.Now())
	}
}

// planRef: doc 09 §5 TLS-1 (re-admitted … connect upstream to a freshly
// admitted address … not the client's claim). ADVERSARIAL.
func TestTunnel_CDNRotation_DialsFreshAdmission_NeverClientClaim(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("registry.npmjs.org")
	// Stale, attacker-favorable admission at 1.2.3.4, already expired.
	h.admit(sess, "registry.npmjs.org", -time.Second, ip("1.2.3.4"))
	// Our re-resolution now yields 5.6.7.8 (CDN rotated).
	h.programReAdmit("registry.npmjs.org", ip("5.6.7.8"))

	origin := newTLSOrigin(t, "echo", "registry.npmjs.org")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("1.2.3.4:443"))
	defer conn.Close()
	// Opaque tunnel preserved: the client still validates the origin cert.
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "registry.npmjs.org"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tunnel after CDN rotation must succeed via the fresh admission: %v", err)
	}
	if !h.dialer.dialedAddr(ap("5.6.7.8:443")) {
		t.Error("upstream must be dialed at the freshly admitted 5.6.7.8:443 (OUR resolution)")
	}
	if h.dialer.dialedAddr(ap("1.2.3.4:443")) {
		t.Error("the client's claimed original destination 1.2.3.4 must NEVER be dialed")
	}
}

// planRef: doc 09 §5 TLS-1 re-admission path × DNS-4 rule 3 (re-resolutions
// go through FULL admission again). ADVERSARIAL.
func TestTunnel_LapsedAdmission_PolicyNowDenies_Refused(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	// once-allowed.com was admitted, has expired, and policy snapshot v2 now denies it.
	h.admit(sess, "once-allowed.com", -time.Second, ip("3.3.3.3"))
	h.policy.deny("once-allowed.com")
	h.policy.setVersion("policy-v2")
	h.programReAdmit("once-allowed.com", ip("3.3.3.3")) // even if re-resolution works, policy must win

	origin := newTLSOrigin(t, "echo", "once-allowed.com")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("3.3.3.3:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "once-allowed.com"})
	if err := tc.Handshake(); err == nil {
		t.Error("a since-blocked domain must be refused on the re-admission path; handshake succeeded")
	}
	if h.dialer.dialedAddr(ap("3.3.3.3:443")) {
		t.Error("no upstream dial may complete a tunnel for a denied domain")
	}
	ev := h.requireEvent(EventPolicyDecision, "once-allowed.com")
	if ev.Provenance.PolicyVersion != "policy-v2" {
		t.Errorf("deny event must carry the NEW policy version, got %q want %q", ev.Provenance.PolicyVersion, "policy-v2")
	}
}

// planRef: doc 09 §4 DNS-2b Done-when (expired mapping refuses even while
// another domain keeps the same IP alive). ADVERSARIAL.
func TestTunnel_ExpiredDomainRefused_WhileOtherDomainHoldsSameIP(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	shared := ip("151.101.1.1")
	h.policy.allow("domain-a.com", "domain-b.com")
	h.admit(sess, "domain-b.com", time.Minute, shared)  // live — keeps the bare IP alive
	h.admit(sess, "domain-a.com", -time.Second, shared) // expired
	// Ask posture: domain-a cannot be silently re-admitted.
	h.readmit.fn = func(_ SessionRef, d string) (Admission, error) {
		return Admission{}, &askPostureErr{domain: d}
	}

	decA, errA := h.gate.Evaluate(ctx, sess, ClientHello{SNI: "domain-a.com"}, ap("151.101.1.1:443"))
	if errA != nil {
		t.Fatalf("Evaluate(domain-a) must refuse cleanly, got error: %v", errA)
	}
	if decA.Action != ActionRefuse {
		t.Fatalf("domain-a Action = %v, want Refuse: per-domain expiry holds even while the bare IP stays alive via domain-b", decA.Action)
	}

	// Control: domain-b on the very same IP succeeds.
	decB, errB := h.gate.Evaluate(ctx, sess, ClientHello{SNI: "domain-b.com"}, ap("151.101.1.1:443"))
	if errB != nil {
		t.Fatalf("Evaluate(domain-b) control: %v", errB)
	}
	if decB.Action == ActionRefuse || decB.Action == ActionUnknown {
		t.Fatalf("domain-b control Action = %v, want an admitting action", decB.Action)
	}
	if decB.Upstream != ap("151.101.1.1:443") {
		t.Errorf("domain-b Upstream = %v, want 151.101.1.1:443", decB.Upstream)
	}
}

type askPostureErr struct{ domain string }

func (e *askPostureErr) Error() string { return "ask posture: approval required for " + e.domain }

// planRef: doc 09 §5 TLS-1 Done-when (conformance clients); doc 06 §2.2 proxy
// data-plane conformance. Conformance clients are modeled with stdlib
// HTTP-over-TLS clients (curl- and git-smart-HTTP-shaped); the real
// curl/git binaries run on the scheduled (d) rig.
func TestTunnel_Conformance_CurlAndGitHTTPS_PassClean(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("github.com")
	h.admit(sess, "github.com", time.Minute, ip("140.82.1.1"))

	const filePayload = "hello-world-payload-2026"
	const refsPayload = "001e# service=git-upload-pack\n0000"
	origin := newTLSOrigin(t, "http", "github.com")
	origin.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/file.txt":
			io.WriteString(w, filePayload)
		case strings.HasSuffix(r.URL.Path, "/info/refs"):
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			io.WriteString(w, refsPayload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("140.82.1.1:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "github.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("conformance client TLS handshake: %v", err)
	}

	// curl-shaped GET.
	resp, body, err := roundTrip(tc, newReq(t, http.MethodGet, "https://github.com/file.txt", nil, ""))
	if err != nil {
		t.Fatalf("curl-shaped GET: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != filePayload {
		t.Fatalf("golden-trace diff: status=%d body=%q, want 200 %q", resp.StatusCode, body, filePayload)
	}

	// git-over-HTTPS-shaped GET on the same connection (keep-alive, no retries).
	resp2, body2, err := roundTrip(tc, newReq(t, http.MethodGet, "https://github.com/org/repo.git/info/refs?service=git-upload-pack", nil, ""))
	if err != nil {
		t.Fatalf("git-shaped GET: %v", err)
	}
	if resp2.StatusCode != http.StatusOK || string(body2) != refsPayload {
		t.Fatalf("golden-trace diff: status=%d body=%q, want 200 %q", resp2.StatusCode, body2, refsPayload)
	}
	if n := origin.connCount(); n != 1 {
		t.Errorf("origin saw %d connections, want 1 (no retries, no reconnects)", n)
	}
}

// planRef: doc 09 OQ3 (a long-lived stream crossing an element expiry); NFT-3
// "established flows ride conntrack" analogue at the proxy.
func TestTunnel_EstablishedTunnelSurvivesAdmissionExpiryMidStream(t *testing.T) {
	h := newHarness(t)
	sess := SessionRef{ID: "sess-a"}
	h.policy.allow("api.anthropic.com")
	h.admit(sess, "api.anthropic.com", 30*time.Second, ip("104.18.0.5"))
	h.programReAdmit("api.anthropic.com", ip("104.18.0.5"))

	origin := newTLSOrigin(t, "echo", "api.anthropic.com")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("104.18.0.5:443"))
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: "api.anthropic.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("stream setup handshake: %v", err)
	}
	echoOnce := func(label string) {
		payload := []byte("chunk-" + label)
		if _, err := tc.Write(payload); err != nil {
			t.Fatalf("write %s: %v", label, err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(tc, buf); err != nil {
			t.Fatalf("read %s: in-flight tunnel must never be severed by admission expiry: %v", label, err)
		}
	}
	echoOnce("before-expiry")
	if n := h.readmit.callsFor("api.anthropic.com"); n != 0 {
		t.Fatalf("no re-admission expected while admission is live; got %d", n)
	}

	// The admission map entry expires mid-stream.
	h.clock.Advance(60 * time.Second)
	echoOnce("after-expiry")

	// A second NEW connection for the same (domain, IP) takes the
	// re-admission path — not a silent pass.
	conn2, _ := h.startTransparent(sess, ap("104.18.0.5:443"))
	defer conn2.Close()
	tc2 := tls.Client(conn2, &tls.Config{RootCAs: origin.pool, ServerName: "api.anthropic.com"})
	if err := tc2.Handshake(); err != nil {
		t.Fatalf("second connection must be re-admitted and succeed: %v", err)
	}
	if n := h.readmit.callsFor("api.anthropic.com"); n != 1 {
		t.Errorf("second NEW connection must take the re-admission path exactly once; ReAdmit calls = %d", n)
	}
}
