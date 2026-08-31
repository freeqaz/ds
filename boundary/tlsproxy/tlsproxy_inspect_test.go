package tlsproxy

// TLS-3 — TLS inspection by the trusted proxy (D17) and TLS-4 — the
// pass-through list for cert-pinned clients (doc 09 §5).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// startTLSListener serves TLS with the given certificate chain on a real
// loopback socket and records every post-handshake application byte.
func startTLSListener(t *testing.T, cert tls.Certificate) (netip.AddrPort, *lockedBuffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	appData := &lockedBuffer{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				if s.Handshake() != nil {
					return
				}
				_, _ = io.Copy(appData, s)
			}(c)
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(ip("127.0.0.1"), uint16(tcp.Port)), appData
}

// isCertVerifyError reports whether err is a certificate-verification
// failure (and not, e.g., the stub's ErrNotImplemented).
func isCertVerifyError(err error) bool {
	if err == nil {
		return false
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "certificate") || strings.Contains(s, "x509")
}

func mintCertWith(t *testing.T, tpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key := mintKey(t)
	tpl.SerialNumber = nextSerial()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("mint cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key, der
}

// planRef: doc 09 §5 TLS-3 Done-when (clients see valid TLS, metadata in
// telemetry)
func TestInspect_PerOriginLeaf_ValidTLS_MetadataTelemetry(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "inspected.example"
	h.policy.allow(domain)
	h.admit(sess, domain, time.Minute, ip("198.51.100.7"))
	up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "inspected-payload")
	}}
	h.dialer.tlsFn = up.dialTLS

	conn, _ := h.startTransparent(sess, ap("198.51.100.7:443"))
	defer conn.Close()
	tc, err := h.sessionTLSClient(conn, sess, domain)
	if err != nil {
		t.Fatalf("client trusting only session CA must see valid TLS: %v", err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	found := false
	for _, n := range leaf.DNSNames {
		if n == domain {
			found = true
		}
	}
	if !found {
		t.Errorf("presented leaf must name the exact origin %q, got %v", domain, leaf.DNSNames)
	}
	resp, body, err := roundTrip(tc, newReq(t, http.MethodGet, "https://"+domain+"/data", nil, ""))
	if err != nil {
		t.Fatalf("inspected GET: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "inspected-payload" {
		t.Fatalf("status=%d body=%q, want 200 inspected-payload", resp.StatusCode, body)
	}
	h.requireEvent(EventHTTP, "GET", domain, "/data", "200")
}

// planRef: doc 09 §5 TLS-3 (strict WebPKI re-validation — at least as strict
// as the client's would have been). ADVERSARIAL.
func TestInspect_UpstreamWebPKI_BadCerts_Refused_TableDriven(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	rootCert, rootKey, rootPEM := mintCACert(t, "webpki-fixture-root")
	_ = rootPEM
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	cfg := Config{Now: clock.Now, UpstreamRoots: roots}
	dialer := NewUpstreamDialer(cfg)
	sess := SessionRef{ID: "sess-a"}

	otherCACert, otherCAKey, _ := mintCACert(t, "untrusted-other-root")

	// Invalid intermediate: signed by the trusted root but NOT a CA.
	badInter, badInterKey, badInterDER := mintCertWith(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "not-actually-a-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, rootCert, rootKey)

	leafViaBadInter := mintLeafCert(t, badInter, badInterKey, []string{"inter.example"}, nil)
	leafViaBadInter.Certificate = append(leafViaBadInter.Certificate, badInterDER)

	untrustedLeaf := mintLeafCert(t, otherCACert, otherCAKey, []string{"untrusted.example"}, nil)
	untrustedLeaf.Certificate = append(untrustedLeaf.Certificate, otherCACert.Raw)

	rows := []struct {
		name   string
		domain string
		cert   tls.Certificate
		wantOK bool
	}{
		{"control: valid WebPKI cert", "good.example",
			mintLeafCert(t, rootCert, rootKey, []string{"good.example"}, nil), true},
		{"self-signed", "self.example", selfSignedLeaf(t, []string{"self.example"}), false},
		{"expired", "expired.example",
			mintLeafCert(t, rootCert, rootKey, []string{"expired.example"},
				&leafOpts{notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)}), false},
		{"hostname mismatch", "mismatch.example",
			mintLeafCert(t, rootCert, rootKey, []string{"other.example"}, nil), false},
		{"untrusted chain", "untrusted.example", untrustedLeaf, false},
		{"invalid intermediate", "inter.example", leafViaBadInter, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			addr, appData := startTLSListener(t, row.cert)
			conn, err := dialer.DialTLS(ctx, sess, row.domain, addr)
			if row.wantOK {
				if err != nil {
					t.Fatalf("control row must dial cleanly: %v", err)
				}
				if conn == nil {
					t.Fatal("control row returned nil conn")
				}
				conn.Close()
				return
			}
			if err == nil {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("bad upstream cert must refuse the connection before any payload byte")
			}
			if !isCertVerifyError(err) {
				t.Errorf("refusal must be a certificate-verification failure, got: %v", err)
			}
			if got := appData.bytes(); len(got) != 0 {
				t.Errorf("zero upstream request bytes expected after refusal, upstream saw %q", got)
			}
		})
	}

	// Via the proxy inspect path: the downstream request dies with a
	// TLS/bad-gateway error and an error event is emitted.
	t.Run("via proxy inspect path", func(t *testing.T) {
		h := newInspectHarness(t)
		const domain = "self.example"
		h.policy.allow(domain)
		h.admit(sess, domain, time.Minute, ip("198.51.100.9"))
		addr, appData := startTLSListener(t, selfSignedLeaf(t, []string{domain}))
		h.dialer.tlsFn = func(d string, _ netip.AddrPort) (net.Conn, error) {
			return dialer.DialTLS(ctx, sess, d, addr)
		}
		resp, _, err := h.inspectRequest(sess, domain, ap("198.51.100.9:443"), newReq(t, http.MethodGet, "https://"+domain+"/", nil, ""))
		if err == nil && resp.StatusCode != http.StatusBadGateway {
			t.Errorf("downstream must fail with a TLS/bad-gateway error, got status %d", resp.StatusCode)
		}
		if got := appData.bytes(); len(got) != 0 {
			t.Errorf("zero upstream request bytes expected, upstream saw %q", got)
		}
		h.requireEvent(EventError, domain)
	})
}

// planRef: doc 09 §5 TLS-3 Done-when (per-session CA from session A useless
// against session B); D17. ADVERSARIAL.
func TestInspect_PerSessionCAIsolation_AUselessAgainstB(t *testing.T) {
	ctx := context.Background()
	h := newInspectHarness(t)
	sessA := SessionRef{ID: "sess-a"}
	sessB := SessionRef{ID: "sess-b"}
	const domain = "inspected.example"
	h.policy.allow(domain)
	h.admit(sessA, domain, time.Minute, ip("198.51.100.7"))
	h.admit(sessB, domain, time.Minute, ip("198.51.100.7"))
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	// The two session CAs are distinct key pairs.
	caA := h.cas.caFor(sessA)
	caB := h.cas.caFor(sessB)
	pubA, _ := caA.caCert.PublicKey.(*ecdsa.PublicKey)
	pubB, _ := caB.caCert.PublicKey.(*ecdsa.PublicKey)
	if pubA == nil || pubB == nil || pubA.Equal(pubB) {
		t.Fatal("session CA key pairs must be distinct")
	}

	// Control: a client trusting B's pool succeeds on B's interface.
	connCtrl, _ := h.startTransparent(sessB, ap("198.51.100.7:443"))
	defer connCtrl.Close()
	if _, err := h.sessionTLSClient(connCtrl, sessB, domain); err != nil {
		t.Fatalf("control: B-pool client on B's interface must handshake: %v", err)
	}

	// (1) A client trusting ONLY A's pool fails on B's interface.
	connAB, _ := h.startTransparent(sessB, ap("198.51.100.7:443"))
	defer connAB.Close()
	tcAB := tls.Client(connAB, &tls.Config{RootCAs: h.cas.poolFor(t, sessA), ServerName: domain})
	if err := tcAB.Handshake(); err == nil {
		t.Error("session A's CA pool must be useless against session B's flow; handshake succeeded")
	} else if !isCertVerifyError(err) {
		t.Errorf("A-pool-on-B failure must be a trust failure, got: %v", err)
	}

	// (2) A leaf signed by A's CA presented as a server cert inside B's flow
	// is rejected by strict upstream WebPKI validation.
	rootCert, _, _ := mintCACert(t, "webpki-fixture-root")
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	realDialer := NewUpstreamDialer(Config{Now: h.clock.Now, UpstreamRoots: roots})
	aLeaf, err := caA.LeafFor(ctx, domain)
	if err != nil {
		t.Fatalf("mint A-signed leaf: %v", err)
	}
	addr, _ := startTLSListener(t, aLeaf)
	if conn, err := realDialer.DialTLS(ctx, sessB, domain, addr); err == nil {
		conn.Close()
		t.Error("an A-CA-signed server cert must be rejected inside B's upstream validation")
	} else if !isCertVerifyError(err) {
		t.Errorf("rejection must be a certificate-verification failure, got: %v", err)
	}
}

// planRef: doc 09 §5 TLS-3 (on-the-fly per-origin leaf certs, cached)
func TestInspect_LeafCache_StablePerOrigin(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const originX = "alpha.example"
	const originY = "beta.example"
	h.policy.allow(originX, originY)
	h.admit(sess, originX, time.Minute, ip("198.51.100.7"))
	h.admit(sess, originY, time.Minute, ip("198.51.100.8"))
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	presented := func(domain, dst string) []byte {
		t.Helper()
		conn, _ := h.startTransparent(sess, ap(dst))
		defer conn.Close()
		tc, err := h.sessionTLSClient(conn, sess, domain)
		if err != nil {
			t.Fatalf("handshake %s: %v", domain, err)
		}
		return tc.ConnectionState().PeerCertificates[0].Raw
	}

	x1 := presented(originX, "198.51.100.7:443")
	x2 := presented(originX, "198.51.100.7:443")
	y := presented(originY, "198.51.100.8:443")

	// The fake SessionCA mints a FRESH leaf per LeafFor call, so byte-equality
	// here forces the real system to cache per (session, origin).
	if !bytes.Equal(x1, x2) {
		t.Error("sequential connections to the same origin must present a byte-identical (cached) leaf")
	}
	if bytes.Equal(x1, y) {
		t.Error("different origins must not share a leaf")
	}
	yCert, err := x509.ParseCertificate(y)
	if err != nil {
		t.Fatalf("parse Y leaf: %v", err)
	}
	names := strings.Join(yCert.DNSNames, ",")
	if !strings.Contains(names, originY) {
		t.Errorf("Y's leaf must name %s, got %q", originY, names)
	}
}

// pinnedTLSClient handshakes verifying ONLY the origin's SPKI pin.
func pinnedTLSClient(conn net.Conn, serverName string, pin [sha256.Size]byte) (*tls.Conn, error) {
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if sha256.Sum256(cert.RawSubjectPublicKeyInfo) != pin {
				return fmt.Errorf("pin mismatch: presented SPKI is not the origin's (interception?)")
			}
			return nil
		},
	})
	return tc, tc.Handshake()
}

// planRef: doc 09 §5 TLS-4 Done-when; §9 row "Pinned pass-through is opaque,
// no swap"; doc 06 §2.2 cert-pinned conformance client.
func TestPassThrough_PinnedClient_OpaqueTunnel_PinHolds(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "pinned.example"
	h.policy.allow(domain)
	h.policy.setPassThrough(domain, true)
	h.admit(sess, domain, time.Minute, ip("203.0.113.5"))
	origin := newTLSOrigin(t, "http", domain)
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("203.0.113.5:443"))
	defer conn.Close()
	tc, err := pinnedTLSClient(conn, domain, origin.spki)
	if err != nil {
		t.Fatalf("pin must validate — the proxy never terminates TLS on listed domains: %v", err)
	}
	resp, _, err := roundTrip(tc, newReq(t, http.MethodGet, "https://"+domain+"/private-path", nil, ""))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned request through opaque tunnel: status=%v err=%v", resp, err)
	}

	h.requireEvent(EventFlow, domain)
	// Opaque means opaque: no HTTP-level metadata may exist for this flow.
	if ev, found := findEventContaining(h.events.all(), "", "/private-path"); found {
		t.Errorf("pass-through flow leaked HTTP metadata into a %s event", ev.Kind)
	}
}

// planRef: doc 09 §5 TLS-4 (NO credential swap) + TLS-5 (pass-through flows
// never swap); D17. ADVERSARIAL — pass-through AND swap-registered.
func TestPassThrough_NeverSwaps_EvenWhenServiceRegistered(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	longLived := newCanary(t, 64)
	_, short := h.setupSwap(sess, "github", []string{"github.com"}, longLived)
	h.policy.setPassThrough("github.com", true)

	origin := newTLSOrigin(t, "http", "github.com")
	h.dialer.rawFn = origin.dialRaw

	conn, _ := h.startTransparent(sess, ap("140.82.1.1:443"))
	defer conn.Close()
	tc, err := pinnedTLSClient(conn, "github.com", origin.spki)
	if err != nil {
		t.Fatalf("pass-through tunnel must be opaque (pinning wins): %v", err)
	}
	sentAuth := bearer(short)
	resp, _, err := roundTrip(tc, newReq(t, http.MethodGet, "https://github.com/user",
		map[string]string{"Authorization": sentAuth}, ""))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("pass-through request: status=%v err=%v", resp, err)
	}

	reqs := origin.requests()
	if len(reqs) != 1 {
		t.Fatalf("origin saw %d requests, want 1", len(reqs))
	}
	if got := reqs[0].Header.Get("Authorization"); got != sentAuth {
		t.Errorf("upstream must receive the client's exact bytes; Authorization = %q, want %q", got, sentAuth)
	}
	if bytes.Contains(origin.recorded.bytes(), longLived) {
		t.Error("the long-lived credential must never be substituted on a pass-through flow")
	}
	if n := h.identity.callCount(); n != 0 {
		t.Errorf("IdentityValidator must never be called on pass-through; calls=%d", n)
	}
	if n := h.secrets.fetchCount(); n != 0 {
		t.Errorf("SecretStore must never be called on pass-through; fetches=%d", n)
	}
	if evs := h.events.byKind(EventCredentialUse); len(evs) != 0 {
		t.Errorf("no CredentialUseEvent may exist for a pass-through flow; got %d", len(evs))
	}
}

// planRef: doc 09 §5 TLS-4 (still SNI + allow-set enforced). ADVERSARIAL.
func TestPassThrough_StillSNIAndAdmissionEnforced(t *testing.T) {
	ctx := context.Background()
	rows := []struct {
		name  string
		hello ClientHello
		dst   string
	}{
		{"listed SNI but origDst not admitted for it", ClientHello{SNI: "pinned.example"}, "203.0.113.99:443"},
		{"origDst admitted for listed domain but SNI is another domain", ClientHello{SNI: "other.example"}, "203.0.113.5:443"},
		{"ECH ClientHello to a listed domain", ClientHello{SNI: "pinned.example", HasECH: true}, "203.0.113.5:443"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newInspectHarness(t)
			sess := SessionRef{ID: "sess-a"}
			h.policy.allow("pinned.example", "other.example")
			h.policy.setPassThrough("pinned.example", true)
			h.admit(sess, "pinned.example", time.Minute, ip("203.0.113.5"))

			dec, err := h.gate.Evaluate(ctx, sess, row.hello, ap(row.dst))
			if err != nil {
				t.Fatalf("Evaluate must refuse cleanly, got error: %v", err)
			}
			if dec.Action != ActionRefuse {
				t.Fatalf("Action = %v, want Refuse: pass-through changes tunnel mode, never the admission verdict", dec.Action)
			}
		})
	}
}

// planRef: §9 row "Pinned pass-through is opaque, no swap; ALL ELSE
// INSPECTED"; doc 09 §5 TLS-4 Done-when.
func TestNonListedDomain_AlwaysInspected(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "ordinary.example"
	h.policy.allow(domain) // NOT on the pass-through list
	h.admit(sess, domain, time.Minute, ip("198.51.100.7"))
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	conn, _ := h.startTransparent(sess, ap("198.51.100.7:443"))
	defer conn.Close()
	tc, err := h.sessionTLSClient(conn, sess, domain)
	if err != nil {
		t.Fatalf("inspected handshake against session CA pool: %v", err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	wantIssuer := "ds-session-ca-" + sess.ID
	if leaf.Issuer.CommonName != wantIssuer {
		t.Errorf("presented leaf issuer = %q, want the per-session CA %q (inspection is the default)", leaf.Issuer.CommonName, wantIssuer)
	}
	if resp, _, err := roundTrip(tc, newReq(t, http.MethodGet, "https://"+domain+"/x", nil, "")); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("inspected request: status=%v err=%v", resp, err)
	}
	h.requireEvent(EventHTTP, domain, "/x")
}

// planRef: doc 09 §5 TLS-4 (the list is policy §6, not code) + POL-4 hot
// reload.
func TestPassThrough_ListIsPolicy_ReloadFlipsMode(t *testing.T) {
	h := newInspectHarness(t)
	sess := SessionRef{ID: "sess-a"}
	const domain = "pinned.example"
	h.policy.allow(domain)
	h.policy.setPassThrough(domain, true) // snapshot v1
	h.admit(sess, domain, time.Minute, ip("203.0.113.5"))
	origin := newTLSOrigin(t, "http", domain)
	h.dialer.rawFn = origin.dialRaw
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS

	// Connection 1 under v1: opaque — the origin cert is presented.
	mark1 := h.events.snapshot()
	conn1, _ := h.startTransparent(sess, ap("203.0.113.5:443"))
	defer conn1.Close()
	if _, err := pinnedTLSClient(conn1, domain, origin.spki); err != nil {
		t.Fatalf("v1 connection must be opaque pass-through: %v", err)
	}
	if _, ok := findEventContaining(h.events.since(mark1), "", domain, "policy-v1"); !ok {
		t.Error("v1 connection events must carry PolicyVersion policy-v1")
	}

	// Hot-swap to snapshot v2 without the listing.
	h.policy.setPassThrough(domain, false)
	h.policy.setVersion("policy-v2")

	// Connection 2 under v2: inspected — session-CA leaf presented.
	mark2 := h.events.snapshot()
	conn2, _ := h.startTransparent(sess, ap("203.0.113.5:443"))
	defer conn2.Close()
	tc2, err := h.sessionTLSClient(conn2, sess, domain)
	if err != nil {
		t.Fatalf("v2 connection must flip to inspected: %v", err)
	}
	if got := tc2.ConnectionState().PeerCertificates[0].Issuer.CommonName; got != "ds-session-ca-"+sess.ID {
		t.Errorf("v2 leaf issuer = %q, want the session CA (inspected)", got)
	}
	if _, ok := findEventContaining(h.events.since(mark2), "", domain, "policy-v2"); !ok {
		t.Error("v2 connection events must carry PolicyVersion policy-v2")
	}
}
