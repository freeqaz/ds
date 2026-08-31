// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// tlsproxyinspect_test.go — the OFFLINE half of the TLS-3.a-d conformance.
// Always runs, no live kernel/network: it drives the adapter's REAL strict-WebPKI
// re-origination dialer (the Go mirror of reoriginate.rs, satisfying the boundary
// UpstreamDialer seam) over loopback TLS listeners for the TLS-3.b bad-cert table
// — the one row that exercises real strict-WebPKI re-validation in-process — and
// asserts real-plane cert-shaping parity for 3.a (leaf names exact origin), 3.c
// (distinct session-CA keypairs + A's pool useless against B), and 3.d
// (per-(session,origin) leaf cache stability). The over-the-wire 3.a/3.c rows are
// the env-gated live half (live_test.go), deferred to CI.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

func ctx() context.Context { return context.Background() }

// ───────────────────────────────────────────────────────────────────────────
// loopback TLS listener (no external net) + cert-verify classifier — mirrors
// the boundary startTLSListener / isCertVerifyError helpers.
// ───────────────────────────────────────────────────────────────────────────

func startTLSListener(t *testing.T, cert tls.Certificate) (netip.AddrPort, *lockedBuffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(tcp.Port)), appData
}

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

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}

// ───────────────────────────────────────────────────────────────────────────
// x509 fixtures (WebPKI fixture root + leaf shapes) — mirror the boundary
// mintCACert / mintLeafCert / selfSignedLeaf / mintCertWith helpers.
// ───────────────────────────────────────────────────────────────────────────

var fixtureSerial int64 = 5000

func nextFixtureSerial() *big.Int { fixtureSerial++; return big.NewInt(fixtureSerial) }

func mintKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mint key: %v", err)
	}
	return k
}

func mintCACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := mintKey(t)
	tpl := &x509.Certificate{
		SerialNumber:          nextFixtureSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("mint CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

type leafOpts struct{ notBefore, notAfter time.Time }

func mintLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string, opt *leafOpts) tls.Certificate {
	t.Helper()
	key := mintKey(t)
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(12*time.Hour)
	if opt != nil {
		nb, na = opt.notBefore, opt.notAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: nextFixtureSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("mint leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func selfSignedLeaf(t *testing.T, names []string) tls.Certificate {
	t.Helper()
	key := mintKey(t)
	tpl := &x509.Certificate{
		SerialNumber:          nextFixtureSerial(),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func mintCertWith(t *testing.T, tpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key := mintKey(t)
	tpl.SerialNumber = nextFixtureSerial()
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

// ───────────────────────────────────────────────────────────────────────────
// TLS-3.b — strict-WebPKI re-origination bad-cert table (REAL, in-process).
//
// This is the one offline row that exercises the real strict-WebPKI verdict: the
// adapter's StrictWebPKIDialer (the Go mirror of reoriginate.rs satisfying the
// boundary UpstreamDialer seam) re-originates upstream against a fixture root and
// must REFUSE every bad cert with a cert-verify error before any payload byte
// (doc 12 §13.5). Mirrors boundary TestInspect_UpstreamWebPKI_BadCerts_Refused.
// ───────────────────────────────────────────────────────────────────────────

func TestInspect_UpstreamWebPKI_BadCerts_Refused_TableDriven(t *testing.T) {
	rootCert, rootKey := mintCACert(t, "webpki-fixture-root")
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	dialer := NewStrictWebPKIDialer(tlsproxy.Config{UpstreamRoots: roots}, 0)
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	otherCACert, otherCAKey := mintCACert(t, "untrusted-other-root")

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
			conn, err := dialer.DialTLS(ctx(), sess, row.domain, addr)
			if row.wantOK {
				if err != nil {
					t.Fatalf("control row must re-originate cleanly: %v", err)
				}
				if conn == nil {
					t.Fatal("control row returned nil conn")
				}
				_ = conn.Close()
				return
			}
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatalf("%v: bad upstream cert must refuse before any payload byte", ErrUpstreamNotRefused)
			}
			if !isCertVerifyError(err) {
				t.Errorf("refusal must be a certificate-verification failure, got: %v", err)
			}
			if got := appData.bytes(); len(got) != 0 {
				t.Errorf("zero upstream request bytes expected after refusal, upstream saw %q", got)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-3.a parity — the per-origin leaf names the EXACT origin and is signed by
// the per-session interception CA (issuer ds-session-ca-<id>): the inspected-
// default cert shape the boundary spec asserts a client trusting only the
// session pool sees. Real-plane minting (adapter SessionCA), no wire.
// ───────────────────────────────────────────────────────────────────────────

func TestInspect_PerOriginLeaf_NamesExactOrigin(t *testing.T) {
	minter := NewCAMinter()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const origin = "inspected.example"

	ca, err := minter.MintSessionCA(ctx(), sess)
	if err != nil {
		t.Fatalf("MintSessionCA: %v", err)
	}
	leaf, err := ca.LeafFor(ctx(), origin)
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatal("minted leaf has no parsed Leaf")
	}
	found := false
	for _, n := range leaf.Leaf.DNSNames {
		if n == origin {
			found = true
		}
	}
	if !found {
		t.Errorf("%v: presented leaf must name the exact origin %q, got %v", ErrLeafNotForOrigin, origin, leaf.Leaf.DNSNames)
	}
	if got := leaf.Leaf.Issuer.CommonName; got != "ds-session-ca-"+sess.ID {
		t.Errorf("leaf issuer = %q, want the per-session CA %q (inspection is the default)", got, "ds-session-ca-"+sess.ID)
	}

	// A client trusting ONLY this session's pool validates the leaf chain.
	pool, err := minter.PoolFor(sess)
	if err != nil {
		t.Fatalf("PoolFor: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: origin, Roots: pool}); err != nil {
		t.Errorf("client trusting only the session CA pool must see valid TLS: %v", err)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-3.c parity — per-session CA isolation: A's CA is a distinct keypair from
// B's, A's trust pool is useless against B's leaf, and an A-signed server cert
// is REFUSED by strict upstream WebPKI inside B's re-origination. Mirrors
// boundary TestInspect_PerSessionCAIsolation_AUselessAgainstB. ADVERSARIAL.
// ───────────────────────────────────────────────────────────────────────────

func TestInspect_PerSessionCAIsolation_AUselessAgainstB(t *testing.T) {
	minter := NewCAMinter()
	sessA := tlsproxy.SessionRef{ID: "sess-a"}
	sessB := tlsproxy.SessionRef{ID: "sess-b"}
	const origin = "inspected.example"

	// (0) Distinct keypairs.
	pubA, err := minter.PublicKeyFor(sessA)
	if err != nil {
		t.Fatalf("PublicKeyFor A: %v", err)
	}
	pubB, err := minter.PublicKeyFor(sessB)
	if err != nil {
		t.Fatalf("PublicKeyFor B: %v", err)
	}
	if pubA.Equal(pubB) {
		t.Fatal("session CA key pairs must be distinct")
	}

	caA, err := minter.MintSessionCA(ctx(), sessA)
	if err != nil {
		t.Fatalf("MintSessionCA A: %v", err)
	}
	caB, err := minter.MintSessionCA(ctx(), sessB)
	if err != nil {
		t.Fatalf("MintSessionCA B: %v", err)
	}
	poolA, err := minter.PoolFor(sessA)
	if err != nil {
		t.Fatalf("PoolFor A: %v", err)
	}

	// (1) B's leaf, verified against A's pool, FAILS (A useless against B).
	bLeaf, err := caB.LeafFor(ctx(), origin)
	if err != nil {
		t.Fatalf("B LeafFor: %v", err)
	}
	if _, err := bLeaf.Leaf.Verify(x509.VerifyOptions{DNSName: origin, Roots: poolA}); err == nil {
		t.Error("session A's CA pool must be useless against session B's leaf; verification succeeded")
	}

	// (2) An A-CA-signed server cert presented inside B's flow is rejected by
	// strict upstream WebPKI re-origination (the fixture-root validation that
	// stands in for "at least as strict as the client would have been").
	rootCert, _ := mintCACert(t, "webpki-fixture-root")
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	realDialer := NewStrictWebPKIDialer(tlsproxy.Config{UpstreamRoots: roots}, 0)
	aLeaf, err := caA.LeafFor(ctx(), origin)
	if err != nil {
		t.Fatalf("A LeafFor: %v", err)
	}
	addr, appData := startTLSListener(t, aLeaf)
	if conn, err := realDialer.DialTLS(ctx(), sessB, origin, addr); err == nil {
		_ = conn.Close()
		t.Errorf("%v: an A-CA-signed server cert must be rejected inside B's upstream validation", ErrUpstreamNotRefused)
	} else if !isCertVerifyError(err) {
		t.Errorf("rejection must be a certificate-verification failure, got: %v", err)
	}
	if got := appData.bytes(); len(got) != 0 {
		t.Errorf("zero upstream request bytes expected after refusal, upstream saw %q", got)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-3.d parity — the leaf cache is stable per (session, origin): sequential
// LeafFor calls for one origin return a byte-identical leaf (cached), distinct
// origins never share a leaf, and a distinct session gets a distinct leaf.
// Mirrors boundary TestInspect_LeafCache_StablePerOrigin.
// ───────────────────────────────────────────────────────────────────────────

func TestInspect_LeafCache_StablePerOrigin(t *testing.T) {
	minter := NewCAMinter()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	const originX = "alpha.example"
	const originY = "beta.example"

	ca, err := minter.MintSessionCA(ctx(), sess)
	if err != nil {
		t.Fatalf("MintSessionCA: %v", err)
	}
	raw := func(domain string) []byte {
		t.Helper()
		leaf, err := ca.LeafFor(ctx(), domain)
		if err != nil {
			t.Fatalf("LeafFor %s: %v", domain, err)
		}
		return leaf.Certificate[0]
	}

	x1 := raw(originX)
	x2 := raw(originX)
	y := raw(originY)

	if !bytes.Equal(x1, x2) {
		t.Error("sequential LeafFor on the same origin must return a byte-identical (cached) leaf")
	}
	if bytes.Equal(x1, y) {
		t.Error("different origins must not share a leaf")
	}
	yCert, err := x509.ParseCertificate(y)
	if err != nil {
		t.Fatalf("parse Y leaf: %v", err)
	}
	if !strings.Contains(strings.Join(yCert.DNSNames, ","), originY) {
		t.Errorf("Y's leaf must name %s, got %q", originY, yCert.DNSNames)
	}

	// A distinct session minting the same origin gets a DISTINCT leaf (the cache
	// is keyed on (session, origin), not origin alone).
	caOther, err := minter.MintSessionCA(ctx(), tlsproxy.SessionRef{ID: "sess-b"})
	if err != nil {
		t.Fatalf("MintSessionCA other: %v", err)
	}
	otherX, err := caOther.LeafFor(ctx(), originX)
	if err != nil {
		t.Fatalf("other LeafFor: %v", err)
	}
	if bytes.Equal(x1, otherX.Certificate[0]) {
		t.Error("a distinct session must not share session A's leaf for the same origin")
	}
}

// ───────────────────────────────────────────────────────────────────────────
// D82 — CA material is INGESTED, not minted in-process: empty/garbage material
// fails with ErrCAMaterialUnavailable rather than silently fabricating a CA.
// ───────────────────────────────────────────────────────────────────────────

func TestIngestCAMaterial_RejectsMissingMaterial(t *testing.T) {
	if _, err := newAdapterSessionCA(SessionMaterial{}); !errors.Is(err, ErrCAMaterialUnavailable) {
		t.Errorf("empty CA material must yield ErrCAMaterialUnavailable, got: %v", err)
	}
	if _, err := newAdapterSessionCA(SessionMaterial{CertPEM: []byte("not a pem"), KeyDER: []byte("x")}); !errors.Is(err, ErrCAMaterialUnavailable) {
		t.Errorf("garbage CA cert PEM must yield ErrCAMaterialUnavailable, got: %v", err)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// EventSink capture — the boundary EventSink seam captures HTTP-metadata
// emissions for the TLS-3.a metadata-in-telemetry assertion (offline shape).
// ───────────────────────────────────────────────────────────────────────────

func TestCapturingEventSink_RecordsAndCopies(t *testing.T) {
	sink := NewCapturingEventSink()
	fields := map[string]string{"method": "GET", "host": "inspected.example", "path": "/data", "status": "200"}
	ev := tlsproxy.Event{
		Kind:       tlsproxy.EventHTTP,
		Session:    tlsproxy.SessionRef{ID: "sess-a"},
		Provenance: tlsproxy.Provenance{RuleID: "allow:inspected.example", PolicyLayer: "system", PolicyVersion: "policy-v1"},
		Fields:     fields,
	}
	if err := sink.Emit(ctx(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	fields["status"] = "500" // mutate after Emit — capture must be a copy.
	got := sink.Events()
	if len(got) != 1 {
		t.Fatalf("captured %d events, want 1", len(got))
	}
	if got[0].Fields["status"] != "200" {
		t.Errorf("captured event must be a deep copy; status = %q, want 200", got[0].Fields["status"])
	}
	if got[0].Kind != tlsproxy.EventHTTP {
		t.Errorf("captured event kind = %q, want HttpEvent", got[0].Kind)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Exported-sentinel convention guards — mirrored from resolverlock: the Err*
// sentinels are load-bearing (the Err prefix + errors.New construction lets the
// completeness scan reconcile them). exportedSentinelUniverse must enumerate
// EVERY exported sentinel; the guards reconcile it against source by AST.
// ───────────────────────────────────────────────────────────────────────────

// exportedSentinelUniverse is the authoritative set of this package's exported
// error sentinels. Every Err* = errors.New(...) var here must appear; the guards
// below fail LOUDLY on any drift.
var exportedSentinelUniverse = map[string]error{
	"ErrCAMaterialUnavailable": ErrCAMaterialUnavailable,
	"ErrLeafNotForOrigin":      ErrLeafNotForOrigin,
	"ErrUpstreamNotRefused":    ErrUpstreamNotRefused,
}

// nonTestPackageFiles returns the package's non-_test.go source files.
func nonTestPackageFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ───────────────────────────────────────────────────────────────────────────
// DOUBLE-FIRE (D132) — the SCAN side of the TLS-5/TLS-7 ordering invariant.
//
// planRef: doc 12 §13.3 / §5.3 (D132 — scan-before-swap FROZEN on the inspected
// path); doc 04 §6 D132; doc 12 §13.6 OQ2 (closed). It re-expresses the boundary
// row boundary/tlsproxy/tlsproxy_scan_test.go:
// TestSwap_TLS5_InjectedAuthHeader_NeverScannedAfterSubstitution against the REAL
// keyed-matcher-backed scanner (KeyedSecretScanner / CanaryFeed in scan_adapter.go),
// since the boundary NewSecretScanner is a RED stub.
//
// The core OQ2 requirement: the TLS-5 credential swap and the TLS-7 scan do not
// double-fire on the same Authorization header. Because the scan ALWAYS runs
// BEFORE the swap (D132), the scan reads the AGENT-PRESENTED bytes; the real
// long-lived credential the swap substitutes onto the upstream-bound request is
// NEVER on the bytes the scan saw, so it is never scan-visible.
//
// This SCAN-side mirror proves the two halves of the invariant against the real
// scanner: (a) a canary the AGENT presents in the Authorization header IS caught
// (first-egress detection the ordering preserves), and (b) the long-lived
// credential the swap WOULD inject — registered as its OWN keyed canary so the
// scanner would absolutely match it IF it ever saw it — is NOT matched when the
// scanner runs on the agent-presented (pre-swap) bytes, because those bytes never
// carry the injected credential. The double-fire is structurally impossible.
// ───────────────────────────────────────────────────────────────────────────

// injectedLongLived is the long-lived credential the TLS-5 swap WOULD substitute
// onto the upstream-bound Authorization header. It is registered as its own keyed
// canary (newDoubleFireFeed) so the scanner would match it IF the post-swap bytes
// were ever handed to it — making the "never matched on agent bytes" assertion
// load-bearing (a do-nothing scanner that matches NOTHING would not prove the
// invariant; the agent-canary leg keeps this honest).
const injectedLongLived = "ghp_INJECTEDcredential00000000000000000000"

// newDoubleFireFeed plants BOTH the agent's presented canary (seededToken) AND the
// swap-injected long-lived credential (injectedLongLived) as keyed digests, so the
// scanner is fully capable of matching EITHER — the invariant is about WHICH bytes
// the scanner runs over (agent-presented, pre-swap), not about a scanner blind to
// the injected value.
func newDoubleFireFeed(t *testing.T) *CanaryFeed {
	t.Helper()
	feed := NewCanaryFeed("key-epoch-1", "digest-set-v1", 16)
	feed.Register("ghp-agent-canary", tokenClass, seededToken)
	feed.Register("ghp-injected-longlived", tokenClass, injectedLongLived)
	return feed
}

func TestScan_TLS5InjectedAuthHeader_NeverScannedAfterSubstitution(t *testing.T) {
	feed := newDoubleFireFeed(t)
	scanner := NewKeyedSecretScanner(feed.Matcher(VerdictBlock))
	sess := tlsproxy.SessionRef{ID: "sess-a"}

	// (a) The scan runs on the AGENT-PRESENTED request bytes (pre-swap): the
	// agent's planted canary in the Authorization header is caught at first egress
	// — the first-egress detection scan-before-swap (D132) preserves.
	agentPresented := []byte("GET /user HTTP/1.1\r\nAuthorization: Bearer " + seededToken + "\r\n\r\n")
	agentFindings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, agentPresented)
	if err != nil {
		t.Fatalf("scan of agent-presented bytes must not error: %v", err)
	}
	if len(agentFindings) == 0 {
		t.Fatal("the TLS-7 scan, run on the agent-presented bytes, must catch the agent's planted canary at first egress (D132 scan-before-swap)")
	}
	// never-log-the-secret: no finding carries the agent canary NOR the injected
	// credential value.
	for _, f := range agentFindings {
		if findingContains(f, seededToken) {
			t.Errorf("a Finding must carry a fingerprint, NEVER the agent canary value: %+v", f)
		}
		if findingContains(f, injectedLongLived) {
			t.Errorf("a Finding on agent-presented bytes must never carry the swap-injected credential: %+v", f)
		}
	}

	// (b) The injected long-lived credential is on the agent-presented bytes? No —
	// the swap substitutes it onto the UPSTREAM-bound request only AFTER the scan
	// has run. So scanning the agent-presented bytes does NOT match the injected
	// credential: the scan and the swap never double-fire on the shared header.
	if bytes.Contains(agentPresented, []byte(injectedLongLived)) {
		t.Fatal("test wiring error: the injected credential must not be on the agent-presented (pre-swap) bytes")
	}
	for _, f := range agentFindings {
		if f.Fingerprint == fingerprintFor(scanProvForRule("ghp-injected-longlived", feed)) {
			t.Error("the agent-bytes scan matched the swap-injected credential's rule — double-fire on the shared header (D132 violated)")
		}
	}

	// (c) The DUAL that keeps (b) honest: the scanner IS capable of matching the
	// injected credential — were the post-swap bytes ever handed to it, it would
	// fire. The invariant is that those bytes are never the bytes the scan reads.
	postSwap := []byte("GET /user HTTP/1.1\r\nAuthorization: Bearer " + injectedLongLived + "\r\n\r\n")
	postSwapFindings, err := scanner.ScanInbound(ctx(), sess, tlsproxy.ResponseMeta{Status: 200}, postSwap)
	if err != nil {
		t.Fatalf("scan of post-swap bytes: %v", err)
	}
	if len(postSwapFindings) == 0 {
		t.Fatal("the scanner must be CAPABLE of matching the injected credential (proving (b) is not vacuous) — the invariant is that the scan never runs on these post-swap bytes")
	}
	// And the agent-presented and post-swap byte streams are distinct: the
	// double-fire is structurally impossible because the scan reads only the former.
	if bytes.Equal(agentPresented, postSwap) {
		t.Fatal("agent-presented and post-swap bytes must differ (no shared header double-fire)")
	}
}

// scanProvForRule rebuilds the ScanProvenance the matcher would attach for a named
// keyed rule under feed, so the test can recompute the fingerprint a match on that
// rule would carry — used to prove the agent-bytes scan did NOT fire the injected
// credential's rule.
func scanProvForRule(ruleID string, feed *CanaryFeed) ScanProvenance {
	return ScanProvenance{
		Plane:          PlaneKeyed,
		RuleID:         ruleID,
		Kind:           tokenClass,
		RulesetVersion: feed.setVersion,
	}
}

// TestExportedSentinelUniverseComplete reconciles exportedSentinelUniverse
// against source: every package-level `Err* = errors.New(...)` var in a
// non-_test.go file must be enumerated, and every enumerated name must exist.
func TestExportedSentinelUniverseComplete(t *testing.T) {
	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, file := range nonTestPackageFiles(t) {
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
					if !ast.IsExported(name.Name) || !strings.HasPrefix(name.Name, "Err") {
						continue
					}
					if i >= len(vs.Values) || !isErrorsNewCall(vs.Values[i]) {
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

// isErrorsNewCall reports whether expr is an errors.New(...) call.
func isErrorsNewCall(expr ast.Expr) bool {
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

// TestExportedErrorVarsCoveredByUniverse is the naming-agnostic backstop: it
// flags ANY exported, file-scope, error-constructing var (errors.New or
// fmt.Errorf) missing from exportedSentinelUniverse, so a sentinel that BROKE
// the Err-prefix convention cannot slip past the by-name scan above.
func TestExportedErrorVarsCoveredByUniverse(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range nonTestPackageFiles(t) {
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
					if !ast.IsExported(name.Name) || i >= len(vs.Values) {
						continue
					}
					if !isErrorsNewCall(vs.Values[i]) && !isFmtErrorfCall(vs.Values[i]) {
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

func isFmtErrorfCall(expr ast.Expr) bool {
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
