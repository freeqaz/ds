package tlsproxy

// Fakes, recording doubles, and the test harness for the ds-tlsproxy
// executable spec. Everything here ships with the tests, not the stubs
// (CONVENTIONS.md "File naming per package").

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const ioTimeout = 3 * time.Second

func ip(s string) netip.Addr     { return netip.MustParseAddr(s) }
func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// ---------------------------------------------------------------------------
// deterministic clock
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
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// canary + grep helpers
// ---------------------------------------------------------------------------

// newCanary returns a high-entropy ASCII needle of n bytes.
func newCanary(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, (n+1)/2)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("canary entropy: %v", err)
	}
	return []byte(hex.EncodeToString(raw))[:n]
}

// encForms returns the credential's VM-observable encodings: raw, base64
// (std + url), hex, and url-encoded.
func encForms(needle []byte) map[string][]byte {
	return map[string][]byte{
		"raw":        needle,
		"base64":     []byte(base64.StdEncoding.EncodeToString(needle)),
		"base64url":  []byte(base64.RawURLEncoding.EncodeToString(needle)),
		"hex":        []byte(hex.EncodeToString(needle)),
		"urlencoded": []byte(url.QueryEscape(string(needle))),
	}
}

// requireNoCanary asserts zero occurrences of the needle, in every encoded
// form, in hay.
func requireNoCanary(t *testing.T, hay, needle []byte, where string) {
	t.Helper()
	for form, enc := range encForms(needle) {
		if bytes.Contains(hay, enc) {
			t.Errorf("credential canary leaked (%s form) in %s", form, where)
		}
	}
}

func requireProvenance(t *testing.T, p Provenance) {
	t.Helper()
	if p.RuleID == "" || p.PolicyLayer == "" || p.PolicyVersion == "" {
		t.Errorf("incomplete decision provenance (POL-3): %+v", p)
	}
}

// ---------------------------------------------------------------------------
// admission map / re-admitter fakes (DNS-2b seam)
// ---------------------------------------------------------------------------

type fakeAdmissionMap struct {
	mu    sync.Mutex
	clock *fakeClock
	m     map[string]map[string]Admission // session -> domain -> admission
}

func (f *fakeAdmissionMap) program(sess SessionRef, a Admission) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m[sess.ID] == nil {
		f.m[sess.ID] = map[string]Admission{}
	}
	f.m[sess.ID][a.Domain] = a
}

func (f *fakeAdmissionMap) Lookup(_ context.Context, sess SessionRef, domain string) (Admission, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.m[sess.ID][domain]
	return a, ok, nil
}

func (f *fakeAdmissionMap) AdmittedFor(_ context.Context, sess SessionRef, addr netip.Addr, domain string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.m[sess.ID][domain]
	if !ok || !a.Expiry.After(f.clock.Now()) {
		return false, nil
	}
	for _, got := range a.Addrs {
		if got == addr {
			return true, nil
		}
	}
	return false, nil
}

type fakeReAdmitter struct {
	mu    sync.Mutex
	fn    func(sess SessionRef, domain string) (Admission, error)
	calls []string
}

func (f *fakeReAdmitter) ReAdmit(_ context.Context, sess SessionRef, domain string) (Admission, error) {
	f.mu.Lock()
	f.calls = append(f.calls, domain)
	fn := f.fn
	f.mu.Unlock()
	if fn == nil {
		return Admission{}, fmt.Errorf("fakeReAdmitter: no re-admission programmed for %q", domain)
	}
	return fn(sess, domain)
}

func (f *fakeReAdmitter) callsFor(domain string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, d := range f.calls {
		if d == domain {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// policy-core fake
// ---------------------------------------------------------------------------

type fakePolicyEngine struct {
	mu           sync.Mutex
	version      string
	connectAllow map[string]bool
	connectRule  map[string]string
	connectFn    func(SessionRef, string) (Decision, bool) // optional per-session override
	httpFn       func(RequestMeta) Decision
	passthrough  map[string]bool
	swapRules    []ServiceRule
}

func newFakePolicyEngine() *fakePolicyEngine {
	return &fakePolicyEngine{
		version:      "policy-v1",
		connectAllow: map[string]bool{},
		connectRule:  map[string]string{},
		passthrough:  map[string]bool{},
	}
}

func (f *fakePolicyEngine) prov(rule string) Provenance {
	return Provenance{RuleID: rule, PolicyLayer: "system", PolicyVersion: f.version}
}

func (f *fakePolicyEngine) allow(domains ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range domains {
		f.connectAllow[d] = true
	}
}

func (f *fakePolicyEngine) deny(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.connectAllow, domain)
	f.connectRule[domain] = "blocklist:" + domain
}

func (f *fakePolicyEngine) setVersion(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = v
}

func (f *fakePolicyEngine) setPassThrough(domain string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if on {
		f.passthrough[domain] = true
	} else {
		delete(f.passthrough, domain)
	}
}

func (f *fakePolicyEngine) EvaluateConnect(_ context.Context, sess SessionRef, domain string) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connectFn != nil {
		if d, ok := f.connectFn(sess, domain); ok {
			return d, nil
		}
	}
	if f.connectAllow[domain] {
		return Decision{Allow: true, Provenance: f.prov("allow:" + domain)}, nil
	}
	rule := f.connectRule[domain]
	if rule == "" {
		rule = "default-deny"
	}
	return Decision{Allow: false, Provenance: f.prov(rule)}, nil
}

func (f *fakePolicyEngine) EvaluateHTTP(_ context.Context, _ SessionRef, req RequestMeta) (Decision, error) {
	f.mu.Lock()
	fn := f.httpFn
	f.mu.Unlock()
	if fn == nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		return Decision{Allow: true, Provenance: f.prov("http:default-allow")}, nil
	}
	return fn(req), nil
}

func (f *fakePolicyEngine) PassThrough(_ context.Context, _ SessionRef, domain string) (bool, Provenance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passthrough[domain], f.prov("passthrough:" + domain), nil
}

func (f *fakePolicyEngine) MatchSwapService(_ context.Context, host string) (ServiceRule, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.swapRules {
		for _, h := range r.Hosts {
			if h == host {
				return r, true, nil
			}
		}
	}
	return ServiceRule{}, false, nil
}

// ---------------------------------------------------------------------------
// x509 fixtures + per-session CA fake (D17 seam, mint owner: Identity)
// ---------------------------------------------------------------------------

var serialCounter int64 = 1000

func nextSerial() *big.Int {
	serialCounter++
	return big.NewInt(serialCounter)
}

func mintKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mint key: %v", err)
	}
	return k
}

// mintCACert mints a self-signed CA. Cert validity uses real wall time on
// purpose: the deterministic-clock rule governs admission/credential expiry
// logic, not TLS plumbing fixtures.
func mintCACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key := mintKey(t)
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
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
	pemBytes := pemEncodeCert(der)
	return cert, key, pemBytes
}

func pemEncodeCert(der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(b64) > 64 {
		sb.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	sb.WriteString(b64 + "\n-----END CERTIFICATE-----\n")
	return []byte(sb.String())
}

type leafOpts struct {
	notBefore time.Time
	notAfter  time.Time
}

func mintLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string, opt *leafOpts) tls.Certificate {
	t.Helper()
	key := mintKey(t)
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(12*time.Hour)
	if opt != nil {
		nb, na = opt.notBefore, opt.notAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: nextSerial(),
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
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type fakeSessionCA struct {
	mu        sync.Mutex
	t         *testing.T
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
	leafCalls []string
}

// LeafFor mints a FRESH leaf on every call (and records the call): the
// byte-identical-leaf assertion in TLS-3.d therefore forces the real system
// to cache per origin rather than mint per connection.
func (ca *fakeSessionCA) LeafFor(_ context.Context, origin string) (tls.Certificate, error) {
	ca.mu.Lock()
	ca.leafCalls = append(ca.leafCalls, origin)
	ca.mu.Unlock()
	return mintLeafCert(ca.t, ca.caCert, ca.caKey, []string{origin}, nil), nil
}

func (ca *fakeSessionCA) CertPool() ([]byte, error) { return ca.caPEM, nil }

// leafCount reports how many leaves this session CA was asked to mint —
// the TLS-LC.a per-cycle "fresh-boot-equivalent call pattern" observable.
func (ca *fakeSessionCA) leafCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.leafCalls)
}

type fakeCAMinter struct {
	mu  sync.Mutex
	t   *testing.T
	cas map[string]*fakeSessionCA
}

func (m *fakeCAMinter) MintSessionCA(_ context.Context, sess SessionRef) (SessionCA, error) {
	return m.caFor(sess), nil
}

func (m *fakeCAMinter) caFor(sess SessionRef) *fakeSessionCA {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ca, ok := m.cas[sess.ID]; ok {
		return ca
	}
	cert, key, pemBytes := mintCACert(m.t, "ds-session-ca-"+sess.ID)
	ca := &fakeSessionCA{t: m.t, caCert: cert, caKey: key, caPEM: pemBytes}
	m.cas[sess.ID] = ca
	return ca
}

func (m *fakeCAMinter) poolFor(t *testing.T, sess SessionRef) *x509.CertPool {
	t.Helper()
	ca := m.caFor(sess)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.caPEM) {
		t.Fatalf("bad session CA PEM for %s", sess.ID)
	}
	return pool
}

// ---------------------------------------------------------------------------
// upstream dialer recorder + fake upstreams
// ---------------------------------------------------------------------------

type dialRecord struct {
	kind   string // "tls" | "raw"
	domain string
	addr   netip.AddrPort
}

type recordingDialer struct {
	mu      sync.Mutex
	records []dialRecord
	tlsFn   func(domain string, addr netip.AddrPort) (net.Conn, error)
	rawFn   func(addr netip.AddrPort) (net.Conn, error)
}

func (d *recordingDialer) DialTLS(_ context.Context, _ SessionRef, domain string, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.records = append(d.records, dialRecord{"tls", domain, addr})
	fn := d.tlsFn
	d.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("recordingDialer: no TLS upstream programmed for %s", domain)
	}
	return fn(domain, addr)
}

func (d *recordingDialer) DialRaw(_ context.Context, _ SessionRef, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.records = append(d.records, dialRecord{"raw", "", addr})
	fn := d.rawFn
	d.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("recordingDialer: no raw upstream programmed for %s", addr)
	}
	return fn(addr)
}

func (d *recordingDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.records)
}

func (d *recordingDialer) dialedAddr(addr netip.AddrPort) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.records {
		if r.addr == addr {
			return true
		}
	}
	return false
}

// dialedAddrs returns every upstream address dialed, in order.
func (d *recordingDialer) dialedAddrs() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]netip.AddrPort, 0, len(d.records))
	for _, r := range d.records {
		out = append(out, r.addr)
	}
	return out
}

type capturedRequest struct {
	Method string
	Host   string
	Path   string
	Header http.Header
	Body   []byte
}

// orderRecorder gives a global happens-before record across fakes.
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

// recordingUpstream is an HTTP/1.1 origin served over an in-memory pipe;
// it records every request it receives.
type recordingUpstream struct {
	mu      sync.Mutex
	reqs    []capturedRequest
	handler http.HandlerFunc
	order   *orderRecorder
	label   string
}

func (u *recordingUpstream) dial() (net.Conn, error) {
	c1, c2 := net.Pipe()
	go u.serveConn(c2)
	return c1, nil
}

func (u *recordingUpstream) dialTLS(string, netip.AddrPort) (net.Conn, error) { return u.dial() }
func (u *recordingUpstream) dialRaw(netip.AddrPort) (net.Conn, error)         { return u.dial() }

func (u *recordingUpstream) serveConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		u.mu.Lock()
		n := len(u.reqs) + 1
		u.reqs = append(u.reqs, capturedRequest{
			Method: req.Method, Host: req.Host, Path: req.URL.RequestURI(),
			Header: req.Header.Clone(), Body: body,
		})
		h := u.handler
		ord, label := u.order, u.label
		u.mu.Unlock()
		if ord != nil {
			ord.note(fmt.Sprintf("upstream:%s:%d:%s %s", label, n, req.Method, req.URL.Path))
		}
		rec := httptest.NewRecorder()
		req.Body = io.NopCloser(bytes.NewReader(body))
		if h != nil {
			h(rec, req)
		} else {
			rec.WriteHeader(http.StatusOK)
			fmt.Fprint(rec, "ok")
		}
		resp := rec.Result()
		resp.ContentLength = int64(rec.Body.Len())
		if err := resp.Write(c); err != nil {
			return
		}
	}
}

func (u *recordingUpstream) requests() []capturedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]capturedRequest(nil), u.reqs...)
}

func (u *recordingUpstream) requestCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

// rawResponder serves scripted raw bytes per received HTTP request — for
// chunk-boundary, malformed-response, and trailer scenarios.
type rawResponder struct {
	mu     sync.Mutex
	script func(req *http.Request, body []byte, w io.Writer)
	reqs   []capturedRequest
}

func (r *rawResponder) dialTLS(string, netip.AddrPort) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go r.serveConn(c2)
	return c1, nil
}

func (r *rawResponder) serveConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		r.mu.Lock()
		r.reqs = append(r.reqs, capturedRequest{
			Method: req.Method, Host: req.Host, Path: req.URL.RequestURI(),
			Header: req.Header.Clone(), Body: body,
		})
		script := r.script
		r.mu.Unlock()
		if script == nil {
			return
		}
		script(req, body, c)
	}
}

// lockedBuffer is a concurrency-safe byte sink.
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

// tlsOrigin is a fake TLS origin for opaque-tunnel paths: the client
// handshakes end-to-end with the ORIGIN certificate (never a session-CA
// leaf). mode "echo" echoes post-handshake bytes; mode "http" answers HTTP.
type tlsOrigin struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	pool     *x509.CertPool
	spki     [sha256.Size]byte
	mode     string
	handler  http.HandlerFunc
	recorded lockedBuffer // plaintext received from the tunnel
	mu       sync.Mutex
	conns    int
	reqs     []capturedRequest
}

func newTLSOrigin(t *testing.T, mode string, names ...string) *tlsOrigin {
	t.Helper()
	cert := selfSignedLeaf(t, names)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return &tlsOrigin{
		cert: cert,
		leaf: cert.Leaf,
		pool: pool,
		spki: sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo),
		mode: mode,
	}
}

func (o *tlsOrigin) dialRaw(netip.AddrPort) (net.Conn, error) {
	c1, c2 := net.Pipe()
	o.mu.Lock()
	o.conns++
	o.mu.Unlock()
	go o.serve(c2)
	return c1, nil
}

func (o *tlsOrigin) connCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.conns
}

func (o *tlsOrigin) requests() []capturedRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]capturedRequest(nil), o.reqs...)
}

func (o *tlsOrigin) serve(c net.Conn) {
	defer c.Close()
	s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{o.cert}})
	if err := s.Handshake(); err != nil {
		return
	}
	switch o.mode {
	case "echo":
		buf := make([]byte, 4096)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				o.recorded.Write(buf[:n])
				if _, werr := s.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	default: // "http"
		br := bufio.NewReader(io.TeeReader(s, &o.recorded))
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			req.Body.Close()
			o.mu.Lock()
			o.reqs = append(o.reqs, capturedRequest{
				Method: req.Method, Host: req.Host, Path: req.URL.RequestURI(),
				Header: req.Header.Clone(), Body: body,
			})
			h := o.handler
			o.mu.Unlock()
			rec := httptest.NewRecorder()
			req.Body = io.NopCloser(bytes.NewReader(body))
			if h != nil {
				h(rec, req)
			} else {
				rec.WriteHeader(http.StatusOK)
				fmt.Fprint(rec, "ok")
			}
			resp := rec.Result()
			resp.ContentLength = int64(rec.Body.Len())
			if err := resp.Write(s); err != nil {
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// identity / secret-store fakes (D22, D8 — outside the boundary)
// ---------------------------------------------------------------------------

type fakeIdentityValidator struct {
	mu    sync.Mutex
	clock *fakeClock
	valid map[string]IdentityClaims // key: string(Credential.Value)
	calls int
}

func (f *fakeIdentityValidator) mint(sess SessionRef, subject string, ttl time.Duration) Credential {
	f.mu.Lock()
	defer f.mu.Unlock()
	// High-entropy value (CONVENTIONS canary rule; TLS-5.g "distinct
	// canaries"): the session/subject binding lives in the claims map below,
	// not in the string shape, and the random suffix makes the value usable
	// as a leak needle (a low-entropy "sl-sess-a-github-0" would be
	// undetectable when partially leaked and its components legitimately
	// appear in events).
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("fakeIdentityValidator: entropy: " + err.Error())
	}
	val := fmt.Sprintf("sl-%s-%s-%s", sess.ID, subject, hex.EncodeToString(entropy[:]))
	cred := Credential{Value: Secret(val), Fingerprint: "fp-short-" + subject + "-" + sess.ID}
	f.valid[val] = IdentityClaims{Session: sess, Subject: subject, Expiry: f.clock.Now().Add(ttl)}
	return cred
}

func (f *fakeIdentityValidator) ValidateShortLived(_ context.Context, sess SessionRef, presented Credential) (IdentityClaims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	claims, ok := f.valid[string(presented.Value)]
	if !ok {
		return IdentityClaims{}, fmt.Errorf("identity: unknown or forged credential")
	}
	if claims.Session != sess {
		return IdentityClaims{}, fmt.Errorf("identity mismatch: credential bound to another session")
	}
	if !claims.Expiry.After(f.clock.Now()) {
		return IdentityClaims{}, fmt.Errorf("identity: credential expired")
	}
	return claims, nil
}

func (f *fakeIdentityValidator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fetchCall struct {
	service string
	claims  IdentityClaims
}

type recordingSecretStore struct {
	mu    sync.Mutex
	creds map[string]Credential // key: service, or service+"|"+sessionID
	calls []fetchCall
}

func (s *recordingSecretStore) program(service string, cred Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[service] = cred
}

func (s *recordingSecretStore) programForSession(service string, sess SessionRef, cred Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[service+"|"+sess.ID] = cred
}

func (s *recordingSecretStore) FetchLongLived(_ context.Context, service string, claims IdentityClaims) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fetchCall{service: service, claims: claims})
	if c, ok := s.creds[service+"|"+claims.Session.ID]; ok {
		return c, nil
	}
	if c, ok := s.creds[service]; ok {
		return c, nil
	}
	return Credential{}, fmt.Errorf("secretstore: no credential for service %q", service)
}

func (s *recordingSecretStore) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// ---------------------------------------------------------------------------
// rate / cap / suspend fakes (TLS-6 seams)
// ---------------------------------------------------------------------------

type fakeRateLimiter struct {
	mu      sync.Mutex
	limitFn func(sess SessionRef, service string) int // 0 = unlimited
	count   map[string]int
}

func (f *fakeRateLimiter) Allow(_ context.Context, sess SessionRef, service string) (RateDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prov := Provenance{RuleID: "rate:" + service, PolicyLayer: "session", PolicyVersion: "policy-v1"}
	limit := 0
	if f.limitFn != nil {
		limit = f.limitFn(sess, service)
	}
	key := sess.ID + "|" + service
	f.count[key]++
	if limit > 0 && f.count[key] > limit {
		return RateDecision{Allowed: false, RetryAfter: 30 * time.Second, Provenance: prov}, nil
	}
	return RateDecision{Allowed: true, Provenance: prov}, nil
}

type fakeCapMonitor struct {
	mu     sync.Mutex
	capID  string
	limit  int
	match  func(ResourceAction) bool
	counts map[string]int
}

func (f *fakeCapMonitor) Record(_ context.Context, sess SessionRef, act ResourceAction) (CapVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prov := Provenance{RuleID: f.capID, PolicyLayer: "session", PolicyVersion: "policy-v1"}
	if f.capID == "" || (f.match != nil && !f.match(act)) {
		return CapVerdict{}, nil
	}
	f.counts[sess.ID]++
	if f.counts[sess.ID] > f.limit {
		return CapVerdict{Breached: true, CapID: f.capID, Provenance: prov}, nil
	}
	return CapVerdict{CapID: f.capID, Provenance: prov}, nil
}

type fakeSuspendSignaler struct {
	mu       sync.Mutex
	calls    []BreachInfo
	order    *orderRecorder
	gate     chan struct{} // if non-nil, Suspend blocks until closed (resume)
	once     sync.Once
	calledCh chan struct{}
}

func newFakeSuspendSignaler() *fakeSuspendSignaler {
	return &fakeSuspendSignaler{calledCh: make(chan struct{})}
}

func (f *fakeSuspendSignaler) Suspend(_ context.Context, _ SessionRef, breach BreachInfo) error {
	f.mu.Lock()
	f.calls = append(f.calls, breach)
	ord, gate := f.order, f.gate
	f.mu.Unlock()
	if ord != nil {
		ord.note("suspend")
	}
	f.once.Do(func() { close(f.calledCh) })
	if gate != nil {
		<-gate
	}
	return nil
}

func (f *fakeSuspendSignaler) callList() []BreachInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]BreachInfo(nil), f.calls...)
}

// ---------------------------------------------------------------------------
// secret-scan fakes (TLS-7)
// ---------------------------------------------------------------------------

type recordingHook struct {
	mu       sync.Mutex
	findings []Finding
}

func (h *recordingHook) OnFinding(_ context.Context, _ SessionRef, f Finding) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.findings = append(h.findings, f)
	return nil
}

func (h *recordingHook) list() []Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Finding(nil), h.findings...)
}

type recordingScanner struct {
	mu       sync.Mutex
	delegate SecretScanner
	calls    int
}

func (s *recordingScanner) ScanInbound(ctx context.Context, sess SessionRef, meta ResponseMeta, body []byte) ([]Finding, error) {
	s.mu.Lock()
	s.calls++
	d := s.delegate
	s.mu.Unlock()
	if d == nil {
		return nil, nil
	}
	return d.ScanInbound(ctx, sess, meta, body)
}

func (s *recordingScanner) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// ---------------------------------------------------------------------------
// event sink recorder
// ---------------------------------------------------------------------------

type recordingSink struct {
	mu  sync.Mutex
	evs []Event
}

func (s *recordingSink) Emit(_ context.Context, ev Event) error {
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

func (s *recordingSink) all() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.evs...)
}

func (s *recordingSink) byKind(k EventKind) []Event {
	var out []Event
	for _, ev := range s.all() {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

func (s *recordingSink) snapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evs)
}

func (s *recordingSink) since(n int) []Event {
	all := s.all()
	if n > len(all) {
		return nil
	}
	return all[n:]
}

func serializeEvent(ev Event) []byte {
	return []byte(fmt.Sprintf("kind=%s session=%s at=%s prov=%+v fields=%v",
		ev.Kind, ev.Session.ID, ev.At.UTC().Format(time.RFC3339Nano), ev.Provenance, ev.Fields))
}

func serializeEvents(evs []Event) []byte {
	var b bytes.Buffer
	for _, ev := range evs {
		b.Write(serializeEvent(ev))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// findEventContaining returns the first event (of kind, or any kind if
// kind == "") whose serialized form contains every substring.
func findEventContaining(evs []Event, kind EventKind, substrs ...string) (Event, bool) {
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
	return Event{}, false
}

// ---------------------------------------------------------------------------
// leak probe fake (harness-side seam over the VM-observable surfaces)
// ---------------------------------------------------------------------------

type fakeLeakProbe struct {
	mu   sync.Mutex
	bufs map[Surface]*lockedBuffer
	dirs map[Surface][]string
}

func newFakeLeakProbe() *fakeLeakProbe {
	p := &fakeLeakProbe{bufs: map[Surface]*lockedBuffer{}, dirs: map[Surface][]string{}}
	for _, s := range []Surface{SurfaceDisk, SurfaceEnv, SurfaceCoWDelta, SurfaceDownstreamBytes} {
		p.bufs[s] = &lockedBuffer{}
	}
	return p
}

func (p *fakeLeakProbe) addBytes(s Surface, b []byte) {
	p.mu.Lock()
	buf := p.bufs[s]
	p.mu.Unlock()
	buf.Write(b)
}

func (p *fakeLeakProbe) addDir(s Surface, dir string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dirs[s] = append(p.dirs[s], dir)
}

func (p *fakeLeakProbe) snapshotEnv() {
	p.addBytes(SurfaceEnv, []byte(strings.Join(os.Environ(), "\n")))
}

func (p *fakeLeakProbe) Search(_ context.Context, _ SessionRef, needle []byte) ([]LeakHit, error) {
	var hits []LeakHit
	p.mu.Lock()
	bufs := map[Surface]*lockedBuffer{}
	for s, b := range p.bufs {
		bufs[s] = b
	}
	dirs := map[Surface][]string{}
	for s, d := range p.dirs {
		dirs[s] = append([]string(nil), d...)
	}
	p.mu.Unlock()

	for surf, buf := range bufs {
		hits = append(hits, grepHits(surf, buf.bytes(), needle, string(surf))...)
	}
	for surf, dd := range dirs {
		for _, dir := range dd {
			_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				data, rerr := os.ReadFile(path)
				if rerr != nil {
					return nil
				}
				hits = append(hits, grepHits(surf, data, needle, path)...)
				return nil
			})
		}
	}
	return hits, nil
}

func grepHits(surf Surface, hay, needle []byte, ctxLabel string) []LeakHit {
	var hits []LeakHit
	off := 0
	for {
		i := bytes.Index(hay[off:], needle)
		if i < 0 {
			return hits
		}
		hits = append(hits, LeakHit{Surface: surf, Offset: int64(off + i), Context: ctxLabel})
		off += i + 1
	}
}

// requireZeroLeaks runs the probe for every encoded form of the needle and
// asserts zero hits.
func requireZeroLeaks(t *testing.T, probe *fakeLeakProbe, sess SessionRef, needle []byte) {
	t.Helper()
	for form, enc := range encForms(needle) {
		hits, err := probe.Search(context.Background(), sess, enc)
		if err != nil {
			t.Fatalf("LeakProbe.Search(%s): %v", form, err)
		}
		for _, h := range hits {
			t.Errorf("credential canary (%s form) found on VM surface %s at offset %d (%s)", form, h.Surface, h.Offset, h.Context)
		}
	}
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

type harness struct {
	t        *testing.T
	clock    *fakeClock
	adm      *fakeAdmissionMap
	readmit  *fakeReAdmitter
	policy   *fakePolicyEngine
	cas      *fakeCAMinter
	dialer   *recordingDialer
	identity *fakeIdentityValidator
	secrets  *recordingSecretStore
	rate     *fakeRateLimiter
	caps     *fakeCapMonitor
	suspend  *fakeSuspendSignaler
	hook     *recordingHook
	scanner  *recordingScanner
	events   *recordingSink
	probe    *fakeLeakProbe
	cfg      Config
	deps     Deps
	proxy    Proxy
	gate     TunnelGate
}

// newHarness builds the TLS-1-stage (opaque-tunnel) harness.
func newHarness(t *testing.T) *harness { return newHarnessCfg(t, false) }

// newInspectHarness builds the TLS-3+ (inspected-default) harness.
func newInspectHarness(t *testing.T) *harness { return newHarnessCfg(t, true) }

func newHarnessCfg(t *testing.T, inspect bool) *harness {
	t.Helper()
	clock := newFakeClock()
	h := &harness{t: t, clock: clock}
	h.adm = &fakeAdmissionMap{clock: clock, m: map[string]map[string]Admission{}}
	h.readmit = &fakeReAdmitter{}
	h.policy = newFakePolicyEngine()
	h.cas = &fakeCAMinter{t: t, cas: map[string]*fakeSessionCA{}}
	h.dialer = &recordingDialer{}
	h.identity = &fakeIdentityValidator{clock: clock, valid: map[string]IdentityClaims{}}
	h.secrets = &recordingSecretStore{creds: map[string]Credential{}}
	h.rate = &fakeRateLimiter{count: map[string]int{}}
	h.caps = &fakeCapMonitor{counts: map[string]int{}}
	h.suspend = newFakeSuspendSignaler()
	h.hook = &recordingHook{}
	h.events = &recordingSink{}
	h.probe = newFakeLeakProbe()

	spool := t.TempDir()
	h.cfg = Config{Now: clock.Now, Inspect: inspect, SpoolDir: spool}
	h.probe.addDir(SurfaceDisk, spool)
	// CoW-delta surface: on the real rig this is the VM image delta; in the
	// harness it is a scratch dir the proxy must never write secrets into.
	h.probe.addDir(SurfaceCoWDelta, t.TempDir())

	d := Deps{
		Admissions: h.adm,
		ReAdmitter: h.readmit,
		Policy:     h.policy,
		CAs:        h.cas,
		Dialer:     h.dialer,
		Identity:   h.identity,
		Secrets:    h.secrets,
		Rate:       h.rate,
		Caps:       h.caps,
		Suspend:    h.suspend,
		Hook:       h.hook,
		Events:     h.events,
	}
	h.gate = NewTunnelGate(h.cfg, d)
	d.Gate = h.gate
	d.Swapper = NewCredentialSwapper(h.cfg, d)
	d.Scrubber = NewResponseScrubber(h.cfg)
	h.scanner = &recordingScanner{delegate: NewSecretScanner(h.cfg)}
	d.Scanner = h.scanner
	h.deps = d

	p, err := New(h.cfg, d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("New must return a non-nil Proxy stub (the RED rule forbids nil-panics)")
	}
	h.proxy = p
	return h
}

func (h *harness) admit(sess SessionRef, domain string, ttl time.Duration, addrs ...netip.Addr) {
	h.adm.program(sess, Admission{Domain: domain, Addrs: addrs, Expiry: h.clock.Now().Add(ttl)})
}

// programReAdmit makes re-admission for domain succeed with addrs and a fresh
// 60s expiry, writing the DNS-2b admission map exactly like ds-dnsgate would.
func (h *harness) programReAdmit(domain string, addrs ...netip.Addr) {
	h.readmit.mu.Lock()
	defer h.readmit.mu.Unlock()
	prev := h.readmit.fn
	h.readmit.fn = func(sess SessionRef, d string) (Admission, error) {
		if d != domain {
			if prev != nil {
				return prev(sess, d)
			}
			return Admission{}, fmt.Errorf("fakeReAdmitter: no re-admission programmed for %q", d)
		}
		a := Admission{Domain: domain, Addrs: addrs, Expiry: h.clock.Now().Add(60 * time.Second)}
		h.adm.program(sess, a)
		return a, nil
	}
}

// startTransparent runs ServeTransparentTLS against a fresh in-memory pipe
// and returns the client (VM) side. The server side is closed when serve
// returns, so red stubs fail fast instead of hanging.
func (h *harness) startTransparent(sess SessionRef, origDst netip.AddrPort) (net.Conn, <-chan error) {
	client, server := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := h.proxy.ServeTransparentTLS(context.Background(), server, sess, origDst)
		server.Close()
		errc <- err
	}()
	_ = client.SetDeadline(time.Now().Add(ioTimeout))
	return client, errc
}

func (h *harness) startCONNECT(sess SessionRef) (net.Conn, <-chan error) {
	client, server := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := h.proxy.ServeCONNECT(context.Background(), server, sess)
		server.Close()
		errc <- err
	}()
	_ = client.SetDeadline(time.Now().Add(ioTimeout))
	return client, errc
}

func (h *harness) startForward(sess SessionRef) (net.Conn, <-chan error) {
	client, server := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := h.proxy.ServeHTTPForward(context.Background(), server, sess)
		server.Close()
		errc <- err
	}()
	_ = client.SetDeadline(time.Now().Add(ioTimeout))
	return client, errc
}

// sessionTLSClient handshakes the downstream leg trusting only the session's
// interception CA pool (the inspected path).
func (h *harness) sessionTLSClient(conn net.Conn, sess SessionRef, serverName string) (*tls.Conn, error) {
	tc := tls.Client(conn, &tls.Config{RootCAs: h.cas.poolFor(h.t, sess), ServerName: serverName})
	return tc, tc.Handshake()
}

// inspectRequest drives one inspected request end to end on the transparent
// path and registers everything the VM observed on the downstream-bytes
// surface of the leak probe.
func (h *harness) inspectRequest(sess SessionRef, domain string, origDst netip.AddrPort, req *http.Request) (*http.Response, []byte, error) {
	conn, _ := h.startTransparent(sess, origDst)
	defer conn.Close()
	tc, err := h.sessionTLSClient(conn, sess, domain)
	if err != nil {
		h.probe.addBytes(SurfaceDownstreamBytes, []byte("handshake-error: "+err.Error()))
		return nil, nil, fmt.Errorf("downstream handshake: %w", err)
	}
	resp, body, err := roundTrip(tc, req)
	if err != nil {
		h.probe.addBytes(SurfaceDownstreamBytes, []byte("roundtrip-error: "+err.Error()))
		return nil, nil, err
	}
	h.probe.addBytes(SurfaceDownstreamBytes, dumpResponse(resp, body))
	return resp, body, nil
}

func newReq(t *testing.T, method, urlStr string, hdr map[string]string, body string) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, urlStr, rdr)
	if err != nil {
		t.Fatalf("newReq: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func roundTrip(conn net.Conn, req *http.Request) (*http.Response, []byte, error) {
	if err := req.Write(conn); err != nil {
		return nil, nil, fmt.Errorf("write request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, body, fmt.Errorf("read body: %w", err)
	}
	return resp, body, nil
}

func dumpResponse(resp *http.Response, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)
	_ = resp.Header.Write(&b)
	_ = resp.Trailer.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// connectThrough issues an HTTP CONNECT for authority and parses the reply
// byte-by-byte so no tunnel bytes are swallowed by buffering.
func connectThrough(conn net.Conn, authority string) (int, error) {
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		return 0, fmt.Errorf("write CONNECT: %w", err)
	}
	var raw []byte
	one := make([]byte, 1)
	for !bytes.HasSuffix(raw, []byte("\r\n\r\n")) {
		if len(raw) > 64*1024 {
			return 0, fmt.Errorf("CONNECT reply too large")
		}
		n, err := conn.Read(one)
		if n == 1 {
			raw = append(raw, one[0])
		}
		if err != nil {
			return 0, fmt.Errorf("read CONNECT reply: %w (got %q)", err, raw)
		}
	}
	line, _, _ := strings.Cut(string(raw), "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed CONNECT status line %q", line)
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		return 0, fmt.Errorf("malformed CONNECT status %q", line)
	}
	return code, nil
}

// requireEvent asserts an event of the given kind whose serialized form
// contains every substring, and that it carries complete provenance.
func (h *harness) requireEvent(kind EventKind, substrs ...string) Event {
	h.t.Helper()
	ev, ok := findEventContaining(h.events.all(), kind, substrs...)
	if !ok {
		h.t.Errorf("no %s event containing %q was emitted (events: %d total)", kind, substrs, len(h.events.all()))
		return Event{}
	}
	requireProvenance(h.t, ev.Provenance)
	return ev
}

// setupSwap programs the full TLS-5 swap chain for one service and returns
// the recording upstream plus a valid short-lived credential for sess.
func (h *harness) setupSwap(sess SessionRef, service string, hosts []string, longLived []byte) (*recordingUpstream, Credential) {
	h.policy.mu.Lock()
	h.policy.swapRules = append(h.policy.swapRules, ServiceRule{
		Service: service, Hosts: hosts, CredLocation: "header:Authorization",
	})
	h.policy.mu.Unlock()
	short := h.identity.mint(sess, service, time.Hour)
	h.secrets.program(service, Credential{Value: Secret(longLived), Fingerprint: "fp-long-" + service})
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS
	for _, host := range hosts {
		h.policy.allow(host)
		h.admit(sess, host, time.Hour, ip("140.82.1.1"))
	}
	return up, short
}

func bearer(c Credential) string { return "Bearer " + string(c.Value) }
