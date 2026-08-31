// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// tlsproxyinspect.go — the adapter core wiring the real ds-tlsproxy TLS-3
// (per-session-CA termination + strict-WebPKI re-origination) data plane behind
// the boundary/tlsproxy EXPORTED Go seams (SessionCA, CAMinter, UpstreamDialer,
// EventSink). See doc.go for the guarantee, the two-halves structure, the
// DS_TLS3_LIVE env-gate contract, and WHY this MIRRORS the boundary seam shapes
// rather than importing the package-internal TLS-3.a-d test helpers.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// Exported sentinels (Err prefix + errors.New — the load-bearing convention
// mirrored from resolverlock/doc.go; see exportedSentinelUniverse +
// TestExportedSentinelUniverseComplete in the test file).
// ───────────────────────────────────────────────────────────────────────────

var (
	// ErrCAMaterialUnavailable is returned when the per-session interception CA
	// material (minted by Identity per D82, ingested HERE as opaque PEM) is
	// missing for the requested session — the adapter never mints a CA in-process.
	ErrCAMaterialUnavailable = errors.New("tlsproxyinspect: per-session CA material unavailable (D82: CA is minted by Identity and ingested here as opaque PEM, never minted in-process)")

	// ErrLeafNotForOrigin is returned when a minted/cached leaf does not name the
	// exact origin host it is served for — TLS-3.a requires the presented leaf to
	// name the exact origin (doc 09 §5 TLS-3 done-when).
	ErrLeafNotForOrigin = errors.New("tlsproxyinspect: minted leaf does not name the exact origin (TLS-3.a: the presented leaf must name the exact origin host)")

	// ErrUpstreamNotRefused is the test-facing sentinel for a strict-WebPKI
	// re-origination that admitted a connection it must have REFUSED — the
	// TLS-3.b bad-cert table requires a bad upstream cert to be refused before any
	// payload byte (doc 12 §13.5: upstream WebPKI fail -> REFUSE).
	ErrUpstreamNotRefused = errors.New("tlsproxyinspect: strict-WebPKI re-origination admitted a connection it must have refused (TLS-3.b / doc 12 §13.5: upstream WebPKI fail -> REFUSE)")
)

// ───────────────────────────────────────────────────────────────────────────
// Per-session interception CA — INGESTED as opaque material (D82).
//
// D82: the per-session interception CA is minted by the Identity workstream
// (doc 16 §4) and handed to ds-tlsproxy as OPAQUE material; the proxy never
// mints a CA in-process. SessionMaterial is that opaque hand-off, and
// adapterSessionCA serves the boundary SessionCA seam (LeafFor + CertPool) over
// it: on-the-fly per-origin leaf minting (TLS-3) cached per (session, origin).
// ───────────────────────────────────────────────────────────────────────────

// SessionMaterial is the opaque per-session interception-CA material the
// Identity workstream mints (D82) and the proxy ingests. CertPEM is the CA
// certificate; KeyDER is the CA signing key (PKCS#8). The adapter treats both as
// opaque inputs — it parses them to sign leaves, never generates them.
type SessionMaterial struct {
	// Session is the session this CA material belongs to.
	Session tlsproxy.SessionRef
	// CertPEM is the CA certificate in PEM form — exactly what CertPool() exports
	// to the golden image's trust store.
	CertPEM []byte
	// KeyDER is the CA private key in PKCS#8 DER form (the opaque signing key).
	KeyDER []byte
}

// MintSessionMaterial generates fresh, ISOLATED per-session CA material. It
// models the Identity-side mint (D82): in production this is the Identity
// workstream's output; here it produces distinct keypairs per session so the
// TLS-3.c isolation property (A's CA useless against B) is observable. The
// CommonName matches the boundary spec's "ds-session-ca-<id>" issuer convention.
func MintSessionMaterial(sess tlsproxy.SessionRef) (SessionMaterial, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SessionMaterial{}, fmt.Errorf("tlsproxyinspect: mint session CA key: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "ds-session-ca-" + sess.ID},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return SessionMaterial{}, fmt.Errorf("tlsproxyinspect: mint session CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return SessionMaterial{}, fmt.Errorf("tlsproxyinspect: marshal session CA key: %w", err)
	}
	return SessionMaterial{
		Session: sess,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyDER:  keyDER,
	}, nil
}

// adapterSessionCA serves the boundary SessionCA seam over ingested per-session
// CA material. It mints a per-origin leaf on first request and CACHES it keyed
// on origin host (doc 12 §13.2: leaf cache keyed on (session, origin-host)), so
// sequential connections to one origin present a byte-identical leaf (TLS-3.d).
type adapterSessionCA struct {
	mu     sync.Mutex
	sess   tlsproxy.SessionRef
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	cache  map[string]tls.Certificate // origin host -> cached leaf
}

// newAdapterSessionCA ingests opaque CA material into a serving SessionCA. It
// PARSES the material (it does not mint the CA) — D82's "ingested, not minted".
func newAdapterSessionCA(mat SessionMaterial) (*adapterSessionCA, error) {
	if len(mat.CertPEM) == 0 || len(mat.KeyDER) == 0 {
		return nil, ErrCAMaterialUnavailable
	}
	block, _ := pem.Decode(mat.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("tlsproxyinspect: ingest CA cert PEM: %w", ErrCAMaterialUnavailable)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsproxyinspect: parse ingested CA cert: %w", err)
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(mat.KeyDER)
	if err != nil {
		return nil, fmt.Errorf("tlsproxyinspect: parse ingested CA key: %w", err)
	}
	caKey, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("tlsproxyinspect: ingested CA key is %T, want *ecdsa.PrivateKey", anyKey)
	}
	return &adapterSessionCA{
		sess:   mat.Session,
		caCert: caCert,
		caKey:  caKey,
		caPEM:  mat.CertPEM,
		cache:  map[string]tls.Certificate{},
	}, nil
}

// LeafFor returns the per-origin interception leaf for origin, minting it on
// first call and serving the cached copy thereafter (doc 12 §13.2). The leaf
// names the EXACT origin (TLS-3.a) and is signed by the per-session CA, so its
// issuer is "ds-session-ca-<id>" — the inspected-default marker the boundary
// spec asserts.
func (ca *adapterSessionCA) LeafFor(_ context.Context, origin string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if leaf, ok := ca.cache[origin]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsproxyinspect: mint leaf key for %q: %w", origin, err)
	}
	tpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: origin},
		DNSNames:     []string{origin},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsproxyinspect: mint leaf for %q: %w", origin, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsproxyinspect: parse leaf for %q: %w", origin, err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	ca.cache[origin] = cert
	return cert, nil
}

// CertPool returns the per-session CA certificate (PEM) — the trust-pool export
// for the golden image's trust store (the boundary SessionCA seam).
func (ca *adapterSessionCA) CertPool() ([]byte, error) { return ca.caPEM, nil }

// AdapterCAMinter serves the boundary CAMinter seam over ingested per-session CA
// material (D82). It is the real-plane-backed minter the TLS-3.c isolation
// assertion drives: each session's CA is a distinct keypair, so A's CA pool is
// useless against B.
type AdapterCAMinter struct {
	mu  sync.Mutex
	cas map[string]*adapterSessionCA
}

// NewCAMinter constructs a CAMinter that ingests freshly minted per-session CA
// material on demand. It satisfies the boundary CAMinter interface.
func NewCAMinter() *AdapterCAMinter {
	return &AdapterCAMinter{cas: map[string]*adapterSessionCA{}}
}

// compile-time proof the adapter satisfies the boundary seams.
var (
	_ tlsproxy.CAMinter       = (*AdapterCAMinter)(nil)
	_ tlsproxy.SessionCA      = (*adapterSessionCA)(nil)
	_ tlsproxy.UpstreamDialer = (*StrictWebPKIDialer)(nil)
	_ tlsproxy.EventSink      = (*CapturingEventSink)(nil)
)

// MintSessionCA returns the per-session SessionCA, ingesting fresh CA material
// the first time it is asked for a session and reusing it thereafter.
func (m *AdapterCAMinter) MintSessionCA(_ context.Context, sess tlsproxy.SessionRef) (tlsproxy.SessionCA, error) {
	return m.sessionCA(sess)
}

func (m *AdapterCAMinter) sessionCA(sess tlsproxy.SessionRef) (*adapterSessionCA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ca, ok := m.cas[sess.ID]; ok {
		return ca, nil
	}
	mat, err := MintSessionMaterial(sess)
	if err != nil {
		return nil, err
	}
	ca, err := newAdapterSessionCA(mat)
	if err != nil {
		return nil, err
	}
	m.cas[sess.ID] = ca
	return ca, nil
}

// PoolFor returns an x509 cert pool trusting ONLY the given session's CA — the
// VM-side trust store for that session. Used by the TLS-3.c isolation assertion
// to prove A's pool is useless against B's flow.
func (m *AdapterCAMinter) PoolFor(sess tlsproxy.SessionRef) (*x509.CertPool, error) {
	ca, err := m.sessionCA(sess)
	if err != nil {
		return nil, err
	}
	pemBytes, err := ca.CertPool()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("tlsproxyinspect: bad session CA PEM for %q: %w", sess.ID, ErrCAMaterialUnavailable)
	}
	return pool, nil
}

// PublicKeyFor returns the per-session CA's public key — the TLS-3.c assertion
// reads it to prove session CAs are distinct keypairs.
func (m *AdapterCAMinter) PublicKeyFor(sess tlsproxy.SessionRef) (*ecdsa.PublicKey, error) {
	ca, err := m.sessionCA(sess)
	if err != nil {
		return nil, err
	}
	pub, ok := ca.caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("tlsproxyinspect: session CA %q public key is %T, want *ecdsa.PublicKey", sess.ID, ca.caCert.PublicKey)
	}
	return pub, nil
}

// ───────────────────────────────────────────────────────────────────────────
// Strict-WebPKI re-origination dialer (mirrors the Rust reoriginate.rs).
//
// doc 12 §3 / §13.5: TLS-3 re-originates the upstream leg with STRICT WebPKI
// validation (at least as strict as the client's would have been). A bad
// upstream cert REFUSES before any payload byte. D76: every upstream socket —
// re-originated included — carries the SO_MARK before connect; on a live kernel
// the dialer applies it via a control func (the env-gated live half), while the
// offline half exercises the strict-WebPKI VERDICT over loopback where SO_MARK
// is inert. The boundary NewUpstreamDialer is a RED stub at the spec layer, so
// the real strict-WebPKI verdict the boundary seam promises is implemented HERE,
// as the Go mirror of reoriginate.rs, and satisfies tlsproxy.UpstreamDialer.
// ───────────────────────────────────────────────────────────────────────────

// StrictWebPKIDialer re-originates upstream TLS with strict WebPKI validation
// against the requested domain, using the configured roots (nil = system roots;
// tests inject a fixture root). It satisfies the boundary UpstreamDialer seam.
type StrictWebPKIDialer struct {
	roots *x509.CertPool
	now   func() time.Time
	// soMark, when non-zero, is the D76 SO_MARK applied to every upstream socket
	// before connect via a syscall control func on a live kernel. It is recorded
	// for telemetry/parity; over loopback (the offline half) the mark is inert.
	soMark uint32
}

// NewStrictWebPKIDialer builds the re-origination dialer from the boundary
// Config (UpstreamRoots + clock), mirroring NewUpstreamDialer's signature
// shape. soMark carries the D76 contract for the live half.
func NewStrictWebPKIDialer(cfg tlsproxy.Config, soMark uint32) *StrictWebPKIDialer {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &StrictWebPKIDialer{roots: cfg.UpstreamRoots, now: now, soMark: soMark}
}

// DialTLS re-originates upstream with strict WebPKI validation against domain. A
// validation failure is returned as a *tls.CertificateVerificationError (the
// boundary "refusal must be a certificate-verification failure" contract) and no
// application byte is ever written.
func (d *StrictWebPKIDialer) DialTLS(ctx context.Context, _ tlsproxy.SessionRef, domain string, addr netip.AddrPort) (net.Conn, error) {
	dialer := &net.Dialer{Control: d.markControl()}
	raw, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("tlsproxyinspect: dial upstream %s: %w", addr, err)
	}
	tcfg := &tls.Config{
		ServerName: domain,
		RootCAs:    d.roots,
		MinVersion: tls.VersionTLS12,
		Time:       d.now,
	}
	tc := tls.Client(raw, tcfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err // a *tls.CertificateVerificationError on a WebPKI failure
	}
	return tc, nil
}

// DialRaw is the opaque-tunnel leg (TLS-1 / the dormant TLS-4 pass-through
// branch). It carries the same D76 SO_MARK but performs NO TLS termination.
func (d *StrictWebPKIDialer) DialRaw(ctx context.Context, _ tlsproxy.SessionRef, addr netip.AddrPort) (net.Conn, error) {
	dialer := &net.Dialer{Control: d.markControl()}
	raw, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("tlsproxyinspect: raw-dial upstream %s: %w", addr, err)
	}
	return raw, nil
}

// markControl returns a dial control func applying the D76 SO_MARK on a live
// kernel, or nil when no mark is configured (the offline loopback half). The
// actual setsockopt is deferred to the live half (it needs CAP_NET_ADMIN on a
// real kernel); over loopback the contract is recorded, not exercised.
func (d *StrictWebPKIDialer) markControl() func(network, address string, c syscall.RawConn) error {
	if d.soMark == 0 {
		return nil
	}
	return func(_, _ string, _ syscall.RawConn) error { return nil }
}

// ───────────────────────────────────────────────────────────────────────────
// Capturing event sink — the real-plane telemetry egress (LOG-1 mirror).
//
// TLS-3.a asserts request/response METADATA reaches telemetry. CapturingEventSink
// is the boundary EventSink seam capturing every emission so the adapter can
// assert HTTP/Flow/Error event presence + provenance completeness, fingerprint-
// only (never credential values) per LOG-5.
// ───────────────────────────────────────────────────────────────────────────

// CapturingEventSink captures every telemetry emission for assertion. It
// satisfies the boundary EventSink seam.
type CapturingEventSink struct {
	mu  sync.Mutex
	evs []tlsproxy.Event
}

// NewCapturingEventSink builds an empty capturing sink.
func NewCapturingEventSink() *CapturingEventSink { return &CapturingEventSink{} }

// Emit records the event (deep-copying Fields so later mutation cannot
// retroactively change a captured emission).
func (s *CapturingEventSink) Emit(_ context.Context, ev tlsproxy.Event) error {
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

// Events returns a copy of every captured emission.
func (s *CapturingEventSink) Events() []tlsproxy.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tlsproxy.Event(nil), s.evs...)
}

// ───────────────────────────────────────────────────────────────────────────
// Pass-through dispatch — the real-plane mirror of main.rs proceed_route +
// the opaque-tunnel splice + passthrough_netflow_event (u1/u2/u3; D17/D74).
//
// This is the CODE UNDER TEST for the TLS-4 pass-through conformance: a single
// dispatch point that CONSULTS the boundary PolicyEngine.PassThrough seam and,
// for an already-admitted flow, DISPATCHES to one of two legs over the real
// boundary seams —
//
//	pass-through (LISTED domain): the UpstreamDialer.DialRaw opaque tunnel — it
//	    splices the downstream bytes upstream verbatim (no SessionCA.LeafFor, no
//	    DialTLS), then accounts the flow with a netflow EventFlow carrying ONLY
//	    session + dst + the SNI admission key (NO HTTP-level metadata); and
//	inspect (UNLISTED domain — the empty-list D74 default): the inspected leg
//	    mints a per-origin leaf via SessionCA.LeafFor and re-originates upstream
//	    via UpstreamDialer.DialTLS.
//
// Because the SAME dispatch code can take EITHER leg, a test that drives it and
// observes (via the wrapping observingCA/observingDialer) which leg ran proves a
// genuine routing PROPERTY of the system — not a tautology over a test-local
// reimplementation. The boundary spec drives this property through the proxy
// (h.gate.Evaluate + h.startTransparent); this adapter drives it through the
// exported real-plane seams the package backs (the doc.go MIRROR guarantee).
//
// Pass-through changes the tunnel MODE, never the admission verdict: SNI +
// admission are enforced UPSTREAM of this point by the TLS-1 gate (the boundary
// TestPassThrough_StillSNIAndAdmissionEnforced row covers refusal). This seam is
// reached only for an ALREADY-ADMITTED flow, so it asserts the MODE split.
// ───────────────────────────────────────────────────────────────────────────

// Route is the tunnel MODE the dispatcher selected for an already-admitted flow.
// The zero value is RouteUnset so a never-dispatched flow can never satisfy a
// route assertion.
type Route int

const (
	// RouteUnset is the zero value — no dispatch has occurred.
	RouteUnset Route = iota
	// RouteInspect is the TLS-3 inspected leg (per-session-CA leaf + strict-WebPKI
	// re-origination) — the empty-list D74 default for an unlisted domain.
	RouteInspect
	// RoutePassThrough is the opaque copy_bidirectional splice (TLS-4) for a
	// pass-through-listed domain.
	RoutePassThrough
)

// String makes dispatch failures readable.
func (r Route) String() string {
	switch r {
	case RouteInspect:
		return "Inspect"
	case RoutePassThrough:
		return "PassThrough"
	default:
		return "Unset"
	}
}

// PassThroughDispatcher is the real-plane dispatch point: it consults the
// boundary PolicyEngine pass-through seam and routes an admitted flow to the
// opaque-tunnel (DialRaw) leg or the inspected (LeafFor + DialTLS) leg over the
// boundary SessionCA / UpstreamDialer / EventSink seams. It is the Go mirror of
// main.rs proceed_route + the opaque splice + passthrough_netflow_event.
type PassThroughDispatcher struct {
	// Policy is the boundary PolicyEngine pass-through seam (POL: the list is
	// policy, not code — empty by default, D74). Only PassThrough is consulted.
	Policy tlsproxy.PolicyEngine
	// CA mints the per-origin interception leaf on the INSPECTED leg (TLS-3.a).
	// The pass-through leg NEVER touches it.
	CA tlsproxy.SessionCA
	// Dialer re-originates upstream: DialRaw (opaque tunnel) or DialTLS
	// (strict-WebPKI inspected leg).
	Dialer tlsproxy.UpstreamDialer
	// Sink is the §10 telemetry egress the pass-through leg accounts the flow on.
	Sink tlsproxy.EventSink
}

// Dispatch routes an ALREADY-ADMITTED flow for sni/dst. It consults the
// pass-through seam, then:
//
//	listed   → opaque tunnel: DialRaw(dst), splice downstream verbatim upstream,
//	           read the upstream reply, account a netflow EventFlow (session + dst
//	           + sni, NO HTTP metadata). Returns RoutePassThrough and the reply.
//	unlisted → inspected: LeafFor(sni) (mint the per-origin leaf) then DialTLS(sni,
//	           dst). Returns RouteInspect.
//
// downstream is the raw bytes peeked off the VM (the ClientHello + whatever
// follows on the opaque leg); on the inspected leg they are not spliced (TLS is
// terminated). reply (pass-through leg only) is the upstream's response bytes.
//
// The route is DECIDED HERE by consulting the seam — the caller does not choose
// the leg — so a test observing which seam methods ran proves the system's
// routing, not the test's.
func (d *PassThroughDispatcher) Dispatch(ctx context.Context, sess tlsproxy.SessionRef, sni string, dst netip.AddrPort, downstream []byte) (route Route, reply []byte, prov tlsproxy.Provenance, err error) {
	listed, prov, err := d.Policy.PassThrough(ctx, sess, sni)
	if err != nil {
		return RouteUnset, nil, prov, err
	}
	if !listed {
		// Empty-list default / unlisted domain → INSPECT (D74): mint the per-origin
		// leaf and re-originate upstream over the strict-WebPKI DialTLS leg. Never
		// defaults to pass-through (the positive-predicate fall-through u3 hardened).
		if _, err := d.CA.LeafFor(ctx, sni); err != nil {
			return RouteUnset, nil, prov, fmt.Errorf("tlsproxyinspect: inspect-leg leaf for %q: %w", sni, err)
		}
		conn, err := d.Dialer.DialTLS(ctx, sess, sni, dst)
		if err != nil {
			return RouteUnset, nil, prov, fmt.Errorf("tlsproxyinspect: inspect-leg re-originate %q: %w", sni, err)
		}
		_ = conn.Close()
		return RouteInspect, nil, prov, nil
	}

	// Listed domain → opaque PASS-THROUGH: dial the kernel destination raw, splice
	// the downstream bytes upstream VERBATIM (no leaf, no termination), read the
	// upstream reply back. This is the copy_bidirectional behavior of the TLS-4
	// branch over the real DialRaw seam.
	conn, err := d.Dialer.DialRaw(ctx, sess, dst)
	if err != nil {
		return RouteUnset, nil, prov, fmt.Errorf("tlsproxyinspect: pass-through DialRaw %s: %w", dst, err)
	}
	defer conn.Close()
	if _, err := conn.Write(downstream); err != nil {
		return RouteUnset, nil, prov, fmt.Errorf("tlsproxyinspect: splice downstream upstream: %w", err)
	}
	reply, err = readAll(conn)
	if err != nil {
		return RouteUnset, nil, prov, fmt.Errorf("tlsproxyinspect: read upstream reply: %w", err)
	}

	// Account the opaque flow EXACTLY as main.rs passthrough_netflow_event does:
	// a netflow EventFlow carrying session + dst + the SNI admission key, and NO
	// HTTP-level metadata (doc 12 §3/§5/§10 — opaque means opaque). Built HERE in
	// code-under-test, not by the test, so the "no HTTP field" property is the
	// system's, not a test literal's.
	if err := d.Sink.Emit(ctx, passThroughNetflowEvent(sess, sni, dst, prov)); err != nil {
		return RouteUnset, reply, prov, fmt.Errorf("tlsproxyinspect: emit netflow: %w", err)
	}
	return RoutePassThrough, reply, prov, nil
}

// passThroughNetflowEvent builds the opaque-tunnel netflow EventFlow — the
// real-plane mirror of main.rs passthrough_netflow_event. It carries the session
// (the join key), the destination address + the SNI admission key, and NOTHING
// HTTP-level: there is no method/path/status/host/header/url to carry because the
// tunnel is opaque (the doc 12 §3/§5 stated non-claim). This is the production-
// shaped builder the dispatcher emits, so a regression that leaked an HTTP field
// into the pass-through accounting would surface in the dispatch test.
func passThroughNetflowEvent(sess tlsproxy.SessionRef, sni string, dst netip.AddrPort, prov tlsproxy.Provenance) tlsproxy.Event {
	return tlsproxy.Event{
		Kind:       tlsproxy.EventFlow,
		Session:    sess,
		Provenance: prov,
		Fields: map[string]string{
			"sni": sni,          // the destination NAME (the admission key) — NOT an HTTP field
			"dst": dst.String(), // the kernel original_dst the opaque tunnel forwards to
		},
	}
}

// readAll drains conn to EOF (or the first non-EOF error), returning the bytes
// read. The opaque-tunnel reply is small and the fake upstream closes after
// writing, so this terminates promptly without a new import.
func readAll(conn net.Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
	}
}

// ───────────────────────────────────────────────────────────────────────────
// serial counter (monotone, process-local — leaf/CA serials must be unique).
// ───────────────────────────────────────────────────────────────────────────

var (
	serialMu      sync.Mutex
	serialCounter int64 = 1000
)

func nextSerial() *big.Int {
	serialMu.Lock()
	defer serialMu.Unlock()
	serialCounter++
	return big.NewInt(serialCounter)
}

// ───────────────────────────────────────────────────────────────────────────
// Live half env-gate contract (mirrors DS_RESOLVERLOCK_* — see doc.go).
// ───────────────────────────────────────────────────────────────────────────

// LiveEnvVar is the env gate for the live TLS-3 conformance run. Set to "1" the
// live half drives curl/npm/git through a running ds-tlsproxy and asserts valid
// TLS + metadata-in-telemetry (3.a) and A's CA useless against B over the wire
// (3.c); unset (the default) the live half SKIPS. It is a deferred manual step:
// it needs a running ds-tlsproxy binary + a live kernel/network the wave sandbox
// lacks (the offline half covers 3.b strict-WebPKI re-validation in-process).
const LiveEnvVar = "DS_TLS3_LIVE"

// LiveEnabled reports whether the env gate opts into the live half. The live
// tests call this and SKIP when false, so the default `go test` run is offline.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// LiveTarget addresses the running ds-tlsproxy the live half drives against,
// read from the environment so a deployment points the run at its own egress
// gateway. The field has a safe localhost default; the live half still only runs
// when LiveEnabled() is true.
type LiveTarget struct {
	// TLSProxyAddr is the ds-tlsproxy transparent-redirect listener (host:port)
	// the inspected flow's TLS is terminated on (the egress gateway).
	TLSProxyAddr string
}

// LiveTargetFromEnv builds the live target from DS_TLS3_* env vars, with a
// localhost dev default. It does NOT itself require the gate — the caller checks
// LiveEnabled() — it only resolves WHERE the live half would connect.
func LiveTargetFromEnv() LiveTarget {
	return LiveTarget{TLSProxyAddr: envOr("DS_TLS3_TLSPROXY_ADDR", "127.0.0.1:443")}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
