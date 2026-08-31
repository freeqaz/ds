// Package tlsproxy is the executable specification (doc 04 D26) for
// ds-tlsproxy — the TLS / HTTP CONNECT proxy + credential swapper of the
// Dream Serpent Boundary workstream (doc 09 §5, TLS-1..TLS-8).
//
// This file defines ONLY the contract seams ("the functions we will need").
// Every New…() constructor returns a non-nil stub whose methods return
// ErrNotImplemented (the RED rule): the accompanying test suite compiles and
// vets clean but fails until the real Rust/Pingora + nftables data plane
// satisfies the documented outcomes.
package tlsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// ErrNotImplemented is the sentinel every stub returns so the whole suite
// fails RED until the data plane satisfies the executable spec (doc 04 D26).
var ErrNotImplemented = errors.New("tlsproxy: not implemented")

// SessionRef threads session identity through every seam.
type SessionRef struct{ ID string }

// Secret is a self-redacting credential value: any formatting verb yields
// "[REDACTED]". Events and logs may only ever carry a Fingerprint, never a
// Value; tests compare raw bytes explicitly via the leak canary.
type Secret []byte

// String implements fmt.Stringer; it never reveals the value.
func (Secret) String() string { return "[REDACTED]" }

// GoString redacts %#v formatting too.
func (Secret) GoString() string { return "[REDACTED]" }

// Credential pairs a secret value with its loggable fingerprint.
type Credential struct {
	Value       Secret
	Fingerprint string
}

// Provenance is the POL-3 decision provenance carried on every verdict and
// event. A missing-provenance event is a test failure.
type Provenance struct {
	RuleID        string
	PolicyLayer   string
	PolicyVersion string
}

// Decision is a policy verdict with full provenance.
type Decision struct {
	Allow      bool
	Provenance Provenance
}

// ClientHello is the parsed SNI-peek result for TLS-1. SNI == "" models
// absent SNI. HasECH covers both real ECH and GREASE ECH — indistinguishable
// by design, both refused (doc 09 §5 TLS-1 edge rule 1).
type ClientHello struct {
	SNI    string
	HasECH bool
	ALPN   []string
	Raw    []byte
}

// Action is the tunnel-gate verdict. The zero value is ActionUnknown so a
// zero-valued TunnelDecision can never satisfy a refusal assertion.
type Action int

const (
	ActionUnknown Action = iota
	ActionRefuse
	ActionTunnelOpaque
	ActionInspect
	ActionPassThrough
)

// String makes test failures readable.
func (a Action) String() string {
	switch a {
	case ActionRefuse:
		return "Refuse"
	case ActionTunnelOpaque:
		return "TunnelOpaque"
	case ActionInspect:
		return "Inspect"
	case ActionPassThrough:
		return "PassThrough"
	default:
		return "Unknown"
	}
}

// TunnelDecision is the TLS-1 admission verdict. Upstream may legally differ
// from the client's original destination only via the re-admission path —
// never sourced from the client's claim.
type TunnelDecision struct {
	Action     Action
	Upstream   netip.AddrPort
	Reason     string
	Provenance Provenance
}

// TunnelGate is the TLS-1 decision seam: SNI allowed by policy AND the
// original destination admitted FOR THAT DOMAIN (DNS-2b); ECH / absent-SNI /
// IP-literal refusal; and the lapsed-admission re-admission path.
type TunnelGate interface {
	Evaluate(ctx context.Context, sess SessionRef, hello ClientHello, origDst netip.AddrPort) (TunnelDecision, error)
}

// Admission is one DNS-2b admission-map entry: domain -> admitted IPs with
// expiry, per session.
type Admission struct {
	Domain string
	Addrs  []netip.Addr
	Expiry time.Time
}

// AdmissionMap is the read side of the DNS-2b host-local per-session
// (domain -> admitted IPs, expiry) store. The NFT sets hold bare IPs and
// cannot answer "admitted for which domain" — this seam can.
type AdmissionMap interface {
	Lookup(ctx context.Context, sess SessionRef, domain string) (Admission, bool, error)
	AdmittedFor(ctx context.Context, sess SessionRef, addr netip.Addr, domain string) (bool, error)
}

// ReAdmitter is the TLS-1 lapsed-admission path back through DNS-2 full
// admission: resolve-once clients survive set expiry; CDN rotation yields a
// freshly admitted upstream address sourced from OUR resolution.
type ReAdmitter interface {
	ReAdmit(ctx context.Context, sess SessionRef, domain string) (Admission, error)
}

// RequestMeta is the HTTP request metadata policy and swap operate on.
type RequestMeta struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
}

// ResponseMeta is the HTTP response metadata visible to scrubbing/scanning.
type ResponseMeta struct {
	Status  int
	Headers map[string]string
}

// ServiceRule is one TLS-5 credential-swap service-registry entry
// (e.g. service "github" -> hosts github.com/api.github.com, credential
// location "header:Authorization").
type ServiceRule struct {
	Service      string
	Hosts        []string
	CredLocation string
}

// PolicyEngine is the embedded policy-core seam: identical rule evaluation
// across transparent/CONNECT/forward modes, the TLS-4 pass-through list
// (policy, not code), and the TLS-5 credential-swap service registry.
type PolicyEngine interface {
	EvaluateConnect(ctx context.Context, sess SessionRef, domain string) (Decision, error)
	EvaluateHTTP(ctx context.Context, sess SessionRef, req RequestMeta) (Decision, error)
	PassThrough(ctx context.Context, sess SessionRef, domain string) (bool, Provenance, error)
	MatchSwapService(ctx context.Context, host string) (ServiceRule, bool, error)
}

// SessionCA is the D17 per-session interception CA: on-the-fly per-origin
// leaf minting (TLS-3) and the trust-pool export for the golden image.
type SessionCA interface {
	LeafFor(ctx context.Context, origin string) (tls.Certificate, error)
	CertPool() ([]byte, error)
}

// CAMinter mints the per-session interception CA (mint owner: Identity
// workstream; faked here). Drives the TLS-3 per-session CA isolation
// assertion (A's CA useless against B).
type CAMinter interface {
	MintSessionCA(ctx context.Context, sess SessionRef) (SessionCA, error)
}

// UpstreamDialer re-originates upstream connections. DialTLS performs strict
// WebPKI validation against domain — at least as strict as the client's would
// have been (TLS-3). DialRaw is the opaque-tunnel leg (TLS-1/TLS-4); tests
// wrap the dialer with a recorder to assert WHICH address was dialed (fresh
// admission vs the client's claim) and exercise bad-cert upstreams.
type UpstreamDialer interface {
	DialTLS(ctx context.Context, sess SessionRef, domain string, addr netip.AddrPort) (net.Conn, error)
	DialRaw(ctx context.Context, sess SessionRef, addr netip.AddrPort) (net.Conn, error)
}

// IdentityClaims is the validated identity bound to a short-lived credential.
type IdentityClaims struct {
	Session SessionRef
	Subject string
	Expiry  time.Time
}

// IdentityValidator is the D22 sidecar seam: the presented short-lived
// credential must validate against THIS session's identity before any
// secret-store fetch. Cross-session / forged / expired creds fail here.
type IdentityValidator interface {
	ValidateShortLived(ctx context.Context, sess SessionRef, presented Credential) (IdentityClaims, error)
}

// SecretStore is the real-credential source OUTSIDE the boundary (separate
// trust zone, D8/D22). Tests assert it is never called on validation failure
// or registry miss, and that its returned Value reaches only the upstream leg.
type SecretStore interface {
	FetchLongLived(ctx context.Context, service string, claims IdentityClaims) (Credential, error)
}

// SwapOutcome reports a D8 credential swap. It carries the fingerprint only —
// never the value.
type SwapOutcome struct {
	Swapped     bool
	Service     string
	Fingerprint string
	Provenance  Provenance
}

// CredentialSwapper performs the D8 swap itself: validate the short-lived
// credential, substitute the long-lived one into the upstream request in
// place.
type CredentialSwapper interface {
	Swap(ctx context.Context, sess SessionRef, rule ServiceRule, req *RequestMeta) (SwapOutcome, error)
}

// ScrubHit records one scrubbed credential occurrence on the VM-bound leg.
type ScrubHit struct {
	Location string // "body" | "header:<name>"
	Form     string // "raw" | "base64" | ...
}

// ResponseScrubber enforces the "not in any readable response" clause of the
// TLS-5 invariant on the VM-bound leg: an upstream echoing the swapped
// Authorization value back must never deliver the long-lived value downstream.
type ResponseScrubber interface {
	ScrubResponse(ctx context.Context, sess SessionRef, resp *ResponseMeta, body io.Reader) (io.Reader, []ScrubHit, error)
}

// RateDecision is a TLS-6 per-(session, service) rate-limit verdict.
type RateDecision struct {
	Allowed    bool
	RetryAfter time.Duration
	Provenance Provenance
}

// RateLimiter enforces TLS-6 per-session and per-service rate limits.
type RateLimiter interface {
	Allow(ctx context.Context, sess SessionRef, service string) (RateDecision, error)
}

// ResourceAction is one cap-counted action on a sensitive resource.
type ResourceAction struct {
	Method   string
	Host     string
	Path     string
	Resource string
}

// CapVerdict reports whether an action tripped a declared behavioral cap.
type CapVerdict struct {
	Breached   bool
	CapID      string
	Provenance Provenance
}

// CapMonitor is the TLS-6 behavioral-cap mechanism.
type CapMonitor interface {
	Record(ctx context.Context, sess SessionRef, act ResourceAction) (CapVerdict, error)
}

// BreachInfo accompanies the suspend signal on a cap breach.
type BreachInfo struct {
	CapID      string
	Action     ResourceAction
	Provenance Provenance
}

// SuspendSignaler is the Stage-0-frozen orchestrator suspend signal (faked in
// tests) for the §9 suspend-on-breach row: the breaching request is held —
// it does not complete upstream before the signal.
type SuspendSignaler interface {
	Suspend(ctx context.Context, sess SessionRef, breach BreachInfo) error
}

// Finding is one inbound-secret detection. It carries a fingerprint, never
// the secret value.
type Finding struct {
	Kind        string
	Fingerprint string
	Where       string
}

// SecretScanner is the TLS-7 inbound secret-scanning gate on the inspected
// path. The boundary owns the inspection point; rules/response ownership
// stays OQ8 (the scanner is pluggable).
type SecretScanner interface {
	ScanInbound(ctx context.Context, sess SessionRef, meta ResponseMeta, body []byte) ([]Finding, error)
}

// SecretHook is the configured TLS-7 response hook.
type SecretHook interface {
	OnFinding(ctx context.Context, sess SessionRef, f Finding) error
}

// EventKind discriminates the LOG-1-mirroring event stream.
type EventKind string

const (
	EventFlow           EventKind = "Flow"
	EventHTTP           EventKind = "HttpEvent"
	EventPolicyDecision EventKind = "PolicyDecision"
	EventCredentialUse  EventKind = "CredentialUseEvent"
	EventScrub          EventKind = "ScrubEvent"
	EventBreach         EventKind = "BreachEvent"
	EventError          EventKind = "ErrorEvent"
	EventSecretFinding  EventKind = "SecretFindingEvent"
)

// Event is a single telemetry emission. Every event carries provenance
// (POL-3) and only ever credential fingerprints, never values (LOG-5).
type Event struct {
	Kind       EventKind
	Session    SessionRef
	At         time.Time
	Provenance Provenance
	Fields     map[string]string
}

// EventSink is the single egress for ALL telemetry/log paths. Tests capture
// every emission to prove credential scrubbing on every log path and
// provenance completeness.
type EventSink interface {
	Emit(ctx context.Context, ev Event) error
}

// Surface names one VM-observable surface for the leak probe.
type Surface string

const (
	SurfaceDisk            Surface = "disk"
	SurfaceEnv             Surface = "env"
	SurfaceCoWDelta        Surface = "cow-delta"
	SurfaceDownstreamBytes Surface = "downstream-bytes"
)

// LeakHit is one canary occurrence on a VM-observable surface.
type LeakHit struct {
	Surface Surface
	Offset  int64
	Context string
}

// LeakProbe is the harness-side seam over every VM-observable surface — disk,
// env, CoW delta, and a full recording of every byte the proxy sent toward
// the VM. The headline credential-leak-absence test greps all surfaces for
// the canary and asserts zero hits.
type LeakProbe interface {
	Search(ctx context.Context, sess SessionRef, needle []byte) ([]LeakHit, error)
}

// Config carries proxy-wide knobs. Tests inject a deterministic clock and the
// WebPKI fixture roots.
type Config struct {
	// Now is the injectable clock; nil means time.Now. Tests inject a fake
	// clock — expiry is always advanced logically, never slept for.
	Now func() time.Time
	// Inspect selects the TLS-3+ inspected default. False models the TLS-1
	// stage where allowed flows tunnel opaquely.
	Inspect bool
	// SpoolDir is the proxy's only permitted scratch/spool directory; the
	// leak probe's disk surface scans it.
	SpoolDir string
	// UpstreamRoots overrides the WebPKI roots for upstream re-origination
	// validation. Nil means system roots; tests inject a fixture root.
	UpstreamRoots *x509.CertPool
}

// Deps bundles every dependency seam so fakes are injected wholesale.
type Deps struct {
	Gate       TunnelGate
	Admissions AdmissionMap
	ReAdmitter ReAdmitter
	Policy     PolicyEngine
	CAs        CAMinter
	Dialer     UpstreamDialer
	Identity   IdentityValidator
	Secrets    SecretStore
	Swapper    CredentialSwapper
	Scrubber   ResponseScrubber
	Rate       RateLimiter
	Caps       CapMonitor
	Suspend    SuspendSignaler
	Scanner    SecretScanner
	Hook       SecretHook
	Events     EventSink
}

// Proxy is the black-box system under test: the three ingress modes (NFT-2b
// transparent redirect with recovered original destination, explicit CONNECT,
// plain-HTTP forward) and per-session teardown in lockstep with NFT-6.
type Proxy interface {
	ServeTransparentTLS(ctx context.Context, downstream net.Conn, sess SessionRef, origDst netip.AddrPort) error
	ServeCONNECT(ctx context.Context, downstream net.Conn, sess SessionRef) error
	ServeHTTPForward(ctx context.Context, downstream net.Conn, sess SessionRef) error
	TeardownSession(ctx context.Context, sess SessionRef) error
	Close(ctx context.Context) error
}

// New constructs the proxy stub. It never returns nil — tests must never
// nil-panic; they fail RED on the documented outcomes instead.
func New(cfg Config, deps Deps) (Proxy, error) { return &stubProxy{}, nil }

// NewTunnelGate returns the TLS-1 tunnel-gate stub.
func NewTunnelGate(cfg Config, deps Deps) TunnelGate { return &stubGate{} }

// NewCredentialSwapper returns the D8 swap stub.
func NewCredentialSwapper(cfg Config, deps Deps) CredentialSwapper { return &stubSwapper{} }

// NewResponseScrubber returns the TLS-5 response-scrubber stub.
func NewResponseScrubber(cfg Config) ResponseScrubber { return &stubScrubber{} }

// NewSecretScanner returns the TLS-7 inbound-scanner stub.
func NewSecretScanner(cfg Config) SecretScanner { return &stubScanner{} }

// NewUpstreamDialer returns the strict-WebPKI upstream dialer stub.
func NewUpstreamDialer(cfg Config) UpstreamDialer { return &stubDialer{} }

type stubProxy struct{}

func (*stubProxy) ServeTransparentTLS(context.Context, net.Conn, SessionRef, netip.AddrPort) error {
	return ErrNotImplemented
}
func (*stubProxy) ServeCONNECT(context.Context, net.Conn, SessionRef) error {
	return ErrNotImplemented
}
func (*stubProxy) ServeHTTPForward(context.Context, net.Conn, SessionRef) error {
	return ErrNotImplemented
}
func (*stubProxy) TeardownSession(context.Context, SessionRef) error { return ErrNotImplemented }
func (*stubProxy) Close(context.Context) error                       { return ErrNotImplemented }

type stubGate struct{}

func (*stubGate) Evaluate(context.Context, SessionRef, ClientHello, netip.AddrPort) (TunnelDecision, error) {
	return TunnelDecision{}, ErrNotImplemented
}

type stubSwapper struct{}

func (*stubSwapper) Swap(context.Context, SessionRef, ServiceRule, *RequestMeta) (SwapOutcome, error) {
	return SwapOutcome{}, ErrNotImplemented
}

type stubScrubber struct{}

func (*stubScrubber) ScrubResponse(context.Context, SessionRef, *ResponseMeta, io.Reader) (io.Reader, []ScrubHit, error) {
	return nil, nil, ErrNotImplemented
}

type stubScanner struct{}

func (*stubScanner) ScanInbound(context.Context, SessionRef, ResponseMeta, []byte) ([]Finding, error) {
	return nil, ErrNotImplemented
}

type stubDialer struct{}

func (*stubDialer) DialTLS(context.Context, SessionRef, string, netip.AddrPort) (net.Conn, error) {
	return nil, ErrNotImplemented
}
func (*stubDialer) DialRaw(context.Context, SessionRef, netip.AddrPort) (net.Conn, error) {
	return nil, ErrNotImplemented
}
