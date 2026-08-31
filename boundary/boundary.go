// Package boundary is the cross-cutting integration layer of the Dream Serpent
// Boundary TDD harness: the §9 guardrail matrix (C9-*), the §8 lifecycle suite
// (E2E-*), the §1 developer-value test (DV-*), the Stage-0 contract seams
// (S0-*), and the load rows (LOAD-*) all drive the Boundary facade defined
// here as a single black box.
//
// Everything in this file is a SEAM: the contract surface the real
// Rust/Pingora + nftables data plane must satisfy. Every constructor returns a
// non-nil stub whose methods return ErrNotImplemented (or zero values), so the
// whole assurance suite compiles, runs, and fails RED until the real data
// plane is wired in. See CONVENTIONS.md — never assert ErrNotImplemented.
//
// planRef: docs/09-boundary-build-plan.md §8 Stage 0 (contracts), §9 (matrix).
package boundary

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// ErrNotImplemented is the sentinel every stub returns. Tests assert
// documented outcomes, so the suite is RED until the real data plane is
// wired. A test observing ErrNotImplemented is failing-as-designed.
var ErrNotImplemented = errors.New("boundary: not implemented")

// Sentinels for documented denial outcomes that surface as errors. Tests
// assert these specific sentinels (errors.Is) — never bare err != nil — so a
// stub returning ErrNotImplemented still fails the assertion (RED).
var (
	// ErrIdentityMismatch: a short-lived credential presented under a
	// session it was not minted for (S0-6, D22).
	ErrIdentityMismatch = errors.New("boundary: credential does not match session identity")
	// ErrCredentialExpired: a short-lived credential past its validity or
	// belonging to a destroyed session (S0-6, E2E-4).
	ErrCredentialExpired = errors.New("boundary: short-lived credential expired or revoked")
)

// ---------------------------------------------------------------------------
// Contract constants — budgets, clamps, and well-known names the tests pin.
// planRef: doc 09 NFT-3 (clamp/grace strawman), DNS-1 (warm p99), doc 06 (b)/(d).
// ---------------------------------------------------------------------------

const (
	// IfacePrefix is the per-session interface naming convention (NFT-2);
	// SessionRef.Iface must be IfacePrefix + session id. It is the
	// unforgeable attribution key (§7, LOG-2).
	IfacePrefix = "dstap-"
	// ServedByDNSGate is the responder identity every VM DNS answer must
	// carry (NFT-4: all port-53 traffic lands on ds-dnsgate).
	ServedByDNSGate = "ds-dnsgate"
	// RedirectTLSProxy is the redirect target for VM tcp/80+443 (NFT-2b).
	RedirectTLSProxy = "ds-tlsproxy"
)

const (
	// TTLClampMin/Max bound the TTL answered to a VM (DNS-1 clamp strawman:
	// 60s–15min).
	TTLClampMin = 60 * time.Second
	TTLClampMax = 15 * time.Minute
	// AllowSetGraceMin/Max is the NFT-3 grace margin added to the clamped
	// TTL for the kernel set element timeout (strawman 30–60s), so the
	// kernel entry strictly outlives any TTL-honoring client cache.
	AllowSetGraceMin = 30 * time.Second
	AllowSetGraceMax = 60 * time.Second
)

const (
	// StartTimeBudget: create->attach headline budget (doc 06 (b), E2E-2).
	StartTimeBudget = 5 * time.Second
	// ProxyP99Budget: inspected-HTTPS p99 under fan-out (doc 06 (d), LOAD-1).
	ProxyP99Budget = 250 * time.Millisecond
	// PolicyPushBudget: push-to-enforced fleet latency (POL-4, LOAD-2).
	PolicyPushBudget = 5 * time.Second
	// DNSWarmP99Budget: added resolution latency, warm cache (DNS-1, LOAD-4).
	DNSWarmP99Budget = 10 * time.Millisecond
)

// BaselineDomains is the D64 (amended by D74) system default allowlist
// strawman (POL-2): the §1 developer-value endpoints that must work with
// zero configuration.
var BaselineDomains = []string{
	"api.anthropic.com",
	"github.com",
	"api.github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"registry.npmjs.org",
}

// BaselineBlockedResolvers is the D64 baseline blocklist strawman of known
// public DoH/DoT resolver domains (POL-2; blocklists always win).
var BaselineBlockedResolvers = []string{
	"dns.google",
	"cloudflare-dns.com",
	"dns.quad9.net",
}

// ---------------------------------------------------------------------------
// Clock seam — deterministic time (CONVENTIONS: never time.Sleep for expiry).
// ---------------------------------------------------------------------------

// Clock is the time source the boundary under test must honor for TTL
// clamps, allow-set/admission expiry, grant TTLs, and event timestamps.
// Tests install a fake clock via SetClock and advance it.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

var activeClock Clock = realClock{}

// SetClock installs the harness time source (a fake clock in tests). The
// real data plane must derive every expiry decision from this seam.
func SetClock(c Clock) {
	if c == nil {
		activeClock = realClock{}
		return
	}
	activeClock = c
}

// Now returns the active clock's time.
func Now() time.Time { return activeClock.Now() }

// ---------------------------------------------------------------------------
// Identity / session types
// ---------------------------------------------------------------------------

// SessionRef is the identity of one agent VM session. Iface is the
// per-session interface (NFT-2, dstap-<session>) — the unforgeable
// attribution key joining nft sets, the flow log, and the admission map.
type SessionRef struct {
	ID    string
	Iface string
}

// Secret is an opaque credential value. It must never be logged.
type Secret string

// CARef identifies a per-session interception CA (D17, TLS-3).
type CARef struct {
	ID      string
	Session SessionRef
}

// CertRef identifies a leaf cert minted under a session CA (TLS-3).
// IssuerCA names the CA the leaf actually chains to — the cross-session
// scoping assertion (C9-22, S0-7) pins it.
type CertRef struct {
	IssuerCA CARef
	Origin   string
}

// IdentityRef names a session identity (D22).
type IdentityRef struct {
	ID string
}

// Posture is the POL-1 policy posture.
type Posture string

const (
	PostureLocked   Posture = "locked"
	PostureStandard Posture = "standard"
	PostureOpen     Posture = "open"
)

// PolicyVersion is the version stamped on a policy snapshot (POL-3).
type PolicyVersion string

// Session is one created agent VM session.
type Session struct {
	Ref            SessionRef
	ShortLivedCred Secret
	InterceptCA    CARef
	StartedAt      time.Time
}

// CreateSessionRequest configures session creation.
type CreateSessionRequest struct {
	Posture  Posture
	Policy   PolicyVersion
	Identity IdentityRef
}

// AttachResult reports a completed attach. VMAddr is the agent VM's address
// on its per-session segment — used by the session-isolation row (C9-17).
type AttachResult struct {
	Attached bool
	VMAddr   netip.Addr
	At       time.Time
}

// SnapshotRef identifies a taken snapshot (E2E-1/5).
type SnapshotRef struct {
	ID      string
	TakenAt time.Time
}

// SuspendReason explains a suspend (TLS-6 cap breach, operator, ...).
type SuspendReason string

const (
	SuspendReasonCapBreach SuspendReason = "cap-breach"
	SuspendReasonOperator  SuspendReason = "operator"
)

// ---------------------------------------------------------------------------
// Boundary facade
// ---------------------------------------------------------------------------

// Boundary is the top-level wiring of ds-dnsgate, ds-tlsproxy, NFTables,
// policy-core, ds-flowlog, and the orchestrator seams: the single black box
// every §8 e2e and §9 guardrail test drives.
type Boundary interface {
	CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error)
	Attach(ctx context.Context, s SessionRef) (AttachResult, error)
	Snapshot(ctx context.Context, s SessionRef) (SnapshotRef, error)
	Suspend(ctx context.Context, s SessionRef, reason SuspendReason) error
	Resume(ctx context.Context, s SessionRef) error
	DestroySession(ctx context.Context, s SessionRef) error
	VM(s SessionRef) VMProbe
	Inspect() HostInspector
	Policy() PolicyControl
	Orchestrator() OrchestratorFake
}

// ---------------------------------------------------------------------------
// VMProbe — the in-VM adversarial surface
// ---------------------------------------------------------------------------

// DNSType is a DNS record type the probe can query.
type DNSType string

const (
	DNSTypeA     DNSType = "A"
	DNSTypeAAAA  DNSType = "AAAA"
	DNSTypeHTTPS DNSType = "HTTPS" // type 65
	DNSTypeSVCB  DNSType = "SVCB"
	DNSTypeCNAME DNSType = "CNAME"
)

// DNSRcode is the response code answered to the VM.
type DNSRcode string

const (
	RcodeNoError  DNSRcode = "NOERROR"
	RcodeNXDomain DNSRcode = "NXDOMAIN"
	RcodeServFail DNSRcode = "SERVFAIL"
	RcodeRefused  DNSRcode = "REFUSED"
)

// DNSRecord is one answer record. Addr is set for A/AAAA (and embedded-v4
// forms); Target for CNAME/HTTPS/SVCB target names.
type DNSRecord struct {
	Name   string
	Type   DNSType
	Addr   netip.Addr
	Target string
	TTL    time.Duration
}

// DNSQuery is a resolution attempt from inside the VM. Nameserver lets an
// adversarial test aim the query at a public resolver (8.8.8.8) — NFT-4 must
// still land it on ds-dnsgate. Zero Nameserver means the configured stub path.
type DNSQuery struct {
	Name       string
	Type       DNSType
	Nameserver netip.Addr
}

// DNSResponse is what the VM observed. ServedBy identifies the actual
// responder; MinTTL is the minimum TTL across the answered records (the
// clamped value driving NFT-3 timeouts).
type DNSResponse struct {
	Rcode    DNSRcode
	Answers  []DNSRecord
	ServedBy string
	MinTTL   time.Duration
}

// L4Proto is the transport of a raw dial.
type L4Proto string

const (
	ProtoTCP L4Proto = "tcp"
	ProtoUDP L4Proto = "udp"
)

// FlowOutcome is what happened to a raw dial. The zero value is invalid so
// a zero-value stub cannot satisfy any outcome assertion.
type FlowOutcome string

const (
	OutcomeConnected  FlowOutcome = "Connected"
	OutcomeDropped    FlowOutcome = "Dropped"
	OutcomeRedirected FlowOutcome = "Redirected"
)

// DialRequest is a raw L4 dial from inside the VM. SpoofSourceIP, when set,
// forges the packet source address (C9-2: matching is iifname, never src IP).
type DialRequest struct {
	Proto         L4Proto
	Dst           netip.AddrPort
	SpoofSourceIP netip.Addr
}

// DialResult reports the observable fate of a dial. RedirectedTo names the
// service that received a redirected flow (ds-dnsgate / ds-tlsproxy).
type DialResult struct {
	Outcome      FlowOutcome
	RedirectedTo string
}

// TLSOutcome is what happened to a TLS connection attempt.
type TLSOutcome string

const (
	TLSTunneled  TLSOutcome = "Tunneled"  // opaque SNI-checked tunnel (TLS-1/TLS-4)
	TLSInspected TLSOutcome = "Inspected" // TLS-terminated at the egress gateway via per-session CA (TLS-3)
	TLSRefused   TLSOutcome = "Refused"
)

// TLSConnectRequest is a TLS handshake attempt from inside the VM.
// OfferECH carries a real ECH extension; GreaseECH carries a GREASE-ECH
// extension (no real config) — C9-12 requires BOTH be refused.
type TLSConnectRequest struct {
	SNI       string
	DstIP     netip.Addr
	OfferECH  bool
	GreaseECH bool
	IPLiteral bool
	ALPN      []string
}

// TLSConnResult reports the handshake fate. LeafCAIssuer is the CA id the
// presented leaf chains to (empty for opaque tunnels); UpstreamCertValidated
// reports strict WebPKI re-origination (TLS-3).
type TLSConnResult struct {
	Outcome               TLSOutcome
	UpstreamCertValidated bool
	LeafCAIssuer          string
}

// HTTPRequest is an HTTP(S) request from inside the VM. ViaProxy selects the
// explicit HTTP_PROXY path (TLS-2) vs the transparent redirect.
type HTTPRequest struct {
	Method   string
	Host     string
	Path     string
	Headers  map[string]string
	Body     []byte
	ViaProxy bool
}

// HTTPResponse is what the VM observed.
type HTTPResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// ScanTarget is an interior surface the adversary can search for leaked
// credentials or observable controls (C9-18, C9-21).
type ScanTarget string

const (
	ScanDisk           ScanTarget = "Disk"
	ScanEnv            ScanTarget = "Env"
	ScanCoWDelta       ScanTarget = "CoWDelta"
	ScanResponseBodies ScanTarget = "ResponseBodies"
	ScanControls       ScanTarget = "Controls"
)

// InteriorScanRequest searches the listed surfaces for Needle.
type InteriorScanRequest struct {
	Targets []ScanTarget
	Needle  []byte
}

// InteriorScan reports needle hits and where they were found.
type InteriorScan struct {
	Found     bool
	Locations []string
}

// L2ProbeKind selects an L2 neighbor-reach probe (C9-17: "incl. ARP/L2
// reach probe" — no agent-to-agent L2 path may exist).
type L2ProbeKind string

const (
	L2ProbeARP L2ProbeKind = "arp"
	L2ProbeNDP L2ProbeKind = "ndp"
)

// L2ProbeRequest is an ARP/NDP neighbor-discovery attempt from inside the VM.
type L2ProbeRequest struct {
	Kind   L2ProbeKind
	Target netip.Addr
}

// L2ProbeResult reports the probe fate. Outcome reuses the FlowOutcome
// domain (zero value invalid, so a zero-value stub cannot satisfy the
// assertion); PeerMAC is the learned link-layer address — empty when no L2
// path exists.
type L2ProbeResult struct {
	Outcome FlowOutcome
	PeerMAC string
}

// VMProbe models everything the untrusted VM can attempt — the adversary's
// whole toolkit as one interface.
type VMProbe interface {
	ResolveDNS(ctx context.Context, q DNSQuery) (DNSResponse, error)
	Dial(ctx context.Context, req DialRequest) (DialResult, error)
	TLSConnect(ctx context.Context, req TLSConnectRequest) (TLSConnResult, error)
	HTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
	ScanInterior(ctx context.Context, req InteriorScanRequest) (InteriorScan, error)
	// ProbeL2 is the C9-17 ARP/NDP reach probe toward another VM's address.
	ProbeL2(ctx context.Context, req L2ProbeRequest) (L2ProbeResult, error)
	// InstallTrustedCA adds ca to the VM's OWN trust store — the C9-22
	// adversarial premise: the VM may trust anything (incl. another
	// session's interception CA); the boundary's scoping must not care.
	InstallTrustedCA(ctx context.Context, ca CARef) error
}

// ---------------------------------------------------------------------------
// HostInspector — out-of-band ground truth
// ---------------------------------------------------------------------------

// IPFamily selects an allow-set family (allow4_<s> / allow6_<s>).
type IPFamily string

const (
	IPv4 IPFamily = "ipv4"
	IPv6 IPFamily = "ipv6"
)

// RulesetSnapshot is the serialized nft ruleset; E2E-3 compares bytes.
type RulesetSnapshot struct {
	Bytes []byte
}

// AllowSetEntry is one element of a per-session allow-set (NFT-3).
type AllowSetEntry struct {
	Addr   netip.Addr
	Expiry time.Time
}

// AdmissionEntry is one DNS-2b admission-map row: domain -> admitted IPs,
// expiring in lockstep with the NFT-3 set timeout.
type AdmissionEntry struct {
	Domain string
	Addrs  []netip.Addr
	Expiry time.Time
}

// AdmissionTraceKind distinguishes the ordered steps of the DNS-2b
// resolve -> insert -> answer pipeline.
type AdmissionTraceKind string

const (
	// TraceInsert: the address landed in the kernel set + admission map.
	TraceInsert AdmissionTraceKind = "insert"
	// TraceAnswer: the answer was published to (made observable by) the VM.
	TraceAnswer AdmissionTraceKind = "answer"
)

// AdmissionTraceEvent is one ordered step of the admission pipeline. Seq is
// a strictly increasing per-session sequence number assigned at the instant
// the step took effect — the ground truth C9-26 pins: for every answered
// address, insert-seq < answer-seq (insert-then-answer, no window).
type AdmissionTraceEvent struct {
	Kind   AdmissionTraceKind
	Domain string
	Addr   netip.Addr
	Seq    uint64
}

// RuleRef is POL-3 decision provenance: matched rule id + policy layer +
// policy version. Every decision event must carry a non-empty RuleRef.
type RuleRef struct {
	RuleID        string
	Layer         string
	PolicyVersion PolicyVersion
}

// FlowRecord is one kernel- or proxy-observed flow (LOG-1; metadata only).
// End is zero while the flow is still open (C9-25 established-survives).
type FlowRecord struct {
	Session         SessionRef
	Iface           string
	AdmittingDomain string
	Dst             netip.AddrPort
	Proto           L4Proto
	Outcome         FlowOutcome
	CtMark          uint32
	BytesIn         int64
	BytesOut        int64
	Start           time.Time
	End             time.Time
}

// DnsEvent is one resolution/denial/scrub event (LOG-1). Kind distinguishes
// e.g. "resolve", "deny", "rebinding-scrub".
type DnsEvent struct {
	Session  SessionRef
	Query    string
	Type     DNSType
	Rcode    DNSRcode
	Kind     string
	Admitted []netip.Addr
	Scrubbed []netip.Addr
	Rule     RuleRef
	At       time.Time
}

// HttpEvent is request/response metadata from the inspected path (LOG-1).
type HttpEvent struct {
	Session SessionRef
	Method  string
	Host    string
	Path    string
	Status  int
	Blocked bool
	Rule    RuleRef
	At      time.Time
}

// PolicyDecision is one policy-core verdict with provenance (POL-3).
type PolicyDecision struct {
	Session  SessionRef
	Decision string // "allow" | "deny" | "ask" | "swap" | "pass-through" | "cap"
	Resource string
	Rule     RuleRef
	At       time.Time
}

// CredentialUseEvent answers "which session used which key, when, for what
// request" — fingerprint only, never the value (LOG-5, D8).
type CredentialUseEvent struct {
	Session     SessionRef
	Service     string
	Fingerprint string
	Request     string
	At          time.Time
}

// SecretScanEvent is a TLS-7 inbound-secret detection.
type SecretScanEvent struct {
	Session     SessionRef
	Surface     string
	Fingerprint string
	At          time.Time
}

// EventBundle is everything the flow log holds for one session.
type EventBundle struct {
	Flows     []FlowRecord
	Dns       []DnsEvent
	Http      []HttpEvent
	Decisions []PolicyDecision
	Creds     []CredentialUseEvent
}

// ReconcileReport is the LOG-4 self-audit verdict: every byte off a VM
// interface explained, or an alarm.
type ReconcileReport struct {
	UnexplainedFlows []FlowRecord
	Alarm            bool
}

// HostInspector exposes the host-side ground truth out of band.
type HostInspector interface {
	NFTRuleset(ctx context.Context) (RulesetSnapshot, error)
	AllowSet(ctx context.Context, s SessionRef, fam IPFamily) ([]AllowSetEntry, error)
	AdmissionMap(ctx context.Context, s SessionRef) ([]AdmissionEntry, error)
	// AdmissionTrace returns the ordered insert/answer trace for the
	// session — the C9-26 insert-then-answer ordering ground truth.
	AdmissionTrace(ctx context.Context, s SessionRef) ([]AdmissionTraceEvent, error)
	Events(ctx context.Context, s SessionRef) (EventBundle, error)
	Reconcile(ctx context.Context) (ReconcileReport, error)
}

// ---------------------------------------------------------------------------
// PolicyControl
// ---------------------------------------------------------------------------

// ResourceKind names what an ask/grant is about.
type ResourceKind string

const (
	ResourceDomain  ResourceKind = "Domain"
	ResourcePort    ResourceKind = "Port"
	ResourceService ResourceKind = "Service"
)

// ResourceRef names a grantable resource.
type ResourceRef struct {
	Kind ResourceKind
	Name string
}

// PolicyLayer is one composition layer (system -> org -> session) of the
// POL-1 schema v0 strawman.
type PolicyLayer struct {
	Name        string // "system" | "org" | "session"
	Allow       []string
	Block       []string // blocklists always win (deny-overrides)
	AskUser     []string
	PassThrough []string       // TLS-4 pinned pass-through list
	Caps        map[string]int // resource -> max requests (TLS-6 behavioral cap)
}

// PolicySnapshot is a layered policy (deny-overrides precedence).
type PolicySnapshot struct {
	Layers []PolicyLayer
}

// AllowGrant is an approval arriving as a session-scoped TTL'd allow grant
// on the policy stream (Stage 0: no second response contract).
type AllowGrant struct {
	Session  SessionRef
	Resource ResourceRef
	TTL      time.Duration
}

// PolicyControl is the one policy-core view both proxies read.
type PolicyControl interface {
	Load(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error)
	Push(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error)
	Grant(ctx context.Context, g AllowGrant) (PolicyVersion, error)
	Active(ctx context.Context) (PolicyVersion, error)
}

// ---------------------------------------------------------------------------
// Stage-0 frozen seams
// ---------------------------------------------------------------------------

// AskUserRequest is the frozen one-way notification boundary -> orchestrator.
type AskUserRequest struct {
	Session     SessionRef
	Kind        ResourceKind
	Name        string
	MatchedRule RuleRef
}

// AskUserSeam is the Stage-0 ask-user contract: Notify is ONE-WAY (error
// only, no decision return); approval comes back asynchronously via
// PolicyControl.Grant.
type AskUserSeam interface {
	Notify(ctx context.Context, req AskUserRequest) error
}

// SuspendSignal is the one-way boundary -> orchestrator suspend notification.
type SuspendSignal struct {
	Session SessionRef
	Reason  SuspendReason
	At      time.Time
}

// OrchestratorFake is the programmable in-memory orchestrator stand-in
// (doc 06 §2): records AskUserRequests and SuspendSignals, and drives
// approvals back as policy grants.
type OrchestratorFake interface {
	AskUserRequests(ctx context.Context) ([]AskUserRequest, error)
	Approve(ctx context.Context, req AskUserRequest, ttl time.Duration) (PolicyVersion, error)
	SuspendSignals(ctx context.Context) ([]SuspendSignal, error)
}

// IdentitySeam mints and validates short-lived creds against session
// identity (Stage-0 D22 seam, TLS-5). Validate returns ErrIdentityMismatch
// for a cred presented under a session it was not minted for, and
// ErrCredentialExpired for a cred past its validity (both errors.Is-able,
// S0-6).
type IdentitySeam interface {
	// MintCredential issues a short-lived cred bound to s's identity, valid
	// for validFor from the active Clock, returning the cred and the
	// identity it is bound to.
	MintCredential(ctx context.Context, s SessionRef, validFor time.Duration) (Secret, IdentityRef, error)
	Validate(ctx context.Context, s SessionRef, presented Secret) (IdentityRef, error)
}

// CAMintSeam mints the per-session interception CA and on-the-fly leaves
// (Stage-0 D17 seam, TLS-3).
type CAMintSeam interface {
	MintSessionCA(ctx context.Context, s SessionRef) (CARef, error)
	LeafFor(ctx context.Context, ca CARef, origin string) (CertRef, error)
}

// ---------------------------------------------------------------------------
// Test-rig control seams (doc 06 §2 fakes of the world outside the boundary).
// The harness uses these to program upstream truth and inject host faults —
// they stand in for "the internet", the secret store, and a misbehaving host.
// ---------------------------------------------------------------------------

// UpstreamDNSControl programs what the boundary's upstream resolution path
// returns for a name — rebinding/rotation/HTTPS-record scenarios (DNS-4).
type UpstreamDNSControl interface {
	SetAnswers(ctx context.Context, name string, recs []DNSRecord) error
}

// UpstreamHTTPControl programs upstream HTTP(S) origin responses — seeded
// inbound tokens (TLS-7), streaming bodies (DV-3) — and records every
// request that actually reached an upstream origin, so C9-1 can assert
// "nothing reaches upstream" (a denied request must never be forwarded).
type UpstreamHTTPControl interface {
	SetResponse(ctx context.Context, host, path string, status int, headers map[string]string, body []byte) error
	// Requests returns every request the named upstream origin received —
	// the hit-recorder read-side (zero hits == nothing reached upstream).
	Requests(ctx context.Context, host string) ([]HTTPRequest, error)
}

// SecretStoreControl seeds the real long-lived credential into the secret
// store OUTSIDE the boundary (D8) so tests know the canary needle.
type SecretStoreControl interface {
	SeedCredential(ctx context.Context, service string, value Secret) error
}

// FaultInjector mutates the host underneath the boundary — the LOG-4
// "deliberately mis-ruled host" lever (C9-23).
type FaultInjector interface {
	// BypassRedirect punches a hole letting the session's flows skip the
	// proxy redirect; undo restores the ruleset.
	BypassRedirect(ctx context.Context, s SessionRef) (undo func() error, err error)
}

// ---------------------------------------------------------------------------
// Contract harness (doc 06 §2): one conformance suite, real AND fake.
// ---------------------------------------------------------------------------

// BoundaryFactory builds a Boundary under test plus its cleanup.
type BoundaryFactory func(t testing.TB) (Boundary, func())

// NewRealBoundary returns the real data-plane-backed Boundary. Stub today:
// non-nil facade whose methods return ErrNotImplemented (RED).
func NewRealBoundary(t testing.TB) (Boundary, func()) {
	return &stubBoundary{}, func() {}
}

// NewFakeBoundary returns the generated in-memory fake published for
// neighbor workstreams (doc 05 OQ3). Stub today, same as the real (RED).
func NewFakeBoundary(t testing.TB) (Boundary, func()) {
	return &stubBoundary{}, func() {}
}

// NewAskUserSeam returns the Stage-0 ask-user seam endpoint (stub).
func NewAskUserSeam() AskUserSeam { return &stubAskUser{} }

// NewIdentitySeam returns the REAL D22 identity-validation seam (stub).
func NewIdentitySeam() IdentitySeam { return &stubIdentity{} }

// NewFakeIdentitySeam returns the published in-memory FAKE of the D22 seam
// (doc 06 §2 contract-twice: real and fake must agree, S0-6). Stub today —
// distinct from NewIdentitySeam so real-vs-fake divergence is catchable.
func NewFakeIdentitySeam() IdentitySeam { return &stubFakeIdentity{} }

// NewCAMintSeam returns the REAL D17 CA-mint seam (stub).
func NewCAMintSeam() CAMintSeam { return &stubCAMint{} }

// NewFakeCAMintSeam returns the published in-memory FAKE of the D17 seam
// (doc 06 §2 contract-twice: real and fake must agree, S0-7). Stub today —
// distinct from NewCAMintSeam so real-vs-fake divergence is catchable.
func NewFakeCAMintSeam() CAMintSeam { return &stubFakeCAMint{} }

// NewUpstreamDNSControl returns the rig's upstream-DNS programmer (stub).
func NewUpstreamDNSControl(t testing.TB) UpstreamDNSControl { return &stubUpstreamDNS{} }

// NewUpstreamHTTPControl returns the rig's upstream-origin programmer (stub).
func NewUpstreamHTTPControl(t testing.TB) UpstreamHTTPControl { return &stubUpstreamHTTP{} }

// NewSecretStoreControl returns the rig's secret-store seeder (stub).
func NewSecretStoreControl(t testing.TB) SecretStoreControl { return &stubSecretStore{} }

// NewFaultInjector returns the rig's host fault lever (stub).
func NewFaultInjector(t testing.TB) FaultInjector { return &stubFault{} }

// BufGate runs `buf lint` + `buf breaking` against the shared proto/ package
// holding the Stage-0 frozen schema (LOG-1 messages, policy snapshot, the
// seams). It is the Stage-0 freeze gate (S0-5). Stub returns ErrNotImplemented
// until the proto package and buf pipeline exist — so the test is RED.
//
// planRef: doc 09 LOG-1 Done-when; §8 Stage 0.
func BufGate(ctx context.Context) error { return ErrNotImplemented }

// secretScanHook is the TLS-7 detection hook seam.
var secretScanHook func(SecretScanEvent)

// SetSecretScanHook installs the hook the TLS-7 gate must fire on an
// inbound long-lived-token detection (C9-27). The real data plane calls it.
func SetSecretScanHook(h func(SecretScanEvent)) { secretScanHook = h }

// RunBoundaryContract is the shared conformance body executed against BOTH
// the real implementation and the generated fake (S0-1). Divergence means
// either the fake lies or the impl drifted. RED until either side is real.
//
// planRef: doc 06 §2 contract-twice; doc 09 §8 Stage 0.
func RunBoundaryContract(t *testing.T, mk BoundaryFactory) {
	t.Helper()
	ctx := context.Background()
	b, done := mk(t)
	defer done()
	if b == nil {
		t.Fatal("contract: factory returned nil Boundary")
	}

	t.Run("CreateSession_yields_iface_keyed_session", func(t *testing.T) {
		sess, err := b.CreateSession(ctx, CreateSessionRequest{Posture: PostureStandard, Identity: IdentityRef{ID: "contract-id"}})
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if sess.Ref.ID == "" {
			t.Fatal("contract: Session.Ref.ID empty")
		}
		if want := IfacePrefix + sess.Ref.ID; sess.Ref.Iface != want {
			t.Fatalf("contract: Iface = %q, want %q (NFT-2 convention)", sess.Ref.Iface, want)
		}
		if sess.ShortLivedCred == "" {
			t.Fatal("contract: ShortLivedCred empty")
		}
		if sess.InterceptCA.ID == "" {
			t.Fatal("contract: InterceptCA unminted (D17)")
		}

		t.Run("baseline_resolves_via_dnsgate", func(t *testing.T) {
			resp, err := b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: "api.anthropic.com", Type: DNSTypeA})
			if err != nil {
				t.Fatalf("ResolveDNS: %v", err)
			}
			if resp.Rcode != RcodeNoError || len(resp.Answers) == 0 {
				t.Fatalf("baseline resolve: rcode=%s answers=%d, want NOERROR with answers", resp.Rcode, len(resp.Answers))
			}
			if resp.ServedBy != ServedByDNSGate {
				t.Fatalf("ServedBy = %q, want %q", resp.ServedBy, ServedByDNSGate)
			}
		})

		t.Run("non_allowlisted_dial_dropped", func(t *testing.T) {
			res, err := b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.MustParseAddrPort("203.0.113.66:443")})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("dial outcome = %q, want Dropped (default-deny)", res.Outcome)
			}
		})

		t.Run("decisions_carry_provenance", func(t *testing.T) {
			ev, err := b.Inspect().Events(ctx, sess.Ref)
			if err != nil {
				t.Fatalf("Events: %v", err)
			}
			if len(ev.Decisions) == 0 {
				t.Fatal("contract: no PolicyDecision events recorded")
			}
			for i, d := range ev.Decisions {
				if d.Rule.RuleID == "" || d.Rule.Layer == "" || d.Rule.PolicyVersion == "" {
					t.Fatalf("decision[%d] missing POL-3 provenance: %+v", i, d.Rule)
				}
			}
		})

		t.Run("destroy_clean", func(t *testing.T) {
			if err := b.DestroySession(ctx, sess.Ref); err != nil {
				t.Fatalf("DestroySession: %v", err)
			}
			entries, err := b.Inspect().AdmissionMap(ctx, sess.Ref)
			if err != nil {
				t.Fatalf("AdmissionMap after destroy: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("admission map not flushed at teardown: %d entries", len(entries))
			}
		})
	})
}

// ---------------------------------------------------------------------------
// Stubs — every method returns ErrNotImplemented / zero values.
// ---------------------------------------------------------------------------

type stubBoundary struct{}

func (s *stubBoundary) CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error) {
	return Session{}, ErrNotImplemented
}
func (s *stubBoundary) Attach(ctx context.Context, ref SessionRef) (AttachResult, error) {
	return AttachResult{}, ErrNotImplemented
}
func (s *stubBoundary) Snapshot(ctx context.Context, ref SessionRef) (SnapshotRef, error) {
	return SnapshotRef{}, ErrNotImplemented
}
func (s *stubBoundary) Suspend(ctx context.Context, ref SessionRef, reason SuspendReason) error {
	return ErrNotImplemented
}
func (s *stubBoundary) Resume(ctx context.Context, ref SessionRef) error { return ErrNotImplemented }
func (s *stubBoundary) DestroySession(ctx context.Context, ref SessionRef) error {
	return ErrNotImplemented
}
func (s *stubBoundary) VM(ref SessionRef) VMProbe      { return &stubProbe{} }
func (s *stubBoundary) Inspect() HostInspector         { return &stubInspector{} }
func (s *stubBoundary) Policy() PolicyControl          { return &stubPolicy{} }
func (s *stubBoundary) Orchestrator() OrchestratorFake { return &stubOrchestrator{} }

type stubProbe struct{}

func (p *stubProbe) ResolveDNS(ctx context.Context, q DNSQuery) (DNSResponse, error) {
	return DNSResponse{}, ErrNotImplemented
}
func (p *stubProbe) Dial(ctx context.Context, req DialRequest) (DialResult, error) {
	return DialResult{}, ErrNotImplemented
}
func (p *stubProbe) TLSConnect(ctx context.Context, req TLSConnectRequest) (TLSConnResult, error) {
	return TLSConnResult{}, ErrNotImplemented
}
func (p *stubProbe) HTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	return HTTPResponse{}, ErrNotImplemented
}
func (p *stubProbe) ScanInterior(ctx context.Context, req InteriorScanRequest) (InteriorScan, error) {
	return InteriorScan{}, ErrNotImplemented
}
func (p *stubProbe) ProbeL2(ctx context.Context, req L2ProbeRequest) (L2ProbeResult, error) {
	return L2ProbeResult{}, ErrNotImplemented
}
func (p *stubProbe) InstallTrustedCA(ctx context.Context, ca CARef) error {
	return ErrNotImplemented
}

type stubInspector struct{}

func (i *stubInspector) NFTRuleset(ctx context.Context) (RulesetSnapshot, error) {
	return RulesetSnapshot{}, ErrNotImplemented
}
func (i *stubInspector) AllowSet(ctx context.Context, s SessionRef, fam IPFamily) ([]AllowSetEntry, error) {
	return nil, ErrNotImplemented
}
func (i *stubInspector) AdmissionMap(ctx context.Context, s SessionRef) ([]AdmissionEntry, error) {
	return nil, ErrNotImplemented
}
func (i *stubInspector) AdmissionTrace(ctx context.Context, s SessionRef) ([]AdmissionTraceEvent, error) {
	return nil, ErrNotImplemented
}
func (i *stubInspector) Events(ctx context.Context, s SessionRef) (EventBundle, error) {
	return EventBundle{}, ErrNotImplemented
}
func (i *stubInspector) Reconcile(ctx context.Context) (ReconcileReport, error) {
	return ReconcileReport{}, ErrNotImplemented
}

type stubPolicy struct{}

func (p *stubPolicy) Load(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error) {
	return "", ErrNotImplemented
}
func (p *stubPolicy) Push(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error) {
	return "", ErrNotImplemented
}
func (p *stubPolicy) Grant(ctx context.Context, g AllowGrant) (PolicyVersion, error) {
	return "", ErrNotImplemented
}
func (p *stubPolicy) Active(ctx context.Context) (PolicyVersion, error) {
	return "", ErrNotImplemented
}

type stubOrchestrator struct{}

func (o *stubOrchestrator) AskUserRequests(ctx context.Context) ([]AskUserRequest, error) {
	return nil, ErrNotImplemented
}
func (o *stubOrchestrator) Approve(ctx context.Context, req AskUserRequest, ttl time.Duration) (PolicyVersion, error) {
	return "", ErrNotImplemented
}
func (o *stubOrchestrator) SuspendSignals(ctx context.Context) ([]SuspendSignal, error) {
	return nil, ErrNotImplemented
}

type stubAskUser struct{}

func (a *stubAskUser) Notify(ctx context.Context, req AskUserRequest) error {
	return ErrNotImplemented
}

type stubIdentity struct{}

func (s *stubIdentity) MintCredential(ctx context.Context, ref SessionRef, validFor time.Duration) (Secret, IdentityRef, error) {
	return "", IdentityRef{}, ErrNotImplemented
}
func (s *stubIdentity) Validate(ctx context.Context, ref SessionRef, presented Secret) (IdentityRef, error) {
	return IdentityRef{}, ErrNotImplemented
}

// stubFakeIdentity is the placeholder for the published in-memory fake of
// the D22 seam (S0-6 contract-twice). Distinct type so the fake leg fails
// independently of the real one.
type stubFakeIdentity struct{ stubIdentity }

type stubCAMint struct{}

func (s *stubCAMint) MintSessionCA(ctx context.Context, ref SessionRef) (CARef, error) {
	return CARef{}, ErrNotImplemented
}
func (s *stubCAMint) LeafFor(ctx context.Context, ca CARef, origin string) (CertRef, error) {
	return CertRef{}, ErrNotImplemented
}

// stubFakeCAMint is the placeholder for the published in-memory fake of the
// D17 seam (S0-7 contract-twice). Distinct type so the fake leg fails
// independently of the real one.
type stubFakeCAMint struct{ stubCAMint }

type stubUpstreamDNS struct{}

func (u *stubUpstreamDNS) SetAnswers(ctx context.Context, name string, recs []DNSRecord) error {
	return ErrNotImplemented
}

type stubUpstreamHTTP struct{}

func (u *stubUpstreamHTTP) SetResponse(ctx context.Context, host, path string, status int, headers map[string]string, body []byte) error {
	return ErrNotImplemented
}
func (u *stubUpstreamHTTP) Requests(ctx context.Context, host string) ([]HTTPRequest, error) {
	return nil, ErrNotImplemented
}

type stubSecretStore struct{}

func (s *stubSecretStore) SeedCredential(ctx context.Context, service string, value Secret) error {
	return ErrNotImplemented
}

type stubFault struct{}

func (f *stubFault) BypassRedirect(ctx context.Context, s SessionRef) (func() error, error) {
	return func() error { return nil }, ErrNotImplemented
}
