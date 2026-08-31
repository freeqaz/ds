// Package dnsgate is the executable specification (doc 04 D26) for the DNS
// gating proxy `ds-dnsgate` (doc 09 §4, steps DNS-1..DNS-5 incl. DNS-2b).
//
// This file defines ONLY the seams — the contract surface the real Rust data
// plane (hickory-dns responder + nftables programming path) must satisfy.
// Every constructor returns a non-nil stub whose methods return
// ErrNotImplemented; the pure functions return zero values. The tests in this
// package assert the documented outcomes and are therefore RED against these
// stubs by design (CONVENTIONS.md, "The RED rule").
package dnsgate

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrNotImplemented is the sentinel every stub returns so the whole suite
// fails RED until the real data plane (or a Go shim over it) satisfies the
// spec. Tests assert outcomes, never this error.
var ErrNotImplemented = errors.New("dnsgate: not implemented")

// ---------------------------------------------------------------------------
// Core domain types (black-box wire model). Session attribution is by source
// interface (never source IP), matching the NFT-2 `dstap-<session>` convention.
// ---------------------------------------------------------------------------

// SessionRef identifies a session by ID and by the source interface that
// attributes its traffic (doc 09 §3 NFT-2: iifname, never source IP).
type SessionRef struct {
	ID        string
	Interface string
}

// RRType is a DNS record type code.
type RRType uint16

// Record types the spec exercises. TypeNS and TypeSOA are included because
// the DNS-5.d poisoning-posture test plants NS/glue hints and the DNS-3.b
// negative-caching test asserts the Authority section carries no SOA.
const (
	TypeA     RRType = 1
	TypeNS    RRType = 2
	TypeCNAME RRType = 5
	TypeSOA   RRType = 6
	TypeAAAA  RRType = 28
	TypeSVCB  RRType = 64
	TypeHTTPS RRType = 65
)

// RCode is a DNS response code.
type RCode int

const (
	RCodeNoError  RCode = 0
	RCodeFormErr  RCode = 1
	RCodeServFail RCode = 2
	RCodeNXDomain RCode = 3
	RCodeRefused  RCode = 5
)

// Query is one structured DNS question from a VM.
type Query struct {
	Session SessionRef
	Name    string
	Type    RRType
	Proto   string // "udp" | "tcp"
}

// RR is one resource record. Data carries opaque rdata so tests can plant
// HTTPS/SVCB (type 65/64) payloads with ECH configs.
type RR struct {
	Name   string
	Type   RRType
	TTL    uint32
	Addr   netip.Addr
	Target string
	Data   []byte
}

// Answer is the structured response released to a VM.
type Answer struct {
	RCode       RCode
	Truncated   bool
	Answers     []RR
	Authority   []RR
	Additionals []RR
}

// ---------------------------------------------------------------------------
// Responder — the component under test.
// ---------------------------------------------------------------------------

// Responder is the full resolve→policy→scrub→admit→answer pipeline.
// ServeRaw is the DNS-5 hardening surface (malformed packets, TC-bit/TCP
// retry) where the structured Query model would hide the bug.
type Responder interface {
	Serve(ctx context.Context, q Query) (Answer, error)
	ServeRaw(ctx context.Context, sess SessionRef, proto string, packet []byte) ([]byte, error)
}

// ---------------------------------------------------------------------------
// PolicyEvaluator — policy-core seam (POL-1/POL-3).
// ---------------------------------------------------------------------------

// Verdict is the policy outcome for a domain.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictDeny
	VerdictAsk
)

// Decision carries the verdict plus POL-3 provenance: every decision names
// the matched rule, the policy layer, and the policy version.
type Decision struct {
	Verdict       Verdict
	RuleID        string
	PolicyLayer   string
	PolicyVersion string
}

// PolicyEvaluator is the policy-core seam. The test fake records which names
// were evaluated — load-bearing for proving CNAME intermediates are NEVER
// policy-evaluated (DNS-2.c).
type PolicyEvaluator interface {
	EvaluateDomain(ctx context.Context, sess SessionRef, domain string) (Decision, error)
}

// ---------------------------------------------------------------------------
// Upstream — upstream-resolver seam (host-egress path per D64).
// ---------------------------------------------------------------------------

// AddrRecord is one terminal address with its upstream TTL.
type AddrRecord struct {
	Addr netip.Addr
	TTL  uint32
}

// CNAMELink is one link of a CNAME chain followed internally by the resolver.
type CNAMELink struct {
	From, To string
	TTL      uint32
}

// ResolutionChain is the upstream's full answer for one query name: the CNAME
// links followed, the chain-terminal addresses, and any extra records the
// upstream piggybacked (glue, smuggled type-65, stray A records).
type ResolutionChain struct {
	QueryName string
	Links     []CNAMELink
	Terminal  []AddrRecord
	Extra     []RR
}

// Upstream resolves a name via the policy-configured resolvers only
// (1.1.1.1 / 8.8.8.8 per D64) over the host's protected egress (DNS-5).
// resolver is the upstream endpoint this resolution targets: the gate must
// only ever pass a member of Deps.Resolvers. The test fake records every
// (resolver, name) pair, making the DNS-5.d poisoning posture black-box
// verifiable — nothing VM-supplied (names, NS hints, glue) may redirect the
// upstream path off the configured resolvers.
type Upstream interface {
	Resolve(ctx context.Context, resolver netip.AddrPort, name string, qtype RRType) (ResolutionChain, error)
}

// ---------------------------------------------------------------------------
// AdmissionStore — allow-set + DNS-2b admission map, one transactional seam.
// ---------------------------------------------------------------------------

// AdmissionTx is one insert-then-answer admission transaction (DNS-2).
type AdmissionTx struct {
	Session SessionRef
	Domain  string // ORIGINAL query name — the SNI join key
	Addrs   []netip.Addr
	Timeout time.Duration // clamped chain-min TTL + grace (NFT-3)

	Decision Decision
}

// Admission is the DNS-2b map entry ds-tlsproxy reads synchronously.
type Admission struct {
	Domain    string
	Addrs     []netip.Addr
	ExpiresAt time.Time
}

// AdmissionStore models DNS-2 + DNS-2b as one transactional seam: Admit must
// complete before Serve releases the answer (insert-then-answer), and writes
// the per-session domain-keyed map the TLS proxy reads. ContainsAddr vs
// Lookup separates "IP alive in the set" from "admitted for this domain" —
// exactly the shared-CDN-IP distinction DNS-2b exists for.
type AdmissionStore interface {
	// Admit is one transaction: allow-set elements AND (domain→IPs,expiry)
	// map entry — both or neither.
	Admit(ctx context.Context, tx AdmissionTx) error
	// Lookup is ds-tlsproxy's synchronous read: admitted for THIS domain?
	Lookup(ctx context.Context, sess SessionRef, domain string, addr netip.Addr) (Admission, bool, error)
	// ContainsAddr is the bare allow-set view (what the kernel sees).
	ContainsAddr(ctx context.Context, sess SessionRef, addr netip.Addr) (bool, error)
	// FlushSession is NFT-6 teardown.
	FlushSession(ctx context.Context, sess SessionRef) error
}

// NewAdmissionStore returns the host-local per-session admission store
// (allow-set + DNS-2b map) the real data plane provides. The DNS-2b contract
// tests run against this surface (and later against the real store, per the
// doc 06 §2.5 run-twice rule). now is the injectable clock used for expiry
// so lockstep tests are deterministic.
func NewAdmissionStore(now func() time.Time) AdmissionStore {
	return &stubAdmissionStore{}
}

// ---------------------------------------------------------------------------
// AskUserNotifier — Stage-0 ask-user seam (doc 09 §8).
// ---------------------------------------------------------------------------

// AskUserRequest is the one-way boundary→orchestrator notification frozen at
// Stage 0. Approval comes back as a policy grant on the PolicyEvaluator seam,
// never as a response on this seam.
type AskUserRequest struct {
	Session       SessionRef
	ResourceKind  string
	Name          string
	RuleID        string
	PolicyLayer   string
	PolicyVersion string
}

// AskUserNotifier is the one-way notification seam.
type AskUserNotifier interface {
	Notify(ctx context.Context, req AskUserRequest) error
}

// ---------------------------------------------------------------------------
// EventSink — LOG-1 emission seam.
// ---------------------------------------------------------------------------

// DNSEvent is §7's "domain that admitted the flow" join key (LOG-2).
type DNSEvent struct {
	Session  SessionRef
	Domain   string
	Addrs    []netip.Addr
	TTL      uint32
	Decision Decision
	At       time.Time
}

// PolicyDecisionEvent carries POL-3 provenance for denials/asks.
type PolicyDecisionEvent struct {
	Session  SessionRef
	Domain   string
	Decision Decision
	RCode    RCode
	At       time.Time
}

// EventSink receives the gate's emitted events.
type EventSink interface {
	EmitDNS(ctx context.Context, ev DNSEvent) error
	EmitPolicyDecision(ctx context.Context, ev PolicyDecisionEvent) error
}

// ---------------------------------------------------------------------------
// ScrubAddr — DNS-4 rule 2 as a pure, exhaustively table-testable function.
// ---------------------------------------------------------------------------

// ScrubReason names why an address was scrubbed (audit trail).
type ScrubReason int

const (
	ReasonNone ScrubReason = iota
	ReasonPrivate4
	ReasonLinkLocal4
	ReasonLoopback4
	ReasonHostRange4
	ReasonLoopback6
	ReasonLinkLocal6
	ReasonULA6
	ReasonHostAddr6
	ReasonEmbedded4
)

// ScrubConfig carries the deployment-specific host/boundary ranges.
type ScrubConfig struct {
	HostRanges4 []netip.Prefix
	HostAddrs6  []netip.Addr
}

// ScrubAddr applies the DNS-4 rule-2 dual-stack sanity filter. Embedded-IPv4
// forms (::ffff:0:0/96 mapped, 64:ff9b::/96 NAT64) extract the inner IPv4 and
// re-apply the IPv4 rules, so ::ffff:10.0.0.5 is scrubbed by the same
// predicate as 10.0.0.5.
func ScrubAddr(addr netip.Addr, cfg ScrubConfig) (admit bool, reason ScrubReason) {
	return false, ReasonNone // stub
}

// ---------------------------------------------------------------------------
// ClampTTL / ChainMinTTL — DNS-1 clamp + DNS-2 chain-minimum, pure.
// ---------------------------------------------------------------------------

// TTLPolicy is the DNS-1 clamp (strawman 60s–15min); Grace is the NFT-3
// margin added to the allow-set element timeout so the kernel entry strictly
// outlives any TTL-honoring client cache.
type TTLPolicy struct {
	Floor, Ceiling, Grace time.Duration
}

// ClampTTL clamps an upstream TTL into [Floor, Ceiling].
func ClampTTL(upstreamTTL uint32, p TTLPolicy) uint32 {
	return 0 // stub
}

// ChainMinTTL returns the raw minimum TTL along the chain (links + terminal).
func ChainMinTTL(chain ResolutionChain) uint32 {
	return 0 // stub
}

// ---------------------------------------------------------------------------
// FilterRecords — record-type suppression, pure, applied to ALL sections.
// ---------------------------------------------------------------------------

// Posture is the record-type suppression posture: v0 AAAA strip (DNS-1/OQ10)
// and total HTTPS(65)/SVCB(64) suppression (DNS-4 rule 4).
type Posture struct {
	StripAAAA         bool
	SuppressHTTPSSVCB bool
}

// FilterRecords returns rrs with the posture's suppressed types removed.
func FilterRecords(rrs []RR, p Posture) []RR {
	return nil // stub
}

// ---------------------------------------------------------------------------
// PlanResponse — the pure admission core.
// ---------------------------------------------------------------------------

// PlannerConfig bundles the pure-core knobs.
type PlannerConfig struct {
	TTL     TTLPolicy
	Scrub   ScrubConfig
	Posture Posture
}

// ScrubbedAddr is one audit-trail entry: an address excluded from both the
// answer and the admission, with the reason. (Named type for the spec's
// `[]struct{ Addr; Reason }` so tests can build expectations ergonomically.)
type ScrubbedAddr struct {
	Addr   netip.Addr
	Reason ScrubReason
}

// Plan is the entire decide-scrub-clamp-admit-answer computation with zero
// I/O: what to admit, what to answer, what to emit. This makes
// "answered ⊆ admitted" (DNS-4 rule 1) and chain-keying provable as pure
// properties; Responder is then just orchestration of Plan over the seams.
type Plan struct {
	Answer        Answer
	Admission     *AdmissionTx // nil when nothing may be admitted
	Scrubbed      []ScrubbedAddr
	DNSEvent      *DNSEvent
	DecisionEvent *PolicyDecisionEvent
	AskUser       *AskUserRequest
}

// PlanResponse computes the full plan for one query given the policy decision
// and the resolved chain (nil chain for deny/ask paths, which never resolve).
func PlanResponse(q Query, dec Decision, chain *ResolutionChain, cfg PlannerConfig, now time.Time) (Plan, error) {
	return Plan{}, ErrNotImplemented // stub
}

// ---------------------------------------------------------------------------
// New — dependency-injection constructor (doc 06 §2 contract-test model).
// ---------------------------------------------------------------------------

// Deps wires every collaborator; each is a fake in tests. Now() makes
// expiry/lockstep tests deterministic.
type Deps struct {
	Policy   PolicyEvaluator
	Upstream Upstream
	// Resolvers are the policy-configured upstream resolver endpoints (the
	// D64 defaults, e.g. 1.1.1.1:53 / 8.8.8.8:53). Every Upstream.Resolve
	// call must target one of these — the DNS-5.d poisoning-posture contract.
	Resolvers  []netip.AddrPort
	Admissions AdmissionStore
	AskUser    AskUserNotifier
	Events     EventSink
	Config     PlannerConfig
	Now        func() time.Time
}

// New returns the DNS gating responder. The stub is non-nil and its methods
// return ErrNotImplemented so tests fail RED, never nil-panic.
func New(deps Deps) (Responder, error) {
	return &stubResponder{}, nil
}

// ---------------------------------------------------------------------------
// Stubs.
// ---------------------------------------------------------------------------

type stubResponder struct{}

func (*stubResponder) Serve(ctx context.Context, q Query) (Answer, error) {
	return Answer{}, ErrNotImplemented
}

func (*stubResponder) ServeRaw(ctx context.Context, sess SessionRef, proto string, packet []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

type stubAdmissionStore struct{}

func (*stubAdmissionStore) Admit(ctx context.Context, tx AdmissionTx) error {
	return ErrNotImplemented
}

func (*stubAdmissionStore) Lookup(ctx context.Context, sess SessionRef, domain string, addr netip.Addr) (Admission, bool, error) {
	return Admission{}, false, ErrNotImplemented
}

func (*stubAdmissionStore) ContainsAddr(ctx context.Context, sess SessionRef, addr netip.Addr) (bool, error) {
	return false, ErrNotImplemented
}

func (*stubAdmissionStore) FlushSession(ctx context.Context, sess SessionRef) error {
	return ErrNotImplemented
}
