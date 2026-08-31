// Package policycore is the contract surface for the Dream Serpent boundary's
// single policy decision engine plus the shipped D64 default baseline pack.
//
// planRef: doc 09 §6 (POL-1..POL-5). One engine, embedded everywhere decisions
// happen, so ds-dnsgate, ds-tlsproxy, and the nftables programming path can
// never disagree about a rule. This file defines only the seams ("the
// functions we will need"); every stub returns ErrNotImplemented (or zero
// values for pure functions without an error result) so the whole test suite
// stays RED until the real data plane satisfies it.
package policycore

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrNotImplemented is returned by every stub so the entire suite is RED
// until the real evaluator (and later the Rust data plane via a conformance
// shim) satisfies the spec. Tests treat ErrNotImplemented as failure — they
// never assert it and never skip on it.
var ErrNotImplemented = errors.New("policycore: not implemented")

// Posture is the policy posture: the default verdict for unlisted resources.
// planRef: doc 09 §6 POL-1.
type Posture string

const (
	PostureLocked   Posture = "locked"
	PostureStandard Posture = "standard"
	PostureOpen     Posture = "open"
)

// Layer is the composition layer a policy (and a decision's provenance)
// belongs to. planRef: doc 09 §6 POL-1 (system → org → session layering).
type Layer string

const (
	LayerSystem  Layer = "system"
	LayerOrg     Layer = "org"
	LayerSession Layer = "session"
)

// SchemaV0 is the only schema version this contract understands. An absent or
// future-versioned document is refused, never guessed at (POL-1.c).
const SchemaV0 = "v0"

// BaselinePackName is the name of the shipped D64 default policy pack.
// planRef: doc 09 §6 POL-2 (D64).
const BaselinePackName = "d30-baseline"

// AskDefaults captures the ask-user posture defaults: what verdict an
// unlisted resource gets under PostureStandard and the default TTL applied to
// approval grants returned on the policy stream (POL-5).
type AskDefaults struct {
	UnlistedDomain Action        // verdict for unlisted domains under PostureStandard (e.g. ActionAsk)
	GrantTTL       time.Duration // default TTL for ask-user approval grants
}

// AllowRule admits a domain (with optional service-endpoint expansion). Scope
// discriminates who may use the entry: the agent VM (ScopeVM / zero value
// semantics are deny-on-zero, see POL-2.c) or ds-dnsgate's own upstream
// egress (ScopeGateUpstream) — the baseline resolver entries are
// gate-upstream only, never direct VM resolver access.
type AllowRule struct {
	ID      string
	Domain  string
	Service string
	Scope   RequestScope
}

// BlockRule denies a domain. Blocklists always win — at any layer, over any
// allow, posture, or grant (deny-overrides, POL-1).
type BlockRule struct {
	ID     string
	Domain string
}

// RateLimitRule is a per-session / per-service behavioral cap (POL-1, TLS-6).
type RateLimitRule struct {
	ID         string
	Service    string
	PerSession int
	PerService int
	Window     time.Duration
}

// GrantScope scopes an escape hatch (or grant) to a session, host, and/or
// org. Empty means unscoped at that level; a fully empty scope is
// conservatively denied until doc 03 OQ7 resolves (POL-5.c).
type GrantScope struct {
	Session string
	Host    string
	Org     string
}

// EscapeHatchRule is an explicit per-protocol/port direct L3/4 allowance
// (the binary-protocol whitelist, doc 03 §3 / POL-5).
type EscapeHatchRule struct {
	ID       string
	Protocol string
	Port     uint16
	Scope    GrantScope
}

// SwapServiceRule is a credential-swap service registry entry (D8, TLS-5):
// service -> hosts -> credential location.
type SwapServiceRule struct {
	ID                 string
	Service            string
	Hosts              []string
	CredentialLocation string
}

// Policy is the YAML schema v0 (POL-1) as Go types: the shape under
// parse/validate/round-trip tests. It lives in the shared contract package
// and versions like every other seam (doc 06 §2).
type Policy struct {
	SchemaVersion string // e.g. "v0"
	Name          string // pack name, e.g. "d30-baseline"
	PackVersion   string // versioned per doc 06 §2
	Posture       Posture
	Allow         []AllowRule       // domains, optional service-endpoint expansion
	Block         []BlockRule       // always win
	RateLimits    []RateLimitRule   // per-session / per-service caps (behavioral caps)
	EscapeHatches []EscapeHatchRule // per-protocol/port direct L3/4 allowances + scope
	PassThrough   []string          // cert-pinned domains: opaque tunnel, no swap
	CredSwap      []SwapServiceRule // service registry: service -> hosts -> credential location
	AskDefaults   AskDefaults       // ask-user posture defaults
}

// Parse parses and structurally checks a schema-v0 YAML policy document.
// Unknown SchemaVersions, unknown fields, and malformed sections are
// rejected with an error naming the offending field — no partial Policy is
// ever returned. planRef: doc 09 §6 POL-1.
func Parse(yamlDoc []byte) (*Policy, error) { return nil, ErrNotImplemented }

// Validate enforces the posture enum, well-formed domains, non-negative
// limits, a known SchemaVersion, and rule-ID uniqueness.
func (p *Policy) Validate() error { return ErrNotImplemented }

// MarshalYAML serializes the policy so that Parse(MarshalYAML(p)) is
// deeply equal to p (round-trip stability, POL-1.a).
func (p *Policy) MarshalYAML() ([]byte, error) { return nil, ErrNotImplemented }

// LayeredPolicy tags a policy with the composition layer it occupies.
type LayeredPolicy struct {
	Layer  Layer
	Policy *Policy
}

// Snapshot is the atomic, versioned, immutable unit of fleet push and hot
// reload (POL-4). Readers always see exactly one snapshot, never a blend.
type Snapshot struct {
	PolicyVersion string // composed-policy version cited in provenance
	Seq           uint64 // monotonic sequence number for catch-up / replay rejection
	// opaque compiled rule state; immutable after Compose/ApplyGrant
}

// Compose flattens system -> org -> session with DENY-OVERRIDES precedence:
// any Block at any layer beats any Allow at any layer. planRef: doc 09 §6
// POL-1. Precedence semantics (including the D64 DoH/DoT baseline blocklist
// always winning) are proven here, not re-implemented per service.
func Compose(layers ...LayeredPolicy) (*Snapshot, error) { return nil, ErrNotImplemented }

// RequestKind is the caller shape asking for a decision: every caller (DNS
// gate, TLS proxy SNI check, HTTP rules, nftables escape-hatch programming)
// is a Request into the one engine.
type RequestKind string

const (
	KindDNSResolve  RequestKind = "dns-resolve"
	KindTLSSNI      RequestKind = "tls-sni"
	KindHTTPRequest RequestKind = "http-request"
	KindL4Direct    RequestKind = "l4-direct"
)

// RequestScope discriminates traffic origin: the agent VM versus
// ds-dnsgate's own upstream egress. The zero value is never defaulted to the
// permissive scope (POL-2.c).
type RequestScope string

const (
	ScopeVM           RequestScope = "vm"            // traffic from an agent VM
	ScopeGateUpstream RequestScope = "gate-upstream" // ds-dnsgate's own upstream egress
)

// Action is the decision verdict.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAsk   Action = "ask"
)

// SessionRef identifies the requesting session and its host/org placement.
type SessionRef struct {
	Session string
	Host    string
	Org     string
}

// Request is the ONE-ENGINE input contract.
type Request struct {
	Session  SessionRef
	Kind     RequestKind
	Scope    RequestScope
	Domain   string
	DstIP    netip.Addr
	DstPort  uint16
	Protocol string // "tcp", "udp", or escape-hatch protocol name

	// KindHTTPRequest only.
	HTTPMethod string
	HTTPPath   string
}

// Provenance is mandatory on every decision: "why was this blocked?" must
// always have a one-line answer (POL-3).
type Provenance struct {
	RuleID        string
	Layer         Layer
	PolicyVersion string
}

// Decision is the ONE-ENGINE output contract.
type Decision struct {
	Action      Action
	Provenance  Provenance // MANDATORY on every decision incl. default-deny
	SwapService string     // non-empty => credential swap applies
	PassThrough bool       // opaque tunnel, never combined with SwapService
	DirectL4    bool       // escape-hatch verdict: direct flow gated by allow-set
}

// Evaluator is policy-core itself (POL-3). Evaluate is a pure function of
// (snapshot, request, now): no hidden state, no I/O, deterministic, safe for
// concurrent use. `now` makes TTL'd grants testable without wall-clock sleep.
type Evaluator interface {
	Evaluate(snap *Snapshot, req Request, now time.Time) (Decision, error)
}

type stubEvaluator struct{}

func (stubEvaluator) Evaluate(*Snapshot, Request, time.Time) (Decision, error) {
	return Decision{}, ErrNotImplemented
}

// NewEvaluator returns the (stub) evaluator. The stub returns
// ErrNotImplemented for every call so all decision tests run RED.
func NewEvaluator() Evaluator { return stubEvaluator{} }

// DefaultBaseline returns the shipped, versioned D64 (amended by D74) policy
// pack as ordinary policy data — removable, extensible, replaceable through
// the same engine.
// planRef: doc 09 §6 POL-2.
func DefaultBaseline() (*Policy, error) { return nil, ErrNotImplemented }

// ValidateProvenance rejects any provenance with a missing rule id, layer,
// or policy version. Wired as the CI gate: a missing-provenance event fails
// the build. planRef: doc 09 §6 POL-3.
func ValidateProvenance(p Provenance) error { return ErrNotImplemented }

// ValidateDecisionEvent rejects any decision event whose provenance is
// incomplete — the executable form of "a missing-provenance event fails CI".
func ValidateDecisionEvent(d Decision) error { return ErrNotImplemented }

// SnapshotSource is the control-plane policy stream (transport TBD, doc 03
// OQ4). Subscribe resumes from a sequence number for offline catch-up.
type SnapshotSource interface {
	Subscribe(ctx context.Context, fromSeq uint64) (<-chan *Snapshot, error)
}

// SnapshotConsumer is what each service (ds-dnsgate, ds-tlsproxy, the nft
// programmer) implements to receive atomic hot reloads.
type SnapshotConsumer interface {
	Reload(snap *Snapshot) error
	CurrentVersion() (version string, seq uint64)
}

// HostSubscriber: exactly ONE per host; fans one snapshot to all registered
// consumers atomically so the two services can never run different policy
// versions (POL-4, doc 03 OQ7). Stale or replayed snapshots (Seq <= current)
// are rejected, never applied.
type HostSubscriber interface {
	Register(c SnapshotConsumer)
	Run(ctx context.Context, src SnapshotSource) error
	Current() *Snapshot
}

type stubHostSubscriber struct{}

func (stubHostSubscriber) Register(SnapshotConsumer) {}
func (stubHostSubscriber) Run(context.Context, SnapshotSource) error {
	return ErrNotImplemented
}
func (stubHostSubscriber) Current() *Snapshot { return nil }

// NewHostSubscriber returns the (stub) per-host policy-stream subscriber.
func NewHostSubscriber() HostSubscriber { return stubHostSubscriber{} }

// AskUserRequest mirrors the Stage-0 contract: a one-way boundary ->
// orchestrator notification (session, resource kind, name, matched rule per
// POL-3). The boundary never grows its own approval UI.
type AskUserRequest struct {
	Session      SessionRef
	ResourceKind string // e.g. "domain", "protocol"
	Name         string
	MatchedRule  Provenance // per POL-3
}

// AskRouter routes Ask decisions over the frozen Stage-0 seam. Fire and
// forget: approvals return on the policy stream, never as a response here.
type AskRouter interface {
	RouteAsk(ctx context.Context, req AskUserRequest) error
}

// DispatchAsk is the production seam that converts an Ask Decision produced
// by Evaluate(req) into the Stage-0 AskUserRequest and routes it over the
// one-way seam: Session derives from req.Session, ResourceKind from the
// request shape (e.g. "domain" for name-shaped requests, "protocol" for
// L4-direct), Name from the asked-about resource (req.Domain / req.Protocol),
// and MatchedRule from d.Provenance (POL-3). Fire and forget — no response
// payload is consumed; approvals return only as grants on the policy stream.
// planRef: doc 09 §6 POL-5 Done-when + doc 09 §8 Stage 0.
func DispatchAsk(ctx context.Context, r AskRouter, req Request, d Decision) error {
	return ErrNotImplemented
}

// Grant is a session-scoped, TTL'd allow returned on the already-frozen
// policy stream after an ask-user approval. No second response contract.
// planRef: doc 09 §8 Stage 0 + §6 POL-5.
type Grant struct {
	Session   SessionRef
	Domain    string
	ExpiresAt time.Time
	Seq       uint64
}

// ApplyGrant produces a NEW snapshot (next Seq) containing the grant; the
// prior snapshot is unchanged (immutability). Deny-overrides applies to
// grants too: a grant can never punch through a blocklist (POL-5.f).
func ApplyGrant(snap *Snapshot, g Grant) (*Snapshot, error) { return nil, ErrNotImplemented }
