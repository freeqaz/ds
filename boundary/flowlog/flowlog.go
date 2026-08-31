// Package flowlog is the executable-specification seam surface for
// ds-flowlog — the Boundary connection & netflow logging component
// (doc 09 §7, LOG-1..LOG-5; doc 04 D26 executable spec).
//
// This package contains ONLY contract seams plus RED stubs: every New…()
// constructor returns a non-nil stub whose methods return ErrNotImplemented
// (or zero values). The production Rust/nftables data plane satisfies this
// contract through its conformance adapter; the tests in this package assert
// the documented outcomes and therefore stay RED until it does.
package flowlog

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

// ErrNotImplemented is returned by every stub so the whole suite starts RED.
// Tests must never assert this error; they assert the documented outcome.
var ErrNotImplemented = errors.New("flowlog: not implemented")

// ErrUnattributed is returned when a flow's attribution keys (ct mark +
// iifname) do not resolve to exactly one registered session (LOG-2).
// An unattributable flow is surfaced, never guessed; it feeds the LOG-4
// reconciler.
var ErrUnattributed = errors.New("flowlog: flow not attributable to any session")

// ErrNoAdmission is returned by AdmissionIndex.AdmittingDomain when no DNS-2
// admission for (session, dst) is valid at the queried instant (LOG-2). Flows
// without an admitting domain are flagged for reconciliation, never silently
// joined.
var ErrNoAdmission = errors.New("flowlog: no admitting domain valid for destination")

// ErrUnroutableTier is returned by Router.Route when no sink is routable for
// the hosting tier (LOG-3 / D19). An unroutable event errors — it never falls
// through to the vendor sink.
var ErrUnroutableTier = errors.New("flowlog: no sink routable for hosting tier")

// ErrEmptySecret is returned by FingerprintCredential for empty input (LOG-5).
var ErrEmptySecret = errors.New("flowlog: empty secret cannot be fingerprinted")

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

const (
	// FingerprintPrefix and FingerprintHexLen define the ONLY valid
	// CredentialFingerprint shape: "sha256:" + 64 lowercase hex digits
	// (LOG-1.e, LOG-5.c). Anything else fails Validate — a raw credential
	// cannot be smuggled into the fingerprint field.
	FingerprintPrefix = "sha256:"
	FingerprintHexLen = 64
)

// DefaultByteToleranceBytes is the LOG-4 byte-accounting tolerance: a kernel
// flow whose byte count exceeds its matching proxy accounting by more than
// this raises AlarmByteMismatch (planRef: doc 09 §7 LOG-4).
const DefaultByteToleranceBytes uint64 = 1 << 20 // 1 MiB

// IngestP99Budget is the Collector ingest latency budget for the Stage-5 load
// rig (strawman 5ms, tunable at the rig — planRef: doc 09 §7 LOG-3, §8 Stage 5).
const IngestP99Budget = 5 * time.Millisecond

// StoryQueryLatencyBudget bounds "queryable off-box minutes after it happened"
// (doc 09 §7 LOG-3 Done-when) at harness scale.
const StoryQueryLatencyBudget = 2 * time.Second

// ---------------------------------------------------------------------------
// Shared identity + enums
// ---------------------------------------------------------------------------

// SessionRef is the shared session identity embedded in every event (LOG-1).
// Iface is the per-session attribution key from NFT-2 ("dstap-<session>");
// equality on SessionRef is what "attributed to the correct session" means in
// LOG-2.
type SessionRef struct {
	SessionID string
	HostID    string
	Iface     string
}

// Proto is the L4 protocol number of a flow.
type Proto uint8

const (
	ProtoICMP Proto = 1
	ProtoTCP  Proto = 6
	ProtoUDP  Proto = 17
)

// FlowVerdict is the kernel disposition of a flow.
type FlowVerdict string

const (
	FlowAccepted FlowVerdict = "accepted"
	FlowDropped  FlowVerdict = "dropped"
)

// Verdict is a policy decision outcome (POL-3 provenance rides alongside).
type Verdict string

const (
	VerdictAllow       Verdict = "allow"
	VerdictDeny        Verdict = "deny"
	VerdictAsk         Verdict = "ask"
	VerdictSwap        Verdict = "swap"
	VerdictPassthrough Verdict = "passthrough"
)

// Window is a half-open time interval [From, To).
type Window struct {
	From time.Time
	To   time.Time
}

// ---------------------------------------------------------------------------
// Event union (the five LOG-1 messages + the visible-loss marker)
// ---------------------------------------------------------------------------

// Event is the sealed union of the LOG-1 messages for the Stage-0 contract
// freeze. Validate() is the executable schema spec: SessionRef required,
// PolicyDecision provenance required (POL-3), CredentialUseEvent
// fingerprint-format required.
type Event interface {
	Ref() SessionRef
	Validate() error
	isEvent()
}

// FlowRecord is netflow-style metadata for one kernel-observed flow, including
// the DNS-2 admitting-domain join. It deliberately has NO payload-capable
// field — full packet capture is explicitly out (doc 03 §4) and a schema-shape
// test enforces it. Byte orientation: BytesOut is bytes egressing the session
// VM (conntrack originator), BytesIn is the reply direction.
type FlowRecord struct {
	Session         SessionRef
	Iface           string
	AdmittingDomain string
	Dst             netip.AddrPort
	Protocol        Proto
	BytesIn         uint64
	BytesOut        uint64
	Start           time.Time
	End             time.Time
	Duration        time.Duration
	CtMark          uint32
	Verdict         FlowVerdict
}

func (e FlowRecord) Ref() SessionRef { return e.Session }
func (FlowRecord) Validate() error   { return ErrNotImplemented }
func (FlowRecord) isEvent()          {}

// DnsEvent is emitted by ds-dnsgate at DNS-2 admission; it is the join key
// that lets ds-flowlog answer "which domain admitted this flow" (LOG-2).
type DnsEvent struct {
	Session     SessionRef
	QueryName   string
	AdmittedIPs []netip.Addr
	TTL         time.Duration
	ExpiresAt   time.Time
	Decision    PolicyDecision
}

func (e DnsEvent) Ref() SessionRef { return e.Session }
func (DnsEvent) Validate() error   { return ErrNotImplemented }
func (DnsEvent) isEvent()          {}

// HttpEvent is metadata-only HTTP telemetry from ds-tlsproxy. No header-value
// or body field exists in the type, so credential values structurally cannot
// ride along (LOG-5).
type HttpEvent struct {
	Session   SessionRef
	Method    string
	Host      string
	Path      string
	Status    int
	ReqBytes  uint64
	RespBytes uint64
	Start     time.Time
	Duration  time.Duration
	Decision  PolicyDecision
}

func (e HttpEvent) Ref() SessionRef { return e.Session }
func (HttpEvent) Validate() error   { return ErrNotImplemented }
func (HttpEvent) isEvent()          {}

// PolicyDecision carries decision + rule provenance per POL-3. Validate()
// fails on missing RuleID/PolicyLayer/PolicyVersion so a missing-provenance
// event fails CI (LOG-1.d).
type PolicyDecision struct {
	Session       SessionRef
	Verdict       Verdict
	RuleID        string
	PolicyLayer   string
	PolicyVersion string
	Resource      string
	At            time.Time
}

func (e PolicyDecision) Ref() SessionRef { return e.Session }
func (PolicyDecision) Validate() error   { return ErrNotImplemented }
func (PolicyDecision) isEvent()          {}

// CredentialFingerprint is a stable, non-reversible digest of a credential
// value in the fixed FingerprintPrefix+hex format. It joins uses of the same
// credential across events without revealing it (LOG-5).
type CredentialFingerprint string

// HttpRequestMeta is the request metadata attached to a credential use.
type HttpRequestMeta struct {
	Method string
	Host   string
	Path   string
	At     time.Time
}

// CredentialUseEvent is the LOG-5 audit record: which session used which
// credential, when, for what request — carrying only the fingerprint, never
// the value.
type CredentialUseEvent struct {
	Session     SessionRef
	Service     string
	Fingerprint CredentialFingerprint
	Request     HttpRequestMeta
}

func (e CredentialUseEvent) Ref() SessionRef { return e.Session }
func (CredentialUseEvent) Validate() error   { return ErrNotImplemented }
func (CredentialUseEvent) isEvent()          {}

// SpoolOverflow is the visible-loss marker (LOG-3): when the disk bound forces
// drop-oldest shedding, a marker carrying the dropped count is emitted into
// the surviving stream so loss is announced, never silent.
type SpoolOverflow struct {
	Session SessionRef
	Dropped int
	At      time.Time
}

func (e SpoolOverflow) Ref() SessionRef { return e.Session }
func (SpoolOverflow) Validate() error   { return ErrNotImplemented }
func (SpoolOverflow) isEvent()          {}

// MarshalEvent encodes an event in the frozen protobuf-shaped wire contract
// (LOG-1, Stage-0 freeze). Round-trips must be byte-for-byte stable.
func MarshalEvent(ev Event) ([]byte, error) { return nil, ErrNotImplemented }

// UnmarshalEvent decodes a wire-encoded event.
func UnmarshalEvent(data []byte) (Event, error) { return nil, ErrNotImplemented }

// FingerprintCredential is the single sanctioned path from secret to event
// (LOG-5): stable (joinable across sessions/time), fixed-format
// (FingerprintPrefix + FingerprintHexLen lowercase hex), non-reversible, and
// rejecting empty secrets with ErrEmptySecret.
func FingerprintCredential(secret []byte) (CredentialFingerprint, error) {
	return "", ErrNotImplemented
}

// ---------------------------------------------------------------------------
// Kernel inputs (NFT-5 conntrack accounting, nflog drops)
// ---------------------------------------------------------------------------

// ConntrackFlow models what NFT-5 conntrack accounting delivers. Src is
// present but must never be an attribution input — addresses are forgeable;
// the attachment point (Iif) and ct mark are not. BytesOrig is the originator
// (VM egress) direction; BytesReply is the reply direction.
type ConntrackFlow struct {
	CtMark     uint32
	Iif        string
	Src        netip.AddrPort
	Dst        netip.AddrPort
	Protocol   Proto
	BytesOrig  uint64
	BytesReply uint64
	Packets    uint64
	Start      time.Time
	End        time.Time
}

// NflogDrop models an nflog-delivered denied dial.
type NflogDrop struct {
	Iif      string
	CtMark   uint32
	Src      netip.AddrPort
	Dst      netip.AddrPort
	Protocol Proto
	At       time.Time
}

// ---------------------------------------------------------------------------
// Attribution seams (LOG-2)
// ---------------------------------------------------------------------------

// SessionRegistry binds the kernel-side attribution keys (ct mark from NFT-5,
// iifname from NFT-2) to a SessionRef at session create, and marks them
// retired at teardown so post-destroy traffic is suspicious, not
// stale-attributed.
type SessionRegistry interface {
	RegisterSession(ctx context.Context, ref SessionRef, ctMark uint32, iface string) error
	RetireSession(ctx context.Context, ref SessionRef, at time.Time) error
}

// NewSessionRegistry returns the RED stub of the attribution-key registry.
func NewSessionRegistry() SessionRegistry { return stubRegistry{} }

type stubRegistry struct{}

func (stubRegistry) RegisterSession(context.Context, SessionRef, uint32, string) error {
	return ErrNotImplemented
}
func (stubRegistry) RetireSession(context.Context, SessionRef, time.Time) error {
	return ErrNotImplemented
}

// AdmissionIndex is the per-session, time-windowed (domain, IPs, expiry) index
// built from the DNS-2 event stream; it answers the admitting-domain join
// honoring admission validity at flow start (LOG-2).
type AdmissionIndex interface {
	ObserveDns(ctx context.Context, ev DnsEvent) error
	AdmittingDomain(ctx context.Context, ref SessionRef, dst netip.Addr, at time.Time) (string, error)
}

// NewAdmissionIndex returns the RED stub of the admission index.
func NewAdmissionIndex() AdmissionIndex { return stubAdmissionIndex{} }

type stubAdmissionIndex struct{}

func (stubAdmissionIndex) ObserveDns(context.Context, DnsEvent) error { return ErrNotImplemented }
func (stubAdmissionIndex) AdmittingDomain(context.Context, SessionRef, netip.Addr, time.Time) (string, error) {
	return "", ErrNotImplemented
}

// Attributor performs the LOG-2 join: ct mark + iifname -> SessionRef, plus
// the AdmissionIndex lookup -> AdmittingDomain. It returns ErrUnattributed
// (never a guessed session) when keys don't resolve; unattributed flows feed
// the LOG-4 reconciler.
type Attributor interface {
	Attribute(ctx context.Context, f ConntrackFlow) (FlowRecord, error)
	AttributeDrop(ctx context.Context, d NflogDrop) (FlowRecord, error)
}

// NewAttributor returns the RED stub attributor over the given registry and
// admission index.
func NewAttributor(reg SessionRegistry, idx AdmissionIndex) Attributor { return stubAttributor{} }

type stubAttributor struct{}

func (stubAttributor) Attribute(context.Context, ConntrackFlow) (FlowRecord, error) {
	return FlowRecord{}, ErrNotImplemented
}
func (stubAttributor) AttributeDrop(context.Context, NflogDrop) (FlowRecord, error) {
	return FlowRecord{}, ErrNotImplemented
}

// ---------------------------------------------------------------------------
// Collect, spool, ship (LOG-3)
// ---------------------------------------------------------------------------

// Collector is the single ingest point for conntrack-derived FlowRecords,
// nflog drops, and both proxies' event streams (LOG-3); it joins on session
// and hands off to the spool.
type Collector interface {
	Ingest(ctx context.Context, ev Event) error
}

// NewCollector returns the RED stub collector writing into the given spool.
func NewCollector(spool Spool) Collector { return stubCollector{} }

type stubCollector struct{}

func (stubCollector) Ingest(context.Context, Event) error { return ErrNotImplemented }

// Spool is disk-bounded local buffering (LOG-3). Overflow behavior is
// contractual: never exceed BoundBytes; on pressure drop-oldest and emit a
// SpoolOverflow marker event so loss is visible, not silent.
type Spool interface {
	Append(ctx context.Context, ev Event) error
	ReadBatch(ctx context.Context, max int) (batch []Event, ack func() error, err error)
	UsageBytes() int64
	BoundBytes() int64
}

// NewSpool returns the RED stub spool persisting under dir with the given
// byte bound.
func NewSpool(dir string, boundBytes int64) Spool { return &stubSpool{bound: boundBytes} }

type stubSpool struct{ bound int64 }

func (*stubSpool) Append(context.Context, Event) error { return ErrNotImplemented }
func (*stubSpool) ReadBatch(context.Context, int) ([]Event, func() error, error) {
	return nil, nil, ErrNotImplemented
}
func (*stubSpool) UsageBytes() int64   { return 0 }
func (s *stubSpool) BoundBytes() int64 { return s.bound }

// HostingTier selects what ships where (D19): on-prem keeps metadata
// customer-side.
type HostingTier int

const (
	TierSaaS HostingTier = iota
	TierOnPrem
)

// SinkID names a registered sink.
type SinkID string

// StoryQuery retrieves a session's complete network story from a sink.
type StoryQuery struct {
	SessionID string
	Window    Window
}

// Router maps an event + hosting tier to a sink (D19). Under TierOnPrem every
// event routes customer-side regardless of the configured default; an
// unroutable tier returns ErrUnroutableTier rather than falling through to
// the vendor sink.
type Router interface {
	Route(ev Event, tier HostingTier) (SinkID, error)
}

// RouterConfig declares the configured default sink (possibly the vendor's)
// and the customer-side sink that TierOnPrem events must always use.
type RouterConfig struct {
	Default      SinkID
	CustomerSide SinkID
}

// NewRouter returns the RED stub router.
func NewRouter(cfg RouterConfig) Router { return stubRouter{} }

type stubRouter struct{}

func (stubRouter) Route(Event, HostingTier) (SinkID, error) { return "", ErrNotImplemented }

// Sink is the off-box log-pipeline contract; it doubles as the doc-06 fake
// against which "queryable off-box" is asserted.
type Sink interface {
	Receive(ctx context.Context, batch []Event) error
	Query(ctx context.Context, q StoryQuery) ([]Event, error)
}

// Shipper drains the spool through the router into the sinks with
// at-least-once + ack semantics (LOG-3).
type Shipper interface {
	Ship(ctx context.Context) error
}

// NewShipper returns the RED stub shipper.
func NewShipper(spool Spool, router Router, sinks map[SinkID]Sink, tier HostingTier) Shipper {
	return stubShipper{}
}

type stubShipper struct{}

func (stubShipper) Ship(context.Context) error { return ErrNotImplemented }

// ---------------------------------------------------------------------------
// Reconciliation (LOG-4) — the boundary audits itself
// ---------------------------------------------------------------------------

// ExplanationKind says what legitimizes a kernel-observed flow.
type ExplanationKind int

const (
	ExplanationProxySession ExplanationKind = iota
	ExplanationEscapeHatch
)

// Explanation ties one kernel flow to the proxy session or escape-hatch
// allowance that explains it. Detail cites the matched evidence (e.g. the
// allowance ID).
type Explanation struct {
	Kind   ExplanationKind
	Flow   ConntrackFlow
	Ref    SessionRef
	Detail string
}

// ReconciliationReport is the outcome of one reconciliation window.
type ReconciliationReport struct {
	Explained   []Explanation
	Unexplained []ConntrackFlow
}

// Allowance is a POL-5 escape-hatch grant: session-scoped, protocol+port
// bounded, time-bounded. Only a matching, in-force allowance explains a
// direct (non-proxied) flow.
type Allowance struct {
	ID         string
	Session    SessionRef
	Protocol   Proto
	Port       uint16
	ValidFrom  time.Time
	ValidUntil time.Time
	Detail     string
}

// AllowanceSource exposes the escape-hatch allowances in scope for a session.
type AllowanceSource interface {
	Allowances(ctx context.Context, ref SessionRef, at time.Time) ([]Allowance, error)
}

// FlowSource feeds kernel-observed conntrack flows (NFT-5) into the
// reconciler for a window.
type FlowSource interface {
	Flows(ctx context.Context, w Window) ([]ConntrackFlow, error)
}

// ProxyEventSource feeds proxy telemetry (HttpEvents and proxy-side records)
// into the reconciler for a window.
type ProxyEventSource interface {
	Events(ctx context.Context, w Window) ([]Event, error)
}

// AlarmKind classifies reconciliation escalations.
type AlarmKind int

const (
	AlarmUnexplainedFlow AlarmKind = iota
	AlarmByteMismatch
	AlarmPostTeardownFlow
)

// Alarm is the typed escalation: an unexplained flow is an alarm, not a log
// line (LOG-4). Session is the attributed session when the attribution keys
// resolve (nil when they don't).
type Alarm struct {
	Kind    AlarmKind
	Flow    ConntrackFlow
	Session *SessionRef
	Detail  string
	At      time.Time
}

// AlarmSink is the escalation channel, distinct from the Event stream and the
// spool: alarm delivery must survive spool pressure and is never subject to
// drop-oldest shedding.
type AlarmSink interface {
	Raise(ctx context.Context, a Alarm) error
}

// ReconcilerConfig wires the reconciler's inputs. Grace is the bounded join
// window tolerating event-arrival skew; ByteToleranceBytes is the LOG-4
// byte-accounting tolerance (DefaultByteToleranceBytes unless overridden);
// Now is the injectable clock.
//
// Events is the reconciler's ordinary-event OUTPUT: explained flows ship as
// ordinary records through this droppable, disk-bounded spool. Alarms never
// ride this channel — they go through Alarms even while Events is at its
// bound and shedding (LOG-4.e: alarm delivery cannot be suppressed by the
// load-shedding that may drop ordinary events).
type ReconcilerConfig struct {
	Kernel             FlowSource
	Proxy              ProxyEventSource
	Index              AdmissionIndex
	Allowances         AllowanceSource
	Registry           SessionRegistry
	Alarms             AlarmSink
	Events             Spool
	Grace              time.Duration
	ByteToleranceBytes uint64
	Now                func() time.Time
}

// Reconciler continuously reconciles kernel accounting against proxy
// telemetry: every byte that left a VM interface must be explained by a proxy
// session or an escape-hatch allowance (LOG-4). Anything unexplained is
// escalated through the AlarmSink, never logged-and-forgotten.
type Reconciler interface {
	Reconcile(ctx context.Context, w Window) (ReconciliationReport, error)
}

// NewReconciler returns the RED stub reconciler.
func NewReconciler(cfg ReconcilerConfig) Reconciler { return stubReconciler{} }

type stubReconciler struct{}

func (stubReconciler) Reconcile(context.Context, Window) (ReconciliationReport, error) {
	return ReconciliationReport{}, ErrNotImplemented
}

// ---------------------------------------------------------------------------
// Credential-use audit (LOG-5)
// ---------------------------------------------------------------------------

// CredentialUseQuery asks "which session used the <Service> key, when, for
// what request" over a window.
type CredentialUseQuery struct {
	Service   string
	SessionID string
	Window    Window
}

// AuditQuerier is LOG-5's query seam over the shipped store.
type AuditQuerier interface {
	CredentialUses(ctx context.Context, q CredentialUseQuery) ([]CredentialUseEvent, error)
}

// NewAuditQuerier returns the RED stub querier over the shipped store.
func NewAuditQuerier(store Sink) AuditQuerier { return stubAuditQuerier{} }

type stubAuditQuerier struct{}

func (stubAuditQuerier) CredentialUses(context.Context, CredentialUseQuery) ([]CredentialUseEvent, error) {
	return nil, ErrNotImplemented
}
