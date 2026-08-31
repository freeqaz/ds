// Package nft is the executable specification for the Dream Serpent
// boundary's NFTables L3/4 layer (doc 09 §3, NFT-1..NFT-6 incl. NFT-2b;
// §9 rows: default-deny, in-VM spoofing, port-53/DoT/QUIC bypass,
// allow-set-never-widens, session A↛B, controls-unobservable).
//
// It models the ruleset as an in-memory black box: a Packet arriving on an
// interface in a conntrack state yields a Decision. The seams below are the
// contract surface the real Rust/nftables data plane must satisfy. New()
// returns stubs whose methods return ErrNotImplemented, so the whole test
// suite is RED until the real data plane exists.
package nft

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Sentinels.
var (
	// ErrNotImplemented is the RED-state sentinel every stub method returns.
	ErrNotImplemented = errors.New("nft: not implemented")

	// ErrUnauthorizedWriter rejects any allow-set write whose principal is
	// not ds-dnsgate (NFT-3: "Only ds-dnsgate writes the sets").
	ErrUnauthorizedWriter = errors.New("nft: only ds-dnsgate may write allow-sets")

	// ErrSessionNotFound is returned for reads or flow continuations that
	// reference a session that does not exist or has been torn down (NFT-6:
	// teardown flushes the session's rules, sets, and conntrack entries).
	ErrSessionNotFound = errors.New("nft: session not found")

	// ErrSharedL2Segment rejects an AttachSession that would let two agent
	// VMs share a VLAN or interface name (§2 placement note, OQ1: agent VMs
	// must never share a port group).
	ErrSharedL2Segment = errors.New("nft: session would share an L2 segment")
)

// SessionID identifies an agent session; it is derived from the attachment
// interface (dstap-<session>), never from packet contents.
type SessionID string

// Family selects an address family for the per-session allow-sets.
type Family int

const (
	FamilyIPv4 Family = iota
	FamilyIPv6
)

// Proto is the L4 (or L3 carve-out) protocol of a modeled packet.
type Proto int

const (
	ProtoTCP Proto = iota
	ProtoUDP
	ProtoICMP
	ProtoGRE
	ProtoSCTP
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoGRE:
		return "gre"
	case ProtoSCTP:
		return "sctp"
	}
	return "proto?"
}

// CtState is the conntrack state the packet arrives in.
type CtState int

const (
	CtStateNew CtState = iota
	CtStateEstablished
	CtStateRelated
	CtStateInvalid
)

func (s CtState) String() string {
	switch s {
	case CtStateNew:
		return "new"
	case CtStateEstablished:
		return "established"
	case CtStateRelated:
		return "related"
	case CtStateInvalid:
		return "invalid"
	}
	return "ctstate?"
}

// Verdict is what the ruleset does with a packet.
type Verdict int

const (
	VerdictDrop Verdict = iota
	VerdictRedirectDNSGate
	VerdictRedirectTLSProxy
	VerdictAcceptDirect
	VerdictAcceptReturn
)

func (v Verdict) String() string {
	switch v {
	case VerdictDrop:
		return "drop"
	case VerdictRedirectDNSGate:
		return "redirect-dnsgate"
	case VerdictRedirectTLSProxy:
		return "redirect-tlsproxy"
	case VerdictAcceptDirect:
		return "accept-direct"
	case VerdictAcceptReturn:
		return "accept-return"
	}
	return "verdict?"
}

// EgressMode selects the NFT-2b posture for tcp 80/443 from VM interfaces.
type EgressMode int

const (
	// EgressStage1Direct: allow-set-gated direct tcp 80/443 egress (the
	// Stage-1 interim mode NFT-2b retires).
	EgressStage1Direct EgressMode = iota
	// EgressProxyRedirect: tcp 80/443 redirected to ds-tlsproxy (Stage 2).
	EgressProxyRedirect
)

// WriterPrincipal identifies who is attempting an allow-set write (D3
// single-writer seam).
type WriterPrincipal int

const (
	PrincipalDNSGate WriterPrincipal = iota
	PrincipalTLSProxy
	PrincipalUnknown
)

// Packet models "a packet from a VM hits the ruleset" as a pure black-box
// question (NFT-1/2/4), without a kernel.
type Packet struct {
	InIface string         // attachment point — the ONLY trusted identity (dstap-<session> or host uplink)
	Src     netip.AddrPort // forgeable from inside the VM; tests prove it is never consulted
	Dst     netip.AddrPort
	Proto   Proto
	CtState CtState
}

// Decision is the ruleset's answer for one packet.
type Decision struct {
	Verdict        Verdict
	RedirectTarget netip.AddrPort // dnsgate/tlsproxy listener when redirected
	OriginalDst    netip.AddrPort // preserved original destination (NFT-2 / OQ4 contract)
	Session        SessionID      // attributed from InIface, never from Src
	CtMark         uint32         // per-session mark (NFT-5 / LOG-2 key)
	RuleID         string         // provenance for drop/accept (POL-3 / nflog join)
	Logged         bool           // true when the verdict emits an nflog/conntrack event
}

// BootstrapConfig is the versioned, declarative ruleset input (NFT-1: a
// build artifact, not hand-applied state).
type BootstrapConfig struct {
	HostUplinkIface string
	DNSGateAddr     netip.AddrPort
	TLSProxyAddr    netip.AddrPort
	EgressMode      EgressMode
	TTLClampMin     time.Duration // strawman 60s (DNS-1 clamp floor)
	TTLClampMax     time.Duration // strawman 15m
	Grace           time.Duration // strawman 30–60s (OQ3)
}

// SessionSpec describes one agent session's attachment (NFT-2 convention).
type SessionSpec struct {
	ID     SessionID
	Iface  string // dstap-<session> convention (NFT-2; §7 attribution key); non-conforming names are rejected
	VLANID uint16 // per-session 802.1Q tag (§2 placement; uniqueness enforced via ErrSharedL2Segment)
	VMAddr netip.Addr
	CtMark uint32 // derived from session (NFT-5)
}

// RulesetManager owns the modeled ruleset lifecycle: bootstrap (NFT-1),
// per-session attach with the dstap naming + VLAN uniqueness (NFT-2, §9
// isolation), the NFT-2b mode flip, atomic teardown (NFT-6), and a canonical
// snapshot for the byte-identical assertion.
type RulesetManager interface {
	Bootstrap(ctx context.Context, cfg BootstrapConfig) error
	AttachSession(ctx context.Context, spec SessionSpec) error
	// DetachSession is atomic: iface rules + allow4/allow6 sets + ct-mark
	// rule, all-or-nothing; the session's conntrack entries are flushed.
	DetachSession(ctx context.Context, id SessionID) error
	// SetEgressMode performs the NFT-2b Stage-1-direct -> proxy-redirect
	// cutover; established flows ride conntrack across the flip.
	SetEgressMode(ctx context.Context, mode EgressMode) error
	Snapshot(ctx context.Context) (RulesetSnapshot, error)
}

// RulesetSnapshot makes "create→destroy ×N leaves the ruleset byte-identical
// to bootstrap" (NFT-6 Done-when) an executable equality.
type RulesetSnapshot interface {
	Bytes() []byte                    // canonical serialized form, stable ordering
	Equal(other RulesetSnapshot) bool // byte-identical comparison (NFT-6 Done-when)
}

// PacketEvaluator is the single black-box question every guardrail test
// asks: given this packet on this interface in this ct state, what does the
// boundary do? All §9 verdict rows reduce to tables over this call.
type PacketEvaluator interface {
	Evaluate(ctx context.Context, pkt Packet) (Decision, error)
}

// FlowID identifies a registered conntrack entry in the FlowSimulator.
type FlowID string

// FlowSimulator is the in-memory conntrack model: proves ct-state-new-only
// gating (established flows survive allow-set expiry and the NFT-2b flip),
// that teardown flushes session flows, and feeds byte/packet/duration
// accounting (NFT-5).
type FlowSimulator interface {
	// OpenFlow evaluates pkt in ct state new and, on an accepting verdict,
	// registers a conntrack entry. On a drop verdict the flow is not
	// registered and the returned FlowID is empty (the Decision still
	// reports the drop).
	OpenFlow(ctx context.Context, pkt Packet) (FlowID, Decision, error)
	// ContinueFlow evaluates further traffic on the flow in ct state
	// established, accumulating byte counters. After the owning session is
	// detached (NFT-6 flushes its conntrack entries) it returns
	// ErrSessionNotFound.
	ContinueFlow(ctx context.Context, id FlowID, bytesOut, bytesIn uint64) (Decision, error)
	// CloseFlow ends the flow and emits the FlowStop accounting event.
	CloseFlow(ctx context.Context, id FlowID) error
}

// AllowSetWriter is the DNS-gate-facing programming seam (D3). Carrying the
// principal makes the single-writer rule a testable refusal.
type AllowSetWriter interface {
	// Admit inserts addrs into allow{4,6}_<session> with element timeout =
	// clamp(ttl, TTLClampMin, TTLClampMax) + Grace.
	// Only PrincipalDNSGate is authorized (NFT-3: "Only ds-dnsgate writes
	// the sets"); any other principal gets ErrUnauthorizedWriter and the
	// set is untouched.
	Admit(ctx context.Context, principal WriterPrincipal, session SessionID, family Family, addrs []netip.Addr, ttl time.Duration) error
}

// AllowEntry is one live allow-set element with its expiry timestamp.
type AllowEntry struct {
	Addr      netip.Addr
	ExpiresAt time.Time
}

// AllowSetReader supports white-box assertions on set contents and expiry
// timestamps: never-silently-widens, exact TTL+grace math, allow6 dormancy,
// and absence after NFT-6 teardown.
type AllowSetReader interface {
	// Entries returns the live (unexpired) elements of the session's set
	// for the family; ErrSessionNotFound after teardown.
	Entries(ctx context.Context, session SessionID, family Family) ([]AllowEntry, error)
}

// EventKind classifies a FlowEvent.
type EventKind int

const (
	EventFlowStart EventKind = iota
	EventFlowStop
	EventDrop
)

// FlowEvent models conntrack accounting + nflog drop emission (NFT-5) so
// attribution completeness (every flow and every drop carries the
// per-session ct mark, keyed by iface not src) is assertable before
// ds-flowlog exists.
type FlowEvent struct {
	Kind     EventKind
	Session  SessionID
	CtMark   uint32
	Iface    string
	Src, Dst netip.AddrPort
	Proto    Proto
	Bytes    uint64
	Packets  uint64
	Start    time.Time
	End      time.Time
	RuleID   string // for drops: which rule dropped it (nflog)
}

// FlowEventSource exposes the recorded event stream. Events returns a
// channel that delivers every event recorded up to the call and is then
// closed (a deterministic drain for tests); it also closes when ctx is done.
type FlowEventSource interface {
	Events(ctx context.Context) (<-chan FlowEvent, error)
}

// Clock is the injectable time source (deterministic expiry tests advance a
// fake clock instead of sleeping; doc 06 §3 (a)-suite budget).
type Clock interface {
	Now() time.Time
}

// New returns the unimplemented stub wiring: every method returns
// ErrNotImplemented (or a Decision zero-value with it) until the real data
// plane satisfies the spec. The stubs are non-nil so tests never nil-panic.
func New(clk Clock) (RulesetManager, PacketEvaluator, FlowSimulator, AllowSetWriter, AllowSetReader, FlowEventSource) {
	s := &stub{clk: clk}
	return s, s, s, s, s, s
}

// stub is the RED-state implementation of every seam.
type stub struct{ clk Clock }

func (s *stub) Bootstrap(ctx context.Context, cfg BootstrapConfig) error  { return ErrNotImplemented }
func (s *stub) AttachSession(ctx context.Context, spec SessionSpec) error { return ErrNotImplemented }
func (s *stub) DetachSession(ctx context.Context, id SessionID) error     { return ErrNotImplemented }
func (s *stub) SetEgressMode(ctx context.Context, mode EgressMode) error  { return ErrNotImplemented }
func (s *stub) Snapshot(ctx context.Context) (RulesetSnapshot, error) {
	return nil, ErrNotImplemented
}

func (s *stub) Evaluate(ctx context.Context, pkt Packet) (Decision, error) {
	return Decision{}, ErrNotImplemented
}

func (s *stub) OpenFlow(ctx context.Context, pkt Packet) (FlowID, Decision, error) {
	return "", Decision{}, ErrNotImplemented
}

func (s *stub) ContinueFlow(ctx context.Context, id FlowID, bytesOut, bytesIn uint64) (Decision, error) {
	return Decision{}, ErrNotImplemented
}

func (s *stub) CloseFlow(ctx context.Context, id FlowID) error { return ErrNotImplemented }

func (s *stub) Admit(ctx context.Context, principal WriterPrincipal, session SessionID, family Family, addrs []netip.Addr, ttl time.Duration) error {
	return ErrNotImplemented
}

func (s *stub) Entries(ctx context.Context, session SessionID, family Family) ([]AllowEntry, error) {
	return nil, ErrNotImplemented
}

func (s *stub) Events(ctx context.Context) (<-chan FlowEvent, error) {
	return nil, ErrNotImplemented
}
