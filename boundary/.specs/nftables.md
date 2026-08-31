# NFTables L3/4 layer (doc 09 §3, NFT-1..NFT-6 incl. NFT-2b; §9 rows: default-deny, in-VM spoofing, port-53/DoT/QUIC bypass, allow-set-never-widens, session A↛B, controls-unobservable)

## SEAMS

### Sentinel and core types (package nft)
Purpose: Shared vocabulary for the whole test surface; ErrNotImplemented is the RED-state sentinel every stub returns; the enums make table-driven packet/verdict tests readable and exhaustive.

```go
package nft // github.com/dream-serpent/dream-serpent/boundary/nft

var ErrNotImplemented = errors.New("nft: not implemented")
var ErrUnauthorizedWriter = errors.New("nft: only ds-dnsgate may write allow-sets")
var ErrSessionNotFound = errors.New("nft: session not found")
var ErrSharedL2Segment = errors.New("nft: session would share an L2 segment")

type SessionID string
type Family int        // FamilyIPv4, FamilyIPv6
type Proto int         // ProtoTCP, ProtoUDP, ProtoICMP, ProtoGRE, ProtoSCTP
type CtState int       // CtStateNew, CtStateEstablished, CtStateRelated, CtStateInvalid
type Verdict int       // VerdictDrop, VerdictRedirectDNSGate, VerdictRedirectTLSProxy, VerdictAcceptDirect, VerdictAcceptReturn
type EgressMode int    // EgressStage1Direct, EgressProxyRedirect
type WriterPrincipal int // PrincipalDNSGate, PrincipalTLSProxy, PrincipalUnknown
```

### Packet / Decision (black-box verdict model)
Purpose: Models 'a packet from a VM hits the ruleset' as a pure black-box question, so default-deny, redirect, spoofing-immunity, and bypass-closure are unit-testable without a kernel.

```go
type Packet struct {
    InIface string          // attachment point — the ONLY trusted identity (dstap-<session> or host uplink)
    Src     netip.AddrPort  // forgeable from inside the VM; tests prove it is never consulted
    Dst     netip.AddrPort
    Proto   Proto
    CtState CtState
}

type Decision struct {
    Verdict        Verdict
    RedirectTarget netip.AddrPort // dnsgate/tlsproxy listener when redirected
    OriginalDst    netip.AddrPort // preserved original destination (NFT-2 / OQ4 contract)
    Session        SessionID      // attributed from InIface, never from Src
    CtMark         uint32         // per-session mark (NFT-5 / LOG-2 key)
    RuleID         string         // provenance for drop/accept (POL-3 / nflog join)
    Logged         bool           // true when the verdict emits an nflog/conntrack event
}
```

### RulesetManager
Purpose: Lifecycle of the modeled ruleset: bootstrap (NFT-1), per-session attach with the dstap naming + VLAN uniqueness (NFT-2, §9 isolation), the NFT-2b mode flip, atomic teardown (NFT-6), and a canonical snapshot for the byte-identical assertion.

```go
type RulesetManager interface {
    Bootstrap(ctx context.Context, cfg BootstrapConfig) error
    AttachSession(ctx context.Context, spec SessionSpec) error
    DetachSession(ctx context.Context, id SessionID) error // atomic: iface rules + allow4/allow6 sets + ct-mark rule, all-or-nothing
    SetEgressMode(ctx context.Context, mode EgressMode) error // NFT-2b Stage-1-direct -> proxy-redirect cutover
    Snapshot(ctx context.Context) (RulesetSnapshot, error)
}

type BootstrapConfig struct {
    HostUplinkIface string
    DNSGateAddr     netip.AddrPort
    TLSProxyAddr    netip.AddrPort
    EgressMode      EgressMode
    TTLClampMin     time.Duration // strawman 60s (DNS-1 clamp floor)
    TTLClampMax     time.Duration // strawman 15m
    Grace           time.Duration // strawman 30–60s (OQ3)
}

type SessionSpec struct {
    ID     SessionID
    Iface  string      // dstap-<session> convention (NFT-2; §7 attribution key)
    VLANID uint16      // per-session 802.1Q tag (§2 placement; uniqueness enforced)
    VMAddr netip.Addr
    CtMark uint32      // derived from session (NFT-5)
}
```

### RulesetSnapshot
Purpose: Makes 'create→destroy ×N leaves the ruleset byte-identical to bootstrap' an executable equality, and lets idempotency/versioned-artifact tests diff state.

```go
type RulesetSnapshot interface {
    Bytes() []byte               // canonical serialized form, stable ordering
    Equal(other RulesetSnapshot) bool // byte-identical comparison (NFT-6 Done-when)
}
```

### PacketEvaluator
Purpose: The single black-box question every guardrail test asks: given this packet on this interface in this ct state, what does the boundary do? All §9 verdict rows reduce to tables over this call.

```go
type PacketEvaluator interface {
    Evaluate(ctx context.Context, pkt Packet) (Decision, error)
}
```

### FlowSimulator (conntrack model)
Purpose: In-memory conntrack: proves ct-state-new-only gating (established flows survive allow-set expiry and the NFT-2b flip), that teardown flushes session flows, and feeds byte/packet/duration accounting (NFT-5).

```go
type FlowID string

type FlowSimulator interface {
    OpenFlow(ctx context.Context, pkt Packet) (FlowID, Decision, error)        // ct state new; registers conntrack entry on accept
    ContinueFlow(ctx context.Context, id FlowID, bytesOut, bytesIn uint64) (Decision, error) // ct state established
    CloseFlow(ctx context.Context, id FlowID) error                            // emits FlowStop accounting
}
```

### AllowSetWriter
Purpose: The DNS-gate-facing programming seam (D3). Carrying the principal makes the single-writer rule a testable refusal instead of a comment.

```go
type AllowSetWriter interface {
    // Admit inserts addrs into allow{4,6}_<session> with element timeout = clamp(ttl) + grace.
    // Only PrincipalDNSGate is authorized (NFT-3: "Only ds-dnsgate writes the sets").
    Admit(ctx context.Context, principal WriterPrincipal, session SessionID, family Family, addrs []netip.Addr, ttl time.Duration) error
}
```

### AllowSetReader
Purpose: White-box assertions on set contents and expiry timestamps: never-silently-widens, exact TTL+grace math, allow6 dormancy, and absence after NFT-6 teardown.

```go
type AllowEntry struct {
    Addr      netip.Addr
    ExpiresAt time.Time
}

type AllowSetReader interface {
    Entries(ctx context.Context, session SessionID, family Family) ([]AllowEntry, error) // ErrSessionNotFound after teardown
}
```

### FlowEventSource
Purpose: Models conntrack accounting + nflog drop emission (NFT-5) so attribution completeness (every flow and every drop carries the per-session ct mark, keyed by iface not src) is assertable before ds-flowlog exists.

```go
type EventKind int // EventFlowStart, EventFlowStop, EventDrop

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

type FlowEventSource interface {
    Events(ctx context.Context) (<-chan FlowEvent, error)
}
```

### Clock (deterministic time)
Purpose: Every expiry/grace/dormancy test advances a fake clock instead of sleeping, keeping the (a)-level suite in the seconds-to-low-minutes budget doc 06 §3 demands.

```go
type Clock interface {
    Now() time.Time
}

// test double in package nfttest:
type FakeClock struct{ /* ... */ }
func (c *FakeClock) Now() time.Time
func (c *FakeClock) Advance(d time.Duration)
```

### Boundary (composition root for stubs)
Purpose: One constructor the whole suite calls; guarantees the seams compose into a single coherent model and gives the RED baseline its single point of truth.

```go
// New returns the unimplemented stub wiring: every method returns ErrNotImplemented
// (or a Decision zero-value with it) until the real data plane satisfies the spec.
func New(clk Clock) (RulesetManager, PacketEvaluator, FlowSimulator, AllowSetWriter, AllowSetReader, FlowEventSource)
```


## TESTS

- **NFT-1.a** `TestBootstrap_DefaultDeny_AllTrafficFromAgentIfaceDrops` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-1 Done-when; §9 row 'Default-deny outbound holds'; doc 06 §3(c) row 1
  - guardrail: A VM behind a freshly bootstrapped host can reach nothing at all
  - fn: PacketEvaluator.Evaluate after RulesetManager.Bootstrap + AttachSession
  - inputs: Table over Packet{InIface: dstap-A, CtState: new} × {tcp/443, tcp/80 (pre-admission), tcp/22, udp/123, udp/4789, icmp echo, gre, sctp/3868, tcp/65535} to public, private, and boundary-host destinations; no Admit calls made
  - expected: Every row returns Verdict==VerdictDrop with Logged==true and a non-empty RuleID; no row returns any accept or redirect except the explicit 53→dnsgate carve-out rows asserted separately
- **NFT-1.b** `TestBootstrap_EstablishedRelatedReturnAccepted` [unit]
  - planRef: doc 09 §3 NFT-1 ('established/related allowed back in')
  - guardrail: Return traffic of an accepted flow flows; default-deny applies to new flows only
  - fn: FlowSimulator.OpenFlow + ContinueFlow
  - inputs: Open an allowed flow (admitted IP, Stage-1 direct tcp/443), then ContinueFlow; separately Evaluate a Packet with CtState==CtStateRelated on the same tuple
  - expected: OpenFlow accepts; ContinueFlow returns VerdictAcceptReturn/AcceptDirect for established; related is accepted; both attributed to session A's CtMark
- **NFT-1.c** `TestBootstrap_InvalidCtStateDrops` [unit, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-1 ('and nothing else')
  - guardrail: Conntrack-invalid packets never pass the established carve-out
  - fn: PacketEvaluator.Evaluate
  - inputs: Packet{InIface: dstap-A, CtState: CtStateInvalid} on a tuple that matches a live admitted flow
  - expected: VerdictDrop, Logged==true — invalid state cannot piggyback on the established exemption
- **NFT-1.d** `TestBootstrap_HostUplinkEgressUnaffected` [unit]
  - planRef: doc 09 §3 NFT-1 ('default drop for all traffic originating on agent-VM interfaces') + POL-2 resolver row ('host-side egress for ds-dnsgate's own upstream queries only')
  - guardrail: Default-deny is scoped to agent ifaces; the host's own resolver egress works
  - fn: PacketEvaluator.Evaluate
  - inputs: Packet{InIface: HostUplinkIface, Dst: 1.1.1.1:53, Proto: udp, CtState: new} and same to 8.8.8.8:53
  - expected: Not VerdictDrop (host-originated upstream resolution is outside the agent default-deny chain)
- **NFT-1.e** `TestBootstrap_Idempotent_SnapshotStable` [unit]
  - planRef: doc 09 §3 NFT-1 ('versioned, declarative ruleset… a build artifact, not hand-applied state')
  - guardrail: Bootstrap is declarative and idempotent
  - fn: RulesetManager.Bootstrap + Snapshot
  - inputs: Bootstrap(cfg); s1 := Snapshot(); Bootstrap(cfg) again; s2 := Snapshot()
  - expected: s1.Equal(s2) is true and s1.Bytes() == s2.Bytes(); re-bootstrap returns no error and changes nothing
- **NFT-1.f** `TestControls_BoundaryServicesUnreachableFromVM` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row 'Controls unobservable/unmodifiable from inside the VM' (NFT-1 + §2 placement); doc 06 §3(c) last row
  - guardrail: From inside the VM, the firewall/proxies/policy plumbing are not reachable, observable, or modifiable
  - fn: PacketEvaluator.Evaluate
  - inputs: Table of Packet{InIface: dstap-A} aimed at the boundary host's own addresses: dnsgate listener on non-53 ports, tlsproxy admin/metrics ports, policy-snapshot path, flowlog spool, ssh tcp/22 to gateway, netlink-shaped traffic — including rows where the dst IP equals the redirect target IP itself
  - expected: Every row VerdictDrop (the only host-reachable surfaces are the explicit 53/80/443 redirect verdicts, which never expose the host addresses directly)
- **NFT-1.g** `TestBootstrap_UnknownIfaceDrops` [unit, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-1 + NFT-2 (only attached, named sessions get rules)
  - guardrail: Traffic on an unattached/unknown interface has no path
  - fn: PacketEvaluator.Evaluate
  - inputs: Packet{InIface: "dstap-ghost"} (never passed to AttachSession), dst 1.1.1.1:53 and tcp/443
  - expected: VerdictDrop for all — even the DNS redirect requires a known attached session interface
- **NFT-2.a** `TestRedirect_Port53ByIifname` [contract]
  - planRef: doc 09 §3 NFT-2 ('Redirect udp/tcp 53 → ds-dnsgate at Stage 1')
  - guardrail: DNS from a session interface always lands on ds-dnsgate
  - fn: PacketEvaluator.Evaluate
  - inputs: Table: Packet{InIface: dstap-A, Dst: <any>:53} × {udp, tcp}
  - expected: Verdict==VerdictRedirectDNSGate, RedirectTarget==cfg.DNSGateAddr, Session==A, CtMark==A's mark
- **NFT-2.b** `TestRedirect_PreservesOriginalDestination` [contract]
  - planRef: doc 09 §3 NFT-2 + OQ4 (original-destination recovery is the redirect-path contract Pingora consumes)
  - guardrail: Redirect never loses the original destination the proxies need
  - fn: PacketEvaluator.Evaluate
  - inputs: udp/53 to 8.8.8.8:53 and (proxy mode) tcp/443 to 140.82.112.3:443 from dstap-A
  - expected: Decision.OriginalDst equals the packet's original Dst exactly, for both dnsgate and tlsproxy redirect verdicts
- **NFT-2.c** `TestSpoof_ForgedSourceIPStillRedirectedAndAttributed` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-2 Done-when; §9 row 'In-VM spoofing fails (interface match)'; doc 06 §3(c) interface-match row
  - guardrail: Forged source addresses do not escape the interface-matched redirect or alter attribution
  - fn: PacketEvaluator.Evaluate
  - inputs: Table of Packet{InIface: dstap-A, Dst: 8.8.8.8:53} with Src forged as: the boundary host's IP, session B's VMAddr, a public IP (52.1.2.3), 0.0.0.0, and a baseline-resolver IP (1.1.1.1)
  - expected: Every row gets the identical Decision as the legitimate-src packet: VerdictRedirectDNSGate, Session==A, CtMark==A's mark — the forged Src changes nothing
- **NFT-2.d** `TestSpoof_ForgedSourceCannotBorrowOtherSessionsAllowSet` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-2 ('addresses can be forged from inside the VM, the attachment point can't') + NFT-3 per-session sets
  - guardrail: Spoofing session B's address from session A's interface gains none of B's admissions
  - fn: AllowSetWriter.Admit + PacketEvaluator.Evaluate
  - inputs: Admit 93.184.216.34 for session B only (Stage-1 direct mode); Evaluate Packet{InIface: dstap-A, Src: B's VMAddr (forged), Dst: 93.184.216.34:443, tcp, new}
  - expected: VerdictDrop — set lookup is keyed by the iface's session (A), whose allow4 is empty; the forged src never selects allow4_B
- **NFT-2.e** `TestEvaluate_SourceIPNeverConsulted_PropertyTable` [unit, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-2 ('match on iifname, never on source IP'); doc 03 §3
  - guardrail: No verdict anywhere in the ruleset is a function of the agent packet's source address
  - fn: PacketEvaluator.Evaluate
  - inputs: Property-style table: for every scenario class in the suite (deny, dns-redirect, proxy-redirect, direct-admitted, bypass-drop), evaluate the same packet under 8 randomized Src values
  - expected: Within each class, all 8 Decisions are deep-equal — Verdict, Session, CtMark, RedirectTarget all invariant under Src
- **NFT-2.f** `TestAttach_IfaceNamingConvention_AttributionKey` [contract]
  - planRef: doc 09 §3 NFT-2 ('dstap-<session>' convention; 'it is also the attribution key for §7') + LOG-2
  - guardrail: The per-session interface convention is established and round-trips as the attribution key
  - fn: RulesetManager.AttachSession + PacketEvaluator.Evaluate
  - inputs: AttachSession{ID: "sess42", Iface: "dstap-sess42", CtMark: 0x2a}; AttachSession with a non-conforming iface name ("eth7"); then Evaluate a packet on dstap-sess42
  - expected: Conforming attach succeeds and Decision carries Session=="sess42" and CtMark==0x2a; non-conforming iface name is rejected with an error
- **NFT-2b.a** `TestEgress_Stage1Direct_AllowSetGatedWebPorts` [unit]
  - planRef: doc 09 §3 NFT-3 ('at Stage 1, direct tcp 80/443 egress') + NFT-2b interim mode; §8 Stage 1
  - guardrail: Stage-1 interim mode: only admitted IPs flow, only on 80/443
  - fn: PacketEvaluator.Evaluate (EgressStage1Direct)
  - inputs: Admit 93.184.216.34 for A; table: {admitted:443 → accept, admitted:80 → accept, unadmitted 198.51.100.7:443 → drop, unadmitted:80 → drop} all ct-new from dstap-A
  - expected: Admitted rows VerdictAcceptDirect with A's CtMark; unadmitted rows VerdictDrop with Logged==true
- **NFT-2b.b** `TestEgress_Stage1Direct_AdmittedIPNonWebPortDrops` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 ('What they gate: at Stage 1, direct tcp 80/443') — admission must not widen beyond the gated ports
  - guardrail: An allow-set entry opens 80/443 only; it is not a general L4 grant
  - fn: PacketEvaluator.Evaluate
  - inputs: Admit 93.184.216.34 for A; Evaluate ct-new flows from dstap-A to 93.184.216.34 on tcp/22, tcp/8443, tcp/853, udp/443, udp/53
  - expected: tcp/22 and tcp/8443 drop (no rule admits them); tcp/853 drops (NFT-4); udp/443 drops (NFT-4); udp/53 redirects to dnsgate — admission never bleeds into other ports
- **NFT-2b.c** `TestEgress_CutoverFlipsNewFlowsToProxyRedirect` [contract]
  - planRef: doc 09 §3 NFT-2b ('flip tcp 80/443 from allow-set-gated direct egress to the ds-tlsproxy redirect')
  - guardrail: Post-cutover, every new 80/443 flow transits the proxy — closing the CDN shared-IP hole's kernel half
  - fn: RulesetManager.SetEgressMode + PacketEvaluator.Evaluate
  - inputs: SetEgressMode(EgressProxyRedirect); Evaluate ct-new tcp/443 and tcp/80 from dstap-A to (a) an admitted IP and (b) an unadmitted IP
  - expected: All four rows VerdictRedirectTLSProxy with RedirectTarget==cfg.TLSProxyAddr and OriginalDst preserved — allow-set membership no longer grants direct 80/443 egress; domain-level decision moves to userspace
- **NFT-2b.d** `TestEgress_Cutover_EstablishedDirectFlowSurvivesFlip` [e2e-lifecycle]
  - planRef: doc 09 §3 NFT-2b Done-when ('conformance clients pass both before and after the flip')
  - guardrail: The cutover is hitless for in-flight connections
  - fn: FlowSimulator.OpenFlow/ContinueFlow across SetEgressMode
  - inputs: In Stage-1 mode open a direct flow A→admitted:443; SetEgressMode(EgressProxyRedirect); ContinueFlow on the open flow; then OpenFlow a fresh tuple
  - expected: ContinueFlow still accepted (rides conntrack, established); the fresh OpenFlow gets VerdictRedirectTLSProxy — old flows finish, new flows redirect
- **NFT-3.a** `TestAllowSet_ExpiryAtTTLPlusGraceBoundaries` [unit]
  - planRef: doc 09 §3 NFT-3 Done-when ('an entry expires on schedule'); OQ3
  - guardrail: Allow-set entries die exactly at clamped-TTL+grace — no early severing, no immortal entries
  - fn: AllowSetWriter.Admit + FakeClock.Advance + PacketEvaluator.Evaluate + AllowSetReader.Entries
  - inputs: Admit(dnsgate, A, v4, [93.184.216.34], ttl=60s) with Grace=30s; Evaluate ct-new tcp/443 at t=+89s, then Advance to t=+91s and Evaluate again; read Entries at both points
  - expected: Entries reports ExpiresAt==t0+90s; at +89s the new flow is accepted; at +91s the identical new flow is VerdictDrop and Entries no longer contains the address
- **NFT-3.b** `TestAllowSet_TTLClampAndGraceMath` [unit]
  - planRef: doc 09 §3 NFT-3 ('element timeout = the clamped TTL answered to the VM plus a grace margin… 60s–15min clamp') + DNS-1 clamp
  - guardrail: Kernel entry strictly outlives any TTL-honoring client cache of the same answer
  - fn: AllowSetWriter.Admit + AllowSetReader.Entries
  - inputs: Table of Admit ttl values {1s, 59s, 60s, 5m, 15m, 24h} with Grace=30s, TTLClampMin=60s, TTLClampMax=15m
  - expected: Stored ExpiresAt == now + clamp(ttl, 60s, 15m) + 30s for every row; in particular ttl=1s yields 90s (floor applied) and ttl=24h yields 15m30s (ceiling applied) — expiry always strictly exceeds the TTL a client could have cached
- **NFT-3.c** `TestAllowSet_EstablishedFlowSurvivesElementExpiry` [contract]
  - planRef: doc 09 §3 NFT-3 Done-when ('established ones survive'); OQ3 ('a long-lived stream crossing an element expiry'); e.g. streaming api.anthropic.com
  - guardrail: Set expiry never severs an in-flight stream — sets gate ct-state-new only
  - fn: FlowSimulator.OpenFlow/ContinueFlow across FakeClock.Advance
  - inputs: Admit X ttl=60s grace=30s; OpenFlow A→X:443 at t=+10s; Advance(10m) — far past expiry; ContinueFlow with more bytes; also OpenFlow a brand-new tuple to X
  - expected: ContinueFlow on the established flow is still accepted at t=+10m; the new OpenFlow to the now-expired X is VerdictDrop — same address, opposite verdicts, split exactly on ct state
- **NFT-3.d** `TestAllowSet_ResolveOnceClient_NewFlowAfterExpiryDrops` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 + OQ3 ('the assurance tests must cover resolve-once clients'); kernel half of TLS-1's re-admission story
  - guardrail: A client that resolved once and dials forever cannot keep direct egress alive past expiry
  - fn: PacketEvaluator.Evaluate (EgressStage1Direct) after FakeClock.Advance
  - inputs: Admit X for A (ttl 60s); Advance past expiry+grace; Evaluate a ct-new flow A→X:443 with no re-Admit (simulating a JVM-style infinite DNS cache redialing)
  - expected: VerdictDrop with Logged==true — at the L3/4 layer the stale dial is refused; recovery is the proxy's re-admission path, never a kernel leniency
- **NFT-3.e** `TestAllowSet_ReResolutionRestoresWithoutWidening` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 Done-when ('a re-resolution restores it without widening anything'); §9 row 'allow-set never silently widens' (DNS-4 + NFT-3)
  - guardrail: Re-admission restores exactly the resolved addresses; the set never accumulates
  - fn: AllowSetWriter.Admit + AllowSetReader.Entries + PacketEvaluator.Evaluate
  - inputs: Admit X1 (ttl 60s); expire it; re-Admit X2 (CDN rotated) for the same domain; read Entries; Evaluate ct-new flows to X1 and X2
  - expected: Entries contains exactly {X2}; flow to X2 accepted, flow to X1 dropped (the old address did not linger); re-admitting X1 later does not resurrect X2 — set contents always equal the latest admissions still inside their own timeouts
- **NFT-3.f** `TestAllowSet_CtStateGatingTable` [unit]
  - planRef: doc 09 §3 NFT-3 ('The sets gate new flows only (ct state new)')
  - guardrail: Allow-set lookup applies to ct-new only; established/related bypass it; invalid drops
  - fn: PacketEvaluator.Evaluate
  - inputs: Table over CtState {new, established, related, invalid} × {addr in set, addr not in set, addr expired} from dstap-A in Stage-1 direct mode
  - expected: new: accept iff in live set; established/related: accept regardless of set membership (conntrack owns them); invalid: drop regardless — 12 rows, no exceptions
- **NFT-3.g** `TestAllowSet_PerSessionScoping` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 ('Named sets per session allow4_<session>')
  - guardrail: One session's admission grants nothing to any other session
  - fn: AllowSetWriter.Admit + PacketEvaluator.Evaluate
  - inputs: Attach A and B; Admit X for A only; Evaluate ct-new flows to X:443 from dstap-A and from dstap-B (legit src each)
  - expected: A's flow accepted; B's identical flow VerdictDrop — sets are keyed allow4_<session> and selected by iface, with no shared/global fallback set
- **NFT-3.h** `TestAllowSet_OnlyDNSGatePrincipalMayWrite` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 ('Only ds-dnsgate writes the sets')
  - guardrail: The single-writer invariant: no other component can widen a session's reachability
  - fn: AllowSetWriter.Admit
  - inputs: Admit calls with principal PrincipalTLSProxy and PrincipalUnknown for session A, addr X
  - expected: Both return ErrUnauthorizedWriter; AllowSetReader.Entries(A) remains empty; a subsequent ct-new flow to X drops
- **NFT-3.i** `TestAllowSet_Allow6Dormant_V6DropsEvenIfAdmitted` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-3 ('allow6 stays dormant until IPv6 turns on') + DNS-1 v0 posture + OQ10
  - guardrail: IPv6 is a closed door in v0 — dormant allow6 contents grant nothing
  - fn: RulesetManager.AttachSession + AllowSetWriter.Admit + PacketEvaluator.Evaluate
  - inputs: Attach A (allow6_A is created, empty); force-Admit 2001:db8::1 into allow6_A as dnsgate; Evaluate ct-new tcp/443 from dstap-A to [2001:db8::1]:443 and udp/53 to a v6 resolver
  - expected: allow6_A exists at attach and is empty; after the admit the v6 flows still VerdictDrop (no rule references the dormant set); the set is nonetheless removed cleanly at DetachSession
- **NFT-4.a** `TestBypass_Port53AnyDestinationRedirectsToDNSGate` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-4 Done-when; §9 row 'Port-53/DoT/QUIC resolver bypass fails'; doc 06 §3(c) DoH/DoT-bypass row
  - guardrail: An in-VM 'nameserver 8.8.8.8' still resolves through us — port-53 traffic cannot reach any other resolver
  - fn: PacketEvaluator.Evaluate
  - inputs: Table: dst {8.8.8.8, 1.1.1.1, 9.9.9.9, an IP currently in allow4_A, the VM's own gateway} × {udp/53, tcp/53} from dstap-A, ct-new
  - expected: Every row VerdictRedirectDNSGate with OriginalDst preserved — including the allow-set-admitted destination (admission does NOT exempt port 53) and the baseline upstream resolvers themselves
- **NFT-4.b** `TestBypass_DoT853Drops_EvenToAdmittedIP` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-4 ('DNS-over-TLS (853) dropped'); §9 bypass row
  - guardrail: DoT cannot smuggle resolution past the gate, even via an admitted address
  - fn: PacketEvaluator.Evaluate
  - inputs: Admit 1.0.0.1 for A (pretend a policy admitted a name resolving there); table: dst {1.0.0.1 (admitted), 8.8.8.8, arbitrary} × {tcp/853, udp/853} from dstap-A, ct-new
  - expected: Every row VerdictDrop with Logged==true and a bypass-specific RuleID — the allow-set never opens 853
- **NFT-4.c** `TestBypass_QUICUdp443Drops_ForcesTCPFallback` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-4 ('udp/443 (QUIC) dropped for now to force TCP fallback the proxy can see'); OQ5; §9 bypass row
  - guardrail: QUIC cannot carry traffic (or DoH3) invisibly past the proxy
  - fn: PacketEvaluator.Evaluate
  - inputs: Admit X for A; table: udp/443 from dstap-A to {X (admitted), unadmitted IP, dns.google's IP} ct-new; control row: tcp/443 to X in current egress mode
  - expected: All udp/443 rows VerdictDrop + Logged; the tcp/443 control row gets the mode-appropriate non-drop verdict — proving the drop is QUIC-specific, not breakage
- **NFT-4.d** `TestBypass_HostUpstreamResolverAllowed_VMRedirected_Asymmetry` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-2 resolver row ('host-side egress only; in-VM packets aimed at these addresses are still redirected') + NFT-4
  - guardrail: The baseline never grants the VM direct resolver access — the same dst is legal from the host and captured from the VM
  - fn: PacketEvaluator.Evaluate
  - inputs: Two packets to 1.1.1.1:53/udp: one with InIface==HostUplinkIface, one with InIface==dstap-A (and a spoofed Src equal to the host's IP)
  - expected: Host-iface packet egresses (not dropped, not redirected); VM-iface packet is VerdictRedirectDNSGate despite the spoofed host Src — the asymmetry is keyed purely on iface
- **NFT-5.a** `TestAccounting_FlowStartStopEventsCarrySessionCtMark` [contract]
  - planRef: doc 09 §3 NFT-5 Done-when ('conntrack flow events… emitted carrying the per-session ct mark')
  - guardrail: Every kernel-observed flow is attributable: start/stop, bytes, packets, duration, session mark
  - fn: FlowSimulator.OpenFlow/ContinueFlow/CloseFlow + FlowEventSource.Events
  - inputs: Open A→X:443, ContinueFlow(4096 out, 1<<20 in) twice, Advance(90s), CloseFlow; drain Events
  - expected: Exactly one EventFlowStart and one EventFlowStop for the tuple; the stop event carries Session==A, CtMark==A's mark, Iface==dstap-A, Bytes==sum of both directions, Packets>0, End-Start==90s
- **NFT-5.b** `TestAccounting_DropEventsCarryIfaceAttributionAndRule` [contract]
  - planRef: doc 09 §3 NFT-5 Done-when ('nflog drop events… land in the Stage-1 local event log') + NFT-1 'drop + log'
  - guardrail: Every drop is a logged, attributed, explainable event — denials are evidence, not silence
  - fn: PacketEvaluator.Evaluate + FlowEventSource.Events
  - inputs: Trigger three distinct drops from dstap-A: default-deny (tcp/9999), DoT (tcp/853), QUIC (udp/443); drain Events
  - expected: Three EventDrop events, each with Session==A, Iface==dstap-A, the original Dst, and a distinct RuleID identifying which rule dropped it
- **NFT-5.c** `TestAccounting_SpoofedSourceAttributedByIfaceNotSrc` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-5 + NFT-2 + LOG-2 (attribution key is the interface); §9 spoofing row's accounting half
  - guardrail: Attribution cannot be forged — a spoofed source still bills to the real session
  - fn: FlowSimulator.OpenFlow + FlowEventSource.Events
  - inputs: From dstap-A, open an allowed flow whose Src is forged to session B's VMAddr; also trigger a drop with Src forged to the host IP; drain Events
  - expected: All events carry Session==A and CtMark==A's mark; no event attributes to B or to the host — Src appears only as recorded packet data, never as the attribution key
- **NFT-5.d** `TestAccounting_ConcurrentSessions_DistinctMarksNoCrossTalk` [contract]
  - planRef: doc 09 §3 NFT-5 ('tag each session's flows with a ct mark derived from the session') + LOG-2 100%-attribution bar
  - guardrail: Marks are per-session, stable, and never collide across concurrent sessions
  - fn: RulesetManager.AttachSession + FlowSimulator + FlowEventSource.Events
  - inputs: Attach A, B, C with distinct CtMarks; interleave flows and drops from all three ifaces concurrently (go test -race); drain Events and partition by mark
  - expected: Every event's (Session, CtMark, Iface) triple is internally consistent; partitioning by CtMark exactly reproduces partitioning by Iface; zero events with an unknown or zero mark
- **NFT-6.a** `TestTeardown_CreateDestroyLoop_RulesetByteIdentical` [e2e-lifecycle]
  - planRef: doc 09 §3 NFT-6 Done-when ('a create→destroy loop run N times leaves the ruleset byte-identical to bootstrap'); doc 06 §3(b) clean-teardown row
  - guardrail: Sessions leave zero residue — no leaked rules, sets, or marks at fleet scale
  - fn: RulesetManager.AttachSession/DetachSession/Snapshot
  - inputs: s0 := Snapshot() after Bootstrap; loop N=50: Attach(sess_i) → Admit 3 addrs → open+close a flow → trigger a drop → Detach(sess_i); s1 := Snapshot()
  - expected: s1.Equal(s0) and bytes.Equal(s1.Bytes(), s0.Bytes()); AllowSetReader.Entries for every sess_i returns ErrSessionNotFound
- **NFT-6.b** `TestTeardown_Atomic_NoGhostAcceptanceAfterDestroy` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §3 NFT-6 ('removes the interface rules and named sets atomically')
  - guardrail: After destroy there is no half-torn state — nothing on the dead interface flows, including previously established streams
  - fn: RulesetManager.DetachSession + PacketEvaluator.Evaluate + FlowSimulator.ContinueFlow
  - inputs: Attach A; Admit X; open a flow A→X:443 with live unexpired entries; DetachSession(A); then Evaluate ct-new to X, Evaluate udp/53, and ContinueFlow on the previously established flow
  - expected: All post-detach evaluations VerdictDrop (even the 53 redirect is gone with the iface rules); ContinueFlow refuses — the session's conntrack entries are flushed at teardown; Entries(A) returns ErrSessionNotFound
- **NFT-6.c** `TestTeardown_OtherSessionsUndisturbed` [e2e-lifecycle]
  - planRef: doc 09 §3 NFT-6 (atomic removal scoped to one session) + doc 06 §3(b) clean-teardown
  - guardrail: Destroying one session never perturbs a neighbor's rules, entries, expiries, or live flows
  - fn: RulesetManager.DetachSession + FlowSimulator + AllowSetReader
  - inputs: Attach A and B; Admit X for B (record ExpiresAt); open a long-lived B flow; DetachSession(A); then ContinueFlow B's flow, Evaluate a ct-new B flow to X, re-read B's Entries
  - expected: B's established flow continues, B's new flow to X is accepted, B's Entries and ExpiresAt are unchanged to the nanosecond — teardown of A is invisible to B
- **ISO-1.a** `TestSessionIsolation_NoPathBetweenAgentVMs` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row 'Session A cannot reach session B (no L2 path between agent VMs)' (§2 placement + NFT-1); OQ1 spike checklist
  - guardrail: No agent VM can reach another agent VM — not via L3 forwarding, not even via a poisoned allow-set
  - fn: PacketEvaluator.Evaluate + AllowSetWriter.Admit
  - inputs: Attach A and B (distinct VLANs/ifaces); table from dstap-A: tcp/443, udp/53, icmp to B's VMAddr; then adversarial row: force-Admit B's VMAddr into allow4_A (as dnsgate, simulating a DNS-4 scrub failure) and retry tcp/443 ct-new
  - expected: Every row VerdictDrop — inter-agent-interface forwarding is denied before allow-set consultation, so even an admitted peer address is unreachable (defense-in-depth behind DNS-4's scrub)
- **ISO-1.b** `TestAttach_RejectsSharedL2Segment` [unit]
  - planRef: doc 09 §2 placement note ('agent VMs must never share a port group') + OQ1 ('proof that no L2 path exists between any two agent VMs')
  - guardrail: The topology model makes a shared segment unrepresentable, not merely unobserved
  - fn: RulesetManager.AttachSession
  - inputs: Attach A with VLANID 100 / iface dstap-A; attempt Attach B with VLANID 100, and attempt Attach C reusing iface name dstap-A
  - expected: Both second attaches fail with ErrSharedL2Segment (and the snapshot is unchanged) — one session per VLAN/iface is an enforced invariant of the model
- **NFT-L.a** `TestLoad_AllowSetChurnManySessions_ExpiryAndAttributionComplete` [load]
  - planRef: doc 09 §8 Stage 5 ('allow-set churn under the doc 06 (d) rig') + doc 06 §3(d) proxy/fan-out scenarios; DNS-1 latency budget's kernel-side share
  - guardrail: Under fleet-scale churn, expiries stay exact, verdicts stay fast, and accounting loses nothing
  - fn: AllowSetWriter.Admit + PacketEvaluator.Evaluate + FlowEventSource.Events under concurrency (paired with a Benchmark func)
  - inputs: 200 sessions × 50 admissions each with randomized TTLs (60s–15m), FakeClock advanced in 10s steps to churn ~10k expiries while goroutines evaluate 100k packets and open/close 10k flows (-race)
  - expected: Zero stale accepts (no ct-new accept after an entry's ExpiresAt), zero premature drops (no ct-new drop before ExpiresAt for a live entry), event count == flows opened+closed+drops with 100% correct session marks, and Evaluate p99 within the declared in-memory budget recorded by the benchmark
