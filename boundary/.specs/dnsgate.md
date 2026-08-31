# DNS gating proxy (ds-dnsgate) — Go executable specification (doc 09 §4, steps DNS-1..DNS-5 incl. DNS-2b), package `dnsgate` in module github.com/dream-serpent/dream-serpent/boundary

## SEAMS

### ErrNotImplemented
Purpose: Sentinel every stub returns so the whole suite fails RED until the Rust data plane (or a Go shim over it) satisfies the spec. Tests assert outcomes, never this error, so passing requires real behavior.

```go
var ErrNotImplemented = errors.New("dnsgate: not implemented")
```

### Core domain types
Purpose: Black-box wire model. Session attribution is by source interface (never source IP), matching the NFT-2 `dstap-<session>` convention. RR.Data carries opaque rdata so tests can plant HTTPS/SVCB (type 65/64) payloads with ECH configs.

```go
type SessionRef struct { ID string; Interface string }
type RRType uint16 // TypeA=1, TypeCNAME=5, TypeAAAA=28, TypeSVCB=64, TypeHTTPS=65
type RCode int // RCodeNoError=0, RCodeFormErr=1, RCodeServFail=2, RCodeNXDomain=3, RCodeRefused=5
type Query struct { Session SessionRef; Name string; Type RRType; Proto string /* "udp"|"tcp" */ }
type RR struct { Name string; Type RRType; TTL uint32; Addr netip.Addr; Target string; Data []byte }
type Answer struct { RCode RCode; Truncated bool; Answers []RR; Authority []RR; Additionals []RR }
```

### Responder
Purpose: The component under test: full resolve→policy→scrub→admit→answer pipeline. ServeRaw is the DNS-5 hardening surface (malformed packets, TC-bit/TCP retry) where the structured Query model would hide the bug.

```go
type Responder interface {
	Serve(ctx context.Context, q Query) (Answer, error)
	ServeRaw(ctx context.Context, sess SessionRef, proto string, packet []byte) ([]byte, error)
}
```

### New (constructor + Deps)
Purpose: Dependency-injection seam: every collaborator is a fake in tests (doc 06 §2 contract-test model). Now() makes expiry/lockstep tests deterministic. Stub returns a Responder whose methods return ErrNotImplemented.

```go
type Deps struct {
	Policy PolicyEvaluator
	Upstream Upstream
	Admissions AdmissionStore
	AskUser AskUserNotifier
	Events EventSink
	Config PlannerConfig
	Now func() time.Time
}
func New(deps Deps) (Responder, error)
```

### PolicyEvaluator
Purpose: policy-core seam (POL-1/POL-3 provenance carried on every decision). The fake records which names were evaluated — load-bearing for proving CNAME intermediates are NEVER policy-evaluated, and for simulating ask→approval as a session-scoped TTL'd allow grant.

```go
type Verdict int // VerdictAllow, VerdictDeny, VerdictAsk
type Decision struct { Verdict Verdict; RuleID string; PolicyLayer string; PolicyVersion string }
type PolicyEvaluator interface { EvaluateDomain(ctx context.Context, sess SessionRef, domain string) (Decision, error) }
```

### Upstream
Purpose: Upstream-resolver seam (host-egress path to 1.1.1.1/8.8.8.8 per D64). The fake scripts CNAME chains, rebinding flips, private/embedded-IPv4 answers, TTL=0 churn, and smuggled type-65 Extra records; it also records every Resolve target for the poisoning-posture test.

```go
type AddrRecord struct { Addr netip.Addr; TTL uint32 }
type CNAMELink struct { From, To string; TTL uint32 }
type ResolutionChain struct { QueryName string; Links []CNAMELink; Terminal []AddrRecord; Extra []RR }
type Upstream interface { Resolve(ctx context.Context, name string, qtype RRType) (ResolutionChain, error) }
```

### AdmissionStore (allow-set + DNS-2b map, atomic)
Purpose: Models DNS-2 + DNS-2b as one transactional seam: Admit must complete before Serve releases the answer (insert-then-answer), and writes the per-session domain-keyed map the TLS proxy reads. ContainsAddr vs Lookup separates 'IP alive in the set' from 'admitted for this domain' — exactly the shared-CDN-IP distinction DNS-2b exists for.

```go
type AdmissionTx struct {
	Session SessionRef
	Domain string // ORIGINAL query name — the SNI join key
	Addrs []netip.Addr
	Timeout time.Duration // clamped chain-min TTL + grace (NFT-3)
	Decision Decision
}
type Admission struct { Domain string; Addrs []netip.Addr; ExpiresAt time.Time }
type AdmissionStore interface {
	Admit(ctx context.Context, tx AdmissionTx) error // one transaction: allow-set elements AND (domain→IPs,expiry) map entry
	Lookup(ctx context.Context, sess SessionRef, domain string, addr netip.Addr) (Admission, bool, error) // ds-tlsproxy's synchronous read
	ContainsAddr(ctx context.Context, sess SessionRef, addr netip.Addr) (bool, error) // bare allow-set view (what the kernel sees)
	FlushSession(ctx context.Context, sess SessionRef) error // NFT-6 teardown
}
```

### AskUserNotifier (Stage-0 ask-user seam)
Purpose: One-way boundary→orchestrator notification frozen at Stage 0 (doc 09 §8). Tests run against the fake orchestrator/client; approval comes back as a policy grant on the PolicyEvaluator fake, never as a response on this seam.

```go
type AskUserRequest struct { Session SessionRef; ResourceKind string; Name string; RuleID string; PolicyLayer string; PolicyVersion string }
type AskUserNotifier interface { Notify(ctx context.Context, req AskUserRequest) error }
```

### EventSink
Purpose: LOG-1 emission seam: the DNSEvent is §7's 'domain that admitted the flow' join key; PolicyDecisionEvent carries POL-3 provenance for denials/asks. Fakes record events for the provenance assertions.

```go
type DNSEvent struct { Session SessionRef; Domain string; Addrs []netip.Addr; TTL uint32; Decision Decision; At time.Time }
type PolicyDecisionEvent struct { Session SessionRef; Domain string; Decision Decision; RCode RCode; At time.Time }
type EventSink interface {
	EmitDNS(ctx context.Context, ev DNSEvent) error
	EmitPolicyDecision(ctx context.Context, ev PolicyDecisionEvent) error
}
```

### ScrubAddr (pure)
Purpose: DNS-4 rule 2 as a pure, exhaustively table-testable function. Embedded-IPv4 forms (::ffff:0:0/96 mapped, 64:ff9b::/96 NAT64) extract the inner IPv4 and re-apply the IPv4 rules, so ::ffff:10.0.0.5 is scrubbed by the same predicate as 10.0.0.5.

```go
type ScrubReason int // ReasonNone, ReasonPrivate4, ReasonLinkLocal4, ReasonLoopback4, ReasonHostRange4, ReasonLoopback6, ReasonLinkLocal6, ReasonULA6, ReasonHostAddr6, ReasonEmbedded4
type ScrubConfig struct { HostRanges4 []netip.Prefix; HostAddrs6 []netip.Addr }
func ScrubAddr(addr netip.Addr, cfg ScrubConfig) (admit bool, reason ScrubReason)
```

### ClampTTL / ChainMinTTL (pure)
Purpose: DNS-1 clamp (strawman 60s–15min) and DNS-2 chain-minimum rule as pure functions; Grace is the NFT-3 margin added to the allow-set element timeout so the kernel entry strictly outlives any TTL-honoring client cache.

```go
type TTLPolicy struct { Floor, Ceiling, Grace time.Duration }
func ClampTTL(upstreamTTL uint32, p TTLPolicy) uint32
func ChainMinTTL(chain ResolutionChain) uint32
```

### FilterRecords (pure)
Purpose: Record-type suppression as a pure function applied to ALL answer sections: v0 AAAA strip (DNS-1/OQ10) and total HTTPS(65)/SVCB(64) suppression (DNS-4 rule 4 — removes ECH configs and alpn=h3 steering).

```go
type Posture struct { StripAAAA bool; SuppressHTTPSSVCB bool }
func FilterRecords(rrs []RR, p Posture) []RR
```

### PlanResponse (pure admission core)
Purpose: The entire decide-scrub-clamp-admit-answer computation with zero I/O: given a query, a policy decision, and a resolved chain, produce exactly what to admit, what to answer, and what to emit. This is what makes 'answered ⊆ admitted' (DNS-4 rule 1) and chain-keying provable as pure properties; Responder is then just orchestration of Plan over the seams.

```go
type PlannerConfig struct { TTL TTLPolicy; Scrub ScrubConfig; Posture Posture }
type Plan struct {
	Answer Answer
	Admission *AdmissionTx // nil when nothing may be admitted
	Scrubbed []struct{ Addr netip.Addr; Reason ScrubReason }
	DNSEvent *DNSEvent
	DecisionEvent *PolicyDecisionEvent
	AskUser *AskUserRequest
}
func PlanResponse(q Query, dec Decision, chain *ResolutionChain, cfg PlannerConfig, now time.Time) (Plan, error)
```


## TESTS

- **DNS-1.a** `TestServe_AllowedDomain_AnswersTerminalAddrs` [contract]
  - planRef: doc 09 §4 DNS-1 Done-when (allowed name resolves through us)
  - guardrail: An allowed name resolves through our resolver and the VM receives only the chain-terminal addresses
  - fn: Responder.Serve
  - inputs: Fake policy: allow(api.anthropic.com); fake upstream: A 160.79.104.10 TTL 300; Query{A, udp} from session s1/dstap-s1
  - expected: Answer RCode=NoError, exactly the upstream terminal A record with clamped TTL; exactly one Upstream.Resolve call (to the configured resolver, not anything VM-supplied)
- **DNS-1.b** `TestClampTTL_FloorCeilingTable` [unit, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-1 (clamped TTLs) + DNS-4 rule 3 (TTL floors prevent churn-forcing) + NFT-3 grace
  - guardrail: Answered TTLs always land in [floor, ceiling]; a TTL=0/1 churn-forcing answer cannot drive set thrash below the floor
  - fn: ClampTTL (pure)
  - inputs: Table over upstream TTLs {0, 1, 59, 60, 300, 900, 3600, 86400, math.MaxUint32} with TTLPolicy{Floor:60s, Ceiling:900s, Grace:45s}
  - expected: {60,60,60,60,300,900,900,900,900}; ClampTTL is monotonic and never returns 0; AdmissionTx.Timeout in PlanResponse equals clamp+Grace (kernel entry strictly outlives client cache)
- **DNS-1.c** `TestServe_V0AAAAStrip_NoIPv6ReachesVMOrSets` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-1 v0 IPv6 posture (strip AAAA, allow6 dormant; OQ10)
  - guardrail: While allow6 is dormant, no IPv6 address is ever answered to a VM or admitted — an ungated v6 answer would be an unenforced path
  - fn: Responder.Serve + FilterRecords (pure)
  - inputs: (1) AAAA query for an allowed domain whose upstream has AAAA records; (2) A query whose upstream chain.Extra smuggles AAAA records; Posture{StripAAAA:true}
  - expected: (1) NoError with zero answer records (not REFUSED — the domain is allowed, the type is stripped); (2) AAAA absent from every section; in both cases zero IPv6 addrs in any AdmissionTx; FilterRecords pure table confirms strip across Answers/Authority/Additionals
- **DNS-1.d** `TestServe_AttributionBySourceInterface` [contract]
  - planRef: doc 09 §4 DNS-1 (per-session view, attributed by source interface) + §7 LOG-2 join key
  - guardrail: Every query, admission, and event is attributed to the session owning the source interface — never to source IP
  - fn: Responder.Serve
  - inputs: Same domain queried from SessionRef{s1,dstap-s1} and SessionRef{s2,dstap-s2}
  - expected: Two AdmissionTx with the correct distinct sessions; DNSEvents carry the right SessionRef; AdmissionStore.Lookup hits only within the originating session
- **DNS-1.e** `TestLoad_ResolutionP99_WarmWithinBudget` [load]
  - planRef: doc 09 §4 DNS-1 Done-when (p99 added latency ≤10ms warm under N concurrent VMs; doc 06 §3(d))
  - guardrail: Resolution sits on every first connection's critical path; added p99 latency under fan-out stays within the strawman budget
  - fn: Responder.Serve
  - inputs: N=200 concurrent sessions × 50 warm-cache queries each against an instant fake upstream; measure added latency distribution
  - expected: p99 added latency ≤ 10ms (budget a tunable const, per Stage-5 (d) rig note); zero errors; guarded by a -short skip so it runs on the scheduled rig
- **DNS-2.a** `TestAdmission_InsertCompletesBeforeAnswerReleased` [contract, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2 (insert-then-answer ordering)
  - guardrail: There is no window in which the VM holds an IP the firewall doesn't admit
  - fn: Responder.Serve ordering vs AdmissionStore.Admit
  - inputs: Fake AdmissionStore whose Admit blocks until released; Serve called in a goroutine for an allowed domain
  - expected: Serve does not return while Admit is blocked; after release, Serve returns and the fake's call log shows Admit happens-before answer release; with an Admit that sleeps, the answered addrs are already ContainsAddr=true at the instant Serve returns
- **DNS-2.b** `TestAdmission_WriteFailure_AnswerWithholdsAddrs` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2 insert-then-answer + DNS-4 rule 1 (no answer bypasses insertion)
  - guardrail: If admission fails, the VM never receives the addresses anyway — failure of the side effect cannot degrade into a bypass
  - fn: Responder.Serve
  - inputs: Fake AdmissionStore.Admit returns an injected error for an otherwise-allowed resolution
  - expected: Answer carries zero address records (RCode=ServFail acceptable; any RCode that includes the unadmitted addrs is a failure); no DNSEvent claiming admission; allow-set unchanged
- **DNS-2.c** `TestCNAME_OnlyOriginalQueryNamePolicyEvaluated` [contract]
  - planRef: doc 09 §4 DNS-2 (admission keyed on original query name; intermediates never policy-evaluated)
  - guardrail: CDN intermediate hostnames need no allowlisting and are never consulted — the policy key equals the SNI join key
  - fn: Responder.Serve vs PolicyEvaluator fake call log
  - inputs: Allowed registry.npmjs.org with chain registry.npmjs.org → cdn.fastly.example → A 151.101.0.1; policy fake would DENY cdn.fastly.example if asked
  - expected: Exactly one EvaluateDomain call, for "registry.npmjs.org"; resolution succeeds despite the deny-if-asked intermediate; AdmissionTx.Domain == "registry.npmjs.org"
- **DNS-2.d** `TestCNAME_TerminalAddrsOnly_IntermediateNamesNeverAdmitted` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2 (only the chain's terminal addresses enter the set)
  - guardrail: Chain-following cannot widen the admission map with intermediate domain keys or non-terminal addresses
  - fn: Responder.Serve + AdmissionStore contents
  - inputs: Chain a.example → b.cdn.example → c.cdn.example → A {151.101.0.1, 151.101.64.1}; chain.Extra plants a stray A record for b.cdn.example
  - expected: AdmissionTx contains exactly the two terminal addrs keyed under a.example; Lookup(s, "b.cdn.example", anyAddr) and Lookup(s, "c.cdn.example", anyAddr) miss; the stray Extra A record is neither answered nor admitted
- **DNS-2.e** `TestCNAME_ChainMinimumTTL_Table` [unit]
  - planRef: doc 09 §4 DNS-2 (element timeout from minimum TTL along the chain) + OQ3
  - guardrail: The allow-set element lifetime is bounded by the shortest-lived link in the chain, clamped
  - fn: ChainMinTTL + PlanResponse (pure)
  - inputs: Table: {CNAME 300, CNAME 60, A 3600}→60; {CNAME 30, A 3600}→30 then clamped to floor 60; {A 120}→120; {CNAME 900, A 45}→45→60; empty-links chain → min of terminal TTLs
  - expected: ChainMinTTL returns the raw minimum; Plan.Answer TTL = ClampTTL(min); Plan.Admission.Timeout = clamp + Grace
- **DNS-2.f** `TestDNSEvent_CarriesAdmittingDomainJoinKey` [contract]
  - planRef: doc 09 §4 DNS-2 (record (session, domain, IPs, TTL, policy rule)) + §7 LOG-2 + POL-3
  - guardrail: Every admission emits the flow-attribution join record with full rule provenance — 'why was this blocked/allowed' always has a one-line answer
  - fn: Responder.Serve → EventSink.EmitDNS
  - inputs: Allowed CNAME-chained resolution under Decision{RuleID:"baseline/npm", PolicyLayer:"system", PolicyVersion:"v0.3"}
  - expected: Exactly one DNSEvent: Session, Domain=original query name, the admitted addrs, the clamped TTL, and the full Decision provenance; a zero-value RuleID/PolicyVersion fails the test (POL-3 missing-provenance rule)
- **DNS-2.g** `TestE2E_M0WalkingSkeleton_AllowedFlowsElseRefused` [e2e-lifecycle]
  - planRef: doc 09 §4 DNS-2 Done-when (M0 smoke: allowed domain flows, everything else drops, incl. CNAME-chained CDN domain)
  - guardrail: The end-to-end gate: baseline domains resolve and admit; any other name yields refusal with zero admission
  - fn: Responder.Serve full pipeline over all fakes
  - inputs: D64-shaped fake policy (api.anthropic.com, github.com set, registry.npmjs.org); queries for each baseline name plus evil.example and a random name
  - expected: Each baseline name: NoError, addrs admitted-before-answer, Lookup hits; evil.example/random: REFUSED, AdmissionStore untouched, PolicyDecisionEvent emitted; registry.npmjs.org exercises the CNAME path
- **DNS-2b.a** `TestAdmissionMap_WrittenAtomicallyWithAllowSet` [contract]
  - planRef: doc 09 §4 DNS-2b (written in the same insert-then-answer transaction as DNS-2)
  - guardrail: The TLS proxy's domain→IP view and the kernel's bare-IP view can never disagree: one Admit produces both or neither
  - fn: AdmissionStore.Admit contract (run against fake and, later, real store per doc 06 §2.5 run-twice rule)
  - inputs: Single Admit(tx{domain:"github.com", addrs:[140.82.114.3], timeout:120s}); then a store that fails the map half mid-transaction
  - expected: Success case: ContainsAddr=true AND Lookup(domain,addr)=hit with ExpiresAt=now+120s; injected-failure case: ContainsAddr=false AND Lookup misses (no half-written state observable)
- **DNS-2b.b** `TestAdmissionMap_ExpiryLockstepWithSetTimeout` [contract]
  - planRef: doc 09 §4 DNS-2b (entries expire in lockstep with NFT-3 set timeouts)
  - guardrail: Map expiry and allow-set element timeout are the same instant — no window where one side is live and the other isn't
  - fn: AdmissionStore.Lookup/ContainsAddr under an injected clock
  - inputs: Admit with Timeout=90s; advance fake Now() to +89s, +90s, +91s
  - expected: +89s: both Lookup and ContainsAddr hit; +91s: both miss; the transition happens at the same clock instant for both views
- **DNS-2b.c** `TestAdmissionMap_ExpiredDomainMisses_WhileSharedIPAliveForOtherDomain` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2b Done-when (expired mapping refuses even while another domain keeps the same IP alive) — the CDN shared-IP hole, doc 03 OQ1 / §9 ECH-row precondition
  - guardrail: An IP alive in the allow-set for domain B does not vouch for expired domain A — admission is per-domain, not per-IP
  - fn: AdmissionStore.Lookup
  - inputs: Admit(a.example→151.101.0.1, 60s) and Admit(b.example→151.101.0.1, 600s); advance clock to +120s
  - expected: ContainsAddr(151.101.0.1)=true (B keeps it alive); Lookup("b.example",151.101.0.1)=hit; Lookup("a.example",151.101.0.1)=MISS — the read ds-tlsproxy uses for its TLS-1 refusal
- **DNS-2b.d** `TestAdmissionMap_CrossSessionLookupAlwaysMisses` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2b (host-local PER-SESSION store) + doc 06 §3(c) session-isolation spirit
  - guardrail: Session A's admissions are invisible to session B even for identical domain and IP
  - fn: AdmissionStore.Lookup
  - inputs: Admit under s1 for github.com→140.82.114.3; Lookup and ContainsAddr under s2 for the same domain/addr
  - expected: Both miss under s2; both hit under s1; FlushSession(s1) leaves s2's own entries untouched
- **DNS-2b.e** `TestAdmissionMap_FlushedAtSessionTeardown_NoResidue` [e2e-lifecycle]
  - planRef: doc 09 §4 DNS-2b (flushed at session teardown, NFT-6) + doc 06 §3(b) clean-teardown row
  - guardrail: Teardown leaves no admission residue that a recycled session ID or interface could inherit
  - fn: AdmissionStore.FlushSession
  - inputs: Admit 3 domains under s1; FlushSession(s1); then create→admit→flush looped 10 times for the same SessionRef
  - expected: After each flush every Lookup and ContainsAddr for s1 misses (including unexpired entries); the loop ends byte-identical to start (no growth, no leaked entries) — the (b) suite's leaked-allow-set-entries assertion at this seam
- **DNS-3.a** `TestDeny_HardDeniedName_ExplicitRefusalWithProvenance` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-3 (hard denial; denials are policy-decision events; OQ6)
  - guardrail: A hard-denied name gets an explicit in-band refusal carrying rule provenance — never a silent forward, never an admission
  - fn: Responder.Serve
  - inputs: Fake policy: Decision{Deny, RuleID:"org/blocklist-7"} for evil.example; upstream fake armed to fail the test if Resolve is called
  - expected: RCode=REFUSED (the OQ6 working answer; rcode is a named const so resolving OQ6 edits one line); zero Upstream.Resolve calls; zero Admit calls; one PolicyDecisionEvent{Deny, rule, layer, version, RCode}
- **DNS-3.b** `TestAsk_RefusedNeverNXDOMAINOrSERVFAIL_NoCacheableSignal` [contract]
  - planRef: doc 09 §4 DNS-3 (REFUSED because NXDOMAIN/SERVFAIL are negatively cached — RFC 2308/9520; this half of OQ6 is closed)
  - guardrail: The ask path never emits a cacheable negative signal that would blind the VM's stub resolver to a subsequent approval
  - fn: Responder.Serve
  - inputs: Table of ask-posture names over UDP and TCP, A and AAAA qtypes
  - expected: Every response RCode==REFUSED; explicitly assert RCode!=NXDomain && RCode!=ServFail; Authority section carries no SOA (nothing for RFC 2308 negative caching to latch onto); zero answer records
- **DNS-3.c** `TestAsk_NotifiesStage0Seam_WithMatchedRule` [contract]
  - planRef: doc 09 §4 DNS-3 (prompt travels the ask-user seam frozen at Stage 0; §8 Stage-0 AskUserRequest shape)
  - guardrail: An ask-posture query produces exactly one prompt with session, resource kind, name, and matched rule per POL-3
  - fn: Responder.Serve → AskUserNotifier.Notify
  - inputs: Ask-posture query for internal-tool.example from s1; same query repeated 3 times rapidly
  - expected: Notify receives AskUserRequest{s1, "domain", "internal-tool.example", rule, layer, version}; the response is REFUSED regardless of Notify outcome (one-way seam — a slow/failing notifier must not stall or change the DNS answer); duplicate-prompt suppression behavior recorded by the fake
- **DNS-3.d** `TestAsk_FirstRetryAfterApproval_SucceedsAndAdmits` [e2e-lifecycle]
  - planRef: doc 09 §4 DNS-3 Done-when (prompt now, FIRST post-approval retry succeeds)
  - guardrail: Approval converts an ask into an allow with no residual refusal state — the very next query resolves and admits
  - fn: Responder.Serve across the ask→approve→retry sequence (against the fake orchestrator/policy, per Stage-0 note)
  - inputs: Query #1 (ask → REFUSED + Notify); flip the policy fake to a session-scoped TTL'd allow grant (the approval path's real mechanism); query #2 immediately
  - expected: Query #2: NoError with addrs, full insert-then-answer admission (DNS-2.a property holds on the retry path too), DNSEvent emitted with the grant's rule id; no stale REFUSED from any internal cache
- **DNS-3.e** `TestDeny_DoHResolverDomains_BaselineBlocklistWins` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §9 row 'DoH endpoint blocking (baseline blocklist…)' (POL-2 enforced by DNS-3 denial) + NFT-4 + doc 06 §3(c) DoH-bypass row
  - guardrail: Known public DoH resolver domains are denied at resolution even when an allowlist would admit them — blocklists always win, closing the resolver-bypass route
  - fn: Responder.Serve
  - inputs: Table: dns.google, cloudflare-dns.com, dns.quad9.net under a policy fake where each name is BOTH on the org allowlist and the D64 baseline blocklist (deny-overrides composition)
  - expected: Every query REFUSED; zero Admit calls; PolicyDecisionEvent provenance names the blocklist rule (not the allowlist rule); zero upstream resolution
- **DNS-3.f** `TestNonAllowVerdicts_ZeroSideEffects` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-3 + DNS-4 rule 1 (denial paths must not touch admission state)
  - guardrail: Deny and ask verdicts cause no allow-set insert, no admission-map write, no upstream query — refusal is side-effect-free
  - fn: Responder.Serve
  - inputs: Table-driven over Verdict∈{Deny, Ask} × qtype∈{A, AAAA, HTTPS} × proto∈{udp, tcp}
  - expected: For all 12 cells: AdmissionStore fake records zero Admit calls, Upstream fake zero Resolve calls, and the prior allow-set contents are bit-identical before/after
- **DNS-4.a** `TestScrubAddr_IPv4Table` [unit, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 2 (IPv4 half) + doc 06 §3(c) rebinding row
  - guardrail: No private, link-local, loopback, or host/boundary IPv4 address ever passes the admission filter
  - fn: ScrubAddr (pure)
  - inputs: Table: 10.0.0.5, 172.16.1.1, 172.31.255.255, 192.168.0.1, 169.254.169.254, 127.0.0.1, 0.0.0.0, 255.255.255.255, plus cfg.HostRanges4 hit 198.51.100.7/0; admitted side: 93.184.216.34, 8.8.8.8, 172.32.0.1 (just outside RFC1918), 1.1.1.1
  - expected: Each scrub case returns (false, correct ScrubReason); each public case (true, ReasonNone); boundary addresses of each prefix (e.g. 172.15.255.255 vs 172.16.0.0) land on the right side
- **DNS-4.b** `TestScrubAddr_IPv6Table` [unit, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 2 (IPv6 half: ::1, fe80::/10, fc00::/7, host's own addrs)
  - guardrail: Dual-stack scrub holds for native IPv6 ranges even though v0 strips AAAA — the filter is load-bearing the day OQ10 flips v6 on
  - fn: ScrubAddr (pure)
  - inputs: Table: ::1, fe80::1, febf::1 (top of fe80::/10), fc00::1, fdff:ffff::1 (top of fc00::/7), cfg.HostAddrs6 member 2001:db8::5; admitted side: 2606:4700:4700::1111, 2620:fe::fe
  - expected: Scrub cases (false, ReasonLoopback6/ReasonLinkLocal6/ReasonULA6/ReasonHostAddr6); public GUAs (true, ReasonNone); fec0::1 (outside fe80::/10) admitted by this rule
- **DNS-4.c** `TestScrubAddr_EmbeddedIPv4_MappedAndNAT64` [unit, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 2 (embedded-IPv4: ::ffff:0:0/96 and 64:ff9b::/96 checked against the IPv4 rules) + §9 row 'Rebinding fails (incl. IPv4-mapped IPv6)'
  - guardrail: An approved domain answering ::ffff:10.0.0.5 gains nothing — the embedded IPv4 is extracted and re-judged by the IPv4 rules
  - fn: ScrubAddr (pure)
  - inputs: Table: ::ffff:10.0.0.5, ::ffff:127.0.0.1, ::ffff:169.254.169.254, ::ffff:192.168.1.1, 64:ff9b::10.0.0.5, 64:ff9b::7f00:1 (embeds 127.0.0.1), ::ffff:<HostRanges4 member>; pass side: ::ffff:93.184.216.34 and 64:ff9b::5db8:d822 (embed public IPv4 → pass THIS rule, with a comment that v0 AAAA-strip still withholds them from answers)
  - expected: All private/loopback/link-local/host embeddings return (false, ReasonEmbedded4); public embeddings pass the embedded check; verdict for ::ffff:X always equals the verdict for plain X
- **DNS-4.d** `TestRebind_PrivateReResolution_ScrubbedNeverAdmittedNeverAnswered` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 Done-when ('never to an internal one including the IPv4-mapped-IPv6 case') + doc 06 §3(c) rebinding assertion
  - guardrail: Classic DNS rebinding fails end-to-end: an approved name flipping to an internal address cannot place it in the answer, the allow-set, or the admission map
  - fn: Responder.Serve (full pipeline)
  - inputs: Allowed rebind.example resolves first to 93.184.216.34 (admitted); fake upstream then rebinds, table-driven over {10.0.0.5, 127.0.0.1, 169.254.169.254, ::ffff:10.0.0.5, 64:ff9b::a00:5, <host boundary addr>}; re-query after TTL expiry
  - expected: Re-query answer contains zero address records (all scrubbed → empty NoError, no admission); ContainsAddr(internal)=false; Lookup(rebind.example, internal)=miss; Plan.Scrubbed records each addr+reason for the audit trail; original public admission untouched
- **DNS-4.e** `TestRebind_ReResolutionGoesThroughFullAdmission_NoSilentWidening` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 3 (re-resolutions go through full admission) + §9 row 'allow-set never silently widens' (DNS-4 + NFT-3)
  - guardrail: A new address only enters the set via the complete policy→scrub→Admit transaction; the set never widens by cache refresh or answer alone
  - fn: Responder.Serve vs PolicyEvaluator/AdmissionStore fake call logs
  - inputs: Allowed name resolves to A1; TTL expires; upstream now returns A2 (public). Second variant: policy flipped to Deny between resolutions
  - expected: Variant 1: second Serve triggers EvaluateDomain again, ScrubAddr on A2, and a fresh AdmissionTx(A2) before answering — never an answer-without-Admit; variant 2: REFUSED, A2 nowhere, and A1's existing entry is not extended
- **DNS-4.f** `TestPlanResponse_AnsweredAddrsSubsetOfAdmitted_Property` [unit, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 1 (the VM is only ever answered with addresses that were actually admitted)
  - guardrail: Invariant over arbitrary upstream answers: answer ⊆ admission, and all-scrubbed answers admit nothing and answer nothing
  - fn: PlanResponse (pure)
  - inputs: Table + a rapid randomized sweep: upstream Terminal mixes of public/private/embedded addrs, including {93.184.216.34, 10.0.0.5}, all-private sets, empty sets, duplicates
  - expected: For every input: set(Plan.Answer address records) ⊆ set(Plan.Admission.Addrs); mixed case answers/admits only the public addr; all-private case yields Plan.Admission==nil and zero answer records; every excluded addr appears in Plan.Scrubbed with a reason
- **DNS-4.g** `TestSuppress_HTTPSAndSVCBQueries_NeverAnswered` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 4 (HTTPS/SVCB suppressed entirely — ECH configs + alpn=h3) + §9 row 'no HTTPS/SVCB answer reaches a VM'
  - guardrail: Suppressing type 65/64 denies clients the ECH config that would defeat the TLS-1 SNI check and the h3 steering at the QUIC we drop
  - fn: Responder.Serve
  - inputs: Direct type-65 (HTTPS) and type-64 (SVCB) queries for an ALLOWED domain; fake upstream armed with a real-shaped HTTPS record (ech=…, alpn=h3,h2)
  - expected: No RR of type 65 or 64 in any section of any answer (response is NoError/empty for the allowed name — suppression, not denial); nothing admitted from the suppressed records; assertion is a sweep over Answers+Authority+Additionals
- **DNS-4.h** `TestSuppress_HTTPSRecordSmuggledInAdditionals_Stripped` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-4 rule 4 + DNS-2 chain handling (chain.Extra path)
  - guardrail: An upstream that piggybacks a type-65 record on an ordinary A answer cannot smuggle an ECH config past the suppression
  - fn: Responder.Serve + FilterRecords (pure)
  - inputs: A-query for an allowed domain; fake upstream ResolutionChain.Extra contains HTTPS(65) and SVCB(64) records (with ech and alpn=h3 rdata) alongside legitimate glue
  - expected: Final answer carries the A records and zero type-65/64 records in any section; FilterRecords pure table proves the strip is section-independent and AAAA-strip-composable
- **DNS-5.a** `TestHardening_MalformedPackets_NoPanicNoAdmission` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-5 (malformed queries)
  - guardrail: Garbage on port 53 can neither crash the gate nor mutate admission state
  - fn: Responder.ServeRaw
  - inputs: Table over udp+tcp: truncated 4-byte header, header claiming QDCOUNT=5 with one question, name-compression pointer loop, label >63 bytes, total name >255 bytes, 0-byte packet, 64KiB random bytes, valid header + trailing garbage
  - expected: Never panics (test wraps in recover-fail); response is FORMERR or no response (dropped) per case; zero Admit/Resolve/Notify calls across the whole table; subsequent valid query on the same Responder still works
- **DNS-5.b** `TestHardening_LargeAnswer_UDPTruncatesThenTCPFull_AdmissionOrderingHolds` [contract]
  - planRef: doc 09 §4 DNS-5 (large answers over TCP)
  - guardrail: The TCP fallback path is a first-class admission path, not a side door — insert-then-answer holds there too
  - fn: Responder.Serve (proto=udp then tcp)
  - inputs: Allowed domain whose fake upstream returns 40 A records (answer exceeds the UDP payload limit); same query over udp, then tcp
  - expected: UDP answer has Truncated=true and the addrs it does carry are all admitted; TCP answer carries the full set, every addr Admitted before the answer returns (DNS-2.a fake ordering check re-run on the TCP path); one admission map entry covering the full set
- **DNS-5.c** `TestHardening_CacheHit_StillGuaranteesLiveAdmissionBeforeAnswer` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-5 (cache behavior) + DNS-4 rule 1 + OQ3 (resolve-once clients vs expiry)
  - guardrail: Serving from cache cannot create an answered-but-expired-in-the-firewall window — a cache hit re-arms admission before answering
  - fn: Responder.Serve with injected clock
  - inputs: Resolve allowed name (admitted, timeout 60s+grace); advance Now() past expiry but within any answer-cache lifetime; re-query
  - expected: At the instant the second answer returns, ContainsAddr and Lookup are live again (fresh or refreshed AdmissionTx recorded by the fake); the answer is never released against an expired admission; upstream re-resolution, if it happened, went through full DNS-4.e admission
- **DNS-5.d** `TestHardening_UpstreamOnlyViaConfiguredResolvers` [contract, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-5 (poisoning posture: upstream path uses host's protected egress) + POL-2 resolver rows (host-side egress only)
  - guardrail: The gate's own upstream queries go only to the policy-configured resolvers — nothing the VM supplies (names, NS hints, glue) can redirect our upstream path
  - fn: Responder.Serve vs Upstream fake target log
  - inputs: Queries whose fake upstream chain includes NS records and glue pointing at attacker-resolver.example/203.0.113.66; config names exactly the D64 defaults
  - expected: Every Resolve call in the fake's log targets only the configured upstreams; the NS/glue hints are never followed or admitted; planted glue records never appear in answers
- **DNS-5.e** `TestLoad_ConcurrentFleetStorm_NoCrossSessionLeakUnderRace` [load, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-5 (concurrency under a fleet of VMs resolving at once) + doc 06 §3(d)
  - guardrail: Under maximum concurrency (and the race detector), every admission lands in exactly the querying session and answered ⊆ admitted never breaks
  - fn: Responder.Serve under -race
  - inputs: 100 sessions × 100 goroutine-interleaved queries over a 20-domain mix (allow/deny/ask, CNAME chains, rebind flips, TTL=0), random udp/tcp
  - expected: Race detector clean; post-hoc audit of the fake stores: zero AdmissionTx with a session other than its query's; for every answered query, addrs ⊆ that session's admissions at answer time; deny/ask counts match zero-side-effect rule; no lost or duplicated DNSEvents
