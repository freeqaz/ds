# System policy layer: policy-core + D64 baseline (doc 09 §6, POL-1..POL-5)

## SEAMS

### ErrNotImplemented sentinel
Purpose: Every stub returns this so the entire suite is RED until the real evaluator (and later the Rust data plane via a conformance shim) satisfies the spec. Tests treat ErrNotImplemented as failure, never skip.

```go
package policycore

var ErrNotImplemented = errors.New("policycore: not implemented")
```

### Policy document + schema v0 (POL-1)
Purpose: The YAML schema v0 the doc 03 TODO calls for, as Go types. The shape under parse/validate/round-trip tests; lives in the shared contract package and versions like every seam.

```go
type Posture string // PostureLocked, PostureStandard, PostureOpen
type Layer string   // LayerSystem, LayerOrg, LayerSession

type Policy struct {
    SchemaVersion string            // e.g. "v0"
    Name          string            // pack name, e.g. "d30-baseline"
    PackVersion   string            // versioned per doc 06 §2
    Posture       Posture
    Allow         []AllowRule       // domains, optional service-endpoint expansion
    Block         []BlockRule       // always win
    RateLimits    []RateLimitRule   // per-session / per-service caps (behavioral caps)
    EscapeHatches []EscapeHatchRule // per-protocol/port direct L3/4 allowances + scope
    PassThrough   []string          // cert-pinned domains: opaque tunnel, no swap
    CredSwap      []SwapServiceRule // service registry: service -> hosts -> credential location
    AskDefaults   AskDefaults       // ask-user posture defaults
}

type AllowRule struct{ ID, Domain, Service string; Scope RequestScope }
type BlockRule struct{ ID, Domain string }
type RateLimitRule struct{ ID, Service string; PerSession, PerService int; Window time.Duration }
type EscapeHatchRule struct{ ID, Protocol string; Port uint16; Scope GrantScope }
type SwapServiceRule struct{ ID, Service string; Hosts []string; CredentialLocation string }
type GrantScope struct{ Session, Host, Org string } // empty = unscoped at that level
```

### Parse / Validate (POL-1)
Purpose: Schema v0 parse+validate seam. Validate enforces posture enum, well-formed domains, non-negative limits, known SchemaVersion, rejects unknown fields.

```go
func Parse(yamlDoc []byte) (*Policy, error)
func (p *Policy) Validate() error
func (p *Policy) MarshalYAML() ([]byte, error) // round-trip stability
```

### Layered composition (POL-1)
Purpose: The single composition function. Precedence semantics (blocklist always wins, including the D64 DoH/DoT baseline blocklist) are proven here, not re-implemented per service.

```go
type LayeredPolicy struct {
    Layer  Layer
    Policy *Policy
}

// Compose flattens system -> org -> session with DENY-OVERRIDES precedence:
// any Block at any layer beats any Allow at any layer.
func Compose(layers ...LayeredPolicy) (*Snapshot, error)
```

### Snapshot (atomic versioned policy state, POL-4)
Purpose: The unit of fleet push and hot reload. Immutable, versioned, sequence-numbered; readers always see exactly one snapshot, never a blend.

```go
type Snapshot struct {
    PolicyVersion string // composed-policy version cited in provenance
    Seq           uint64 // monotonic sequence number for catch-up / replay rejection
    // opaque compiled rule state; immutable after Compose/ApplyGrant
}
```

### Request / Decision / Provenance (the pure decision function's I/O)
Purpose: ONE-ENGINE I/O contract. Every caller shape (DNS gate, TLS proxy SNI check, HTTP rules, nftables escape-hatch programming) is a Request; every outcome carries full provenance so 'why was this blocked?' always has a one-line answer.

```go
type RequestKind string // KindDNSResolve, KindTLSSNI, KindHTTPRequest, KindL4Direct
type RequestScope string // ScopeVM (traffic from agent VM), ScopeGateUpstream (ds-dnsgate's own upstream egress)
type Action string // ActionAllow, ActionDeny, ActionAsk

type SessionRef struct{ Session, Host, Org string }

type Request struct {
    Session   SessionRef
    Kind      RequestKind
    Scope     RequestScope
    Domain    string
    DstIP     netip.Addr
    DstPort   uint16
    Protocol  string // "tcp", "udp", or escape-hatch protocol name
    HTTPMethod, HTTPPath string // KindHTTPRequest only
}

type Provenance struct {
    RuleID        string
    Layer         Layer
    PolicyVersion string
}

type Decision struct {
    Action      Action
    Provenance  Provenance // MANDATORY on every decision incl. default-deny
    SwapService string     // non-empty => credential swap applies
    PassThrough bool       // opaque tunnel, never combined with SwapService
    DirectL4    bool       // escape-hatch verdict: direct flow gated by allow-set
}
```

### Evaluator (policy-core itself, POL-3)
Purpose: The single evaluator embedded everywhere decisions happen. Tested as a pure decision function so the two services and the nftables programming path can never disagree.

```go
// Evaluate is a pure function of (snapshot, request, now): no hidden state,
// no I/O, deterministic, safe for concurrent use. `now` makes TTL'd grants testable.
type Evaluator interface {
    Evaluate(snap *Snapshot, req Request, now time.Time) (Decision, error)
}

func NewEvaluator() Evaluator // stub: every Evaluate returns ErrNotImplemented
```

### D64 (amended by D74) default baseline pack (POL-2)
Purpose: The out-of-the-box allow set (Anthropic API, GitHub real endpoints, npm registry, host-side resolvers for the gate's upstream only) plus the DoH/DoT resolver blocklist. Tests pin its exact admit surface.

```go
// DefaultBaseline returns the shipped, versioned D64 (amended by D74) policy
// pack as ordinary policy data — removable, extensible, replaceable through
// the same engine.
func DefaultBaseline() (*Policy, error)

const BaselinePackName = "d30-baseline"
```

### Provenance gate (POL-3 CI hook)
Purpose: Makes 'a missing-provenance decision is a failure' executable rather than aspirational.

```go
// ValidateProvenance rejects any decision/event with missing rule id, layer,
// or policy version. Wired as the CI gate: a missing-provenance event fails the build.
func ValidateProvenance(p Provenance) error
func ValidateDecisionEvent(d Decision) error
```

### Policy stream + host subscriber (POL-4)
Purpose: Live fleet-wide push: atomic versioned snapshot, hot reload, no inter-service skew, offline catch-up by sequence number, replay/rollback rejection.

```go
// SnapshotSource is the control-plane policy stream (transport TBD, doc 03 OQ4).
type SnapshotSource interface {
    Subscribe(ctx context.Context, fromSeq uint64) (<-chan *Snapshot, error)
}

// SnapshotConsumer is what each service (ds-dnsgate, ds-tlsproxy, nft programmer) implements.
type SnapshotConsumer interface {
    Reload(snap *Snapshot) error
    CurrentVersion() (version string, seq uint64)
}

// HostSubscriber: exactly ONE per host; fans one snapshot to all registered
// consumers atomically so the two services can never run different policy versions.
type HostSubscriber interface {
    Register(c SnapshotConsumer)
    Run(ctx context.Context, src SnapshotSource) error
    Current() *Snapshot
}

func NewHostSubscriber() HostSubscriber // stub
```

### Ask-user routing seam (POL-5, Stage-0 frozen seam)
Purpose: Ask decisions route to the (fake) orchestrator/client wrapper; the boundary never grows its own approval UI. Tests run against the Stage-0 fake.

```go
// AskUserRequest mirrors the Stage-0 contract: one-way boundary -> orchestrator.
type AskUserRequest struct {
    Session      SessionRef
    ResourceKind string // e.g. "domain", "protocol"
    Name         string
    MatchedRule  Provenance // per POL-3
}

type AskRouter interface {
    RouteAsk(ctx context.Context, req AskUserRequest) error
}
```

### Approval grants (POL-5: approvals return on the policy stream)
Purpose: Encodes 'approvals return as session-scoped TTL'd allow grants on the policy stream'; Evaluate(now) honors the grant only for that session and only until expiry.

```go
// Grant is a session-scoped, TTL'd allow returned on the already-frozen policy
// stream after an ask-user approval. No second response contract.
type Grant struct {
    Session   SessionRef
    Domain    string
    ExpiresAt time.Time
    Seq       uint64
}

// ApplyGrant produces a NEW snapshot (next Seq) containing the grant;
// the prior snapshot is unchanged (immutability).
func ApplyGrant(snap *Snapshot, g Grant) (*Snapshot, error)
```


## TESTS

- **POL-1.a** `TestParse_SamplePolicyPerPosture_RoundTrips` [unit]
  - planRef: doc 09 §6 POL-1 Done-when: a sample policy per posture round-trips parse→evaluate
  - guardrail: Schema v0 faithfully represents every documented field for all three postures
  - fn: Parse / Policy.Validate / Policy.MarshalYAML
  - inputs: Table of three complete YAML fixtures (locked/standard/open), each exercising every schema section: allowlist with service expansion, blocklist, rate limits, escape hatches, pass-through, cred-swap registry, ask defaults
  - expected: Each parses without error, Validate passes, MarshalYAML→Parse yields a deeply-equal Policy (stable round-trip), and SchemaVersion == "v0"
- **POL-1.b** `TestParse_InvalidPolicies_Rejected` [unit, ADVERSARIAL]
  - planRef: doc 09 §6 POL-1 (schema validation half)
  - guardrail: Malformed policy can never load and silently widen access
  - fn: Parse / Policy.Validate
  - inputs: Table of invalid YAML docs: unknown posture value, unknown SchemaVersion, unknown top-level field, malformed domain (embedded whitespace, leading dot, bare IP in domain allowlist), negative rate limit, escape hatch with port 0/65536, cred-swap entry with empty hosts, duplicate rule IDs
  - expected: Every case returns a non-nil error naming the offending field; no partial Policy is returned
- **POL-1.c** `TestSchemaV0_ContractPackageVersioning` [contract]
  - planRef: doc 09 §6 POL-1 Done-when: schema merged into shared contract package and versioned per doc 06 §2
  - guardrail: The schema is a versioned seam: an unversioned or future-versioned document is refused, never guessed at
  - fn: Parse
  - inputs: YAML with SchemaVersion absent; YAML with SchemaVersion "v1" (not yet defined); YAML with "v0"
  - expected: Absent and "v1" are rejected with a version error; "v0" parses. (Golden fixture pinned so a silent schema reshape breaks this contract test.)
- **POL-1.d** `TestCompose_SystemOrgSession_DenyOverrides` [unit, ADVERSARIAL]
  - planRef: doc 09 §6 POL-1 Done-when: layered system→org→session composition with deny-overrides precedence covered by tests
  - guardrail: DENY-OVERRIDES: a Block at any layer beats an Allow at any layer
  - fn: Compose + Evaluator.Evaluate
  - inputs: Table-driven 3x3 layer matrix: for each (blocking layer, allowing layer) pair in {system, org, session}², compose policies where layer X blocks domain D and layer Y allows D; evaluate a KindDNSResolve request for D
  - expected: All nine cells yield ActionDeny, with Provenance.RuleID = the block rule and Provenance.Layer = the blocking layer
- **POL-1.e** `TestCompose_SameLayerAllowAndBlock_BlockWins` [unit, ADVERSARIAL]
  - planRef: doc 09 §6 POL-1 (blocklists always win)
  - guardrail: Within a single layer, blocklist beats allowlist regardless of rule order
  - fn: Compose + Evaluator.Evaluate
  - inputs: One policy listing domain D in both Allow and Block, with the Allow rule both before and after the Block rule (two table cases); also subdomain case: Allow "*.example.com", Block "bad.example.com", evaluate bad.example.com
  - expected: ActionDeny in all cases; provenance cites the Block rule. Rule ordering in the document has no effect on the verdict
- **POL-1.f** `TestEvaluate_PostureSemantics` [unit]
  - planRef: doc 09 §6 POL-1 posture (locked/standard/open)
  - guardrail: Posture sets the default verdict for unlisted domains and is itself subject to layering
  - fn: Evaluator.Evaluate
  - inputs: Table: unlisted domain under posture locked (expect Deny), standard (expect Ask per ask-user defaults), open (expect Allow); plus a blocked domain under posture open
  - expected: Verdicts match the posture table; the blocked-domain-under-open case still denies (blocklist beats posture); every decision carries provenance citing the posture/default rule
- **POL-2.a** `TestBaseline_AdmitsExactlyTheIntendedEndpoints` [guardrail-assurance]
  - planRef: doc 09 §6 POL-2 Done-when: every endpoint the §1 test touches is admitted by the shipped pack and nothing else
  - guardrail: The D64 pack admits the exact strawman endpoint set — no more, no fewer
  - fn: DefaultBaseline + Compose + Evaluator.Evaluate
  - inputs: Compose([system: DefaultBaseline()]) alone; evaluate KindDNSResolve and KindTLSSNI for: api.anthropic.com, github.com, api.github.com, codeload.github.com, objects.githubusercontent.com, raw.githubusercontent.com, registry.npmjs.org (all Scope=ScopeVM)
  - expected: All return ActionAllow with provenance citing the d30-baseline pack name+version at LayerSystem. Test asserts the pack's allowlist length equals exactly the enumerated set, so adding an endpoint without updating this spec fails RED
- **POL-2.b** `TestBaseline_DeniesEverythingElse_IncludingLookalikes` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-2 Done-when ("and nothing else") + doc 06 §3(c) default-deny row
  - guardrail: Default-deny holds under the baseline: anything not enumerated is denied, including suffix/prefix lookalike bypasses
  - fn: DefaultBaseline + Evaluator.Evaluate
  - inputs: Table of adversarial names: example.com, api.anthropic.com.evil.test (allowed name as a label prefix), evil-github.com, github.com.attacker.io, xgithub.com, registry.npmjs.org.cdn.attacker.net, GITHUB.COM%00.evil.test, ssh to github.com:22 as KindL4Direct (no hatch), plus an empty-domain request
  - expected: Every case returns ActionDeny (or Ask only if the standard-posture default says so — the baseline test composes with posture locked to isolate the allowlist); none ever returns Allow; each denial carries provenance citing the default-deny/posture rule
- **POL-2.c** `TestBaseline_HostResolvers_GateUpstreamOnly_NeverVM` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-2 baseline table row: 1.1.1.1/8.8.8.8 are host-side egress for ds-dnsgate's own upstream only — never direct VM resolver access
  - guardrail: Baseline resolver entries cannot be exploited by the VM to reach the resolvers directly
  - fn: DefaultBaseline + Evaluator.Evaluate (RequestScope discrimination)
  - inputs: Table: DstIP 1.1.1.1 and 8.8.8.8, ports 53/853/443, Scope=ScopeVM (six cases) vs Scope=ScopeGateUpstream port 53 (two cases)
  - expected: All ScopeVM cases: ActionDeny. ScopeGateUpstream port-53 cases: ActionAllow with provenance citing the upstream-resolution baseline rule. A request that omits Scope (zero value) is denied, never defaulted to the permissive scope
- **POL-2.d** `TestBaseline_DoHDoTResolverBlocklist_Wins` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §9 row "DoH endpoint blocking (baseline blocklist...)" owned by POL-2; doc 09 §6 POL-2 resolver-lock row; doc 06 §3(c) DoH/DoT-bypass row
  - guardrail: Known public DoH/DoT resolver domains are blocked by the shipped baseline, and the block is not overridable by lower layers
  - fn: DefaultBaseline + Compose + Evaluator.Evaluate
  - inputs: Part 1: baseline alone; evaluate KindDNSResolve and KindTLSSNI for dns.google, cloudflare-dns.com, dns.quad9.net. Part 2 (bypass attempt): compose baseline + an org policy AND a session policy that explicitly ALLOWLIST dns.google; re-evaluate
  - expected: Part 1: all ActionDeny with provenance citing the baseline blocklist rule at LayerSystem. Part 2: still ActionDeny — deny-overrides means no downstream allowlist can reopen a baseline-blocked resolver
- **POL-2.e** `TestBaseline_IsOrdinaryPolicy_EmptyExtendReplace` [unit]
  - planRef: doc 09 §6 POL-2: "a team can empty it, extend it, or replace it through the same engine — nothing magic about the defaults"
  - guardrail: No hardcoded allow path exists outside the policy data
  - fn: Compose + Evaluator.Evaluate
  - inputs: Three compositions: (1) empty system policy replacing the baseline → evaluate api.anthropic.com; (2) baseline + org allowlist adding pypi.org → evaluate pypi.org; (3) baseline replaced wholesale by a custom pack admitting only internal.corp.example
  - expected: (1) api.anthropic.com denied — proving the baseline's admits live in data, not code; (2) pypi.org allowed with LayerOrg provenance; (3) only internal.corp.example allowed, all baseline endpoints denied
- **POL-2.f** `TestBaseline_PackIsVersionedAndCitedInProvenance` [contract]
  - planRef: doc 09 §6 POL-2 "a versioned, named policy pack" + POL-3 provenance
  - guardrail: Every baseline decision is attributable to a specific shipped pack version
  - fn: DefaultBaseline + Evaluator.Evaluate
  - inputs: DefaultBaseline(); inspect Name/PackVersion; evaluate one allowed and one blocked domain
  - expected: Name == "d30-baseline", PackVersion non-empty and semver-shaped; both decisions' Provenance.PolicyVersion embeds the composed snapshot version derived from the pack version
- **POL-2.g** `TestE2E_FreshInstall_ReachabilityHalf_ZeroConfig` [e2e-lifecycle]
  - planRef: doc 09 §6 POL-2 Done-when: the reachability half of the §1 test passes on a fresh install with zero policy configuration; doc 09 §1 developer-value test
  - guardrail: Out of the box, the baseline domains resolve and flow and everything else drops, with no policy configured
  - fn: Full boundary harness seam (Evaluator wired into fake ds-dnsgate + fake ds-tlsproxy stubs) with DefaultBaseline as the only layer
  - inputs: Simulated fresh session lifecycle: DNS resolve + TLS SNI connect for each baseline domain; then resolve+connect for example.com and a direct L4 dial to 93.184.216.34:443
  - expected: All baseline-domain steps produce Allow decisions end-to-end; example.com and the raw-IP dial produce Deny decisions; zero policy-layer mutations occurred during the run (snapshot Seq unchanged). Fails RED on ErrNotImplemented until the data plane exists
- **POL-3.a** `TestEvaluate_EveryDecisionCarriesFullProvenance` [contract]
  - planRef: doc 09 §6 POL-3 Done-when: every event carries rule id, policy layer, policy version
  - guardrail: No decision exists without rule id + layer + policy version — including default-deny and Ask
  - fn: Evaluator.Evaluate + ValidateProvenance
  - inputs: Generated matrix: all four RequestKinds x outcomes {explicit allow, blocklist deny, posture default deny, ask, pass-through, swap-service, escape-hatch} against a composed three-layer snapshot (~28 cases, table-driven)
  - expected: ValidateProvenance(decision.Provenance) passes for every cell: non-empty RuleID, Layer in {system,org,session}, PolicyVersion equal to the snapshot's. The implicit default-deny carries a synthetic but stable rule id (e.g. "default-deny"), not an empty string
- **POL-3.b** `TestValidateProvenance_MissingProvenanceIsAFailure` [guardrail-assurance]
  - planRef: doc 09 §6 POL-3 Done-when: a missing-provenance event fails CI
  - guardrail: The CI gate function actually rejects provenance-free decisions
  - fn: ValidateProvenance / ValidateDecisionEvent
  - inputs: Table: zero-value Provenance; missing RuleID only; missing Layer only; missing PolicyVersion only; Layer with an undefined value ("global"); fully-populated Provenance
  - expected: First five cases return a non-nil error identifying the missing/invalid field; the populated case passes. This function is the hook the doc-09 CI rule wires in
- **POL-3.c** `TestProvenance_AttributesTheActuallyMatchedRule` [unit]
  - planRef: doc 09 §6 POL-3: "why was this blocked?" must always have a one-line answer
  - guardrail: Provenance names the rule that decided, not merely a rule that matched
  - fn: Evaluator.Evaluate
  - inputs: Snapshot where domain D matches session-layer allow rule A1 AND org-layer block rule B1 AND a system-layer allow A2; evaluate D
  - expected: Decision is Deny with Provenance.RuleID == B1 and Provenance.Layer == LayerOrg — never A1/A2's id, never the wrong layer
- **POL-3.d** `TestEvaluate_PureDeterministicAndRaceFree` [unit]
  - planRef: doc 09 §6 POL-3 / §2: one engine, identical decision semantics embedded in both services and the nftables path
  - guardrail: Evaluate is a pure function: same (snapshot, request, now) → identical Decision, no mutation, concurrency-safe
  - fn: Evaluator.Evaluate
  - inputs: Fixed snapshot + 1000 evaluations of the same request from 32 goroutines under -race; then deep-compare the snapshot before/after; repeat the single call twice and compare Decisions
  - expected: All 1000 decisions byte-identical; snapshot unchanged (immutability); no race detected; calling order has no effect
- **POL-3.e** `TestOneEngine_AllCallerShapesAgree` [contract]
  - planRef: doc 09 §6 intro: "the DNS gate, the TLS proxy, and the firewall programming can never disagree about a rule"
  - guardrail: The same domain gets the same verdict regardless of which service shape asks
  - fn: Evaluator.Evaluate across RequestKinds
  - inputs: Table over domains {allowed, blocked, unlisted, ask-posture}: for each, evaluate as KindDNSResolve, KindTLSSNI, and KindHTTPRequest with identical session/scope
  - expected: For each domain the Action and Provenance.RuleID are identical across all three kinds (kind-specific fields like SwapService may differ, the verdict may not). Encodes the D63 'siblings can't skew on semantics' property at the pure-function level
- **POL-4.a** `TestSnapshotApply_AtomicNoMixedVersionDecisions` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-4: atomic versioned snapshot + hot reload
  - guardrail: A reload mid-traffic never produces a decision blending two policy versions
  - fn: HostSubscriber.Run + SnapshotConsumer.Reload + Evaluator.Evaluate
  - inputs: Snapshot v1 allows D1 and blocks D2; v2 inverts both. Push v2 while 16 goroutines continuously evaluate D1 and D2, recording (verdict, Provenance.PolicyVersion) pairs
  - expected: Every recorded pair is internally consistent: PolicyVersion v1 ⇒ (D1 allow, D2 deny); v2 ⇒ (D1 deny, D2 allow). No pair ever shows v1's verdict with v2's version or vice versa; no evaluation errors during the swap
- **POL-4.b** `TestHostSubscriber_OnePerHost_ServicesNeverSkew` [guardrail-assurance]
  - planRef: doc 09 §6 POL-4 + OQ7: one subscription per host so the two services can never run different policy versions
  - guardrail: ds-dnsgate and ds-tlsproxy always observe the same policy version after every push
  - fn: HostSubscriber.Register / Run
  - inputs: One HostSubscriber with two registered fake consumers (dnsgate-shaped, tlsproxy-shaped); a fake SnapshotSource pushes 50 sequential snapshots, with the second consumer's Reload artificially slowed
  - expected: After each push quiesces, both consumers' CurrentVersion() agree exactly; at no quiesced point does consumer A run vN while B runs vN-1; the subscriber holds exactly one Subscribe call against the source for its lifetime
- **POL-4.c** `TestCatchUp_OfflineHostResumesBySequenceNumber` [contract]
  - planRef: doc 09 §6 POL-4: offline catch-up via snapshot + sequence number
  - guardrail: A host that missed pushes converges to the latest policy, in order, with no gaps applied
  - fn: SnapshotSource.Subscribe(fromSeq) + HostSubscriber.Run
  - inputs: Fake source advances through Seq 1..10; subscriber runs through Seq 3, is cancelled, then restarted with fromSeq=4 while the source is already at Seq 10
  - expected: On resume the subscriber reaches Seq 10 (either via the snapshots 4..10 in strictly increasing order or a direct latest-snapshot catch-up — never out of order, never a decrease); Current().Seq == 10 and consumers report Seq 10
- **POL-4.d** `TestPush_StaleOrReplayedSnapshotRejected` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-4 (versioned snapshot semantics) — the rollback/replay bypass
  - guardrail: A replayed or out-of-date snapshot cannot roll back a newer block (e.g. un-block a centrally blocked malicious domain)
  - fn: HostSubscriber.Run / SnapshotConsumer.Reload
  - inputs: Apply Seq 5 (blocks evil.test), then inject Seq 4 (predates the block) and a duplicate Seq 5 through the fake source
  - expected: Both injections are refused: Current().Seq stays 5, evil.test still evaluates Deny, consumers' Reload is not invoked for the stale snapshots, and a rejection is observable (error/metric hook recorded by the fake)
- **POL-4.e** `TestPushToEnforced_LatencyBudget` [load]
  - planRef: doc 09 §6 POL-4 Done-when: push-to-enforced latency has a number and the (d) rig tracks it; doc 06 §3(d) policy-push fan-out row
  - guardrail: A centrally pushed malicious-domain block is enforced within the budget ("within seconds")
  - fn: HostSubscriber + Evaluator end-to-end timing
  - inputs: Steady-state evaluations of evil.test (initially allowed by a permissive test policy) at 1k req/s across 100 simulated host subscribers off one fake source; T0 = source emits a snapshot blocklisting evil.test; record per-host T1 = first Deny decision
  - expected: p99(T1−T0) across all hosts is asserted against the budget constant (strawman ≤2s in-process; the constant is the number the rig publishes); 100% of hosts converge; the measurement is emitted as a benchmark metric for the (d) rig dashboard
- **POL-4.f** `TestHotReload_NoEvaluationOutageUnderChurn` [load]
  - planRef: doc 09 §6 POL-4 hot reload; doc 06 §3(d) proxy-tail-latency concern (policy engine is on every request path)
  - guardrail: Continuous snapshot churn never blocks or errors the decision path
  - fn: HostSubscriber.Reload concurrent with Evaluator.Evaluate
  - inputs: 200 snapshots applied at 20/s while 64 goroutines evaluate a mixed request table; record per-call latency and errors
  - expected: Zero Evaluate errors; no call observes latency above the stall budget (no reload-wide lock); throughput during churn ≥ 90% of no-churn baseline
- **POL-5.a** `TestEscapeHatch_WhitelistedProtocolFlowsDirect` [unit]
  - planRef: doc 09 §6 POL-5 Done-when: a whitelisted binary protocol flows direct, gated by the allow-set
  - guardrail: An explicit per-protocol/port hatch yields a direct-L4 allow verdict (which NFT-3 then gates by allow-set)
  - fn: Evaluator.Evaluate (KindL4Direct)
  - inputs: Policy with EscapeHatchRule{Protocol:"ssh", Port:22, Scope: session S1}; evaluate KindL4Direct ssh/22 for github.com from session S1
  - expected: ActionAllow with DirectL4 == true, SwapService empty, PassThrough false; provenance cites the hatch rule id and its defining layer
- **POL-5.b** `TestEscapeHatch_UnlistedPortDeniedWithLoggableDecision` [unit, ADVERSARIAL]
  - planRef: doc 09 §6 POL-5 Done-when: an unlisted port drops and logs
  - guardrail: Anything outside the hatch list is denied, and the denial is a fully-attributed policy-decision event
  - fn: Evaluator.Evaluate (KindL4Direct) + ValidateDecisionEvent
  - inputs: Same policy as POL-5.a; table of bypass attempts: ssh/2222 (right protocol, wrong port), telnet/22 (wrong protocol, right port), udp/123 NTP, tcp/25 SMTP, tcp/22 from session S2 (out of scope)
  - expected: Every case: ActionDeny, DirectL4 false, ValidateDecisionEvent passes (the deny is emittable to ds-flowlog as a PolicyDecision with full provenance) — the 'drops and logs' half made executable at the decision layer
- **POL-5.c** `TestEscapeHatch_ScopeConfinement` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §6 POL-5: scoped per-session/host/org (doc 03 OQ7)
  - guardrail: A hatch granted to one session/host/org never leaks to another
  - fn: Evaluator.Evaluate (GrantScope matching)
  - inputs: Table: hatch scoped {session:S1} evaluated from S1 (allow) and S2 (deny); hatch scoped {org:O1} evaluated from a session in O1 (allow) and O2 (deny); hatch scoped {host:H1} from H1 (allow) and H2 (deny); empty-scope hatch behavior pinned explicitly (deny-by-default until OQ7 resolves, asserted so a future change is a conscious one)
  - expected: All in-scope cells allow, all out-of-scope cells deny; the unscoped-hatch cell denies (documented conservative default)
- **POL-5.d** `TestAskUser_RoutedOverStage0Seam_WithProvenance` [contract]
  - planRef: doc 09 §6 POL-5 Done-when: an ask-routed request surfaces in the (fake) client wrapper over the Stage-0 ask-user seam; doc 09 §8 Stage 0 AskUserRequest contract
  - guardrail: Ask decisions travel the frozen one-way seam carrying session, resource kind, name, and matched rule — the boundary grows no approval UI
  - fn: Evaluator.Evaluate (ActionAsk) + AskRouter.RouteAsk against the Stage-0 fake orchestrator
  - inputs: Standard-posture policy with newdomain.example unlisted; evaluate KindDNSResolve from session S1; pipe the Ask decision through a recording fake AskRouter
  - expected: Decision is ActionAsk with full provenance; exactly one AskUserRequest is recorded with Session==S1, ResourceKind=="domain", Name=="newdomain.example", MatchedRule equal to the decision's provenance; RouteAsk is fire-and-forget (no response payload consumed)
- **POL-5.e** `TestAskApproval_TTLGrantOnPolicyStream_ThenExpires` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §8 Stage 0: approvals return as session-scoped TTL'd allow grants on the already-frozen policy stream; doc 09 §6 POL-5
  - guardrail: An approval admits exactly the approved name for exactly the granted TTL — an expired grant readmits nothing
  - fn: ApplyGrant + Evaluator.Evaluate(now)
  - inputs: Snapshot at Seq N where newdomain.example evaluates Ask for S1; ApplyGrant(Grant{S1, newdomain.example, ExpiresAt: T+5m, Seq: N+1}); evaluate at now=T+1m, now=T+4m59s, now=T+5m1s; also evaluate a sibling name approved-name.example.evil.test at T+1m
  - expected: T+1m and T+4m59s: ActionAllow with provenance citing the grant (LayerSession, snapshot version N+1). T+5m1s: back to ActionAsk — expiry is enforced by the pure function via `now`, no wall-clock sleep. The lookalike name stays Ask/Deny (grant matches the exact approved name). Original Seq-N snapshot still evaluates Ask (immutability)
- **POL-5.f** `TestAskGrant_SessionScoped_NoCrossSessionAdmission` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §8 Stage 0 (session-scoped grants) + doc 06 §3(c) spirit: session A's privileges never reach session B
  - guardrail: A grant approved for session A cannot admit the same domain for session B, and cannot override a blocklist
  - fn: ApplyGrant + Evaluator.Evaluate
  - inputs: Grant for (S1, newdomain.example); evaluate from S2 within the TTL window. Second bypass: ApplyGrant for (S1, dns.google) — a domain on the D64 baseline blocklist — and evaluate from S1
  - expected: S2's request stays Ask/Deny (grant is session-scoped). The dns.google grant either fails ApplyGrant or evaluates Deny with the blocklist's provenance — deny-overrides applies to grants too; an approval can never punch through the resolver-lock blocklist
