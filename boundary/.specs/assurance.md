# Cross-cutting guardrail-assurance (doc 09 §9 matrix) + end-to-end staging (§8) + Stage-0 contract seams — the integration/black-box layer above the per-component suites. Package boundary (github.com/dream-serpent/dream-serpent/boundary). All seams are stubs returning ErrNotImplemented; every test below fails RED until the Rust/Pingora+nftables data plane satisfies the documented outcome.

## SEAMS

### ErrNotImplemented
Purpose: Sentinel every stub returns (errors.Is-checkable). Tests assert documented outcomes, so the suite is RED until the real data plane is wired. A test that sees ErrNotImplemented is failing-as-designed, not erroring.

```go
var ErrNotImplemented = errors.New("boundary: not implemented")
```

### Boundary (facade)
Purpose: Top-level wiring of ds-dnsgate, ds-tlsproxy, NFTables, policy-core, ds-flowlog and the orchestrator seams. The single object every e2e (§8) and §9 guardrail test drives; VM()/Inspect()/Policy()/Orchestrator() expose the black-box surfaces.

```go
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
```

### SessionRef / Session / CreateSessionRequest
Purpose: Identity of one agent VM session. Iface is the per-session interface (NFT-2) used for interface-matched attribution; SessionRef is the join key across nft sets, flow log, and admission map.

```go
type SessionRef struct { ID string; Iface string } // Iface = dstap-<session>, the unforgeable attribution key
type Session struct { Ref SessionRef; ShortLivedCred Secret; InterceptCA CARef; StartedAt time.Time }
type CreateSessionRequest struct { Posture Posture; Policy PolicyVersion; Identity IdentityRef }
```

### VMProbe (in-VM adversarial surface)
Purpose: Models everything the untrusted VM can attempt: forged-source dials, DoT/QUIC/port-53 probes, ECH/absent-SNI/IP-literal TLS, DoH HTTP, and interior scans for leaked creds or observable controls. The adversary's whole toolkit as one interface.

```go
type VMProbe interface {
  ResolveDNS(ctx context.Context, q DNSQuery) (DNSResponse, error)
  Dial(ctx context.Context, req DialRequest) (DialResult, error)
  TLSConnect(ctx context.Context, req TLSConnectRequest) (TLSConnResult, error)
  HTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
  ScanInterior(ctx context.Context, req InteriorScanRequest) (InteriorScan, error)
}
type DNSQuery struct { Name string; Type DNSType; Nameserver netip.Addr } // Nameserver lets a test aim at 8.8.8.8
type DNSResponse struct { Rcode DNSRcode; Answers []DNSRecord; ServedBy string; MinTTL time.Duration }
type DialRequest struct { Proto L4Proto; Dst netip.AddrPort; SpoofSourceIP netip.Addr }
type DialResult struct { Outcome FlowOutcome; RedirectedTo string } // Connected|Dropped|Redirected
type TLSConnectRequest struct { SNI string; DstIP netip.Addr; OfferECH bool; IPLiteral bool; ALPN []string }
type TLSConnResult struct { Outcome TLSOutcome; UpstreamCertValidated bool; LeafCAIssuer string } // Tunneled|Inspected|Refused
type HTTPRequest struct { Method, Host, Path string; Headers map[string]string; Body []byte; ViaProxy bool }
type HTTPResponse struct { Status int; Headers map[string]string }
type InteriorScanRequest struct { Targets []ScanTarget; Needle []byte } // Disk|Env|CoWDelta|ResponseBodies|Controls
type InteriorScan struct { Found bool; Locations []string }
```

### HostInspector (host-side observation)
Purpose: Out-of-band ground truth: the nft ruleset/sets, the DNS-2b admission map, the flow-log event streams (with POL-3 provenance), and the LOG-4 reconciliation verdict. Lets tests assert insert-then-answer ordering, expiry, teardown byte-equality, attribution, and the self-audit alarm.

```go
type HostInspector interface {
  NFTRuleset(ctx context.Context) (RulesetSnapshot, error)
  AllowSet(ctx context.Context, s SessionRef, fam IPFamily) ([]AllowSetEntry, error)
  AdmissionMap(ctx context.Context, s SessionRef) ([]AdmissionEntry, error) // DNS-2b domain->IPs,expiry
  Events(ctx context.Context, s SessionRef) (EventBundle, error) // Flow/Dns/Http/PolicyDecision/CredentialUse
  Reconcile(ctx context.Context) (ReconcileReport, error) // LOG-4
}
type AllowSetEntry struct { Addr netip.Addr; Expiry time.Time }
type AdmissionEntry struct { Domain string; Addrs []netip.Addr; Expiry time.Time }
type EventBundle struct { Flows []FlowRecord; Dns []DnsEvent; Http []HttpEvent; Decisions []PolicyDecision; Creds []CredentialUseEvent }
type ReconcileReport struct { UnexplainedFlows []FlowRecord; Alarm bool }
```

### PolicyControl
Purpose: The one policy-core view both proxies read. Load for baselines/postures, Push for the live malicious-domain block (measured by the (d) rig), Grant for ask-user approvals arriving as TTL'd session-scoped allow grants — so no second response contract is needed.

```go
type PolicyControl interface {
  Load(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error)
  Push(ctx context.Context, snap PolicySnapshot) (PolicyVersion, error) // POL-4 live fleet push
  Grant(ctx context.Context, g AllowGrant) (PolicyVersion, error)       // approval-as-policy-grant
  Active(ctx context.Context) (PolicyVersion, error)
}
type AllowGrant struct { Session SessionRef; Resource ResourceRef; TTL time.Duration }
type PolicySnapshot struct { Layers []PolicyLayer } // system->org->session, deny-overrides
```

### AskUserSeam + AskUserRequest (Stage-0 frozen)
Purpose: The frozen Stage-0 ask-user contract: boundary -> orchestrator notification with no return decision. Approval comes back asynchronously via PolicyControl.Grant on the already-frozen policy stream. Tests pin the one-way shape so neither side can grow a hidden synchronous approval path.

```go
type AskUserSeam interface {
  Notify(ctx context.Context, req AskUserRequest) error // ONE-WAY: error only, no decision return
}
type AskUserRequest struct {
  Session SessionRef
  Kind ResourceKind // Domain|Port|Service
  Name string
  MatchedRule RuleRef // POL-3 provenance: rule id + layer + policy version
}
```

### OrchestratorFake
Purpose: Programmable in-memory orchestrator stand-in (doc 06 §2 fake). Records AskUserRequests and SuspendSignals the boundary emits, and drives approvals back as policy grants — the fake the DNS-3 / TLS-6 tests run against instead of the real attach wrapper.

```go
type OrchestratorFake interface {
  AskUserRequests(ctx context.Context) ([]AskUserRequest, error)
  Approve(ctx context.Context, req AskUserRequest, ttl time.Duration) (PolicyVersion, error)
  SuspendSignals(ctx context.Context) ([]SuspendSignal, error)
}
type SuspendSignal struct { Session SessionRef; Reason SuspendReason; At time.Time }
```

### IdentitySeam (D22) + CAMintSeam (D17)
Purpose: The two Stage-0 neighbor seams the credential swap and TLS inspection depend on: validate the short-lived cred against session identity (TLS-5), and mint the per-session interception CA + on-the-fly leaves (TLS-3). Frozen contract-first, fakes published for neighbor workstreams.

```go
type IdentitySeam interface {
  Validate(ctx context.Context, s SessionRef, presented Secret) (IdentityRef, error)
}
type CAMintSeam interface {
  MintSessionCA(ctx context.Context, s SessionRef) (CARef, error)
  LeafFor(ctx context.Context, ca CARef, origin string) (CertRef, error)
}
```

### Contract harness (real + fake, doc 06 §2)
Purpose: The linchpin of parallel development: one conformance suite run against the real impl and the generated fake. Divergence means either the fake lies or the impl drifted — both caught at the seam per-commit.

```go
type BoundaryFactory func(t testing.TB) (Boundary, func())
func NewRealBoundary(t testing.TB) (Boundary, func())
func NewFakeBoundary(t testing.TB) (Boundary, func())
func RunBoundaryContract(t *testing.T, mk BoundaryFactory) // shared conformance suite executed against BOTH
```


## TESTS

- **C9-1** `TestDefaultDeny_NonAllowlisted_DroppedAtL34AndViaProxy` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Default-deny outbound holds (NFT-1)
  - guardrail: A VM reaching any non-allowlisted destination is denied at L3/4 before the proxy AND via the proxy.
  - fn: VMProbe.Dial, VMProbe.HTTP
  - inputs: Fresh session, baseline policy. Table: raw TCP dial to evil.example:443; HTTP GET http://evil.example/; UDP dial to random:9999.
  - expected: Every attempt -> DialResult.Outcome=Dropped / HTTP refused; HostInspector.Events shows nflog drop with per-session ct mark; nothing reaches upstream.
- **C9-2** `TestSpoof_ForgedSourceIP_StillInterfaceMatched` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: In-VM spoofing fails (NFT-2); Done-when NFT-2
  - guardrail: Forged source addresses do not escape the interface-matched redirect — matching is on iifname, never source IP.
  - fn: VMProbe.Dial
  - inputs: Dial to allowed dst with SpoofSourceIP set to the host/gateway address and to another session's address.
  - expected: Traffic still redirected/gated by the VM's interface; spoof grants no extra reach; drop logged. Outcome independent of SpoofSourceIP.
- **C9-3** `TestResolverBypass_Port53AtPublicIP_StillHitsGate` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Port-53/DoT/QUIC bypass fails (NFT-4); Done-when NFT-4
  - guardrail: All dst-port-53 traffic lands on ds-dnsgate regardless of the IP the VM aimed at.
  - fn: VMProbe.ResolveDNS
  - inputs: DNSQuery{Name:github.com, Nameserver:8.8.8.8} and Nameserver:1.1.1.1.
  - expected: DNSResponse.ServedBy == ds-dnsgate (not the public resolver); answer is the gated/clamped one; a DnsEvent is recorded for the session.
- **C9-4** `TestResolverBypass_DoT853_Dropped` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Port-53/DoT/QUIC bypass fails (NFT-4)
  - guardrail: DNS-over-TLS (TCP 853) is dropped.
  - fn: VMProbe.Dial
  - inputs: Dial TCP to dns.google:853 and to 8.8.8.8:853.
  - expected: DialResult.Outcome=Dropped; drop logged.
- **C9-5** `TestResolverBypass_QUICudp443_DroppedForcingTCPFallback` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Port-53/DoT/QUIC bypass fails (NFT-4, OQ5)
  - guardrail: UDP/443 (QUIC) is dropped so clients fall back to TCP the proxy can see.
  - fn: VMProbe.Dial
  - inputs: Dial UDP to an allowed domain's admitted IP:443.
  - expected: Outcome=Dropped; subsequent TCP/443 to the same host succeeds through the proxy path.
- **C9-6** `TestDoH_BaselineBlocklistDomain_RefusedBySNIandDNS` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: DoH endpoint blocking — baseline half (POL-2 + NFT-4, Stage 2)
  - guardrail: Known public DoH resolver domains are blocked by both DNS denial and the TLS-1 SNI check.
  - fn: VMProbe.ResolveDNS, VMProbe.TLSConnect
  - inputs: Table over dns.google, cloudflare-dns.com, dns.quad9.net: ResolveDNS(name) and TLSConnect{SNI:name}.
  - expected: ResolveDNS -> denied (REFUSED/sinkhole per OQ6); TLSConnect -> TLSOutcome=Refused; PolicyDecision carries the blocklist rule provenance.
- **C9-7** `TestDoH_HTTPLevelOnAllowedHost_Blocked` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: DoH endpoint blocking — HTTP-level half (TLS-6, Stage 4)
  - guardrail: DoH served from an otherwise-allowed host/path is detected and blocked at the HTTP layer.
  - fn: VMProbe.HTTP
  - inputs: HTTP POST to an allowed host with Content-Type application/dns-message (and the GET ?dns= variant).
  - expected: Request blocked at HTTP level; HttpEvent + PolicyDecision recorded; no DoH response body returned.
- **C9-8** `TestRebinding_ReResolveNewPublicIP_NoSilentWiden` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Rebinding fails; allow-set never silently widens (DNS-4 + NFT-3); Done-when DNS-4
  - guardrail: An approved name re-resolving to a new public IP goes through full admission again and never silently widens the set.
  - fn: VMProbe.ResolveDNS, HostInspector.AllowSet
  - inputs: Resolve allowed name (IP A admitted), then upstream rotates to IP B; resolve again.
  - expected: After re-resolution AllowSet contains B via fresh admission; A is not retained beyond its TTL+grace; no widening to extra addresses.
- **C9-9** `TestRebinding_PrivateLinkLocalLoopbackHost_Scrubbed` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Rebinding fails (DNS-4 rule 2)
  - guardrail: Admitted addresses pass the dual-stack sanity filter; private/link-local/loopback/host ranges are never inserted and are scrubbed from answers.
  - fn: VMProbe.ResolveDNS, HostInspector.AllowSet
  - inputs: Table: approved name answers 10.0.0.5, 127.0.0.1, 169.254.1.1, host/gateway addr, ::1, fe80::1, fc00::1.
  - expected: Each scrubbed from DNSResponse.Answers; none appear in AllowSet; a rebinding-scrub DnsEvent is recorded.
- **C9-10** `TestRebinding_IPv4MappedIPv6AndNAT64_Scrubbed` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Rebinding fails incl. IPv4-mapped IPv6 (DNS-4 rule 2, explicit)
  - guardrail: An embedded-IPv4 answer (IPv4-mapped ::ffff:0:0/96 or NAT64 64:ff9b::/96) has the embedded address checked against the IPv4 rules before admission.
  - fn: VMProbe.ResolveDNS, HostInspector.AllowSet
  - inputs: Approved name answers ::ffff:10.0.0.5 and 64:ff9b::a00:5 (embeds 10.0.0.5).
  - expected: Both scrubbed; AllowSet gains nothing; an approved domain cannot reach an internal host via an embedded-v4 answer.
- **C9-11** `TestHTTPSSVCB_Type65Suppressed_NoneReachesVM` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: no HTTPS/SVCB answer reaches a VM (DNS-4 rule 4)
  - guardrail: HTTPS (type 65)/SVCB records are suppressed entirely so no ECH config or alpn=h3 hint reaches the VM.
  - fn: VMProbe.ResolveDNS
  - inputs: DNSQuery{Type:HTTPS} and {Type:SVCB} for an allowed name that really has such records upstream.
  - expected: DNSResponse contains no type-65/SVCB answer (empty/NODATA); the record type never appears in any answer to a VM.
- **C9-12** `TestECH_ClientHelloRefused` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: ECH can't hide a domain behind an admitted IP (TLS-1 + DNS-4)
  - guardrail: ECH ClientHellos are refused (GREASE included) so an encrypted inner name cannot defeat the SNI check.
  - fn: VMProbe.TLSConnect
  - inputs: TLSConnect{SNI:cdn-outer, DstIP:admitted-shared-IP, OfferECH:true}.
  - expected: TLSOutcome=Refused; no opaque tunnel to the shared CDN IP is opened.
- **C9-13** `TestECH_CannotHideDomainBehindAdmittedIP_Integrated` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: ECH can't hide a non-admitted domain behind an admitted IP (DNS-4 + TLS-1)
  - guardrail: With HTTPS-record suppression removing real ECH configs and ECH CH refusal, a non-admitted domain cannot ride an admitted shared IP.
  - fn: VMProbe.ResolveDNS, VMProbe.TLSConnect
  - inputs: Admit cdn-allowed.example (shared IP X). Attempt TLSConnect to X with inner name evil-notadmitted.example via ECH.
  - expected: No ECH config obtained (suppressed) and ECH CH refused; connection to X for the hidden domain fails; only the admitted domain tunnels.
- **C9-14** `TestSNIMismatch_AllowedIPDisallowedSNI_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: TLS-1 Done-when; CDN shared-IP hole (doc 03 OQ1)
  - guardrail: A connection to an admitted IP whose SNI is not the domain that admitted it is refused.
  - fn: VMProbe.TLSConnect
  - inputs: Admit domainA->IP. TLSConnect{SNI:domainB, DstIP:IP} where domainB is not admitted for IP.
  - expected: TLSOutcome=Refused; admission-map lookup for (domainB,IP) misses; PolicyDecision recorded.
- **C9-15** `TestAbsentSNIandIPLiteralTLS_RefusedByDefault` [guardrail-assurance, ADVERSARIAL]
  - planRef: TLS-1 Done-when (edge rules)
  - guardrail: Absent-SNI and IP-literal TLS are refused by default.
  - fn: VMProbe.TLSConnect
  - inputs: Table: TLSConnect{SNI:""} and TLSConnect{IPLiteral:true, DstIP:admitted}.
  - expected: Both -> TLSOutcome=Refused.
- **C9-16** `TestResolveOnceClient_SetExpiryMidSession_ReAdmittedNotRefused` [guardrail-assurance]
  - planRef: TLS-1 Done-when; OQ3; DNS-2b
  - guardrail: A policy-allowed domain whose admission expired (resolve-once/pooled client) is re-admitted, not refused.
  - fn: VMProbe.TLSConnect, HostInspector.AdmissionMap
  - inputs: Admit domain, let admission+set entry expire, then TLSConnect to the cached original IP without re-resolving.
  - expected: Re-resolution through DNS-2 admission path; connection succeeds upstream to a freshly admitted address even if CDN rotated; not Refused.
- **C9-17** `TestSessionIsolation_AtoB_NoL2Path` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Session A cannot reach session B (§2 placement + NFT-1)
  - guardrail: No L2 path exists between any two agent VMs; A cannot reach B directly.
  - fn: VMProbe.Dial
  - inputs: Two sessions A,B. From A, Dial B's VM address on several ports incl. ARP/L2 reach probe.
  - expected: All attempts Dropped/unreachable; traffic never transits agent-to-agent; only the gateway path exists.
- **C9-18** `TestCredentialNeverInVM_DiskEnvCoWResponse` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Long-lived credential never enters the VM (TLS-5 Done-when)
  - guardrail: The long-lived credential never appears inside the VM — not on disk, env, CoW delta, or any readable response.
  - fn: VMProbe.ScanInterior, VMProbe.HTTP
  - inputs: Perform a credential-swapped GitHub request, then ScanInterior{Targets:[Disk,Env,CoWDelta,ResponseBodies], Needle:realToken}.
  - expected: InteriorScan.Found=false everywhere; only the short-lived cred is present; a CredentialUseEvent exists carrying a fingerprint, never the value.
- **C9-19** `TestPinnedPassThrough_OpaqueNoSwap_OffListInspected` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Pinned pass-through opaque, no swap; all else inspected (TLS-4)
  - guardrail: A pass-through-listed pinned client tunnels opaquely with no cred swap; everything off the list is TLS-terminated at the egress gateway.
  - fn: VMProbe.TLSConnect, HostInspector.Events
  - inputs: Table: pinned domain (on list) and a non-pinned allowed domain.
  - expected: Pinned -> TLSOutcome=Tunneled, LeafCAIssuer empty, no CredentialUseEvent, still SNI+allow-set enforced + netflow-accounted. Non-pinned -> Inspected with per-session leaf and HttpEvent metadata.
- **C9-20** `TestSuspendOnBreach_FiresAndResumeInvisible` [guardrail-assurance]
  - planRef: §9 row: Suspend-on-breach fires; resume invisible (TLS-6); Stage 4
  - guardrail: Tripping a declared behavioral cap suspends the VM mid-action and the resume is invisible to the agent.
  - fn: VMProbe.HTTP, Boundary.Resume, OrchestratorFake.SuspendSignals
  - inputs: Policy with a cap on one resource; drive requests past the cap, then Resume.
  - expected: A SuspendSignal is emitted, the VM is paused mid-action, and after Resume the agent's in-flight action continues with no observable gap.
- **C9-21** `TestControlsUnobservable_FromInsideVM` [guardrail-assurance, ADVERSARIAL]
  - planRef: §9 row: Controls unobservable/unmodifiable from inside the VM (NFT-1 + §2 placement)
  - guardrail: From inside the VM the proxy/NFTables/policy engine/identity are neither observable nor modifiable.
  - fn: VMProbe.ScanInterior, VMProbe.Dial
  - inputs: ScanInterior{Targets:[Controls]}; attempt to reach the boundary's own nft/control/admin ports from the VM; attempt to write firewall sets.
  - expected: InteriorScan.Found=false for control artifacts; all reach/modify attempts Dropped; no allow-set mutation possible from the VM.
- **C9-22** `TestPerSessionCA_SessionAUselessAgainstB` [guardrail-assurance, ADVERSARIAL]
  - planRef: TLS-3 Done-when
  - guardrail: The per-session interception CA from session A is useless against session B.
  - fn: CAMintSeam.MintSessionCA, VMProbe.TLSConnect
  - inputs: Mint CA for A; from B, present/trust A's CA and TLSConnect through B's path.
  - expected: B's inspected leaves chain to B's CA only; A's CA does not validate any B flow; cross-session interception fails.
- **C9-23** `TestReconciliation_MisruledHost_TripsAlarm` [guardrail-assurance, ADVERSARIAL]
  - planRef: LOG-4 Done-when; §9 (c) self-audit
  - guardrail: Every byte off a VM interface must be explained by a proxy session or escape-hatch; an unexplained flow is an alarm.
  - fn: HostInspector.Reconcile
  - inputs: Deliberately mis-rule the host so a flow bypasses the redirect; run Reconcile.
  - expected: ReconcileReport.Alarm=true with the unexplained flow listed; clean host yields Alarm=false.
- **C9-24** `TestProvenance_EveryEventCarriesRuleLayerVersion` [contract]
  - planRef: POL-3 Done-when
  - guardrail: Every decision event from both proxies carries matched rule id, policy layer, and policy version; a missing-provenance event fails CI.
  - fn: HostInspector.Events
  - inputs: Drive the (a) suite of allow/deny/ask/swap/pass-through/cap flows; collect Decisions.
  - expected: Every PolicyDecision has non-empty rule id + layer + version; any event missing provenance fails the test.
- **C9-25** `TestAllowSet_EntryExpires_NewDroppedEstablishedSurvives_ReResolveRestores` [guardrail-assurance]
  - planRef: NFT-3 Done-when
  - guardrail: On expiry, new flows to the address drop while an in-flight established stream survives; re-resolution restores without widening.
  - fn: HostInspector.AllowSet, VMProbe.Dial, VMProbe.ResolveDNS
  - inputs: Admit address, open a long-lived stream, let the entry timeout (TTL+grace), then attempt a new flow and a re-resolution.
  - expected: Established stream uninterrupted (ct state established); new flow to the expired addr Dropped; re-resolution restores exactly that address, set unchanged otherwise.
- **C9-26** `TestAdmission_InsertThenAnswer_NoWindow` [guardrail-assurance, ADVERSARIAL]
  - planRef: DNS-2 Done-when; DNS-2b
  - guardrail: On an allowed resolution the IP enters the nft set and admission map before the VM is answered — no window where the VM holds an IP the firewall lacks.
  - fn: VMProbe.ResolveDNS, HostInspector.AllowSet, HostInspector.AdmissionMap
  - inputs: Resolve an allowed name; immediately (racing) read AllowSet and AdmissionMap before/at answer time.
  - expected: At the moment the answer is observable to the VM, the address is already in AllowSet and AdmissionMap (insert-then-answer ordering holds).
- **C9-27** `TestSecretScanInbound_SeededTokenDetected_HookFires` [guardrail-assurance]
  - planRef: TLS-7 Done-when
  - guardrail: A long-lived token entering the VM on the inspected path is detected and the configured hook fires.
  - fn: VMProbe.HTTP
  - inputs: Inbound inspected response carrying a seeded long-lived token pattern.
  - expected: Detection event recorded and the configured hook fires; pass-through (uninspected) path is out of scope and not asserted here.
- **E2E-1** `TestLifecycle_CreateAttachWorkSnapshotSuspendResumeDestroy` [e2e-lifecycle]
  - planRef: §8 e2e; doc 06 (b)
  - guardrail: The full session lifecycle completes deterministically end to end.
  - fn: Boundary.CreateSession, Attach, Snapshot, Suspend, Resume, DestroySession
  - inputs: One session driven through every stage with a representative workload (resolve+flow+HTTP).
  - expected: Each stage succeeds; the work performed pre-snapshot is intact post-resume; destroy returns clean.
- **E2E-2** `TestLifecycle_CreateToAttach_StartTimeBudget` [e2e-lifecycle]
  - planRef: doc 06 (b) seconds-to-start; doc 04 §4
  - guardrail: create->attach completes within the headline start-time budget.
  - fn: Boundary.CreateSession, Boundary.Attach
  - inputs: Timed create then attach, repeated for a stable percentile.
  - expected: Elapsed within the asserted budget; a regression is a release blocker (RED until measured against the real stack).
- **E2E-3** `TestTeardown_NoLeakedNFTRulesOrSets_ByteIdentical` [e2e-lifecycle]
  - planRef: NFT-6 Done-when; doc 06 (b) clean-teardown
  - guardrail: create->destroy run N times leaves the ruleset byte-identical to bootstrap.
  - fn: Boundary.DestroySession, HostInspector.NFTRuleset, HostInspector.AllowSet
  - inputs: Snapshot bootstrap RulesetSnapshot; loop create->destroy N times; re-snapshot.
  - expected: Final NFTRuleset byte-identical to bootstrap; AllowSet and AdmissionMap empty for destroyed sessions; no leaked interface rules/sets.
- **E2E-4** `TestTeardown_NoDanglingOverlayIdentityOrProxySession` [e2e-lifecycle]
  - planRef: doc 06 (b) clean-teardown (overlay/identity/proxy session)
  - guardrail: Destroy leaves no stranded proxy session, no leftover minted identity, no dangling admission/overlay state.
  - fn: Boundary.DestroySession, HostInspector.AdmissionMap, IdentitySeam.Validate
  - inputs: Create with minted identity + active proxy session + admission entries; destroy; probe for residue.
  - expected: AdmissionMap empty, the minted identity no longer validates, the proxy session is gone; zero residue.
- **E2E-5** `TestResumeInvisible_StateSurvivesRoundTrip` [e2e-lifecycle]
  - planRef: doc 06 (b) state-survives; doc 03 §7 / OQ8
  - guardrail: snapshot->suspend->resume returns an agent that cannot tell it was paused; in-flight tooling recovers.
  - fn: Boundary.Snapshot, Suspend, Resume
  - inputs: Start in-VM work and an in-flight TCP stream, snapshot+suspend mid-stream, resume.
  - expected: In-VM work continues; the in-flight stream recovers (no agent-visible break); state matches pre-suspend.
- **DV-1** `TestReachabilityHalf_BaselineDomainsFlow_EverythingElseDrops_ZeroConfig` [e2e-lifecycle]
  - planRef: §1 reachability half; POL-2; Stage 2
  - guardrail: On a fresh install with zero policy config the baseline domains resolve+flow and everything else drops.
  - fn: VMProbe.ResolveDNS, VMProbe.HTTP, VMProbe.Dial
  - inputs: Table over the D64 baseline (api.anthropic.com, github.com/api.github.com/codeload/objects/raw.githubusercontent.com, registry.npmjs.org) plus a not-allowed control domain.
  - expected: Each baseline endpoint resolves and an HTTPS flow succeeds; the control domain is denied at DNS and L3/4; nothing outside the pack is admitted.
- **DV-2** `TestReachabilityHalf_CNAMEChainedCDN_TerminalsOnlyAdmitted` [contract]
  - planRef: DNS-2 Done-when (registry.npmjs.org)
  - guardrail: A CNAME-chained CDN domain flows by admitting only the chain's terminal addresses; intermediate CDN hostnames are never allowlisted.
  - fn: VMProbe.ResolveDNS, HostInspector.AllowSet, HostInspector.AdmissionMap
  - inputs: Resolve registry.npmjs.org (CNAME chain to a CDN).
  - expected: Flow succeeds; AllowSet holds only terminal addresses keyed to the original query name; intermediate CNAME targets are neither evaluated nor admitted; chain-minimum TTL drives the timeout.
- **DV-3** `TestCredentialedHalf_AnthropicAPICall_StreamingSurvivesExpiry` [e2e-lifecycle]
  - planRef: §1 credentialed half; Stage 3; NFT-3 established-flow rule
  - guardrail: The agent's own model API call succeeds and a streaming response is never severed by an allow-set expiry.
  - fn: VMProbe.HTTP
  - inputs: Long streaming request to api.anthropic.com that outlives the allow-set element timeout.
  - expected: Stream completes uninterrupted (established flow rides conntrack); HttpEvent metadata recorded.
- **DV-4** `TestCredentialedHalf_GitHubPush_NoLongLivedCred_AuditEmitted` [e2e-lifecycle]
  - planRef: §1 credentialed half; TLS-5 + LOG-5; Stage 3
  - guardrail: A GitHub push succeeds with the credential swapped, the long-lived cred never in the VM, and the use is auditable without the value.
  - fn: VMProbe.HTTP, VMProbe.ScanInterior, HostInspector.Events
  - inputs: Push to api.github.com using the short-lived cred; then ScanInterior for the real token; read CredentialUseEvent.
  - expected: Push succeeds; ScanInterior.Found=false; a CredentialUseEvent answers which session used the GitHub key, when, for what request — value absent, fingerprint present.
- **S0-1** `TestContractParity_BoundaryRealVsFake` [contract]
  - planRef: doc 06 §2 contract-twice; Stage 0
  - guardrail: The boundary conformance suite passes identically against the real impl and the generated fake; divergence is caught.
  - fn: RunBoundaryContract, NewRealBoundary, NewFakeBoundary
  - inputs: RunBoundaryContract(t, NewRealBoundary) and RunBoundaryContract(t, NewFakeBoundary).
  - expected: Both runs assert the same observable contract; any divergence fails (the fake is lying or the impl drifted).
- **S0-2** `TestAskUserSeam_OneWayNotification_NoDecisionReturn` [contract]
  - planRef: Stage 0 ask-user seam
  - guardrail: AskUserRequest is a one-way notification boundary->orchestrator carrying session/kind/name/matched-rule, with no return decision.
  - fn: AskUserSeam.Notify, OrchestratorFake.AskUserRequests
  - inputs: Trigger an ask-posture flow; inspect the Notify signature and the recorded request.
  - expected: Notify returns only error (no decision value); the recorded AskUserRequest carries SessionRef, ResourceKind, Name, and POL-3 RuleRef provenance.
- **S0-3** `TestAskUser_ApprovalAsPolicyGrant_PostApprovalRetrySucceeds` [contract]
  - planRef: Stage 0; DNS-3; POL-5
  - guardrail: Approval returns as a session-scoped TTL'd allow grant on the already-frozen policy stream — no second response contract — and the first post-approval retry succeeds.
  - fn: OrchestratorFake.Approve, PolicyControl.Grant, VMProbe.ResolveDNS
  - inputs: Ask-posture name -> Notify; Approve with a TTL; re-resolve.
  - expected: No separate approval-response API exists; the grant lands on the policy stream; the first post-approval retry resolves successfully and expires at TTL.
- **S0-4** `TestAskUser_DenyIsREFUSED_NotCacheableSignal` [guardrail-assurance, ADVERSARIAL]
  - planRef: DNS-3 Done-when; OQ6
  - guardrail: Ask-posture names get an immediate REFUSED (never NXDOMAIN/SERVFAIL) so in-VM stubs do not negatively cache the denial through the approval window.
  - fn: VMProbe.ResolveDNS
  - inputs: Resolve an ask-posture name against the golden-image stub-resolver config.
  - expected: Rcode=REFUSED (not NXDOMAIN, not SERVFAIL); no cacheable negative answer; the post-approval retry is not blinded by a stub cache.
- **S0-5** `TestFlowLogSchema_LOG1Frozen_BufGreen` [contract]
  - planRef: LOG-1 Done-when; Stage 0 freeze
  - guardrail: The LOG-1 event messages are part of the Stage-0 contract freeze and survive buf lint + breaking.
  - fn: HostInspector.Events (schema shape)
  - inputs: Construct FlowRecord, DnsEvent, HttpEvent, PolicyDecision, CredentialUseEvent sharing SessionRef; run the buf gate fixture.
  - expected: All messages present in shared proto, buf lint + buf breaking green, fakes regenerate; metadata-only (no packet capture fields).
- **S0-6** `TestIdentityValidationSeam_Contract_RealVsFake` [contract, ADVERSARIAL]
  - planRef: Stage 0 identity-validation seam (D22)
  - guardrail: The short-lived cred validates against the session identity through a stable seam, identical on real and fake.
  - fn: IdentitySeam.Validate
  - inputs: Valid cred for session A; A's cred presented under session B; expired cred.
  - expected: A-valid -> IdentityRef for A; cross-session and expired -> error; real and fake agree.
- **S0-7** `TestCAMintSeam_Contract_PerSessionScoped` [contract, ADVERSARIAL]
  - planRef: Stage 0 CA-mint seam (D17)
  - guardrail: The per-session interception CA is minted through a stable seam and scoped to its session.
  - fn: CAMintSeam.MintSessionCA, CAMintSeam.LeafFor
  - inputs: Mint CA for A and B; request leaves for an origin under each.
  - expected: Each leaf chains only to its own session CA; A's CA cannot issue/validate B's leaves; real and fake agree.
- **S0-8** `TestSuspendSignalSeam_Contract_OneWayObservable` [contract]
  - planRef: Stage 0 suspend signal
  - guardrail: The suspend signal is a one-way boundary->orchestrator notification, observable on the fake.
  - fn: OrchestratorFake.SuspendSignals
  - inputs: Drive a breach that emits a suspend; read SuspendSignals.
  - expected: A SuspendSignal with session + reason + timestamp is recorded; no synchronous suspend-decision return path exists.
- **S0-9** `TestPolicySnapshot_LayeredCompose_DenyOverrides_RoundTrip` [contract]
  - planRef: POL-1 Done-when; Stage 0 policy stream
  - guardrail: A system->org->session layered policy round-trips parse->evaluate with deny-overrides precedence.
  - fn: PolicyControl.Load, PolicyControl.Active
  - inputs: Three layers where a session-layer allow is overridden by an org-layer block and a blocklist entry.
  - expected: Evaluation yields deny (blocklists/deny always win); a sample policy per posture round-trips; version is stamped on the snapshot.
- **LOAD-1** `TestLoad_ConcurrentVMs_ProxyP99WithinBudget` [load]
  - planRef: doc 06 (d); §5; Stage 5
  - guardrail: Many VMs through one proxy keep p99 latency within budget under fan-out.
  - fn: VMProbe.HTTP (N concurrent sessions)
  - inputs: N concurrent sessions issuing inspected HTTPS through ds-tlsproxy.
  - expected: Measured p99 within the asserted budget; the resource floor holds under oversubscription.
- **LOAD-2** `TestLoad_PolicyPushFanout_EnforcedWithinSeconds` [load]
  - planRef: POL-4 Done-when; doc 06 (d)
  - guardrail: A centrally pushed malicious-domain block is enforced fleet-wide within seconds.
  - fn: PolicyControl.Push, VMProbe.ResolveDNS
  - inputs: Push a block for a previously-allowed domain across the fleet; measure time until every host denies it.
  - expected: Push-to-enforced latency is measured and within the seconds budget across all hosts; both services on a host share the version.
- **LOAD-3** `TestLoad_PackageStampede_CacheEffective` [load]
  - planRef: doc 06 (d); doc 03 §6; Stage 5
  - guardrail: A swarm of fresh sessions pulling dependencies at once does not saturate the registry proxy.
  - fn: VMProbe.HTTP (stampede of sessions)
  - inputs: M fresh sessions simultaneously pulling from registry.npmjs.org through the cache.
  - expected: Cache/pre-bake absorbs the stampede; the single registry proxy stays within latency/throughput bounds.
- **LOAD-4** `TestLoad_DNSResolutionP99_WarmBudget` [load]
  - planRef: DNS-1 Done-when; doc 06 (d)
  - guardrail: Added DNS resolution latency stays within budget under a fleet of VMs resolving at once.
  - fn: VMProbe.ResolveDNS (N concurrent)
  - inputs: N concurrent VMs resolving allowed names, warm cache.
  - expected: p99 added resolution latency within the strawman budget (<=10ms warm); it sits on every first connection's critical path.
- **LOAD-5** `TestLoad_AllowSetChurn_UnderFanout` [load]
  - planRef: NFT-3; Stage 5 (d) rig
  - guardrail: Allow-set insert/expire churn under fan-out does not drop valid new flows or leak entries.
  - fn: HostInspector.AllowSet, VMProbe.ResolveDNS
  - inputs: High-rate resolve/expire cycles across many sessions.
  - expected: Set stays consistent under churn; valid new flows admitted, expired entries reaped, no cross-session leakage.
