# ds-tlsproxy — TLS / HTTP CONNECT proxy + credential swapper (doc 09 §5, TLS-1..TLS-8)

## SEAMS

### ErrNotImplemented
Purpose: Sentinel every stub returns so the whole suite fails RED until the Rust data plane satisfies the executable spec (doc 04 D26).

```go
var ErrNotImplemented = errors.New("tlsproxy: not implemented")
```

### SessionRef / Secret / Credential
Purpose: Session identity threading plus a self-redacting secret type: events/logs may only ever carry Fingerprint, never Value. Tests compare raw bytes explicitly via the canary.

```go
type SessionRef struct{ ID string }; type Secret []byte; func (Secret) String() string { return "[REDACTED]" }; type Credential struct { Value Secret; Fingerprint string }
```

### Provenance / Decision
Purpose: POL-3 decision provenance carried on every verdict and event; a missing-provenance event is a test failure.

```go
type Provenance struct { RuleID, PolicyLayer, PolicyVersion string }; type Decision struct { Allow bool; Provenance Provenance }
```

### ClientHello
Purpose: Parsed SNI-peek result for TLS-1. SNI=="" models absent SNI; HasECH covers both real ECH and GREASE (indistinguishable by design, both refused).

```go
type ClientHello struct { SNI string; HasECH bool; ALPN []string; Raw []byte }
```

### TunnelGate
Purpose: The TLS-1 decision seam: SNI allowed by policy AND origDst admitted FOR THAT DOMAIN (DNS-2b), ECH/absent-SNI/IP-literal refusal, and the re-admission path. Upstream may legally differ from origDst only via re-admission — never from the client's claim.

```go
Evaluate(ctx context.Context, sess SessionRef, hello ClientHello, origDst netip.AddrPort) (TunnelDecision, error) — with type Action int (ActionRefuse|ActionTunnelOpaque|ActionInspect|ActionPassThrough); type TunnelDecision struct { Action Action; Upstream netip.AddrPort; Reason string; Provenance Provenance }
```

### AdmissionMap
Purpose: Read side of the DNS-2b host-local per-session (domain -> admitted IPs, expiry) store. Faked/programmable in tests: the NFT sets hold bare IPs and cannot answer 'admitted for which domain' — this seam can.

```go
Lookup(ctx context.Context, sess SessionRef, domain string) (Admission, bool, error); AdmittedFor(ctx context.Context, sess SessionRef, addr netip.Addr, domain string) (bool, error) — with type Admission struct { Domain string; Addrs []netip.Addr; Expiry time.Time }
```

### ReAdmitter
Purpose: TLS-1 lapsed-admission path back through DNS-2 full admission: resolve-once clients survive set expiry; CDN rotation yields a freshly admitted upstream address sourced from OUR resolution.

```go
ReAdmit(ctx context.Context, sess SessionRef, domain string) (Admission, error)
```

### PolicyEngine
Purpose: Embedded policy-core seam: identical rule evaluation across transparent/CONNECT/forward modes, the TLS-4 pass-through list (policy, not code), and the TLS-5 credential-swap service registry (ServiceRule{Service, Hosts, CredLocation}).

```go
EvaluateConnect(ctx, sess SessionRef, domain string) (Decision, error); EvaluateHTTP(ctx, sess SessionRef, req RequestMeta) (Decision, error); PassThrough(ctx, sess SessionRef, domain string) (bool, Provenance, error); MatchSwapService(ctx, host string) (ServiceRule, bool, error)
```

### CAMinter / SessionCA
Purpose: D17 per-session interception CA seam (mint owner: Identity workstream; faked here). Drives TLS-3 on-the-fly per-origin leaf minting and the per-session CA isolation assertion (A's CA useless against B).

```go
MintSessionCA(ctx context.Context, sess SessionRef) (SessionCA, error); type SessionCA interface { LeafFor(ctx context.Context, origin string) (tls.Certificate, error); CertPool() ([]byte, error) }
```

### UpstreamDialer
Purpose: Upstream re-origination with strict WebPKI validation against domain (at least as strict as the client's would have been). Tests wrap it with a recorder to assert WHICH address was dialed (fresh admission vs client claim) and exercise bad-cert upstreams.

```go
DialTLS(ctx context.Context, sess SessionRef, domain string, addr netip.AddrPort) (net.Conn, error)
```

### IdentityValidator
Purpose: D22 sidecar seam: the presented short-lived credential must validate against THIS session's identity before any secret-store fetch. Cross-session/forged/expired creds fail here.

```go
ValidateShortLived(ctx context.Context, sess SessionRef, presented Credential) (IdentityClaims, error) — with type IdentityClaims struct { Session SessionRef; Subject string; Expiry time.Time }
```

### SecretStore
Purpose: The real-credential source OUTSIDE the boundary (separate trust zone, D8/D22). Tests assert it is never called on validation failure or registry miss, and that its returned Value reaches only the upstream leg.

```go
FetchLongLived(ctx context.Context, service string, claims IdentityClaims) (Credential, error)
```

### CredentialSwapper
Purpose: The D8 swap itself: validate short-lived cred, substitute the long-lived one into the upstream request in place. Outcome carries fingerprint only — never the value.

```go
Swap(ctx context.Context, sess SessionRef, rule ServiceRule, req *RequestMeta) (SwapOutcome, error) — with type SwapOutcome struct { Swapped bool; Service string; Fingerprint string; Provenance Provenance }
```

### ResponseScrubber
Purpose: Enforces the 'not in any readable response' clause of the TLS-5 invariant on the VM-bound leg — an upstream echoing the swapped Authorization header back must never deliver the long-lived value downstream.

```go
ScrubResponse(ctx context.Context, sess SessionRef, resp *ResponseMeta, body io.Reader) (io.Reader, []ScrubHit, error)
```

### RateLimiter / CapMonitor / SuspendSignaler
Purpose: TLS-6 seams: per-session/per-service rate limits, the behavioral-cap mechanism, and the Stage-0-frozen orchestrator suspend signal (faked) for the suspend-on-breach §9 row.

```go
Allow(ctx, sess SessionRef, service string) (RateDecision, error); Record(ctx, sess SessionRef, act ResourceAction) (CapVerdict, error); Suspend(ctx, sess SessionRef, breach BreachInfo) error
```

### SecretScanner / SecretHook
Purpose: TLS-7 inbound secret-scanning gate on the inspected path: the boundary owns the inspection point and the hook; rules/response ownership stays OQ8 (scanner is pluggable).

```go
ScanInbound(ctx context.Context, sess SessionRef, meta ResponseMeta, body []byte) ([]Finding, error); OnFinding(ctx context.Context, sess SessionRef, f Finding) error
```

### EventSink
Purpose: Single egress for ALL telemetry/log paths (HttpEvent, PolicyDecision, CredentialUseEvent, Flow — mirrors LOG-1). Tests capture every emission to prove credential scrubbing on every log path and provenance completeness (POL-3).

```go
Emit(ctx context.Context, ev Event) error — with type Event struct { Kind EventKind; Session SessionRef; At time.Time; Provenance Provenance; Fields map[string]string }
```

### LeakProbe
Purpose: Harness-side seam over every VM-observable surface — disk, env, CoW delta, and a full recording of every byte the proxy sent toward the VM. The headline credential-leak-absence test greps all surfaces for the canary and asserts zero hits.

```go
Search(ctx context.Context, sess SessionRef, needle []byte) ([]LeakHit, error) — with type Surface string (disk|env|cow-delta|downstream-bytes); type LeakHit struct { Surface Surface; Offset int64; Context string }
```

### Proxy + New
Purpose: The black-box system under test: the three ingress modes (NFT-2b transparent redirect with recovered original destination, explicit CONNECT, plain-HTTP forward), per-session teardown in lockstep with NFT-6, and a constructor bundling all dependency seams (Deps struct) so fakes are injected wholesale.

```go
type Proxy interface { ServeTransparentTLS(ctx context.Context, downstream net.Conn, sess SessionRef, origDst netip.AddrPort) error; ServeCONNECT(ctx context.Context, downstream net.Conn, sess SessionRef) error; ServeHTTPForward(ctx context.Context, downstream net.Conn, sess SessionRef) error; TeardownSession(ctx context.Context, sess SessionRef) error; Close(ctx context.Context) error }; func New(cfg Config, deps Deps) (Proxy, error)
```


## TESTS

- **TLS-1.a** `TestTunnel_AllowedDomainAdmittedIP_TunnelsOpaque` [contract]
  - planRef: doc 09 §5 TLS-1 Done-when (conformance clients pass cleanly)
  - guardrail: An allowed domain whose original destination is live-admitted for that domain tunnels opaquely end to end
  - fn: Proxy.ServeTransparentTLS / TunnelGate.Evaluate
  - inputs: Session S; admission map programmed {github.com -> 140.82.1.1, expiry +60s}; ClientHello SNI=github.com; origDst=140.82.1.1:443; fake upstream echoes bytes
  - expected: TunnelDecision{ActionTunnelOpaque, Upstream=140.82.1.1:443}; payload bytes flow both ways unmodified; FlowEvent emitted with provenance
- **TLS-1.b** `TestTunnel_MismatchedSNI_SharedCDNIP_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 Done-when (non-matching SNI refused) + §4 DNS-2b Done-when; doc 03 OQ1 shared-CDN hole
  - guardrail: An IP admitted for domain A must not admit a connection presenting domain B's SNI — admission is per-domain, not per-IP
  - fn: TunnelGate.Evaluate
  - inputs: Admission map: {allowed-a.com -> 151.101.1.1}; ClientHello SNI=evil-behind-cdn.com (not admitted, and table variant: admitted for a DIFFERENT IP); origDst=151.101.1.1:443
  - expected: ActionRefuse; zero upstream bytes; PolicyDecision event with deny provenance
- **TLS-1.c** `TestTunnel_ECHClientHello_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 edge rule 1; §9 row 'ECH can't hide a non-admitted domain behind an admitted IP'
  - guardrail: An encrypted inner server name cannot defeat the SNI check behind a shared CDN IP
  - fn: TunnelGate.Evaluate / Proxy.ServeTransparentTLS
  - inputs: ClientHello with encrypted_client_hello extension, outer SNI=allowed-cdn-name.com, origDst admitted for that outer name (the strongest bypass shape)
  - expected: ActionRefuse despite outer SNI+IP both being admitted; no tunnel, no upstream dial
- **TLS-1.d** `TestTunnel_GREASEECH_Refused_DocumentedBehavior` [unit, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 edge rule 1 (GREASE indistinguishable, refused, documented+tested)
  - guardrail: GREASE ECH cannot be used as a labeling loophole — anything carrying the ECH extension is refused uniformly
  - fn: TunnelGate.Evaluate
  - inputs: ClientHello with GREASE-pattern ECH payload, SNI and origDst otherwise fully admitted
  - expected: ActionRefuse with a distinct, documented Reason; behavior identical to real ECH
- **TLS-1.e** `TestTunnel_AbsentSNI_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 edge rule 2
  - guardrail: No SNI means no domain-level policy check is possible — refuse by default
  - fn: TunnelGate.Evaluate
  - inputs: ClientHello SNI=""; origDst is an admitted IP (admitted for some allowed domain)
  - expected: ActionRefuse; admitted-IP status alone never admits a flow
- **TLS-1.f** `TestTunnel_IPLiteralSNI_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 edge rule 2 (absent-SNI / IP-literal refused by default)
  - guardrail: An IP literal in SNI cannot substitute for a policy-evaluated domain name
  - fn: TunnelGate.Evaluate
  - inputs: Table: SNI="140.82.1.1", SNI="[2606:50c0::1]", origDst matching the literal and admitted for an allowed domain
  - expected: ActionRefuse for every row
- **TLS-1.g** `TestTunnel_LapsedAdmission_SameIP_ReAdmitted` [contract]
  - planRef: doc 09 §5 TLS-1 Done-when (resolve-once client survives set expiry); OQ3 resolve-once clients
  - guardrail: A policy-allowed domain whose admission expired is re-admitted, not refused — JVM/pooled clients that resolved once keep working
  - fn: Proxy.ServeTransparentTLS + ReAdmitter.ReAdmit
  - inputs: Admission for api.anthropic.com expired (Expiry in past); ClientHello SNI=api.anthropic.com; origDst=old IP; fake ReAdmitter re-resolves to the same IP
  - expected: ReAdmit called exactly once; connection succeeds to that IP; fresh Admission recorded; no refusal
- **TLS-1.h** `TestTunnel_CDNRotation_DialsFreshAdmission_NeverClientClaim` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 (re-admitted ... connect upstream to a freshly admitted address ... not the client's claim)
  - guardrail: After CDN rotation the upstream address comes from OUR resolution; the client's claimed original destination is never dialed
  - fn: Proxy.ServeTransparentTLS + UpstreamDialer (recorded)
  - inputs: Expired admission for registry.npmjs.org at 1.2.3.4; client connects with origDst=1.2.3.4 (attacker-favorable stale IP); ReAdmitter now returns {5.6.7.8}
  - expected: UpstreamDialer.DialTLS called with 5.6.7.8:443; 1.2.3.4 never dialed; tunnel succeeds; client-side origin cert validation still possible (opaque tunnel preserved)
- **TLS-1.i** `TestTunnel_LapsedAdmission_PolicyNowDenies_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-1 re-admission path × DNS-4 rule 3 (re-resolutions go through FULL admission again)
  - guardrail: Expiry cannot be ridden past a policy change — re-admission re-evaluates policy, so a since-blocked domain is refused
  - fn: Proxy.ServeTransparentTLS + PolicyEngine.EvaluateConnect
  - inputs: Admission for once-allowed.com expired; policy snapshot updated to deny (e.g. pushed blocklist); client reconnects with SNI=once-allowed.com
  - expected: ActionRefuse; ReAdmit either not called or its result discarded after deny; PolicyDecision event carries the new policy version
- **TLS-1.j** `TestTunnel_ExpiredDomainRefused_WhileOtherDomainHoldsSameIP` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §4 DNS-2b Done-when (expired mapping refuses even while another domain keeps the same IP alive)
  - guardrail: Per-domain admission expiry is enforced even when the bare IP remains alive in the allow-set via a different domain
  - fn: TunnelGate.Evaluate + AdmissionMap.AdmittedFor
  - inputs: Shared IP 151.101.1.1 live-admitted for domain-b.com; admission for domain-a.com on the same IP expired; SNI=domain-a.com, origDst=151.101.1.1, policy made unable to re-admit a (ask posture)
  - expected: Refused for domain-a.com; a control connection with SNI=domain-b.com to the same IP succeeds
- **TLS-1.k** `TestTunnel_Conformance_CurlAndGitHTTPS_PassClean` [contract]
  - planRef: doc 09 §5 TLS-1 Done-when (conformance clients); doc 06 §2.2 proxy data-plane conformance
  - guardrail: Real clients cannot tell the SNI-checked tunnel from a vanilla network path
  - fn: Proxy.ServeTransparentTLS (full byte path)
  - inputs: Real curl HTTPS GET and git-over-HTTPS clone against fake origins through the transparent path, all admissions live
  - expected: Both complete with no TLS errors, no retries, bodies intact; golden-trace diff clean
- **TLS-1.l** `TestTunnel_EstablishedTunnelSurvivesAdmissionExpiryMidStream` [contract]
  - planRef: doc 09 OQ3 (a long-lived stream crossing an element expiry); NFT-3 'established flows ride conntrack' analogue at the proxy
  - guardrail: Admission expiry gates NEW connections only; an in-flight tunnel (e.g. streaming api.anthropic.com response) is never severed
  - fn: Proxy.ServeTransparentTLS
  - inputs: Open tunnel streaming a slow response; admission map entry expires mid-stream; afterwards a second NEW connection arrives for the same (domain, IP)
  - expected: First stream completes uninterrupted; second connection takes the re-admission path (not a silent pass)
- **TLS-2.a** `TestCONNECT_AllowedDomain_TunnelPlusTelemetry` [contract]
  - planRef: doc 09 §5 TLS-2 Done-when (explicit path with per-request telemetry)
  - guardrail: Explicit CONNECT enforces the identical policy and emits per-request telemetry
  - fn: Proxy.ServeCONNECT
  - inputs: CONNECT github.com:443 from session S; admission/policy allow; inner TLS to fake upstream
  - expected: 200 established; tunnel works; HttpEvent (CONNECT metadata) + PolicyDecision with provenance emitted
- **TLS-2.b** `TestCONNECT_DeniedDomain_RefusedWithProvenance` [contract]
  - planRef: doc 09 §5 TLS-2 (both modes evaluate the identical policy-core rules) + POL-3
  - guardrail: A denied domain is refused on the explicit path with a one-line 'why was this blocked' answer
  - fn: Proxy.ServeCONNECT
  - inputs: CONNECT blocked-domain.example:443; policy denies (blocklist layer)
  - expected: HTTP 403 to client; no upstream dial; PolicyDecision event carries RuleID, layer, policy version
- **TLS-2.c** `TestCONNECT_InnerSNIMismatchesAuthority_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-2 × TLS-1 SNI rule (transparent-path rules must hold inside explicit tunnels)
  - guardrail: Declaring an allowed CONNECT authority then handshaking with a different inner SNI cannot smuggle a non-admitted domain
  - fn: Proxy.ServeCONNECT
  - inputs: CONNECT github.com:443 (allowed) accepted; inner ClientHello carries SNI=exfil.evil.com
  - expected: Tunnel torn down at the inner ClientHello; no upstream bytes; deny event names the mismatch
- **TLS-2.d** `TestPolicyParity_TransparentCONNECTForward_TableDriven` [contract]
  - planRef: doc 09 §5 TLS-2 Done-when (both modes evaluate identical policy-core rules)
  - guardrail: The three ingress modes can never disagree on a verdict for the same (session, domain, request)
  - fn: Proxy.ServeTransparentTLS / ServeCONNECT / ServeHTTPForward vs PolicyEngine
  - inputs: Table of (domain, method, path, expected verdict) rows from one policy snapshot, each row driven through all three modes
  - expected: Identical allow/deny outcome and identical Provenance.RuleID per row across all modes
- **TLS-2.e** `TestCONNECT_Conformance_NpmInstallGitClone` [contract]
  - planRef: doc 09 §5 TLS-2 Done-when (npm install and git clone via explicit path; push with hand-supplied short-lived test cred pending TLS-5)
  - guardrail: Well-behaved proxy-aware clients work through HTTP_PROXY/HTTPS_PROXY with zero client-visible difference
  - fn: Proxy.ServeCONNECT + ServeHTTPForward
  - inputs: npm install and git clone against fake registry/origin with HTTPS_PROXY set; git push with a hand-supplied short-lived test credential
  - expected: All operations succeed; per-request HttpEvents present for each request
- **TLS-2.f** `TestCONNECT_IPLiteralAuthority_Refused` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-2 × TLS-1 edge rule 2 (IP-literal refused by default, mode-consistent)
  - guardrail: CONNECT to a bare IP bypasses domain policy and is refused, even if the IP sits in some allow-set
  - fn: Proxy.ServeCONNECT
  - inputs: CONNECT 140.82.1.1:443 where that IP is admitted for github.com
  - expected: Refused (403); no upstream dial
- **TLS-3.a** `TestInspect_PerOriginLeaf_ValidTLS_MetadataTelemetry` [contract]
  - planRef: doc 09 §5 TLS-3 Done-when (conformance suite: clients see valid TLS, metadata in telemetry)
  - guardrail: Inspection is invisible to a client trusting the per-session CA, and yields full request/response metadata
  - fn: Proxy.ServeTransparentTLS (inspect path) + SessionCA.LeafFor
  - inputs: Client TLS config trusting only session S's CA pool; GET to allowed inspected domain; fake upstream with valid WebPKI cert
  - expected: Handshake succeeds with a leaf for the exact origin signed by S's CA; HttpEvent contains method/host/path/status metadata
- **TLS-3.b** `TestInspect_UpstreamWebPKI_BadCerts_Refused_TableDriven` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-3 (strict WebPKI re-validation — at least as strict as the client's would have been)
  - guardrail: Delegated trust is never weaker than the client's own: a bad upstream cert kills the flow before any payload byte
  - fn: UpstreamDialer.DialTLS via Proxy inspect path
  - inputs: Table of fake upstreams: self-signed, expired, hostname mismatch, untrusted chain, revoked-style invalid intermediate
  - expected: Every row: upstream connection refused, downstream request fails with a TLS/bad-gateway error, zero upstream request bytes sent, error event emitted
- **TLS-3.c** `TestInspect_PerSessionCAIsolation_AUselessAgainstB` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-3 Done-when (per-session CA from session A useless against session B); D17
  - guardrail: Compromising one session's interception CA grants nothing in any other session
  - fn: CAMinter.MintSessionCA + Proxy inspect path
  - inputs: Mint CAs for sessions A and B; (1) client trusting only A's pool connects on B's interface; (2) a leaf signed by A's CA is presented as a server cert inside B's flow
  - expected: (1) handshake fails (B's leaf not trusted by A-pool); (2) A-signed leaf rejected; the two CA key pairs are distinct
- **TLS-3.d** `TestInspect_LeafCache_StablePerOrigin` [unit]
  - planRef: doc 09 §5 TLS-3 (on-the-fly per-origin leaf certs, cached)
  - guardrail: Leaf minting is cached per origin within a session — no per-connection mint churn, no cross-origin reuse
  - fn: SessionCA.LeafFor
  - inputs: Two sequential connections to origin X, one to origin Y, same session
  - expected: X connections present byte-identical leaf; Y's leaf differs and names Y
- **TLS-4.a** `TestPassThrough_PinnedClient_OpaqueTunnel_PinHolds` [guardrail-assurance]
  - planRef: doc 09 §5 TLS-4 Done-when; §9 row 'Pinned pass-through is opaque, no swap'; doc 06 §2.2 cert-pinned conformance client
  - guardrail: A pass-through-listed pinned client sees the true origin certificate — the proxy never terminates TLS on listed domains
  - fn: Proxy.ServeTransparentTLS (pass-through path)
  - inputs: Policy pass-through list contains pinned.example; cert-pinning client (pin = fake origin's real SPKI hash) connects; admission live
  - expected: Pin validates (origin cert seen, not a session-CA leaf); bytes opaque; FlowEvent (netflow accounting) emitted; no HttpEvent body/header metadata
- **TLS-4.b** `TestPassThrough_NeverSwaps_EvenWhenServiceRegistered` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-4 (NO credential swap) + TLS-5 (pass-through flows never swap); D17
  - guardrail: A domain on both the pass-through list and the swap registry tunnels opaquely with zero swap activity — pinning wins, no secret fetch
  - fn: Proxy pass-through path + SecretStore (recorded)
  - inputs: github.com placed on the pass-through list while also in the swap registry; client sends request with short-lived cred through the opaque tunnel
  - expected: Upstream receives the client's exact bytes (short-lived cred untouched); IdentityValidator and SecretStore never called; no CredentialUseEvent
- **TLS-4.c** `TestPassThrough_StillSNIAndAdmissionEnforced` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-4 (still SNI + allow-set enforced)
  - guardrail: The pass-through list is not an enforcement bypass: mismatched SNI or non-admitted destination is refused even for listed domains
  - fn: TunnelGate.Evaluate + Proxy pass-through path
  - inputs: Table: (a) SNI=pinned.example but origDst not admitted for it; (b) origDst admitted for pinned.example but SNI=other.example; (c) ECH ClientHello to a listed domain
  - expected: All refused; pass-through status changes the tunnel mode, never the admission verdict
- **TLS-4.d** `TestNonListedDomain_AlwaysInspected` [guardrail-assurance]
  - planRef: §9 row 'Pinned pass-through is opaque, no swap; ALL ELSE INSPECTED'; doc 09 §5 TLS-4 Done-when (everything off the list is inspected)
  - guardrail: Inspection is the default — only an explicit policy listing yields an opaque tunnel
  - fn: Proxy.ServeTransparentTLS
  - inputs: Allowed, admitted domain NOT on the pass-through list; client inspects the presented server cert chain
  - expected: Presented leaf is signed by the per-session CA (inspected), not the origin cert; HttpEvent metadata present
- **TLS-4.e** `TestPassThrough_ListIsPolicy_ReloadFlipsMode` [contract]
  - planRef: doc 09 §5 TLS-4 (the list is policy §6, not code) + POL-4 hot reload
  - guardrail: Pass-through membership is live policy: removing a domain flips the next connection to inspected, with new policy-version provenance
  - fn: PolicyEngine.PassThrough + Proxy
  - inputs: Connect once with pinned.example listed (snapshot v1); hot-swap snapshot to v2 without the listing; connect again
  - expected: First connection opaque, second inspected; events carry v1 then v2 PolicyVersion
- **TLS-5.a** `TestSwap_GitHubToken_UpstreamGetsLongLived_VMNeverDoes` [contract]
  - planRef: doc 09 §5 TLS-5 (swap rules in service registry; substitute upstream); doc 05 M1 first service
  - guardrail: On a registry match with a valid short-lived cred, the upstream sees the long-lived credential and the VM-side connection never carries it
  - fn: CredentialSwapper.Swap via Proxy inspect path
  - inputs: Registry: service github -> hosts github.com/api.github.com, location Authorization header; request with valid short-lived cred for session S; fake GitHub upstream records received headers; fake SecretStore returns canary long-lived token
  - expected: Upstream-received Authorization == long-lived canary; downstream recording contains zero canary bytes; CredentialUseEvent{session, service, fingerprint} emitted
- **TLS-5.b** `TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-5 Done-when; §9 row 'Long-lived credential never enters the VM'; doc 06 §3(c) credential-swap row — THE HEADLINE
  - guardrail: The long-lived credential never appears inside the VM: not on disk, not in env, not in the CoW delta, not in any readable response, not in any log path
  - fn: Proxy (whole) + LeakProbe.Search + EventSink capture
  - inputs: High-entropy 64-byte canary as long-lived cred; adversarial driver exercises: happy-path swap, upstream 401/500 with header echo, 3xx redirect chain, TRACE-style reflection, oversized response, proxy-generated error pages, connection abort mid-swap, malformed upstream response; then LeakProbe.Search(canary) over disk/env/cow-delta/downstream-bytes and a byte-grep of every captured Event and error string
  - expected: Zero LeakHits on every surface; zero canary occurrences in any event/log/error; only the short-lived cred ever observable VM-side
- **TLS-5.c** `TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-5 Done-when ('not in any readable response'); ResponseScrubber seam
  - guardrail: A hostile/buggy upstream reflecting the swapped Authorization value cannot deliver the long-lived credential into the VM
  - fn: ResponseScrubber.ScrubResponse via Proxy
  - inputs: Table: canary echoed in (a) response body (httpbin-style JSON), (b) a response header, (c) split across two body chunks straddling a buffer boundary, (d) base64 of the canary (documents whether encoding is in/out of scope)
  - expected: (a)-(c): delivered response contains no canary bytes (scrubbed or whole response blocked) and a ScrubHit/security event is emitted; (d): asserted per documented contract decision
- **TLS-5.d** `TestSwap_CrossSessionShortLivedCred_RejectedNoFetch` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-5 (validate the presented short-lived credential against the session identity, D22)
  - guardrail: Session B replaying session A's short-lived credential gets no swap — credentials are bound to session identity, not merely valid-looking
  - fn: IdentityValidator.ValidateShortLived via Proxy
  - inputs: Valid short-lived cred minted for session A presented on session B's interface to api.github.com
  - expected: Request refused (401/403); SecretStore.FetchLongLived NEVER called (recorded fake); audit/deny event names the identity mismatch without either credential value
- **TLS-5.e** `TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-5 (sidecar validation seam D22)
  - guardrail: Expired, forged, malformed, or absent short-lived credentials never trigger a secret-store fetch or a swapped upstream request
  - fn: CredentialSwapper.Swap + SecretStore (recorded)
  - inputs: Table: expired cred, tampered signature, random garbage token, empty Authorization, cred for a different service
  - expected: Every row: no fetch, no swap, upstream never receives any Authorization fabricated by the proxy, deny event with provenance
- **TLS-5.f** `TestSwap_NoRegistryMatch_RequestUntouched` [unit]
  - planRef: doc 09 §5 TLS-5 (swap rules live in the service registry)
  - guardrail: Hosts outside the registry, and non-credential headers on registry hosts, pass through the inspect path byte-identically
  - fn: PolicyEngine.MatchSwapService + CredentialSwapper.Swap
  - inputs: Table: (a) allowed non-registry host with an Authorization header; (b) registry host with cred in a non-registered location (cookie); (c) registry host, no credential present
  - expected: No swap, no IdentityValidator/SecretStore calls; upstream receives the original headers unmodified
- **TLS-5.g** `TestSwap_EveryLogPathScrubbed_FingerprintOnly` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-5 (scrub BOTH credentials from every log path) + LOG-5 (fingerprint, never the credential)
  - guardrail: Neither the short-lived nor the long-lived credential value appears in any emitted event on any code path; CredentialUseEvent carries fingerprint only
  - fn: EventSink (captured) across all Proxy paths
  - inputs: Distinct canaries for short- and long-lived creds; drive swap success, swap failure, policy deny, upstream error, scrubber hit; serialize every captured Event to bytes
  - expected: Zero occurrences of either canary across all events; CredentialUseEvent.Fields contains the expected fingerprint and no value field
- **TLS-5.h** `TestE2E_GitHubPushWithOnlyShortLivedCredInVM` [e2e-lifecycle]
  - planRef: doc 09 §5 TLS-5 Done-when (push to GitHub works end to end) + §1 credentialed half (Stage 3)
  - guardrail: The developer-value test's credentialed half: a real git push succeeds with no long-lived credential ever in the VM
  - fn: Proxy (whole) end to end
  - inputs: git push over HTTPS through the explicit path; VM holds only the short-lived cred; fake GitHub upstream accepts only the long-lived canary; LeakProbe afterwards
  - expected: Push succeeds (upstream saw long-lived canary); LeakProbe.Search(canary) over all surfaces returns zero hits; CredentialUseEvent answers 'which session used the GitHub key, when, for what request'
- **TLS-6.a** `TestHTTPPolicy_MethodHostPathRules_TableDriven` [unit]
  - planRef: doc 09 §5 TLS-6 (method/host/path rules)
  - guardrail: HTTP-level rules enforce at request granularity with full provenance
  - fn: PolicyEngine.EvaluateHTTP via Proxy inspect path
  - inputs: Table: allowed GET, denied DELETE on sensitive path, allowed host + denied path, deny-overrides layering case
  - expected: Per-row verdicts match; denied requests never reach upstream; each PolicyDecision carries RuleID/layer/version
- **TLS-6.b** `TestRateLimit_PerSessionAndPerService_Isolated` [contract]
  - planRef: doc 09 §5 TLS-6 (per-session and per-service rate limits)
  - guardrail: Limits bind to (session, service): exhausting one bucket never throttles another session or another service
  - fn: RateLimiter.Allow via Proxy
  - inputs: Limit N/min on service github for session A; drive N+1 requests from A to github, N from A to npm, N from session B to github
  - expected: Only A's N+1th github request is refused (with RetryAfter + provenance event); A→npm and B→github fully succeed
- **TLS-6.c** `TestCap_BreachSuspendsMidAction_BreachingRequestHeld` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-6 Done-when; §9 row 'Suspend-on-breach fires'; doc 06 §3(c) suspend row (e.g. 5-deletions/hour)
  - guardrail: Tripping a declared behavioral cap signals suspend MID-ACTION — the breaching request does not complete upstream before the signal
  - fn: CapMonitor.Record + SuspendSignaler.Suspend via Proxy
  - inputs: Cap: 5 DELETE/hour on a sensitive resource; drive 6 DELETEs in-session; fake SuspendSignaler records call ordering vs upstream forwarding
  - expected: Suspend(sess, BreachInfo{cap, provenance}) called exactly once, before the 6th request's upstream bytes are sent; requests 1-5 unaffected; breach event emitted
- **TLS-6.d** `TestCap_ResumeInvisibleToAgent` [guardrail-assurance]
  - planRef: doc 09 §5 TLS-6 Done-when (resume is invisible to the agent); §9 suspend row second half; doc 03 §7
  - guardrail: After suspend→approve→resume, the agent's in-flight connection continues without any observable error or reset
  - fn: Proxy + fake orchestrator suspend/resume cycle
  - inputs: Connection paused mid-response at the breach point; fake orchestrator approves and resumes after a delay within client timeout
  - expected: The held request then completes successfully; client sees one normal (slow) response — no 5xx, no connection reset, no retry needed
- **TLS-6.e** `TestDoH_OnAllowedHost_DetectedAndBlocked` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-6 (DoH on otherwise-allowed hosts detected/blocked at HTTP level); §9 row 'DoH endpoint blocking (HTTP-level half)'; NFT-4 layering
  - guardrail: Resolver bypass via DoH served from an allowed, inspected host fails — closing the half the baseline blocklist cannot see
  - fn: PolicyEngine.EvaluateHTTP via Proxy inspect path
  - inputs: Table on an allowed inspected host: (a) POST with Content-Type application/dns-message; (b) GET ?dns=<base64url query>; (c) Accept: application/dns-json query; (d) control: ordinary JSON POST to the same host
  - expected: (a)-(c) blocked with a DoH-specific rule provenance, zero upstream forwarding; (d) passes — detection is content-shaped, not host-wide
- **TLS-6.f** `TestTelemetry_MetadataOnlyByDefault_NoBodies` [contract]
  - planRef: doc 09 §5 TLS-6 (telemetry is request metadata by default; bodies only where policy requires)
  - guardrail: Default telemetry never captures payload bodies — privacy posture is structural, not configuration luck
  - fn: EventSink capture via Proxy inspect path
  - inputs: Inspected POST with a distinctive body sentinel under default policy; same request under a policy that explicitly requires body examination
  - expected: Default: no event field contains the sentinel; explicit-policy run: the examining rule fires, and the decision event carries that rule's provenance
- **TLS-7.a** `TestSecretScan_SeededLongLivedTokenInbound_HookFires` [contract]
  - planRef: doc 09 §5 TLS-7 Done-when (seeded token entering on the inspected path is detected; configured hook fires)
  - guardrail: The inspection point detects a long-lived secret entering the VM and fires the configured hook — the doc 02 §6 hand-fed-token scenario
  - fn: SecretScanner.ScanInbound + SecretHook.OnFinding via Proxy
  - inputs: Inbound response on the inspected path containing a seeded long-lived token pattern (e.g. ghp_… fixture); recorded fake hook
  - expected: OnFinding called with Finding{kind, fingerprint, where}; the finding carries a fingerprint, never the token value; delivery behavior matches configured mode
- **TLS-7.b** `TestSecretScan_NearMissContent_NoFalseTrigger` [unit]
  - planRef: doc 09 §5 TLS-7 (rules ownership OQ8 — the gate must not be noise)
  - guardrail: Near-miss content (high-entropy non-secrets, token-shaped docs) does not fire the hook
  - fn: SecretScanner.ScanInbound
  - inputs: Table: README documenting token FORMATS, random base64 blobs, UUIDs, truncated token prefixes
  - expected: Zero findings for every row
- **TLS-7.c** `TestSecretScan_PassThroughNotScanned_GuaranteeBoundaryDocumented` [unit]
  - planRef: doc 09 §5 TLS-7 (the gate exists on the inspected path only — doc 05 §7 HTTP-level-visibility dependency)
  - guardrail: The scan guarantee is scoped to inspected flows; pass-through tunnels are documented as outside it (no false promise)
  - fn: SecretScanner (recorded) via Proxy pass-through path
  - inputs: Seeded token delivered through a pass-through-listed opaque tunnel
  - expected: ScanInbound never invoked for the opaque flow (recorded fake); the test name/comment is the living documentation of the boundary of the guarantee
- **TLS-8.a** `TestProtocol_WebSocketThroughInspection` [contract]
  - planRef: doc 09 §5 TLS-8 Done-when (WebSocket conformance through inspection with telemetry)
  - guardrail: WebSocket upgrade and bidirectional frames survive the inspected path with telemetry
  - fn: Proxy inspect path
  - inputs: Real WebSocket client/echo-server pair through inspection; ping/pong + binary frames both directions
  - expected: 101 upgrade succeeds; frames intact both ways; HttpEvent records the upgrade metadata
- **TLS-8.b** `TestProtocol_HTTP2MultiplexedThroughInspection` [contract]
  - planRef: doc 09 §5 TLS-8 (HTTP/2 upstreams, Pingora-native)
  - guardrail: Multiplexed h2 streams are inspected and individually attributed in telemetry
  - fn: Proxy inspect path
  - inputs: h2 client opening concurrent streams to an h2 fake upstream (ALPN h2)
  - expected: All streams complete; per-stream HttpEvents emitted; no head-of-line corruption
- **TLS-8.c** `TestProtocol_GRPCUnaryAndStreamingThroughInspection` [contract]
  - planRef: doc 09 §5 TLS-8 Done-when (gRPC conformance clients pass with telemetry)
  - guardrail: gRPC unary and server-streaming calls pass inspection with metadata telemetry
  - fn: Proxy inspect path
  - inputs: gRPC test service (unary echo + server stream) through the inspected path
  - expected: Calls succeed with correct trailers/status; HttpEvents carry :path (method) metadata, bodies absent per TLS-6.f
- **TLS-8.d** `TestProtocol_QUICBlocked_TCPFallbackSucceeds` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §5 TLS-8 Done-when (QUIC blocked-with-fallback per OQ5); NFT-4 udp/443 drop; DNS-4 rule 4 (no alpn=h3 steering)
  - guardrail: An h3-preferring client cannot escape inspection via QUIC: udp/443 yields nothing and the TCP fallback lands on the proxy
  - fn: Harness network model (no UDP listener) + Proxy.ServeTransparentTLS
  - inputs: Client attempts QUIC to an allowed admitted domain (harness models the NFT-4 drop as a dead UDP path), then falls back to TCP 443
  - expected: QUIC attempt times out/refused with no handshake; TCP fallback connection succeeds through the normal TLS-1 checks; only the TCP flow appears in telemetry
- **TLS-LC.a** `TestLifecycle_SessionTeardown_NoStrandedProxyState` [e2e-lifecycle]
  - planRef: doc 06 §3(b) clean-teardown row ('no stranded proxy session'); doc 09 NFT-6 lockstep + DNS-2b flush
  - guardrail: Session destroy leaves zero proxy residue: no admissions honored, no session CA usable, no live tunnels, no swap state
  - fn: Proxy.TeardownSession
  - inputs: Session with live tunnels, cached leafs, swap state, admissions; call TeardownSession; then attempt a new connection replaying the old session's parameters, and re-run a create→destroy loop N times
  - expected: Post-teardown connection refused; old per-session CA rejected; N-cycle loop leaves proxy-internal state empty/equal to fresh-boot (no leak growth)
- **TLS-LD.a** `TestLoad_FanOutP99WithinBudget_NoVerdictBleed` [load]
  - planRef: doc 06 §3(d) proxy throughput + p99 under fan-out; doc 09 Stage 5
  - guardrail: Many sessions through one proxy keep p99 added latency within budget and never cross-contaminate policy verdicts
  - fn: Proxy (whole) under concurrency
  - inputs: N sessions × M concurrent mixed flows (tunnel/inspect/CONNECT) with per-session distinct policies and admission churn; measure added latency distribution
  - expected: p99 added latency within the budget constant; every response/verdict attributed to the correct session (zero cross-session allow where that session's policy denies)
- **TLS-LD.b** `TestLoad_ConcurrentSwaps_NoCrossSessionCredentialBleed` [load, ADVERSARIAL]
  - planRef: doc 06 §3(d) × §9 credential row — the leak-absence invariant must hold under race, not just single-flight
  - guardrail: Under heavy parallel swap traffic, session A's upstream never receives session B's long-lived credential and no canary ever reaches any VM surface
  - fn: CredentialSwapper.Swap + Proxy under concurrency
  - inputs: K sessions with K distinct long-lived canaries swapping concurrently against recording upstreams; aggressive connection reuse/pooling to provoke state bleed; LeakProbe per session afterwards
  - expected: Every upstream records exactly its own session's canary; zero canary hits on any session's VM surfaces; CredentialUseEvents attribute correctly per session
