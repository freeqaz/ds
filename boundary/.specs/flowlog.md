# ds-flowlog — Connection & netflow logging (doc 09 §7, LOG-1..LOG-5)

## SEAMS

### SessionRef
Purpose: The shared session identity embedded in every event (LOG-1). Iface is the per-session attribution key from NFT-2 (`dstap-<session>`); equality on SessionRef is what 'attributed to the correct session' means in LOG-2.

```go
type SessionRef struct { SessionID string; HostID string; Iface string }
```

### Event (sealed union of the five LOG-1 messages)
Purpose: Protobuf-shaped event union for the Stage-0 contract freeze. Validate() is the executable schema spec: SessionRef required, PolicyDecision provenance required (POL-3), CredentialUseEvent fingerprint-format required. Stubs return ErrNotImplemented.

```go
type Event interface { Ref() SessionRef; Validate() error; isEvent() }
```

### FlowRecord
Purpose: Netflow-style metadata for one kernel-observed flow, including the DNS-2 admitting-domain join. Deliberately has NO payload-capable field — full packet capture is explicitly out (doc 03 §4), and a schema-shape test enforces it.

```go
type FlowRecord struct { Session SessionRef; Iface string; AdmittingDomain string; Dst netip.AddrPort; Protocol Proto; BytesIn, BytesOut uint64; Start, End time.Time; Duration time.Duration; CtMark uint32; Verdict FlowVerdict /* accepted | dropped */ }
```

### DnsEvent
Purpose: Emitted by ds-dnsgate at DNS-2 admission; it is the join key that lets ds-flowlog answer 'which domain admitted this flow' (LOG-2).

```go
type DnsEvent struct { Session SessionRef; QueryName string; AdmittedIPs []netip.Addr; TTL time.Duration; ExpiresAt time.Time; Decision PolicyDecision }
```

### HttpEvent
Purpose: Metadata-only HTTP telemetry from ds-tlsproxy. No header-value or body field exists in the type, so credential values structurally cannot ride along (supports LOG-5).

```go
type HttpEvent struct { Session SessionRef; Method, Host, Path string; Status int; ReqBytes, RespBytes uint64; Start time.Time; Duration time.Duration; Decision PolicyDecision }
```

### PolicyDecision
Purpose: Decision + rule provenance per POL-3; Validate() fails on missing RuleID/PolicyLayer/PolicyVersion so a missing-provenance event fails CI.

```go
type PolicyDecision struct { Session SessionRef; Verdict Verdict /* allow|deny|ask|swap|passthrough */; RuleID string; PolicyLayer string; PolicyVersion string; Resource string; At time.Time }
```

### CredentialUseEvent + FingerprintCredential
Purpose: The LOG-5 audit record: which session used which credential, when, for what request — carrying only a stable, non-reversible fingerprint, never the value. FingerprintCredential is the single sanctioned path from secret to event.

```go
type CredentialFingerprint string
type CredentialUseEvent struct { Session SessionRef; Service string; Fingerprint CredentialFingerprint; Request HttpRequestMeta /* Method, Host, Path, At */ }
func FingerprintCredential(secret []byte) (CredentialFingerprint, error)
```

### SessionRegistry
Purpose: Binds the kernel-side attribution keys (ct mark from NFT-5, iifname from NFT-2) to a SessionRef at session create, and marks them retired at teardown so post-destroy traffic is suspicious, not stale-attributed.

```go
type SessionRegistry interface { RegisterSession(ctx context.Context, ref SessionRef, ctMark uint32, iface string) error; RetireSession(ctx context.Context, ref SessionRef, at time.Time) error }
```

### ConntrackFlow / NflogDrop (kernel inputs)
Purpose: Models what NFT-5 conntrack accounting and nflog drop events deliver. Src is present but must never be an attribution input (addresses are forgeable; the attachment point is not).

```go
type ConntrackFlow struct { CtMark uint32; Iif string; Src, Dst netip.AddrPort; Protocol Proto; BytesOrig, BytesReply uint64; Packets uint64; Start, End time.Time }
type NflogDrop struct { Iif string; CtMark uint32; Src, Dst netip.AddrPort; Protocol Proto; At time.Time }
```

### Attributor
Purpose: The LOG-2 join: ct mark + iifname -> SessionRef, plus the AdmissionIndex lookup -> AdmittingDomain. Returns ErrUnattributed (never a guessed session) when keys don't resolve; unattributed flows feed the LOG-4 reconciler.

```go
type Attributor interface { Attribute(ctx context.Context, f ConntrackFlow) (FlowRecord, error); AttributeDrop(ctx context.Context, d NflogDrop) (FlowRecord, error) }
var ErrUnattributed = errors.New("flowlog: flow not attributable to any session")
```

### AdmissionIndex
Purpose: Per-session, time-windowed (domain, IPs, expiry) index built from the DNS-2 event stream; answers the admitting-domain join honoring admission validity at flow start.

```go
type AdmissionIndex interface { ObserveDns(ctx context.Context, ev DnsEvent) error; AdmittingDomain(ctx context.Context, ref SessionRef, dst netip.Addr, at time.Time) (string, error) }
```

### Collector
Purpose: Single ingest point for conntrack-derived FlowRecords, nflog drops, and both proxies' event streams (LOG-3); joins on session and hands off to the spool.

```go
type Collector interface { Ingest(ctx context.Context, ev Event) error }
```

### Spool
Purpose: Disk-bounded local buffering (LOG-3). Overflow behavior is contractual: never exceed BoundBytes; on pressure drop-oldest and emit a SpoolOverflow marker event so loss is visible, not silent.

```go
type Spool interface { Append(ctx context.Context, ev Event) error; ReadBatch(ctx context.Context, max int) (batch []Event, ack func() error, err error); UsageBytes() int64; BoundBytes() int64 }
```

### Shipper + Router + Sink
Purpose: Off-box shipping through the log-pipeline contract with hosting-tier routing (D19): on-prem metadata stays customer-side. Sink doubles as the doc-06 fake against which 'queryable off-box' is asserted.

```go
type HostingTier int // TierSaaS, TierOnPrem
type SinkID string
type Router interface { Route(ev Event, tier HostingTier) (SinkID, error) }
type Sink interface { Receive(ctx context.Context, batch []Event) error; Query(ctx context.Context, q StoryQuery) ([]Event, error) }
type Shipper interface { Ship(ctx context.Context) error }
```

### Reconciler
Purpose: LOG-4: every byte that left a VM interface must be explained by a proxy session or an escape-hatch allowance. Windowed to tolerate event skew; anything unexplained is escalated, never logged-and-forgotten.

```go
type Explanation struct { Kind ExplanationKind /* ProxySession | EscapeHatch */; Flow ConntrackFlow; Ref SessionRef; Detail string }
type ReconciliationReport struct { Explained []Explanation; Unexplained []ConntrackFlow }
type Reconciler interface { Reconcile(ctx context.Context, w Window) (ReconciliationReport, error) }
type AllowanceSource interface { Allowances(ctx context.Context, ref SessionRef, at time.Time) ([]Allowance, error) }
```

### AlarmSink
Purpose: The 'alarm, not a log line' channel: a typed escalation path distinct from the Event stream, exercised by the deliberately-mis-ruled-host test and required to work even under spool pressure.

```go
type AlarmKind int // UnexplainedFlow, ByteMismatch, PostTeardownFlow
type Alarm struct { Kind AlarmKind; Flow ConntrackFlow; Session *SessionRef; Detail string; At time.Time }
type AlarmSink interface { Raise(ctx context.Context, a Alarm) error }
```

### AuditQuerier
Purpose: LOG-5's query seam: 'which session used the GitHub key, when, for what request' as a first-class API over the shipped store.

```go
type CredentialUseQuery struct { Service string; SessionID string; Window Window }
type AuditQuerier interface { CredentialUses(ctx context.Context, q CredentialUseQuery) ([]CredentialUseEvent, error) }
```

### ErrNotImplemented
Purpose: Sentinel returned by every stub so the whole suite starts RED; tests assert documented outcomes, so they fail until the Rust data plane (via its conformance adapter) satisfies them.

```go
var ErrNotImplemented = errors.New("flowlog: not implemented")
```


## TESTS

- **LOG-1.a** `TestEventSchema_RoundTrip_AllMessages` [contract]
  - planRef: doc 09 §7 LOG-1 Done-when (Stage-0 contract freeze); doc 06 §2 contract model
  - guardrail: The five event messages + SessionRef are a stable, lossless wire contract
  - fn: Event.Marshal/Unmarshal (protobuf-shaped encoding) for FlowRecord, DnsEvent, HttpEvent, PolicyDecision, CredentialUseEvent
  - inputs: Table-driven: one fully-populated canonical fixture per message type, including zero-duration flows, IPv6 dst, and multi-IP DnsEvent
  - expected: Encode->decode round-trips byte-for-byte equal; encoded bytes match the frozen golden descriptor fixture (a re-shape of the schema fails the golden diff, standing in for buf-breaking in the Go harness)
- **LOG-1.b** `TestEventValidate_SessionRefRequired` [unit]
  - planRef: doc 09 §7 LOG-1 (all messages share a SessionRef)
  - guardrail: No event exists without session attribution
  - fn: Event.Validate()
  - inputs: Table-driven: each of the five event types with zero-value SessionRef, missing SessionID, and missing Iface
  - expected: Validate() returns a non-nil error naming the missing field for every row; a valid SessionRef passes
- **LOG-1.c** `TestEventSchema_MetadataOnly_NoPayloadCapture` [guardrail-assurance]
  - planRef: doc 09 §7 LOG-1 ('netflow-style metadata only; full packet capture is explicitly out', doc 03 §4)
  - guardrail: The schema is structurally incapable of carrying packet payloads or HTTP bodies
  - fn: reflect.TypeOf over FlowRecord, HttpEvent, DnsEvent, PolicyDecision, CredentialUseEvent
  - inputs: Reflection walk of all exported fields (recursively) of every event type
  - expected: No field of type []byte/string named or tagged body/payload/capture/raw/headers-with-values exists; HttpEvent carries exactly Method/Host/Path/Status/sizes/timing; the assertion list is the allowlist of fields, so any added payload field turns the test red
- **LOG-1.d** `TestPolicyDecision_RequiresProvenance` [unit]
  - planRef: doc 09 §6 POL-3 Done-when ('a missing-provenance event fails CI') as enforced at the LOG-1 schema
  - guardrail: Every decision event carries rule id, policy layer, and policy version
  - fn: PolicyDecision.Validate()
  - inputs: Table-driven: decisions missing RuleID, missing PolicyLayer, missing PolicyVersion, and fully populated
  - expected: The three incomplete rows fail Validate with the field named; the complete row passes — 'why was this blocked?' always has a one-line answer
- **LOG-1.e** `TestCredentialUseEvent_RejectsRawSecretShapedFingerprint` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-1/LOG-5 (CredentialUseEvent: 'credential fingerprint — never the credential')
  - guardrail: A raw credential cannot be smuggled into the fingerprint field
  - fn: CredentialUseEvent.Validate() + FingerprintCredential
  - inputs: Events whose Fingerprint is (1) a seeded GitHub-token-shaped value ghp_..., (2) an arbitrary high-entropy string not in fingerprint format, (3) the output of FingerprintCredential
  - expected: Rows 1–2 fail Validate (fingerprint must match the fixed fingerprint format, e.g. algo-prefixed fixed-length digest); row 3 passes
- **LOG-2.a** `TestAttribute_KernelFlow_ByCtMarkAndIface` [unit]
  - planRef: doc 09 §7 LOG-2 (resolves doc 03 OQ6: iifname convention + ct mark)
  - guardrail: Kernel-observed flows attribute via the unforgeable keys
  - fn: Attributor.Attribute(ctx, ConntrackFlow)
  - inputs: Table-driven: registered sessions A/B with distinct (ctMark, dstap-<id>) pairs; flows carrying each pair; a flow where mark and iface agree vs a flow where they disagree
  - expected: Matching pairs yield FlowRecord.Session == the registered SessionRef with correct bytes/duration mapping; a mark/iface disagreement returns ErrUnattributed (never a coin-flip between A and B)
- **LOG-2.b** `TestAttribute_ForgedSourceIP_IsIgnored` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-2 + §3 NFT-2 rationale (addresses forgeable, attachment point not); doc 06 §3(c) in-VM-spoofing row
  - guardrail: Attribution never keys on source IP — a VM spoofing another session's address cannot pollute that session's audit record
  - fn: Attributor.Attribute
  - inputs: Session A's iface+ctMark on a ConntrackFlow whose Src is session B's IP (and a second row: an IP belonging to no session)
  - expected: Both rows attribute to session A; session B's flow story contains nothing; mutating Src across the whole table never changes the attributed SessionRef
- **LOG-2.c** `TestAttribute_AdmittingDomainJoin` [contract]
  - planRef: doc 09 §7 LOG-2 ('the DNS event stream (DNS-2) provides the domain that admitted the flow join')
  - guardrail: Every flow names the domain whose resolution admitted it
  - fn: AdmissionIndex.ObserveDns + Attributor.Attribute
  - inputs: DnsEvent(session A, registry.npmjs.org -> {104.16.0.5}, TTL 60s) then ConntrackFlow(session A, dst 104.16.0.5:443) starting inside the validity window
  - expected: FlowRecord.AdmittingDomain == "registry.npmjs.org"; a flow to an address never admitted for A yields empty domain + the record flagged for reconciliation
- **LOG-2.d** `TestAttribute_SharedIPAcrossSessions_NoCrossJoin` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-2 100%-correct-session Done-when; CDN shared-IP context (doc 03 OQ1)
  - guardrail: Two sessions admitted to the same CDN IP via different domains each get their own domain join
  - fn: AdmissionIndex.AdmittingDomain per-session keying
  - inputs: DnsEvent(A, alloweda.example -> 151.101.1.1); DnsEvent(B, allowedb.example -> 151.101.1.1); flows from A and B to 151.101.1.1:443
  - expected: A's FlowRecord joins alloweda.example, B's joins allowedb.example; querying AdmittingDomain(A, ip) never returns B's domain
- **LOG-2.e** `TestAttribute_UnknownCtMark_NeverGuessed` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-2 (100% attributed to the CORRECT session) feeding LOG-4
  - guardrail: An unattributable flow surfaces as unattributed rather than being assigned to any session
  - fn: Attributor.Attribute
  - inputs: ConntrackFlow with an unregistered ctMark on an unregistered iface; same with a registered iface but zero ctMark
  - expected: Both return ErrUnattributed; no FlowRecord with any registered SessionRef is produced; the flow is queued for the Reconciler (asserted via the unexplained set in LOG-4.a's clean run)
- **LOG-2.f** `TestAttribute_AdmissionExpiry_TimeWindowed` [unit]
  - planRef: doc 09 §7 LOG-2 + §4 DNS-2b expiry lockstep; doc 09 OQ3 (resolve-once clients)
  - guardrail: The domain join honors admission validity at flow start — expiry does not retro-strip or falsely grant attribution
  - fn: AdmissionIndex.AdmittingDomain(at time.Time)
  - inputs: Admission valid [t0, t0+90s); flows starting at t0+30s (in-window, ending after expiry), and at t0+120s (post-expiry, no re-admission)
  - expected: In-window flow keeps AdmittingDomain even though it ends after expiry (established flows ride conntrack, NFT-3); post-expiry flow gets no domain and is flagged unexplained
- **LOG-2.g** `TestAttribute_ProxyUpstreamLeg_ViaProxyEvents` [contract]
  - planRef: doc 09 §7 LOG-2/LOG-4 parenthetical (host-egress reconciliation rides on proxy events pending OQ11)
  - guardrail: ds-tlsproxy's own upstream flows are attributed to the originating session through proxy events, not left dangling as host traffic
  - fn: Collector.Ingest(HttpEvent) + Reconciler treatment of proxy-upstream kernel flows
  - inputs: HttpEvent(session A, host github.com) plus a host-egress ConntrackFlow to github.com's admitted IP with no VM iface
  - expected: The upstream-leg flow is explained by A's proxy session in the ReconciliationReport (ExplanationKind ProxySession), not raised as an alarm
- **LOG-2.h** `TestAttribution_MultiVM_100PercentIncludingDrops` [e2e-lifecycle]
  - planRef: doc 09 §7 LOG-2 Done-when ('multi-VM test host attributes 100% of generated flows — kernel- and proxy-observed — including the admitting-domain join')
  - guardrail: Attribution is complete at host scale, for accepted flows AND nflog drops
  - fn: Attributor + AdmissionIndex + Collector end to end against fake kernel/proxy sources
  - inputs: 20 simulated sessions, each generating a scripted mix: admitted HTTPS flows, DNS events, nflog drops of denied dials, proxy HttpEvents — interleaved concurrently with a deterministic manifest
  - expected: Every manifest entry appears exactly once in the collected stream attributed to its generating session with the right admitting domain; attributed/generated ratio == 100% with zero cross-session assignments
- **LOG-3.a** `TestSpool_DiskBoundNeverExceeded_LossIsVisible` [contract]
  - planRef: doc 09 §7 LOG-3 ('spools to disk-bounded local storage')
  - guardrail: Spool usage never exceeds its byte bound, and any shedding is announced, not silent
  - fn: Spool.Append / UsageBytes / BoundBytes
  - inputs: Bound set to a small budget (e.g. 1 MiB); Append a stream of events totaling 10x the bound while the Sink is unreachable
  - expected: UsageBytes() <= BoundBytes() after every Append (property checked per-iteration); when shedding starts, oldest events go first and a SpoolOverflow marker event with dropped-count is present in the surviving stream
- **LOG-3.b** `TestShip_SinkOutage_RecoverWithoutLossWithinBound` [contract]
  - planRef: doc 09 §7 LOG-3 ('ships off-box through the log-pipeline contract')
  - guardrail: A sink outage shorter than spool capacity loses nothing; delivery resumes in order with at-least-once + ack semantics
  - fn: Shipper.Ship + Spool.ReadBatch/ack against a fault-injected fake Sink
  - inputs: Fake Sink scripted: fail all Receive for a period, then recover; 500 events ingested across the outage, staying under the spool bound; one batch acked then re-sent (duplicate) case
  - expected: After recovery the Sink holds all 500 events in ingest order; un-acked batches are re-shipped; the duplicate re-send is tolerated by event identity (idempotent receive), so the queryable story has exactly 500
- **LOG-3.c** `TestRoute_OnPremTier_MetadataNeverLeavesCustomerSide` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-3 ('what ships where follows the hosting tier (D19) — on-prem keeps metadata customer-side')
  - guardrail: Hosting-tier routing holds even against a misconfigured vendor sink
  - fn: Router.Route + Shipper with two registered sinks (customer-side, vendor)
  - inputs: Table-driven: every event type under TierOnPrem with a vendor sink configured as the global default; same events under TierSaaS
  - expected: Under TierOnPrem the vendor fake Sink's Receive is never called for any event type (recorded-calls assertion) and all events land customer-side; under TierSaaS routing follows the default; an event with an unroutable tier errors rather than falling through to the vendor sink
- **LOG-3.d** `TestShip_SessionNetworkStory_QueryableOffBox` [e2e-lifecycle]
  - planRef: doc 09 §7 LOG-3 Done-when ('a session's complete network story ... queryable off-box minutes after it happened')
  - guardrail: Every flow, every decision, every credential use for a session is retrievable off-box, complete and time-ordered
  - fn: Collector.Ingest -> Spool -> Shipper -> Sink.Query(StoryQuery{SessionID})
  - inputs: A scripted full session: DnsEvents, FlowRecords (incl. one drop), HttpEvents, PolicyDecisions (allow+deny), one CredentialUseEvent; then teardown
  - expected: Sink.Query returns exactly the ingested set (no gaps, no extras), ordered by event time, within the harness latency budget; the story includes the denial with its rule provenance
- **LOG-3.e** `TestLoad_CollectorFanout_P99UnderBudgetNoSheddingBelowBound` [load]
  - planRef: doc 09 §7 LOG-3 + §8 Stage 5 (doc 06 §3(d) rig)
  - guardrail: Ingest keeps up with many-VMs-per-host event rates without shedding while under the spool bound
  - fn: Collector.Ingest under concurrent producers
  - inputs: N=100 concurrent session producers at a configured events/sec mix (flow-heavy with DNS/HTTP interleave) for a fixed duration, healthy sink
  - expected: Zero SpoolOverflow markers; p99 Ingest latency under the budget constant (strawman 5ms, tunable at the Stage-5 rig); attribution remains 100% under concurrency (re-asserts LOG-2.h invariant under load)
- **LOG-4.a** `TestReconcile_AllExplained_CleanReport` [unit]
  - planRef: doc 09 §7 LOG-4 ('every byte that left a VM interface must be explained')
  - guardrail: The reconciler's positive baseline: proxied traffic reconciles to zero unexplained
  - fn: Reconciler.Reconcile
  - inputs: Window containing kernel flows that each match a proxy event (session, dst, byte counts within tolerance); no escape hatches
  - expected: Report.Unexplained is empty; every flow appears in Explained with Kind=ProxySession; AlarmSink.Raise never called (recorded-calls fake)
- **LOG-4.b** `TestReconcile_EscapeHatchFlow_ExplainedByAllowance` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-4 ('... or an explicit escape-hatch allowance'); §6 POL-5
  - guardrail: Direct (non-proxied) flows are only ever explained by a matching, in-force allowance
  - fn: Reconciler.Reconcile + AllowanceSource
  - inputs: Table-driven: a direct tcp/22 flow with a live session-scoped allowance (port+protocol match); same flow with the allowance expired; same flow on a different port than the allowance grants
  - expected: Row 1 -> Explained Kind=EscapeHatch citing the allowance; rows 2–3 -> Unexplained + AlarmSink.Raise(Kind=UnexplainedFlow) — an expired or mismatched allowance explains nothing
- **LOG-4.c** `TestReconcile_MisRuledHost_UnexplainedFlowRaisesAlarm` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-4 Done-when ('a deliberately mis-ruled test host trips the alarm'); §8 Stage 4 exit ('reconciliation alarm proven'); doc 06 §3(c)
  - guardrail: A hole in the redirect (traffic escaping without a proxy session) is an ALARM, not a log line — the boundary audits itself
  - fn: Reconciler.Reconcile + AlarmSink
  - inputs: Simulated mis-ruled host: a kernel flow from session A's iface straight to 203.0.113.7:443 with NO corresponding proxy event and no allowance (the redirect hole)
  - expected: Exactly one Alarm{Kind: UnexplainedFlow, Session: A, Flow: that flow} raised through AlarmSink; the flow does NOT appear as an ordinary accepted FlowRecord in the shipped story without the alarm; report lists it Unexplained
- **LOG-4.d** `TestReconcile_KernelProxyByteMismatch_Alarms` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-4 ('every BYTE ... must be explained' — accounting, not just flow existence)
  - guardrail: Bytes smuggled past proxy accounting on an otherwise-explained connection are detected
  - fn: Reconciler.Reconcile byte-accounting comparison
  - inputs: Kernel flow reporting 50 MiB egress on a 5-tuple whose matching proxy session accounts only 1 MiB (beyond the configured tolerance); control row within tolerance
  - expected: Mismatch row raises Alarm{Kind: ByteMismatch} carrying both counts; control row reconciles clean — tolerance is a named constant the test pins
- **LOG-4.e** `TestReconcile_AlarmPathSurvivesSpoolPressure` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-4 ('an unexplained flow is an alarm, not a log line')
  - guardrail: Alarm delivery cannot be suppressed by the load-shedding that may drop ordinary events
  - fn: AlarmSink.Raise while Spool is at BoundBytes
  - inputs: Spool driven to its bound (shedding active, per LOG-3.a), then an unexplained flow enters reconciliation
  - expected: AlarmSink.Raise is still invoked and returns success; the alarm is not subject to drop-oldest shedding (asserted by fake AlarmSink recorded calls, distinct from the Event spool)
- **LOG-4.f** `TestReconcile_LateProxyEventWithinGrace_NoFalseAlarm` [unit]
  - planRef: doc 09 §7 LOG-4 (continuous reconciliation must be operable; alarm fatigue would un-prove the guardrail)
  - guardrail: Event-arrival skew inside the join-grace window does not produce false alarms; beyond the window it does
  - fn: Reconciler.Reconcile windowing
  - inputs: Kernel flow at t0; matching proxy event arriving at t0+grace/2 (late but in-window); second pair where the proxy event arrives after the window closes
  - expected: First pair reconciles clean with zero Raise calls; second pair alarms — proving the window is bounded, not infinitely forgiving
- **LOG-4.g** `TestReconcile_FlowAfterSessionTeardown_Alarms` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-4 + §3 NFT-6 teardown hygiene; doc 06 §3(b) clean-teardown row
  - guardrail: Traffic on a retired session's attribution keys is treated as a hole, never attributed to the dead session silently
  - fn: SessionRegistry.RetireSession + Reconciler
  - inputs: Session A registered then retired at t1; ConntrackFlow on A's iface/ctMark starting at t1+10s
  - expected: Alarm{Kind: PostTeardownFlow, Session: A} raised; the flow is not appended to A's normal shipped story as an ordinary FlowRecord
- **LOG-5.a** `TestCredentialAudit_WhichSessionUsedTheGitHubKey` [contract]
  - planRef: doc 09 §7 LOG-5 Done-when ('which session used the GitHub key, when, for what request' returns the answer for a test push)
  - guardrail: Credential use is fully attributable: session, service, time, request
  - fn: AuditQuerier.CredentialUses over a shipped store
  - inputs: Scripted TLS-5 test push: CredentialUseEvent{Session A, Service github, Fingerprint fp, Request{POST api.github.com /repos/x/git-receive-pack}} ingested and shipped; query {Service: github, Window covering it}
  - expected: Exactly one result: session A, the push timestamp, and the request metadata (method/host/path); querying a window before the push returns empty
- **LOG-5.b** `TestCredentialValue_AppearsNowhereInAnyLogPath` [guardrail-assurance, ADVERSARIAL]
  - planRef: doc 09 §7 LOG-5 Done-when ('the credential value appears nowhere in the event'); §5 TLS-5 ('scrub both credentials from every log path'); doc 06 §3(c) credential row
  - guardrail: Neither the long-lived nor the short-lived credential value survives anywhere in events, spool bytes, or shipped batches
  - fn: Whole pipeline as a sink-of-bytes: Collector.Ingest -> Spool files on disk -> Sink received batches
  - inputs: Seeded canary secrets (long-lived ghp_LONGCANARY..., short-lived ds_SHORTCANARY...) woven through a scripted session including the credential-use event; scanner checks raw, base64, URL-encoded, and hex encodings of both canaries
  - expected: Zero scanner hits across (1) every serialized Event, (2) the spool's on-disk bytes read directly, (3) every batch the fake Sink received, (4) the Alarm payloads; the fingerprint that IS present does not contain any canary substring
- **LOG-5.c** `TestFingerprint_StableJoinableNonReversible` [unit]
  - planRef: doc 09 §7 LOG-5 (fingerprint as the attribution payoff of D8)
  - guardrail: Fingerprints correlate uses of the same credential across events without revealing it
  - fn: FingerprintCredential
  - inputs: Table-driven: same secret twice; two secrets differing by one byte; empty secret; a 10 KiB secret
  - expected: Same secret -> identical fingerprint (joinable across sessions/time); near-identical secrets -> different fingerprints; output is fixed-length, matches the LOG-1.e format check, contains no substring of the input; empty secret is rejected with an error
- **LOG-5.d** `TestCredentialAudit_PassThroughFlows_NoUseEventButFlowStillAccounted` [contract]
  - planRef: doc 09 §7 LOG-5 + §5 TLS-4 ('pass-through flows never swap' but are 'still ... netflow-accounted'); doc 06 §3(c) pass-through row
  - guardrail: The audit trail's negative space is correct: pinned pass-through traffic produces flow accounting but never a CredentialUseEvent
  - fn: Collector + AuditQuerier over a pass-through session script
  - inputs: Scripted pass-through tunnel to a pinned domain (FlowRecord + PolicyDecision{Verdict: passthrough} present, no swap performed)
  - expected: CredentialUses query for the window returns empty; the FlowRecord and the passthrough PolicyDecision with rule provenance ARE present in the story — accounted but unswapped
