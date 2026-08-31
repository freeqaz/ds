// SPDX-License-Identifier: Apache-2.0

// Package netflowadapter is the conformance adapter for proxy-side netflow
// telemetry with admitting-DNS-name attribution (doc 09 §7 LOG-1..LOG-5; doc 12
// §3/§5/§10; D17/D74). It is the assurance twin of the boundary/flowlog
// executable spec (D26): it WIRES the real ds-tlsproxy event stream behind the
// boundary/flowlog Collector / Attributor (SessionRegistry + AdmissionIndex) /
// Spool / Shipper / Sink seams so the netflow-emission contract is satisfied
// against the real plane, not fakes.
//
// The headline run (netflowadapter.go + netflowadapter_test.go) covers LOG-1..
// LOG-3 over the real dispatcher. The full LOG-* surface is completed here in
// three additive files that satisfy the remaining boundary/flowlog seams from
// the conformance adapter (never editing boundary/, the tlsproxyinspect
// precedent):
//
//   - schema_audit.go (LOG-1 wire codec + Validate; LOG-5 FingerprintCredential +
//     AuditQuerier): a lossless, byte-stable MarshalEvent/UnmarshalEvent envelope
//     over the sealed Event union; Validate enforcing SessionRef + POL-3
//     provenance + the FULL CredentialFingerprint format; a SHA-256 fingerprint
//     (stable/avalanche/non-reversible/fixed, empty rejected); and a credential-
//     use audit querier over the shipped store.
//   - reconcile.go (LOG-4): the self-auditing reconciler — every kernel byte must
//     be explained by a proxy session or an in-force, session-scoped, port+proto
//     escape-hatch allowance, else a TYPED alarm (unexplained / byte-mismatch /
//     post-teardown) raised on a channel DISTINCT from the droppable Events spool.
//
// # The guarantee
//
// Doc 09 §7 LOG-1..LOG-5: the boundary emits netflow-style telemetry for every
// admitted egress connection, joined to the DNS-2 admitting domain (LOG-2), and
// at the correct CARDINALITY — one flow record per connection, never per HTTP
// request. The inspected path additionally emits HTTP metadata (HttpEvent); the
// opaque pass-through path emits ONLY the connection-level FlowRecord (the tunnel
// is opaque — doc 12 §3/§5/§10 non-claim). This package drives SCRIPTED sessions
// through the real proxy dispatch plane and proves all four properties hold of
// the emitted stream.
//
// # The precedent and what this REUSES (tlsproxyinspect)
//
// assurance/conformance-adapter/tlsproxyinspect is the TLS-3 precedent: it
// implements the boundary/tlsproxy SessionCA / CAMinter / UpstreamDialer /
// EventSink seams with real-plane-backed adapter types and exposes the
// PassThroughDispatcher — the Go mirror of main.rs proceed_route + the opaque
// splice + passThroughNetflowEvent. The DISPATCHER, not a test, consults the
// pass-through seam and routes an admitted flow to either the inspected leg
// (LeafFor + DialTLS, which yields HTTP-level telemetry) or the opaque pass-
// through leg (DialRaw, which emits the connection-level netflow EventFlow). This
// package REUSES that real dispatcher (and its env-gated DS_TLS3_LIVE live-harness
// posture) as the source of proxy emissions, then JOINS each emission to the
// admitting domain and INGESTS it through the boundary/flowlog seams. So the
// emissions under test are the system's (the dispatcher chose the leg and built
// the event), not test literals.
//
// # Two seam families, one adapter
//
// The proxy emits in the boundary/tlsproxy vocabulary (tlsproxy.Event: EventFlow
// for the opaque tunnel, EventHTTP for the inspected request). ds-flowlog
// COLLECTS in the boundary/flowlog vocabulary (flowlog.Event union: FlowRecord +
// HttpEvent + DnsEvent + CredentialUseEvent + PolicyDecision). This adapter is the
// bridge: the proxyDriver runs the dispatcher (which CHOOSES the leg and, on the
// opaque leg, emits its own tlsproxy.EventFlow into a capturing sink) and reads
// back the dispatcher's ROUTE decision. Driven by that route value, the driver
// SYNTHESIZES the flowlog twin — it builds exactly one FlowRecord per connection
// from the connection-level conntrack and ATTRIBUTES it through the LOG-2 join
// (the SessionRegistry's ct mark + iifname -> SessionRef and the AdmissionIndex's
// SNI -> admitting domain), and on RouteInspect adds one HttpEvent per request.
// The dispatcher's opaque EventFlow carries only session + dst + SNI (no byte
// counts), so the connection-level FlowRecord cannot be derived from it; the
// capturing sink merely ABSORBS the dispatcher's emission (so the opaque leg's
// Emit does not error) — the FlowRecord is synthesized route-side, not translated
// from the captured EventFlow. The synthesized flowlog.Events are INGESTED through
// a real flowlog.Collector into a real flowlog.Spool, drained by a real
// flowlog.Shipper into a real flowlog.Sink. The dispatcher choosing the leg is
// what makes the route — and thus the HTTP-vs-no-HTTP split — the system's.
//
// # The four proven properties (acceptance)
//
//   - (1) DNS-name attribution: every emitted FlowRecord and HttpEvent carries
//     the admitting domain joined from the SNI via the AdmissionIndex (LOG-2). The
//     join is performed by the Attributor / AdmissionIndex this package implements,
//     not asserted of test code.
//   - (2) inspected flows emit BOTH a FlowRecord (L3/4 connection metadata) AND an
//     HttpEvent (HTTP request metadata): the inspected leg sees the request, so
//     both planes of telemetry are present.
//   - (3) passthrough flows emit ONLY a FlowRecord, never an HttpEvent: the tunnel
//     is opaque, so no HTTP-level metadata exists to carry (doc 12 §3/§5/§10). A
//     leaked HTTP field on a pass-through flow fails the suite.
//   - (4) cardinality: exactly ONE FlowRecord per connection — driving N HTTP
//     requests over one inspected connection yields one FlowRecord and N
//     HttpEvents, never N FlowRecords. The connection is the netflow unit (LOG-1).
//
// # The boundary/flowlog seams this IMPLEMENTS (real, not stub)
//
// boundary/flowlog ships RED stubs (every New…() returns ErrNotImplemented). This
// adapter provides REAL implementations of the seams the netflow path needs —
// SessionRegistry (ct mark + iifname -> SessionRef, retired at teardown),
// AdmissionIndex (DNS-2 stream -> time-windowed admitting-domain index),
// Attributor (the LOG-2 join), Collector (single ingest point), Spool (in-memory
// disk-bounded buffer), Router (D19 tier routing), Shipper (drain spool -> sink),
// and Sink (the queryable off-box store the doc-06 "queryable" assertion reads).
// The adapter NEVER edits the boundary/flowlog seams — it satisfies them from
// here (the precedent set by tlsproxyinspect against boundary/tlsproxy).
//
// # Scope boundary — the Rust §10 emission seam is NOT this unit
//
// The netflow seam ITSELF — emission from the Rust ds-tlsproxy data plane
// (passthrough_netflow_event in main.rs + the inspected-path HttpEvent in
// telemetry_http.rs) — is a §10 seam unit, NOT part of this adapter. This adapter
// is Go-only: it drives the dispatcher (the real-plane Go mirror of that emission)
// and proves the COLLECTION + ATTRIBUTION + CARDINALITY contract over what the
// proxy emits. The Rust emission is exercised by its own dataplane unit and the
// env-gated DS_TLS3_LIVE live half.
//
// # The DS_TLS3_LIVE env-gate contract (inherited from tlsproxyinspect)
//
// The live half — driving curl/npm/git over HTTPS through a RUNNING ds-tlsproxy
// and asserting netflow emission over the wire — is env-gated behind DS_TLS3_LIVE
// (the tlsproxyinspect.LiveEnvVar), default SKIPPED. The offline default drives
// the real dispatcher in-process over loopback, which is deterministic and needs
// no live kernel/network. CI never sets the gate, so the default `go test` run is
// offline.
//
// # Egress-gateway / TLS-termination vocabulary
//
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-TERMINATING boundary service. The
// inspected path TERMINATES the VM's TLS (a per-origin leaf) and re-originates
// upstream; the pass-through path leaves an OPAQUE tunnel. Netflow accounts both;
// only the inspected path observes HTTP metadata.
//
// # The sentinel naming convention is LOAD-BEARING (Err prefix + errors.New)
//
// Every exported reject cause is `Err<Name> = errors.New("netflowadapter: …")`
// (netflowadapter.go: ErrUnattributedFlow, ErrMissingAdmittingDomain), wrapped
// at the return site with fmt.Errorf("%w …", ErrName, …). This mirrors the
// tlsproxyinspect / resolverlock convention.
package netflowadapter
