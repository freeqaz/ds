// SPDX-License-Identifier: Apache-2.0

// Package tlsproxyinspect is the conformance adapter for the TLS-3 guarantee
// (D17) — per-session-CA TLS termination + strict-WebPKI re-origination by
// ds-tlsproxy, the TLS-terminating egress gateway (doc 12 §3; doc 09 §5 TLS-3).
//
// # The guarantee
//
// Doc 09 §5 TLS-3 done-when (#1, the proxy-conformance-suite-passes row): the
// doc 06 proxy conformance suite passes — curl, npm, and git over HTTPS through
// the egress gateway see VALID TLS (the per-session interception CA mints a
// per-origin leaf naming the exact origin, the client trusting the session pool
// validates it), the request/response METADATA reaches telemetry, AND session
// A's per-session interception CA is USELESS against session B. This package
// wires the REAL ds-tlsproxy TLS-3 plane behind the boundary/tlsproxy seams so
// the executable spec (D26) is satisfied against the real impl, not fakes.
//
// # Why this MIRRORS the boundary seam shapes (it cannot import the TLS-3 tests)
//
// The boundary TLS-3.a-d tests live in boundary/tlsproxy/tlsproxy_inspect_test.go
// as PACKAGE-INTERNAL test funcs (TestInspect_PerOriginLeaf_ValidTLS_Metadata-
// Telemetry [3.a], TestInspect_UpstreamWebPKI_BadCerts_Refused_TableDriven [3.b],
// TestInspect_PerSessionCAIsolation_AUselessAgainstB [3.c],
// TestInspect_LeafCache_StablePerOrigin [3.d]), and ALL their helpers
// (newInspectHarness, mintCACert, mintLeafCert, selfSignedLeaf, recordingUpstream,
// fakeSessionCA, fakeCAMinter, lockedBuffer, startTLSListener) live in
// boundary/tlsproxy/tlsproxy_fakes_test.go — a _test.go file. None of that is
// importable. Only the EXPORTED seams in boundary/tlsproxy/tlsproxy.go are
// reachable (SessionCA, CAMinter, UpstreamDialer, EventSink, Config, Event,
// Provenance, SessionRef, …). So this adapter cannot literally import-and-green
// the TLS-3.a-d tests; per the build plan it MIRRORS the seam shapes — it
// IMPLEMENTS the exported CAMinter / SessionCA / UpstreamDialer / EventSink
// interfaces with real-plane-backed adapter types (AdapterCAMinter,
// StrictWebPKIDialer, CapturingEventSink) and re-expresses the TLS-3.a-d
// assertions in this package's own _test.go files against those real-plane-backed
// seams. (Note: boundary's own NewUpstreamDialer is a RED stub returning
// ErrNotImplemented at the spec layer, so the strict-WebPKI re-origination verdict
// the seam promises is implemented HERE as the Go mirror of dataplane's
// reoriginate.rs — the adapter IS the real plane behind the seam for the offline
// row.)
//
// # Two halves, one source
//
// This package has an OFFLINE half and a LIVE half over ONE adapter that drives
// the real TLS-3 plane:
//
//   - OFFLINE (default, always runs; no live kernel/network): drives the real
//     StrictWebPKIDialer over loopback TLS listeners for the TLS-3.b bad-cert
//     table — self-signed, expired, hostname-mismatch, untrusted-chain, and
//     invalid-intermediate upstreams each REFUSE with a certificate-verification
//     error and zero upstream payload bytes, while a control valid cert
//     re-originates cleanly (doc 12 §13.5: upstream WebPKI fail -> REFUSE). This
//     is the one row that exercises real strict-WebPKI re-validation in-process.
//     It also asserts real-plane cert-shaping PARITY for the rows that need a live
//     wire to run end-to-end: 3.a (the minted per-origin leaf names the exact
//     origin and is issued by ds-session-ca-<id>, the inspected-default marker;
//     a client trusting only the session pool validates the chain), 3.c (distinct
//     per-session CA keypairs; A's trust pool is useless against B's leaf; an
//     A-CA-signed server cert is refused inside B's strict-WebPKI re-origination),
//     and 3.d (the leaf cache is stable per (session, origin) — sequential
//     LeafFor calls return a byte-identical cached leaf, distinct origins/sessions
//     never share one; doc 12 §13.2).
//
//   - LIVE (env-gated DS_TLS3_LIVE=1, default SKIPPED): drives curl / npm / git
//     over HTTPS through a RUNNING ds-tlsproxy at DS_TLS3_TLSPROXY_ADDR and asserts
//     valid TLS + metadata-in-telemetry (3.a) and per-session-CA isolation over
//     the wire (3.c). It is a DEFERRED MANUAL step: it needs a running ds-tlsproxy
//     binary + a live kernel/network the wave sandbox lacks. Until an operator
//     wires the real driver, the runners fail LOUDLY when the gate is on
//     (the notYetWired scaffold), so DS_TLS3_LIVE=1 never reports a false green.
//
// The over-the-wire TLS-3.a/3.c real-plane rows are therefore DEFERRED TO CI; the
// 3.b strict-WebPKI re-validation is exercised in-process offline.
//
// # The DS_TLS3_LIVE env-gate contract
//
// DS_TLS3_LIVE (the LiveEnvVar constant) is the single switch for the live half:
//
//   - UNSET or any value other than "1" (the default, and the CI posture): the
//     live half is disabled — LiveEnabled() returns false, TestLive_Inspect-
//     Conformance SKIPS naming this var, and no network is touched. CI never sets
//     it, so the default `go test ./...` is offline and deterministic.
//   - "1": the operator opts into the live run. Until the real driver lands the
//     scaffold fails LOUDLY per workload (never a vacuous pass).
//   - DS_TLS3_TLSPROXY_ADDR (read by LiveTargetFromEnv): points the live run at a
//     deployment's egress gateway; localhost dev default otherwise. It only
//     resolves WHERE the live half would connect — it does not by itself enable
//     it; the gate above still governs.
//
// # D82 — the per-session CA is INGESTED, not minted in-process
//
// D82 (two-root hierarchy): the per-session interception CA is minted by the
// Identity workstream (doc 16 §4) and handed to ds-tlsproxy as OPAQUE material;
// the proxy never mints a CA in-process. AdapterCAMinter models that hand-off —
// SessionMaterial is the opaque (CertPEM, KeyDER) input the adapter INGESTS and
// PARSES to serve LeafFor / CertPool; it never fabricates a CA. Missing or
// malformed material fails with ErrCAMaterialUnavailable rather than silently
// minting one.
//
// # D76 — every upstream socket carries the SO_MARK before connect
//
// D76: every upstream socket, re-originated leg included, carries the session
// SO_MARK before connect. StrictWebPKIDialer applies it via a net.Dialer.Control
// func on a live kernel (the env-gated live half, which needs CAP_NET_ADMIN);
// over loopback (the offline half) the mark is inert and the dialer exercises the
// strict-WebPKI VERDICT, which is the property the offline row asserts.
//
// # D40 / doc 12 §13.1 — pingora confinement holds across the seam
//
// Pingora is confined to the ds-tlsproxy binary (main.rs); the lib-side TLS-3
// modules (ca.rs, reoriginate.rs, telemetry_http.rs) are pingora-free. This Go
// adapter trivially satisfies the confinement — it CANNOT import pingora — and it
// drives the real plane via the EXPORTED Go seams (offline) and over the wire
// against a running ds-tlsproxy (live), NEVER reaching into pingora wiring. So the
// confinement story is complete across the seam: neither the lib modules nor this
// adapter touch pingora; only main.rs does.
//
// # Egress-gateway / TLS-termination vocabulary
//
// This package uses the project's network-proxy vocabulary consistently:
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-TERMINATING boundary service on the
// egress path. TLS-3 is where the egress gateway TERMINATES the VM's TLS with a
// per-session interception CA, mints a per-origin leaf, and RE-ORIGINATES upstream
// with strict WebPKI validation. "Egress gateway" and "TLS termination" are the
// canonical terms throughout.
//
// # The sentinel naming convention is LOAD-BEARING (Err prefix + errors.New)
//
// Every exported reject cause is declared as a package-level var of the form
// `Err<Name> = errors.New("tlsproxyinspect: …")` (tlsproxyinspect.go:
// ErrCAMaterialUnavailable, ErrLeafNotForOrigin, ErrUpstreamNotRefused), and each
// is enumerated in exportedSentinelUniverse (tlsproxyinspect_test.go). This is not
// style: TestExportedSentinelUniverseComplete reconciles that table against source
// by parsing exactly the `Err* = errors.New(...)` var specs across non-_test.go
// files, and TestExportedErrorVarsCoveredByUniverse is a naming-AGNOSTIC backstop
// that flags ANY exported error-constructing var (errors.New or fmt.Errorf)
// missing from the universe — so a sentinel that BROKE the convention cannot slip
// past the by-name scan. DO declare every new exported reject cause as
// `Err<Name> = errors.New(...)` and add it to exportedSentinelUniverse; wrap
// runtime detail with fmt.Errorf("%w …", ErrName, …) at the RETURN site, keeping
// the package-level SENTINEL an errors.New Err* var.
//
// # What this package does NOT own
//
// The TLS-3 VERDICT is owned by the ds-tlsproxy data plane (dataplane/services/
// ds-tlsproxy: ca.rs / reoriginate.rs / telemetry_http.rs) and the boundary/ spec
// (boundary/tlsproxy). This package is the runnable bridge to that plane plus the
// offline strict-WebPKI re-validation + cert-shaping parity that keeps CI honest
// about the contract the live half will check over the wire.
package tlsproxyinspect
