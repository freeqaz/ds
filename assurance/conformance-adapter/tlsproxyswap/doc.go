// SPDX-License-Identifier: Apache-2.0

// Package tlsproxyswap is the conformance adapter for the TLS-5 guarantee
// (D8) — the credential SWAP performed by ds-tlsproxy, the TLS-terminating
// egress gateway: the long-lived credential never enters the VM (doc 12 §1;
// doc 09 §5 TLS-5; doc 06 §3(c)). This is the M1 HEADLINE — the first service.
//
// # The guarantee
//
// Doc 06 §3(c) credential-swap row: "long-lived credential never enters the VM
// (not on disk, env, CoW delta, or any readable response)". Doc 09 §5 TLS-5
// done-when: the VM presents a SHORT-LIVED, session-bound credential; the egress
// gateway VALIDATES it against the session identity (D22), FETCHES the real
// long-lived credential from a secret store OUTSIDE the boundary (D8/D39),
// SUBSTITUTES it into the upstream request in place of the short-lived one, and
// SCRUBS both credentials from every VM-bound surface and every log path — the
// upstream sees the long-lived credential; the VM never does. A push to GitHub
// works end to end with only a short-lived credential ever present in the VM.
//
// This package wires the REAL ds-tlsproxy TLS-5 plane (dataplane/services/
// ds-tlsproxy/src/swap.rs: SwapRegistry → IdentityValidator → SecretStore fetch
// → upstream substitution → ResponseScrubber → CredentialUseEvent) behind the
// boundary/tlsproxy seams so the executable spec (D26) is satisfied against the
// real impl, not fakes.
//
// # Why this MIRRORS the boundary seam shapes (it cannot import the swap tests)
//
// The boundary TLS-5 tests live in boundary/tlsproxy/tlsproxy_swap_test.go as
// PACKAGE-INTERNAL test funcs (TestSwap_GitHubToken_UpstreamGetsLongLived_VM-
// NeverDoes, TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep [THE
// HEADLINE], TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked,
// TestSwap_CrossSessionShortLivedCred_RejectedNoFetch,
// TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven,
// TestSwap_NoRegistryMatch_RequestUntouched, TestSwap_EveryLogPathScrubbed_-
// FingerprintOnly, TestE2E_GitHubPushWithOnlyShortLivedCredInVM), and ALL their
// helpers (newInspectHarness, setupSwap, inspectRequest, newCanary,
// requireZeroLeaks, requireNoCanary, fakeIdentityValidator, recordingSecretStore,
// recordingUpstream, fakeLeakProbe, recordingSink, …) live in
// boundary/tlsproxy/tlsproxy_fakes_test.go — a _test.go file. None of that is
// importable. Only the EXPORTED seams in boundary/tlsproxy/tlsproxy.go are
// reachable (PolicyEngine, IdentityValidator, SecretStore, CredentialSwapper,
// ResponseScrubber, EventSink, LeakProbe, Credential, Secret, ServiceRule,
// SwapOutcome, ScrubHit, Event, SessionRef, …). So this adapter cannot literally
// import-and-green the TLS-5 tests; per doc 12 §1 (the tlsproxyinspect TLS-3
// package is the precedent) it MIRRORS the seam shapes — it IMPLEMENTS the
// exported PolicyEngine / IdentityValidator / SecretStore / CredentialSwapper /
// ResponseScrubber / EventSink / LeakProbe interfaces with real-plane-backed
// adapter types (AdapterSwapEngine and its collaborators) and re-expresses the
// swap assertions in this package's own _test.go file against those seams.
//
// # The CODE UNDER TEST — AdapterSwapEngine, the Go mirror of swap.rs
//
// AdapterSwapEngine is the single dispatch point that drives one HTTP request
// through the real TLS-5 pipeline over the boundary seams, exactly as main.rs
// drives swap.rs on the inspected path:
//
//  1. REGISTRY MATCH (PolicyEngine.MatchSwapService): a registry miss is NOT a
//     swap — the request is forwarded untouched, the validator and secret store
//     are NEVER called (boundary TestSwap_NoRegistryMatch_RequestUntouched).
//  2. CREDENTIAL LOCATION: the presented short-lived credential is read from the
//     rule's CredLocation (header:Authorization). Absent at that location ⇒ not a
//     swap (the cookie/no-cred rows pass through untouched).
//  3. SYNCHRONOUS VALIDATE (IdentityValidator.ValidateShortLived, D22): the
//     presented credential must validate against THIS session. Cross-session,
//     forged, expired, tampered, or wrong-service creds DENY here with a readable
//     4xx — the secret store is NEVER consulted on a validation failure
//     (boundary TestSwap_CrossSessionShortLivedCred_RejectedNoFetch,
//     TestSwap_InvalidShortLivedCreds_RejectedNoFetch_TableDriven).
//  4. FETCH (SecretStore.FetchLongLived, D8/D39): only on an ALLOW is the real
//     long-lived credential fetched from the store OUTSIDE the boundary.
//  5. SUBSTITUTE: the long-lived value replaces the short-lived one in the
//     outbound Authorization header IN PLACE — the upstream gets the long-lived
//     credential, the short-lived one never leaves the boundary.
//  6. SCRUB (ResponseScrubber.ScrubResponse): an upstream echoing the swapped
//     credential back must never deliver it downstream — the VM-bound response is
//     scrubbed (raw AND encoded forms, base64 in scope) or the response is
//     blocked; a ScrubEvent is emitted on a hit (boundary
//     TestSwap_UpstreamEchoesCredential_ResponseScrubbedOrBlocked).
//  7. AUDIT (EventSink, LOG-5): a CredentialUseEvent records which session used
//     the service key, when (the injected clock), and for what request — carrying
//     the FINGERPRINT only, never a credential byte (boundary
//     TestSwap_EveryLogPathScrubbed_FingerprintOnly). On a proxy-generated error
//     page (upstream dial fails mid-swap) the proxy answers with its own 502, a
//     VM surface the headline grep covers.
//
// Because the SAME dispatch code takes EITHER leg (swap / no-swap / deny) and the
// fetch/validate ORDER is the system's, a test driving it and asserting which
// seam methods ran (and in which order) proves a genuine property of the system —
// not a tautology over a test-local reimplementation.
//
// # THE HEADLINE — the all-surfaces canary grep
//
// TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep mirrors the boundary
// headline: it drives the adversarial scenarios that each try to smuggle the
// long-lived canary onto a VM surface (happy-path swap, upstream 401/500 echoing
// the header, redirect chains carrying it in Location, TRACE reflection, oversized
// responses straddling buffer boundaries, proxy-generated error pages, abort
// mid-swap, malformed upstream responses), records every byte the proxy sent
// toward the VM plus disk / env / CoW-delta surfaces on an AdapterLeakProbe, then
// GREPS all surfaces for the canary in every encoded form (raw/base64/base64url/
// hex/url-encoded) and asserts ZERO hits. TestE2E_GitHubPushWithOnlyShortLived-
// CredInVM drives a git-receive-pack push whose fake GitHub accepts ONLY the
// long-lived canary, proving the push works end to end while the VM holds only the
// short-lived credential and zero long-lived bytes are observable anywhere.
//
// # NEVER-LOG-THE-SECRET is structural (D73 §5.1 / LOG-5), not a scrub pass
//
// Every event this engine emits carries credential FINGERPRINTS only, never
// values; the long-lived credential bytes live only inside the upstream-bound
// header substitution and are dropped immediately after. The scrubber is the
// belt-and-suspenders for an upstream that ECHOES the swapped value back toward
// the VM; the event/log paths never carry a credential byte in the first place.
// The headline grep over serialized events asserts this.
//
// # The sentinel naming convention is LOAD-BEARING (Err prefix + errors.New)
//
// Mirrored from tlsproxyinspect: every exported reject cause is declared as a
// package-level var of the form `Err<Name> = errors.New("tlsproxyswap: …")`
// (tlsproxyswap.go: ErrNoSwapRule, ErrIdentityRejected, ErrSecretUnavailable,
// ErrCredentialLeaked) and enumerated in exportedSentinelUniverse
// (tlsproxyswap_test.go). TestExportedSentinelUniverseComplete reconciles the
// table against source by parsing the `Err* = errors.New(...)` var specs, and
// TestExportedErrorVarsCoveredByUniverse is a naming-agnostic backstop flagging
// ANY exported error-constructing var missing from the universe. DO declare every
// new exported reject cause as `Err<Name> = errors.New(...)` and add it to the
// universe; wrap runtime detail with fmt.Errorf("%w …", ErrName, …) at the return
// site, keeping the package-level SENTINEL an errors.New Err* var.
//
// # The DS_TLS5_LIVE env-gate contract (mirrors DS_TLS3_LIVE)
//
// DS_TLS5_LIVE (the LiveEnvVar constant) is the single switch for the live half:
//
//   - UNSET or any value other than "1" (the default, the CI posture): the live
//     half is disabled — LiveEnabled() returns false, TestLive_SwapConformance
//     SKIPS, no network is touched. CI never sets it, so the default
//     `go test ./...` is offline and deterministic.
//   - "1": the operator opts into the live run; until the real driver lands the
//     scaffold fails LOUDLY per workload (never a vacuous pass) — the over-the-
//     wire git-push-to-real-GitHub leg is a DEFERRED MANUAL step (it needs a
//     running ds-tlsproxy + a live kernel/network + a real long-lived credential
//     the wave sandbox lacks). DS_TLS5_TLSPROXY_ADDR (read by LiveTargetFromEnv)
//     points the run at a deployment's egress gateway; it does not by itself
//     enable the gate.
//
// The in-process swap pipeline + all-surfaces canary grep is the OFFLINE half
// (always runs, deterministic); the over-the-wire git-push-to-real-GitHub row is
// the env-gated live half deferred to CI.
//
// # D40 / doc 12 §13.1 — pingora confinement holds across the seam
//
// Pingora is confined to the ds-tlsproxy binary (main.rs); the lib-side TLS-5
// module (swap.rs) is pingora-free. This Go adapter trivially satisfies the
// confinement — it CANNOT import pingora — and drives the real plane via the
// EXPORTED Go seams, never reaching into pingora wiring.
//
// # Egress-gateway / TLS-termination vocabulary
//
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-TERMINATING boundary service on the
// egress path. TLS-5 is where the egress gateway, having terminated the VM's TLS
// (TLS-3), SWAPS the short-lived credential for the long-lived one before
// re-originating upstream. "Egress gateway" and "TLS termination" are the
// canonical terms throughout.
//
// # What this package does NOT own
//
// The TLS-5 VERDICT is owned by the ds-tlsproxy data plane (dataplane/services/
// ds-tlsproxy/src/swap.rs) and the boundary/ spec (boundary/tlsproxy). This
// package is the runnable bridge to that plane plus the offline swap-pipeline +
// all-surfaces canary grep that keeps CI honest about the headline the live half
// will check over the wire.
package tlsproxyswap
