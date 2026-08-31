// SPDX-License-Identifier: Apache-2.0

// Package grantfetchconform is the conformance adapter that stands up the REAL
// identity/grant-service GrantFetchServiceServer behind the central fakes-first
// dual-run (doc 16 §5.1/§5.4/§9; doc 06 §2.1; D24/D14/D39/D50/D80).
//
// # What gap this closes (01KV4KBZYF)
//
// The central dual-run for the GrantFetchService credential-swap-fetch seam lives
// in assurance/contract-harness/dualrun/grantfetch_dualrun_test.go. Before this
// adapter it stood up BOTH dual-run ends through the generated identityv1fake
// wrapping an honest in-test responder (honestGrantFetchResponder) — so it proved
// the FAKE agrees with the documented contract, but it never exercised the actual
// identity/grant-service/service.go + server.go. A real-impl drift was invisible
// to the central seam; only the module-local server_test.go saw the served RPC.
//
// This adapter exposes the real grant-service Server registration on the central
// dual-run's shared in-process bufconn (mirroring tlsproxyinspect/ + resolverlock/),
// so the central dual-run's "real" end now dials the ACTUAL
// grantservice.NewServer(Service) — its grant_ref-binding guard, own-session
// liveness check, per-session cache, and the §5.1 store-outage stall-vs-deny
// classification all run for real. A deliberately drifted real impl now fails the
// CENTRAL seam, not just the module-local pin. The adapter returns the generated
// RegisterGrantFetchServiceServer registration func (not a dualrun.Dialer), so it
// depends only on grant-service + proto/gen/go + grpc and the contract-harness
// dual-run test hands it to dualrun.InProcess — no conformance-adapter ->
// contract-harness module edge, no module import cycle.
//
// # How the real Service reproduces the dual-run fixtures
//
// The dual-run drives a synthetic fleet (D50): a live github-granted session, a
// revoked (not-live) session, a live github-granted session whose key store is in
// a transient §5.1 outage, plus the warm-cache complement (an in-flight session
// warmed pre-outage that rides its cache, and a cold-miss session that stalls).
// The real grantservice.Service models each leg natively:
//
//   - liveness — RegisterSession admits the live sessions; an UNregistered session
//     (the revoked fixture) fails closed as SESSION_NOT_LIVE;
//   - grant_ref binding + grant-not-found — the Service's own grantRefMatches guard
//     rejects a mismatched ref (GRANT_REF_MISMATCH) before any store read, and a
//     ref with no stored credential is GRANT_NOT_FOUND;
//   - the §5.1 store outage — the Backend seam (D39) is the store. The Service
//     classifies a cache-miss Backend ErrStoreUnavailable as the retryable
//     STORE_UNAVAILABLE stall and ErrGrantNotFound as a definitive deny, exactly
//     as backend.go/service.go do.
//
// The static suite needs ONE session to fetch OK and grant-not-found while ANOTHER
// session's NEW fetch stalls in the SAME run. The real Service's Backend is keyed
// by grant_ref (which encodes session×service), so the adapter backs it with a
// refStallBackend (this file): a synthetic Backend that returns the real synthetic
// credential for the live refs, ErrStoreUnavailable for the per-session
// store-outage refs, and ErrGrantNotFound otherwise — the per-ref shape the
// responder's per-session storeDown bit encoded, driven through the REAL Service.
// The warm-cache suite instead uses the production FileKVBackend with a global
// SetAvailable flip (the actual §5.1 outage lever), exposed via SetStoreAvailable.
//
// # Synthetic / in-process only (D50)
//
// bufconn is an in-memory pipe — no socket, no off-box transport, no live KV. The
// credentials are obviously-synthetic swap-class fixtures. The only thing that
// varies between the real and fake dual-run ends is the registered server (the
// generated fake vs. this real Server), so a divergence is attributable to the
// contract, never the plumbing — the assurance/contract-harness/dualrun InProcess
// principle. proto/gen/go is the one legal cross-tree import (D80); grant-service
// (and its kv-client Backend sibling) arrive via go.mod require+replace + a go.work
// use entry, the standalone-module pattern mint/grant-service already follow, so
// both the workspace build and the GOWORK=off standalone build stay green.
package grantfetchconform
