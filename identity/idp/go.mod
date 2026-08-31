// SPDX-License-Identifier: Apache-2.0

// The Identity IdP front end — Okta-via-generic-OIDC launch-time HUMAN auth
// (doc 16 §11.2; doc 07 §2c; D45/D55/D56/D57).
//
// This module is the IdP half of the M1 integration: it authenticates the
// launching HUMAN at mint time and resolves the OIDC subject to the claim value
// the workload identity's `launching_user` field carries (doc 16 §3.1/§3.2). It
// runs the OAuth 2.0 device-authorization grant (RFC 8628) for the CLI and
// exposes the redirect-flow seam for the D18 web client; it validates the OIDC
// ID token against the IdP's JWKS, extracts the §11.2 claim mapping (subject →
// launching_user, groups → platform roles), and carries the offboarding ladder
// seam (SCIM/session signal → grant-issuance re-check → suspend signal).
//
// The IdP is a MINT-TIME-ONLY authority: it NEVER participates in per-request
// workload validation — that is the frozen D22 `Validate` seam (identity/mint),
// stated in code where the boundary is visible. This module holds no D22 logic.
//
// Deliberately OUTSIDE go.work — the same standalone-module pattern as
// ../mint, ../grant-service, and ../fakes/digest-publisher (a substrate swap
// must not perturb the workspace; built/vetted/tested under GOWORK=off in the
// off-workspace CI lane). STDLIB-ONLY: generic OIDC is HTTP + JSON + JWS, all
// covered by net/http, encoding/json, crypto/rsa, crypto/ecdsa, and
// encoding/base64 — no OIDC/JWT library, no proto/grpc. The platform-side
// principal upsert + launch gate live in orchestrator/internal/auth (this
// module is reachable across the resolved-claim DATA shape, never imported with
// a store handle). No real IdP and no real key material anywhere — a fake OIDC
// server (httptest) with in-test synthetic keys drives every test (D50).
module github.com/dream-serpent/dream-serpent/identity/idp

go 1.25.11
