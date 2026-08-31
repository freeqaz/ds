<!-- SPDX-License-Identifier: Apache-2.0 -->

# identity/idp — Okta-via-generic-OIDC launch-time human auth

**Charter.** The IdP front end for the M1 integration: authenticate the launching
**human** at mint time and resolve the OIDC subject to the `launching_user` claim
value the workload identity carries (doc 16 §11.2; doc 07 §2c). Okta is implemented as
**generic OIDC** so a second IdP (Entra ID, Google Workspace, any OIDC provider)
is a new config row, not new code (D55).

**Owner / mark / decisions.** Identity workstream; OSS contracts, paid brokerage
(the IdP integration/mapping is the D85 paid side — this module is the
standards-seam machinery the brokerage configures). D45 (org-admin / role
taxonomy), D55 (config-not-code), D56 (enrollment), D57 (seats/viewers
reserved-shape), D50 (synthetic fixtures only).

## What it does

- **Device-code flow (CLI).** OAuth 2.0 device-authorization grant (RFC 8628):
  request a device + user code, print the verification URL, poll the token
  endpoint until the human completes auth + MFA in any browser (`DeviceFlow`).
- **Redirect-flow seam (web client).** OIDC authorization-code-with-PKCE — the
  D18 web client is a separate epic; this exposes the `AuthURL` + `Exchange`
  seam it plugs into (`RedirectFlow`). Both flows converge on one validated
  `AuthResult`.
- **Generic OIDC config + ID-token validation.** Discovery, JWKS, and
  signature + `iss`/`aud`/`exp`/nonce validation (RS256/ES256), stdlib JWS
  (`Config`, `Provider`).
- **Group → role mapping.** The org-level `GroupRoleMap` maps asserted IdP
  groups to the §3.2 platform roles; roles are **derived** from the asserted
  groups every auth (never a stored ACL), and an unmapped group confers no role
  (fail-closed) (`Config.MapGroups`).
- **Offboarding ladder.** Rung 1 `Subscriber` (SCIM/session signals where
  available) → rung 2 `RecheckActive` (the universal grant-issuance re-check
  floor) → rung 3 `SuspendSink` (fires the **existing** `SUSPENDED(user)`
  signal, D35 — wired as data/interface, no new state) (`Offboarder`).

## The mint-time-only boundary (load-bearing)

The IdP participates **only** at mint time — it authenticates the human and
asserts group claims. It is **never** on the per-request hot path: every egress
request's credential is validated at the frozen **D22 `Validate` seam**
(`identity/mint`), with no call to the IdP. This module holds no D22 logic; it
ends at the validated `AuthResult`. The orchestrator-side principal upsert + the
launch gate live in [`orchestrator/internal/auth`](../../orchestrator/internal/auth/).

## Build

Standalone Go module, **outside `go.work`** (the same pattern as `../mint`,
`../grant-service`, `../fakes/digest-publisher`). **Stdlib-only** — generic OIDC
is HTTP + JSON + JWS, no OIDC/JWT library and no proto/grpc.

```sh
cd identity/idp && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./...
```

Every test is driven by a **fake OIDC server** (`httptest`) with **synthetic
keys generated in-test** — no live IdP, no real key material (D50).

**CI.** This module is compiled/vetted/tested by the `off-workspace-modules`
job in `.github/workflows/go.yml` (`GOWORK=off`,
beside `../mint` and `../grant-service`) — so the alg-confusion CVE pins below
run in GitHub Actions, not only in the wave green-gate, and the module cannot
silently rot outside `go.work`. That lane's first step asserts every
off-workspace `go.mod` declares the same `go` line as `go.work` (its `setup-go`
resolves one toolchain for the whole lane from a single `go.mod`), so a stray
`go`-line bump here would fail closed rather than build on a mismatched
toolchain.

The JWS verifier's alg-confusion defense (`verifyJWS`: alg must match the JWKS
key type; `none`/unknown alg is a hard `ErrToken`) is pinned by direct negative
tests in `algconfusion_test.go` — the classic JWS-verification CVEs as
refusals: **alg:none** (and its `None`/`NONE` casing variants, with and without
smuggled signature bytes), **RS256-over-an-EC-key**, **ES256-over-an-RSA-key**,
**kid-swap** (a valid signature presented under a different key's `kid`), and
**unknown-kid**. The symmetric-confusion CVE is pinned too:
**HS256-over-the-published-public-key** — a token signed `HS256` with the
server's RSA/EC public-key bytes (attacker-known, published in the JWKS) as the
HMAC secret. `verifyJWS` has no `HS256` arm, so the token falls to the default
"unsupported or unsafe signing alg" refusal; the test pins that named reason
(across RSA + EC keys, the PKIX-DER and raw-modulus secret encodings, and the
`hs256`/`Hs256`/`HS384`/`HS512` casing/sibling variants) so a future regression
adding an HS256 arm that fed the JWKS key to an HMAC verify would flip the reason
and fail the test. Each must surface `ErrToken` and never validate; the kid-swap
and HS256-kid-points-at-asymmetric-key cases carry positive controls (the
correctly-`kid`'d / correctly-`RS256`'d token still validates) so each rejection
is proven to be the intended defense, not a broken harness.

**Structural allowlist + header-member contract (landed this wave).** The
never-reach-HMAC property is now a **structural invariant**, not an inference
from an absent switch arm: `verifyJWS` checks an explicit `{RS256, ES256}` alg
allowlist *before* key resolution and *before* the verify switch, so a
symmetric / `none` / unknown alg is rejected by construction — the property is
reviewable at a glance (doc 16 §11.2
"the key source is the IdP JWKS only"). The same change pins the JWS
protected-header members that would move key resolution *off* the JWKS or
smuggle an unprocessed extension: `jku`/`x5u`/`x5c` (self-declared key sources)
must never redirect key resolution, and a non-empty `crit` (RFC 7515 §4.1.11
unknown critical extension) fails closed — both refused at header parse, before
`keyFor`, so the verifier's key is always the JWKS key the `kid` names and never
a token-asserted one. `algconfusion_test.go` carries the matching negative cases.
(That this contract is not yet cited by a `D`-number in docs/04 §6 is filed as a
ratification follow-up — see the wave findings note below.)

**`x5t`/`x5t#S256` cert-thumbprint policy (landed orch16).** The JWS `x5t`
(SHA-1) and `x5t#S256` (SHA-256) X.509 cert-thumbprint members (RFC 7515
§4.1.7/§4.1.8) are **refused on presence**, the same fail-closed fence as
`x5c`/`x5u`: a thumbprint names a certificate the *token* chose, not the JWKS key
the `kid` resolves. Key resolution is `kid`-only, so a thumbprint can only
*describe* — never *move* — resolution; we refuse anyway for fence consistency
with the other self-declared cert references and as defense-in-depth (an
unverified cert assertion in the protected header is a member the verifier does
not process, so it fails closed rather than being silently ignored — same posture
as `crit`). Enforced in `jwsHeader.validate` (see `oidc.go` `x5tDecision`);
`algconfusion_test.go` pins both the refusals and the no-over-rejection controls,
and `oidc_test.go` carries an end-to-end device-code refusal proving the contract
holds on the integrated mint-time path.

**`typ`-header policy (landed orch15).** The JWS `typ` (JOSE object type) member
is pinned to the set **{absent, JWT-family}** for OIDC ID-token verification: a
missing `typ` is accepted (RFC 7519 §5.1 makes it optional and many IdPs omit it
on ID tokens) and a present `typ` must be the JWT media type (`JWT` /
`application/JWT`, matched case-insensitively with the optional `application/`
prefix), while a `typ` naming a *distinct* JOSE object — `at+jwt` (RFC 9068
access token), `logout+jwt`, `dpop+jwt` (RFC 9449), `secevent+jwt`, etc. — is a
hard `ErrToken` refusal, so a token the IdP minted for another purpose cannot be
replayed as an ID token (the `typ`-confusion defense). This is enforced in
`jwsHeader.validate` via the `typAllowed` predicate, at header parse alongside
the other header-member checks (doc 16 §11.2's "key source is the IdP JWKS only"
header-member contract); `algconfusion_test.go` pins both the accepted shapes
(absent / JWT spellings validate) and the wrong-type refusals (named reason, at
parse before `keyFor`).

## Wave findings — orch14 (2026-06-13)

The orch14 task-wave landed the structural allowlist + header-member contract
above (the `idp-allowlist` unit: `oidc.go`, `algconfusion_test.go`, doc 16
§11.2). Four sibling units did **not** land this wave, and are tracked for the
next loop wave:

- **`jws-alg-allowlist-ratification` — blocked.** This unit would mint the
  ratification-packet `P`-row + doc 16 §11.2 cross-reference that makes the
  alg-allowlist / JWS-header-member contract citable. It hit a content merge
  conflict against the merged `idp-allowlist` unit (both rewrote the same
  §11.2 "IdP-half landed" paragraph in incompatible ways) and the two were not
  file-disjoint on doc 16. The merge was aborted (survivor kept). Re-scope:
  rebase onto an `idp-allowlist`-inclusive base and harmonize the single shared
  paragraph, or split so only the non-conflicting step-4 prose + the §14 OQ12
  ratification candidate land.
- **`idp-typ-header-policy` — deferred** (files-overlap with `idp-allowlist` on
  `identity/idp/oidc.go`). The next alg-confusion-adjacent surface: pin the JWS
  `typ` header member ({`JWT`, absent}) so an `at+jwt`/logout/refresh token is
  refused as an ID token, or document why `typ` is intentionally unconstrained.
- **`spine-production-wiring` — deferred** (files-overlap with the spine unit on
  `orchestrator/internal/sessions`; also blocked on the P-T2 `role_ref` proto
  freeze). Wire `RunCreateSpine` into `main.go`'s CreateSession path with a
  single-store coherence accessor/assertion.
- **`pg-conformance-0009-lane` — deferred** (files-overlap on
  `.github/workflows/go.yml`). Run the store conformance suite against a
  throwaway Postgres service container to exercise the 0009 role-pin columns.

The wave gate (build / vet / test for the touched `identity/idp` module, plus
the orchestrator and workflow checks) was green at merge.

## Wave findings — orch15 (2026-06-13)

The orch15 task-wave landed the **`typ`-header policy** above (the `idp-typ-header`
unit: `oidc.go` `typAllowed` + `jwsHeader.validate`, `algconfusion_test.go`
positive/negative cases, doc 16 §11.2's `typ`-confusion landed-note). The JWS
header-member contract the verifier now refuses is `jku`/`x5u`/`x5c`/`crit`/`typ`
plus the `{RS256, ES256}` alg allowlist. Two follow-ups did **not** land this wave
and are tracked OPEN for the next loop wave:

- **`idp-x5t-thumbprint` — LANDED orch16** (was deferred for a file-overlap with
  `idp-typ-header` on `identity/idp/oidc.go`). The decision — **refuse** `x5t` /
  `x5t#S256` on presence, same self-declared-cert fence as `x5c`/`x5u` — landed as
  the `idp-x5t` unit (`oidc.go` `x5tDecision` + `jwsHeader.validate`,
  `algconfusion_test.go` refusal/control cases, and the optional fakeOIDC
  end-to-end device-code refusal in `oidc_test.go`); see the cert-thumbprint policy
  note above.
- **`oq12-pj1-typ-ratify` — deferred** (packet-editable-wave-gated). Fold `typ`
  into the doc 16 §14 OQ12 `P`-J1 candidate row so the `typ`-confusion defense
  becomes a citable `D`-row contract; can only land in a wave the orchestrator
  opens for §6 / ratification-packet edits (both HANDS-OFF otherwise).

The wave gate (build / vet / test for `identity/idp` GOWORK=off, plus orchestrator,
workflow, snapshot-golden, land-check, and repo-lints) was green at merge.
