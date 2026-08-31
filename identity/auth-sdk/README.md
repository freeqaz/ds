# identity/auth-sdk — Auth SDK

**Status:** Design-stage skeleton (doc 23; D123–D129 proposed, pending round-5 ratification)

**Owner:** Identity workstream  
**License:** Apache-2.0 (OSS; doc 23 §1 / D129)

## Charter

The auth SDK is the single entry point for human-principal authentication into the Dream Serpent
platform. It handles SAML 2.0 SP-initiated SSO (HTTP-POST binding, D124) and OIDC/OAuth2
(authorisation-code + PKCE / device-code, D55/D123), then mints a short-lived user auth token
(D125) regardless of which IdP protocol was used.

At D18 fan-out time the orchestrator calls `TokenAttenuationService.DeriveAgentToken` to derive
one attenuated sub-token (D126) per agent VM. Agents receive their sub-token injected into the VM
at mount time — they never fetch credentials over the network.

## Package layout

```
identity/auth-sdk/
  oidc/         — OIDC/OAuth2 flows: PKCE, device-code, id_token validation
  saml/         — SAML 2.0 SP: AuthnRequest signing, ACS handler, assertion validation
  token/        — User auth token: JWT issuance, JWKS endpoint, revocation
  attenuation/  — Sub-token derivation: DeriveAgentToken, ListDerivedTokens (Biscuit)
```

## Proto contract

`dreamserpent.auth.v1` — see `proto/dreamserpent/auth/v1/`

Services:
- `AuthSessionService` (auth_session.proto) — OIDC + SAML initiation/completion, revocation
- `TokenAttenuationService` (token_attenuation.proto) — sub-token derivation at D18 fan-out

**Status: OPEN** — freeze PR (task 01KV1MSDKATH00000000000003) ships bodies + baselines + fakes.

## D-numbers

| D# | Decision |
|---|---|
| D123 | Auth SDK scope — unified `identity/auth-sdk/` module for all human-IdP auth |
| D124 | SAML 2.0 support — first-class path, overrides doc 16 §11.2 v0 exclusion |
| D125 | User auth token — short-lived session-bound JWT (15min, ECDSA P-256) |
| D126 | Sub-token derivation at D18 fan-out — Biscuit attenuation, monotonic scope narrowing |
| D127 | Token scope taxonomy — 8 standard scopes at `v1:` prefix |
| D128 | Agent notification via ds-telemetry EventSink — issued / expiry_warn / revoked |
| D129 | `dreamserpent.auth.v1` proto package — AuthSessionService + TokenAttenuationService |

## References

- docs/23-auth-sdk-design.md — full design
- docs/16-identity-and-credentials-design.md — identity plane context
- docs/19-scoped-agent-credentials-design.md — D19 scoped agent tokens (D97–D105)
- [proto/dreamserpent/auth/v1/](../../proto/dreamserpent/auth/v1/) — proto stubs
