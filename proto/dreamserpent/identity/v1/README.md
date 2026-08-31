# dreamserpent.identity.v1

**Charter.** The four identity-owned seams frozen at Stage 0
(docs/16 §9;
doc 09 §8 names doc 16 as their home): validation, CA mint, the digest feed, and the
identity-plane events. One frozen `Validate` contract is what makes the substrate
progression — M0 throwaway shim → M1 minimal CA → M3 SPIFFE/SPIRE — a swap, not a
rebuild (D22; doc 05 §7 edge 5).

**Owner workstream:** Identity & credentials. **License:** [OSS] public contract
(D58; D85 puts the mint/swap/digest path itself OSS so D26/D51 conformance is runnable
against any deployment). **Freeze stage:** Stage 0 — row OPEN in
[FREEZE.md](../../../FREEZE.md). The D82 blocker (CA-mint owner row in doc 04 §6)
landed 2026-06-11; nothing else blocks this package's freeze PR.

## Stage-0 proto files (landed)

The three identity-owned Stage-0 proto bodies in this directory (authored as
freeze-PR candidate content; the digest-feed file is a sibling unit's, listed but
unchanged here):

| File | Carries | Key citations |
|---|---|---|
| [`validate.proto`](validate.proto) | `IdentityValidationService.Validate` — the D22 seam: req `{presented_credential, session_ref, service_id}`, resp `{verdict ALLOW \| DENY{machine_readable_reason}, grant_ref, expiry}`; sync, session-liveness + swap-path-latency-budget doc-comments; DENY surfaces as the in-band structured 403. P-T1 token-lineage numbers reserved on the response. | D22, D77, D39; doc 19 P-T1 (D104) |
| [`ca_mint.proto`](ca_mint.proto) | `IdentityMintService.MintInterceptionCA` — per-session CA under the interception root (hierarchy 2), session-lifecycle (D72-exempt), proxy-bound key delivery. `MintGrants` **promoted** (M0-window additive, D111) to `rpc MintGrants(MintGrantsRequest) returns (GrantSet)` (messages in `grants.proto`). `MintWorkloadIdentity` (→ `MintWorkloadIdentityRequest`/`MintWorkloadIdentityResponse` — §3.1 X.509-leaf-with-SPIFFE-SAN + parallel JWT, hierarchy 1) and `RevokeSession` (→ `RevokeSessionRequest`/`RevokeSessionResponse` — §5.4 active-eviction ack) also **promoted** (M0-window additive, D111); their messages live here in `ca_mint.proto`, mirroring the native `mint.Shim` types. `MintSessionToken` (→ `MintSessionTokenRequest`/`MintSessionTokenResponse` — the doc 19 §3 scoped per-session base token, D99/D97) is now **promoted** too (M0-window additive, D111), mirroring the native `mint.MintSessionTokenReq`/`SessionTokenBundle` (`sessiontoken.go`); **no mint RPC remains reserved**. | D17, D82, D72, D39, D111, D99, D97; doc 16 §3.1/§5.4, doc 19 §3 |
| [`grants.proto`](grants.proto) | the grant-record contract (the `MintGrants` `GrantSet` response, M0-window additive promotion, D111): `Grant` (identity × service × scope × TTL), `GrantScope` enum (SESSION/FLEET), `GrantSet`, `MintGrantsRequest`, `ServiceRegistryEntry`, `EnvSpec`, `PlaceholderToken` — mirroring the tested internal Go model `identity/mint/grants.go` (doc 16 §5.1); `grant_ref` is the opaque secret-free fetch key, the `ISSUED{service_id}` `cred_class_digest_tag` is derived from the record (§6). The grant-FETCH protocol that consumes `grant_ref` landed as `grant_fetch.proto` (row below); D55 Vault integration proper is still future. | D111, D39, D52, D83, D98; doc 16 §5.1/§9 |
| [`grant_fetch.proto`](grant_fetch.proto) | the per-session grant-FETCH protocol (**M1 additive promotion — the M1/D55 swap rider deferred by `grants.proto`**, doc 16 §5.1/§5.2/§9 grant-fetch row): `GrantFetchService.Fetch(GrantFetchRequest) → GrantFetchResponse`, `FetchedCredential` (the REAL swap-class credential — `secret` bytes + `location`, mirroring `Credential` in `identity/grant-service/backend.go`), `CredentialClass` enum (SWAP/INJECT, doc 16 §2/§7), `GrantFetchReason` enum (the five Go errors as the in-band stall-vs-deny split). Mirrors `identity/grant-service/*.go` field-for-field (`Service.Fetch(sessionUUID, serviceID, grantRef, grantExpiry)`); the fail-closed `grant_ref` re-derivation is `grantref.go` `grantRefMatches`. **Sole consumer: the off-VM ds-tlsproxy swap executor** — D8/D39-honoring because the real credential is delivered OUTSIDE the VM trust boundary (the ca_mint/validate proxy-bound-key precedent). **Store-agnostic wire** — the Go `Backend` seam picks OSS local file/KV vs customer OpenBao (§11.3), never a wire field. **Three open-question defaults flagged for seam-owner confirmation** (each additive-safe; doc-commented in-file): Fetch-only/no-lifecycle-RPC, in-band `GrantFetchReason`, `grant_expiry` request-input + response-echo. Reserved generously around the Fetch messages so later lifecycle/reason/lease-handle growth stays additive. NOT a re-freeze, NOT a break — a new service + messages on the flipped package; `buf breaking` passes vs the pre-existing baseline. Go repoint of `grant-service` onto these types is a separate mechanical follow-up. | D39, D76, D8, D85, D83; doc 16 §2/§5.1/§5.2/§7/§9/§11.3 |
| [`log_events.proto`](log_events.proto) | identity-plane LOG-1 minimal event set — `IdentityMinted`, `ValidationResult`, `GrantIssued/Denied/Evicted`, `DigestRegistered/Revoked` (fleet), `AskIssued/Approved/Denied` (+ approver), `CAMinted`; `SessionRef` join key (cross-package, `boundary.v1`); fingerprint-only. D60 consent-class tag on the ask/approval events (tag/reserve only). P-T1 token-lineage numbers reserved on `IdentityMinted` + `ValidationResult`. | D60, D77, D78, D118; doc 16 §9; doc 19 P-T1 (D104) |
| `digest_feed.proto` (sibling unit) | the doc 14 §7 entry shape + publish/revoke + ack (doc 16 §6.6) — **owned by the digest-feed unit**, not authored here; named without collision against the `DigestRegistered/Revoked` LOG-1 events above. | D73, D84, D72 |

`SessionRef` is the **shared canonical message owned by `dreamserpent.boundary.v1`**
(doc 14 §2 / §4 — the orchestrator session record is the authority): it is **not
redefined** in this package. The three files above hold a `string session_ref`
handle pre-freeze and doc-comment the cross-package import intent
(`dreamserpent.boundary.v1.SessionRef`, both Stage-0 packages freezing together);
this is **to-be-unified to the imported `boundary.v1.SessionRef` at the freeze PR**.

### Module-root requirement (freeze-PR coordination fact)

The house-style cross-file import — `import "dreamserpent/identity/v1/validate.proto"`
inside `log_events.proto`, and the future `import
"dreamserpent/boundary/v1/session_ref.proto"` once `SessionRef` is unified — is only
resolvable when the buf module root is `proto/` itself (`proto/buf.yaml` `path: .`), so a
file's directory matches its package path (`PACKAGE_DIRECTORY_MATCH`, part of STANDARD). A
`path: dreamserpent` root strips the leading `dreamserpent/` segment and makes the
canonical import unresolvable (`buf lint` exits non-zero). `proto/buf.yaml` is co-owned by
Boundary + Orchestrator (CODEOWNERS `/proto/`); the Stage-0 freeze PR — which lands both
`identity.v1` and `boundary.v1` bodies and their cross-package import — must carry this
root, not a per-package one. With that root, `buf lint` (STANDARD, module root `.`) and
the no-stray-proto gate are green across all eight Stage-0 bodies of both packages.

The P-T1 token-lineage reservations are authored on `IdentityMinted` / `ValidationResult`
(D104); population stays deferred behind the Validate-seam token fold.

## Inventory this package WILL hold

**`service IdentityValidation`** — the D22 seam, consumed by ds-tlsproxy on the TLS-5
path (doc 16 §4):

- `Validate(presented_credential, session_ref, service_id)` →
  `{verdict ALLOW | DENY{machine_readable_reason}, grant_ref, expiry}` — signature +
  freshness + **session liveness** + grant lookup; sync, swap-path latency budget.
  Failure surfaces as the in-band structured 403 (D77 block+log).

**`service IdentityMint`** — the orchestrator *fronts* the mint (D35, doc 15 §5.3) but
carries **no Mint RPC itself**; `dreamserpent.orchestrator.v1` owns only the fronting path.
`IdentityMint` is deliberately a separate service on a dedicated instance (D22/D39, doc 02 §7)
so an orchestrator/KVM compromise yields no signing keys.

**Stage-0 seams vs M0-window mint RPCs (doc 16 §9 reconciliation, D22/D35/D82):** of this
package, the **four Stage-0 seams** — `Validate`, `MintInterceptionCA`, the digest feed, and
the identity-plane LOG-1 events — ride the Stage-0 flip; `MintWorkloadIdentity`, `MintGrants`,
and `RevokeSession` pin in the **M0 window** as additive service/RPC additions to the flipped
package, or are explicitly reserved with planned field numbers in the Stage-0 PR (**confirmed —
D111**, ratified 2026-06-12; sessions/round4 packet §3).

- `MintWorkloadIdentity` → cert with SPIFFE-compatible URI SAN + parallel JWT, TTL =
  session (doc 16 §3.1 claim set incl. reserved `service_principal`) — root hierarchy 1
- `MintInterceptionCA` → per-session CA cert + key, proxy-bound, lifetime = session —
  root **hierarchy 2** (D17/D82: two separate root hierarchies; compromise of one never
  yields the other's signing capability)
- `MintGrants` → `GrantSet` — typed records identity × service × scope × TTL from the
  env spec + org `services[]` registry (doc 16 §5.1; no Cedar in v0)
- `RevokeSession` → `RevokeAck` — marks the session record; `Validate` fails closed

**Digest feed (D73/D84)** — producer → boundary, frozen entry shape per
doc 14 §7:
`{key_id, algo, digest, cred_class: ISSUED{service_id}|FORBIDDEN, scope: SESSION|FLEET,
expiry, variant_tag RAW|BASE64|URLENC|HEX}`. Invariants frozen with it: plaintext never
crosses the seam; mint-before-attach (session not routable until digests acked);
fail-closed while the keyed plane is loaded. The feed sits **beside the D22 seam in this
package** (doc 14 §7 placement) and is designed multi-consumer (registration,
per-consumer ack, distribution policy — doc 16 §6.5; attach-side scanning runs
orchestrator-side, digests never leave trusted territory).

**Identity-plane LOG-1 events** (doc 16 §9, minimal Stage-0 set, additive later):
`IdentityMinted`, `ValidationResult`, `GrantIssued/Denied/Evicted`,
`DigestRegistered/Revoked` (fleet), `AskIssued/Approved/Denied` (+ approver identity),
`CAMinted` — `SessionRef` join key, fingerprint-only, D60 consent-class flag on
approval events.

**Scoped agent tokens (doc 19,
ratified 2026-06-12 — D97–D105; no new service, no new package):** the attenuable session
token rides `Validate`'s `presented_credential` **opaquely** — a credential-class
substrate behind the same frozen seam, exactly like the X.509/JWT story (D97/D101).
A `MintSessionToken` RPC has now **joined** the `IdentityMint` surface as an
additive M0-window promotion (D111; doc 19 §3, D99/D97 — `ca_mint.proto`,
`MintSessionTokenRequest`/`MintSessionTokenResponse` mirroring `sessiontoken.go`),
the host-agent U5 session-token shim dialing it via the generated client. The one
freeze-time obligation was
**D104** (was doc 19 P-T1): reserve token-lineage field numbers (chain/block
fingerprints, `parent_session` hops, attenuation depth) on `IdentityMinted` and
`ValidationResult` **before** this package's one-shot Stage-0 freeze — the reservation
edits landed with the 2026-06-11 skeleton commit and the gate is recorded discharged
(**D112**). Fingerprint-only: token bytes never appear in events.

## Gating

Freeze PR cites the four doc 16 §9 Stage-0 rows and ships the **fake publisher in the
same PR** (doc 14 §7/§10 hard-deadline row 1; lands in `identity/fakes/digest-publisher/`
beside the generated D22 seam fakes). Scope classification (fleet = policy artifact
under `policy_log`; session = lifecycle data; digest-set version = non-policy
namespace) is frozen per D72/D73.

## What must NOT live here

- ~~The grant-fetch protocol (D39 swap executor ↔ grant service) — freezes with the **M1**
  credential-swap design, not Stage 0 (doc 16 §9).~~ **LANDED 2026-06-13** as the additive
  `grant_fetch.proto` (`GrantFetchService.Fetch`), the M1/D55 swap rider (table row above).
  What remains future is the D55 Vault INTEGRATION proper (live OpenBao/AWS Secrets Manager
  wiring) — the wire it rides is now frozen and store-agnostic.
- The SSH remote-signing seam — designed-for, built post-v0 (D83, doc 16 §5.3);
  reserved as `identity/ssh-signer/`, no proto until its trigger fires.
- `SecretMatcher` trait + verdict semantics — Rust, in `dataplane/crates/policy-core`
  (doc 14 §6); this package feeds it, never defines it.
- Any DNS-layer identity check — an explicit non-edge (doc 16 §10).
