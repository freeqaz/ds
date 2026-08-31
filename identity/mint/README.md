# identity/mint/ — IdentityMint

**Owner workstream:** Identity & credentials · **OSS** (the minimal CA ships with the OSS data plane per D85)
**Status:** **M0 shim landed.** Standalone **Go** module (`go.mod`, deliberately OUTSIDE `go.work` — same pattern as `../fakes/digest-publisher`); the language decision and its rationale are recorded one level up in [`../README.md`](../README.md). The M0 throwaway substrate (D22) is implemented behind the frozen Stage-0 `identity.v1` seams; M1 (own minimal CA) and M3 (SPIFFE/SPIRE) swap in behind the unchanged `Validate` contract.

## What the M0 shim implements

A standalone service substrate (`mint.Shim`) wiring all four mint-surface methods:

| Method | Kind | Hierarchy / behavior |
|---|---|---|
| `Validate` | generated grpc seam (`IdentityValidationService`) | signature + freshness + session-liveness + grant lookup; DENY = the D77 in-band-403 shape, never a transport error |
| `MintInterceptionCA` | generated grpc seam (`IdentityMintService`) | hierarchy 2 (D82): a per-session interception CA under a per-session interception root, proxy-bound key delivery, session-lifetime expiry |
| `MintWorkloadIdentity` | native Go (RESERVED-only in proto) | hierarchy 1: X.509 leaf with SPIFFE-compatible URI SAN `spiffe://<org>/session/<uuid>` + parallel ES256-JWS presentation, the §3.1 claim set incl. the reserved `service_principal` marker |
| `MintGrants` | native Go (RESERVED-only in proto) | §5.1 grant model — typed records (identity × service × scope × TTL) issued by the **deterministic** intersection of the env spec (D7) and the org `services[]` registry (no Cedar, D52); plus the per-service short-lived **placeholder token** the agent holds. The `ISSUED{service_id}` digest tag derives from the grant record (`IssuedDigestTag`). A placeholder validates at the `Validate` seam for its service only, and **never** as workload identity or interception material. |
| `MintSessionToken` | native Go (RESERVED-only in proto) | doc 19 §3 scoped per-session **base token**, minted on behalf of the launching user (D99); the doc 16 §3.1 claim set (`launching_user` root attribution + `session_uuid`/`org`/`repo_branch`/`role_ref`/`task_ref`/`parent_session` scoping, `parent_session` EMPTY on the base token) over a **third D39 signing context** — Biscuit (D98 primary) behind a clean `SubstrateSigner` seam, Ed25519 public-key verification, never either D82 hierarchy. Rides the existing `Validate` seam unchanged (`presented_credential` format-opaque, doc 19 §5); grant lookup is intersected with the token's attenuated service scope (doc 19 §8). Offline attenuation at D18 fan-out (`AttenuateSessionToken`) derives strictly-narrower child tokens with **zero** mint RPCs (doc 19 §4). A session-token signature validates as **neither** workload identity **nor** interception material (doc 19 §13). |
| `RevokeSession` | native Go (RESERVED-only in proto) | marks the in-memory session record; `Validate` then fails CLOSED with the operator reason on the D77 channel — and the session-token chain fails closed with it (whole chain keyed on the root `session_uuid` claim, doc 19 §7) |

Substrate is in-memory/throwaway (D22) and every key is synthetic (D50) — **no real credentials anywhere, ever**. The two generated seams are exercised over an in-process grpc client (the `digest-publisher` precedent); the two native seams are tested directly. The doc 16 §13 isolation rows are executable tests: **per-session CA isolation** (session A's interception CA never validates a session-B leaf) and **hierarchy separation** (an interception-hierarchy cert never validates as workload identity, and vice versa).

The `launching_user` resolution (the orchestrator principal-store linkage, doc 04 §5) is a **function seam** (`PrincipalResolver`), injected — never imported — so `orchestrator/` (a different module) stays untouched.

**Build (standalone module — `GOWORK=off`, like `digest-publisher`):** `cd identity/mint && GOWORK=off go build ./... && GOWORK=off go test ./...`.

## Test evidence (the done-when, mapped to tests)

The task done-when is "contract tests against the Stage-0 protos pass and the §13 isolation rows hold." Each criterion maps to a named test (all synthetic, D50):

| Done-when / assurance row | Test |
|---|---|
| Generated `MintInterceptionCA` seam round-trips the frozen `MintInterceptionCAResponse` shape over an in-process grpc client | `TestMintInterceptionCASeam` |
| Generated `Validate` seam round-trips ALLOW + the DENY (D77 in-band-403, never a transport error) shape | `TestValidateSeamAllowAndDeny` |
| Hierarchy-1 workload identity: SPIFFE URI SAN + the §3.1 claim set incl. the reserved `service_principal` marker; cert + parallel JWT name one identity | `TestMintWorkloadIdentity_ClaimSetAndSPIFFE` |
| `PrincipalResolver` linkage seam applied without importing `orchestrator/` | `TestPrincipalResolver_Seam` |
| `RevokeSession` → `Validate` fails closed immediately (liveness-as-revocation, §5.4) | `TestRevokeSession_ValidateFailsClosed` |
| Every `Validate` failure branch fails closed with the right machine-readable reason | `TestValidate_FailClosedBranches` |
| **§13 per-session CA isolation** — session A's interception CA never validates a session-B leaf | `TestPerSessionCAIsolation` |
| **§13 hierarchy separation** — an interception-hierarchy cert never validates as workload identity, and vice versa (D82) | `TestHierarchySeparation` |
| **§5.1 deterministic grant issuance** — grants = the pure env-spec × `services[]` registry intersection; unknown services confer no grant (fail-closed); no Cedar (D52) | `TestIssueGrants_DeterministicLookup` |
| §5.1 grant TTL clamped to the session lifetime (D39 ceiling); env override shortens never lengthens | `TestIssueGrants_TTLClampedToSession` |
| §5.1/§6 `ISSUED{service_id}` digest tag **derives from** the grant record | `TestIssuedDigestTag_DerivesFromGrant` |
| §5.1 `MintGrants` placeholder validates at the `Validate` seam for its service; returns the grant_ref | `TestMintGrants_PlaceholderValidatesAtSeam` |
| §5.1 **negative property** — a placeholder NEVER validates as workload identity (it is not a JWS over the workload key), and never cross-service | `TestPlaceholder_NeverValidatesAsWorkloadIdentity`, `TestPlaceholder_NeverValidatesCrossService` |
| §5.1 negative property, **interception direction** — a placeholder cannot validate as interception material is *structural*, not a separate test: interception output (`MintInterceptionCA`) is a DER cert+key bundle, never a `Validate`-presentable token, so the seam has no leg a placeholder could take toward it (covered by the placeholder routing in `validate.go` plus `TestHierarchySeparation`) | structural (see `validate.go` `IsPlaceholder` routing) |
| **§9 GrantRef contract, WRITER side** — `FormatGrantRef`/`ParseGrantRef` round-trips, and the committed golden fixture pins the wire shape; issuance emits the contract format | `TestGrantRef_GoldenContract_WriterSide`, `TestParseGrantRef_FailClosed` |
| **§6.1 composition** — synthetic `GrantSet` via `MintGrants` → the `RegisterSession` inputs → `IssuedDigestTag` derives from the grant record end to end | `TestComposition_MintGrantsToIssuedDigestTag` |
| **doc 19 §3 base-token claim set** — the doc 16 §3.1 claim set on the base token, `parent_session` EMPTY, TTL = session lifetime (a SYNTHETIC golden, D50) | `TestMintSessionToken_ClaimSetGolden` |
| doc 19 §3 `launching_user` resolution applied on the token path (same `PrincipalResolver` seam as workload identity — joins in audit) | `TestMintSessionToken_PrincipalResolverSeam` |
| doc 19 §5 the token rides the existing `Validate` seam (ALLOW with grant ∩ token scope); every DENY branch fails closed with the right reason | `TestSessionToken_ValidatesAtSeam`, `TestSessionToken_FailClosedBranches` |
| doc 19 §6 **public-key signature is load-bearing** — a forged (foreign-key) or tampered token fails closed | `TestSessionToken_ForgedAndTamperedRejected` |
| doc 19 §7 `RevokeSession` fails the token chain closed immediately (whole chain keyed on the root claim) | `TestSessionToken_RevokeFailsChainClosed` |
| doc 19 §7 / §13 **whole-chain liveness on the ROOT** — revoking the originating root fails a descendant (depth 1 AND depth 2) closed even while its own session is live; an unknown root is not a local failure | `TestChainRevocation_RootRevokeFailsDescendantClosed`, `TestChainRevocation_RootRevokeFailsGrandchildClosed`, `TestChainRevocation_UnknownRootDoesNotFailLocally` |
| **doc 19 §13 / §3 — the third signing context** — a session-token signature validates as NEITHER workload identity NOR interception material, and the reverse; the token key is structurally distinct from both D82 roots | `TestSessionToken_NeverValidatesAsWorkloadIdentity`, `TestSessionToken_NeverValidatesAsInterceptionMaterial`, `TestSessionToken_PublicKeyIsThirdContext` |
| doc 16 §5.4 / doc 19 §3 **park/resume/expiry** — token survives park; resume re-checks liveness (revoked-while-parked fails closed); expired tokens re-mint | `TestSessionToken_ParkResume`, `TestSessionToken_ResumeRevokedFailsClosed`, `TestSessionToken_ExpiredReMint` |
| doc 19 §4 **offline attenuation at fan-out** — child narrows monotonically (⊆ parent scope, ≤ parent expiry, appended lineage hop), widening fails closed; N children derive with ZERO mint RPCs | `TestSessionToken_AttenuateNarrowsMonotonically`, `TestSessionToken_FanOutWithoutMint` |
| doc 19 §4 **typed template vocabulary** — `BuildChildAttenuation` composes identity × service × scope × TTL into a narrowing record (never widens: services intersect ⊆ parent, TTL clamps to soonest, unconstrained axes inherit) | `TestBuildChildAttenuation_NarrowsAllAxes`, `TestBuildChildAttenuation_NeverWidens`, `TestBuildChildAttenuation_InheritsWhenUnconstrained` |
| doc 19 §11 **role-template seam** — a `RoleTemplateResolver` keyed by `role_ref` folds a role's default service ceiling + `MaxTTL` in by intersection; unknown role / nil resolver = no default (v0) | `TestRoleTemplateSeam_AppliesDefaultNarrowing`, `TestRoleTemplateSeam_UnknownRoleIsNoDefault` |
| doc 19 §4 **`DeriveChildSession` fan-out entrypoint** — derives ⊆ from the parent token's own claims, validates §8 grant ∩ scope; depth-≥2 child-of-child narrows ⊆ child ⊆ root with widening rejected at the deeper hop; 5-wide + depth-2 fan-out with ZERO mint RPCs | `TestDeriveChildSession_OfflineNarrowingThroughTemplate`, `TestDeriveChildSession_DepthTwoChildOfChild`, `TestDeriveChildSession_FanOutZeroMintRPCs`, `TestDeriveChildSession_RejectsMissingInputs` |
| doc 19 §6 **biscuit read-path golden guard** — the appended-block `Code()` render shape + base64url payload are pinned to a synthetic golden, so a biscuit-go renderer-shape/encoding drift fails loudly (version pinned at v2.2.0) | `TestBiscuitBlockRender_ScaffoldGolden`, `TestBiscuitBlockRender_RegexExtractsGolden`, `TestBiscuitBlockRender_RoundTripGolden` |
| doc 19 §6 substrate seam is swappable — a stdlib-only fallback signer mints + validates unchanged via `WithSubstrateSigner` | `TestSessionToken_StdlibFallbackSeam` |
| doc 19 §9 **token lineage on audit events** — `DeriveChildSessionWithLineage` populates the FINGERPRINT-ONLY `TokenLineage` (block fingerprints + full root→leaf `parent_session` hops + attenuation depth + inherited `launching_user` + leaf `task_ref`), answering the LOG-5 "which subagent, for which task, on behalf of which user" join across a depth-2 chain; base token has an empty hop chain; ZERO token bytes / raw revocation-id bytes appear in the serialized record | `TestLineage_RoundTripsDepthTwoChain`, `TestLineage_NoTokenBytes`, `TestLineage_BaseTokenHasEmptyHopChain`, `TestLineage_FanOutWithLineageZeroMintRPCs` |
| doc 19 §11 **default role-template resolver** — `DefaultRoleTemplateResolver` recognizes the recorded de-risking default (`default@<vN>`, ok=true → empty template = no narrowing, roles/SCHEMA.md rule 4) and treats every other ref as unknown (ok=false); folds through `DeriveChildSession` adding no extra ceiling | `TestDefaultRoleTemplateResolver_DeRiskingDefault`, `TestDefaultRoleTemplateResolver_FoldsThroughDerivation` |
| **doc 18 §8 / doc 15 §4.1 step 5 — role scope_template CONSUMED at grant mint** — `IssueGrantsScoped`/`MintGrantsScoped` narrow the env-spec × `services[]` envelope by **intersection** (`grants ∩ role scope_template`); the template can only NARROW, never widen (a role-named service the request lacks is never added; one the org registry lacks confers no grant — fail-closed); NULL template = full envelope, EMPTY `services:[]` = empty intersection mints nothing (distinct boundary cases, roles/SCHEMA.md rule 4); a NULL-template path is byte-identical to a bare `MintGrants` (existing goldens untouched) | `TestIssueGrantsScoped_NarrowingApplied`, `TestIssueGrantsScoped_NeverWidens`, `TestIssueGrantsScoped_NullTemplateFullEnvelope`, `TestIssueGrantsScoped_EmptyServicesMintsNothing`, `TestNullVsEmptyAreDistinct`, `TestMintGrantsScoped_NullTemplateByteIdenticalToMintGrants` |
| doc 18 §8 **unknown-scope fails closed, NAMED** — a role scope_template naming a service absent from the org grant set (env-spec ∩ registry) fails closed under strict mode with an `UnknownRoleScopeError` naming the service AND role_ref (wraps the `errUnknownRoleScope` sentinel); the non-strict default drops it silently (no grant), never widening | `TestIssueGrantsScoped_UnknownScopeFailClosedNamed`, `TestIssueGrantsScoped_NonStrictDropsAbsentSilently`, `TestIssueGrantsScoped_StrictAllInRegistryNoError` |

## Charter

The mint service — a **separate deployable on a dedicated instance** (D22/D39, doc 02 §7), fronted by the orchestrator's `MintIdentity` RPC (D35) but never co-located with it, so an orchestrator/KVM compromise yields no signing keys and security/IT can own the box. It mints:

1. **Workload identity** — X.509 cert with SPIFFE-compatible URI SAN (`spiffe://<org>/session/<session_uuid>`) + parallel JWT presentation; TTL = session lifetime (doc 16 §3.1).
2. **The per-session interception CA** (D17/D82) — minted at session create, injected into the per-session CoW overlay between CloneFromImage and entrypoint fail-closed, delivered to ds-tlsproxy for per-origin leaf minting, destroyed at teardown (doc 16 §4).
3. **Grants** (`MintGrants`, doc 16 §5.1) and session revocation (`RevokeSession`).
4. **The per-session scoped base token** (`MintSessionToken`, doc 19 §3) — the RPC was slated to join the mint surface if doc 19 §2 ratified; it did (ratified 2026-06-12, D97–D105; issuance = D99, wave placement per D111). Minted on behalf of the launching user at create step 5; its signing key is a **third D39 signing context**, beside but never under either D82 hierarchy — a token signature must never validate as workload identity or interception material (the D82 separation property, extended).

## Two CA root hierarchies (D82 — frozen)

Workload-identity and interception roots are **separate hierarchies** so compromise of one never yields the other's signing capability — an interception-root signature must never validate as workload identity (assurance row, doc 16 §13). Both roots live off-host in the D39 secret-store trust zone. The hierarchy separation is a decision-log property, not an implementation detail.

## The D22 Validate seam

This service implements `IdentityValidation.Validate(presented_credential, session_ref, service_id) → {verdict ALLOW | DENY{machine_readable_reason}, grant_ref, expiry}` — sync, session-liveness-checked, swap-path latency budget; consumed by ds-tlsproxy on the TLS-5 path (doc 16 §9). Stage-0 freeze, fakes-first, D24-versioned. Validation failure surfaces as the in-band structured 403 (D77). (Erratum fixed 2026-06-12: superseded response shape replaced with the frozen shape per doc 16 §4/§9 — doc 16 §15 sanctions this fix.)

## The scoped session token (doc 19 §3 — `MintSessionToken`)

`MintSessionToken` mints the doc 19 §3 scoped per-session **base token** on behalf of
the launching user (D99) — the substrate for the doc 16 §5.1 placeholder slot / doc 15
§4.1 step-8 session token. It is the doc 15 §4.1 **step-5** issuance, delivered through
the **existing step-8 entrypoint slot** — no new choreography step.

- **Claims** mirror the doc 16 §3.1 workload-identity set so the two credentials join
  trivially in audit (doc 19 §9): `launching_user` (root attribution, resolved through the
  same `PrincipalResolver` seam), `session_uuid`/`org`/`repo_branch`/`role_ref`/`task_ref`
  scoping, and `parent_session` — **EMPTY on the base token**, populated by the fan-out hop
  (doc 19 §4). TTL = session lifetime.
- **Third signing context (D99):** the token signing key is a **third D39 signing context**,
  beside but **never under either D82 root hierarchy** and never on the virtual-metal host.
  The default substrate is **Biscuit (D98 primary)** — Ed25519 public-key verification (the
  verifier holds only a public key, never forge-capable material) — reached through a clean
  `SubstrateSigner` seam (`sessiontoken_biscuit.go`). The separation is **structural**: a
  Biscuit is a different cryptosystem and wire shape than the ECDSA/P-256 X.509 certs both
  D82 hierarchies issue, so a session-token signature can validate as **neither** workload
  identity **nor** interception material (doc 19 §13, executable isolation tests).
- **Substrate seam (doc 19 §5/§6):** the credential format lives behind `SubstrateSigner`,
  exactly as `presented_credential` is **format-opaque** at the frozen D22 seam — a flip
  (the named macaroon alternative, or the stdlib-only fallback `sessiontoken_stdlib.go`) is
  a seam-internal change, never a contract event. The M1 flip-trigger spike (tasks
  `01KTWJ72WR` / `01KTWJ73W0`) recorded that **no §6 flip trigger fires** — core block-append
  attenuation parity holds in biscuit-go v2.2.0, verify cost sits far under the sync
  swap-path budget, and per-block revocation IDs serve the §7 fleet list — so the default
  lands on Biscuit. biscuit-go is Apache-2.0; issuance + attenuation + verification are all
  in this OSS mint (P-R7/D103 — no paid-side import).
- **Offline attenuation at D18 fan-out (doc 19 §4, D100):** `AttenuateSessionToken` derives a
  strictly-narrower child token **offline** (no mint round-trip): a child `session_uuid`
  (appended as the next `parent_session` lineage hop), a service set ⊆ the parent's, and a
  shorter-or-equal TTL. **Monotonic** — a widening request fails closed. Attenuation content
  is generated from the **typed** claim vocabulary, never hand-authored Datalog (D52, the
  no-Cedar posture carried).
- **Template vocabulary + role seam (doc 19 §4/§11, `attenuation_template.go`):** callers never
  author a narrowing by hand — `BuildChildAttenuation` composes the four grant-model dimensions
  (identity × service × scope × TTL) into a `SessionTokenAttenuation` from **typed records only**,
  and `DeriveChildSession` is the one-call fan-out entrypoint (reads the parent's effective scope
  from the parent token's own claims, then applies the offline append — still **zero mint RPCs**,
  no network). The **role-template seam (§11)** is a typed, reserved hook: a `RoleTemplateResolver`
  keyed by `role_ref` may supply a role's default service ceiling + `MaxTTL`, folded in by
  intersection so a role can only ever narrow. The v0 resolver (`roletemplate.go`,
  `DefaultRoleTemplateResolver`) recognizes only the recorded de-risking default role
  (`default@<vN>` → an empty template = no narrowing, the full envelope per roles/SCHEMA.md rule 4
  / doc 18 §7 "recorded, not null"); every other ref is unknown (ok=false). A nil resolver is also
  "no role default". doc 18 §8 installs the real catalog-backed resolver without changing the
  shape — the only coupling doc 19 §11 creates ("consumes the template and designs nothing
  further"). The fold can only ever shrink: service sets intersect to ⊆ parent and TTL clamps to
  the soonest horizon, so the substrate's subset/expiry check can never reject a record this
  layer builds.
- **Role scope_template CONSUMED at grant mint (doc 18 §8 / doc 15 §4.1 step 5,
  `roletemplate_consume.go`):** the fan-out seam above narrows the *token* at a hop; this is the
  GRANT-MINT consumption doc 18 §8 reserves ("the template is input to grant issuance, doc 16 §5.1
  … it selects/narrows the scope dimension"). `IssueGrantsScoped`/`MintGrantsScoped` resolve the
  role's `scope_template` through the SAME `RoleTemplateResolver` hook, then narrow the env-spec ×
  `services[]` envelope by **intersection** (`grants ∩ role scope_template`) before the existing
  deterministic `IssueGrants` registry lookup runs. The template can only ever NARROW: a service it
  names that the request did not ask for is never added (intersection is bounded by the request),
  and a service it names that the org registry lacks **confers no grant** (fail-closed — the
  registry intersection is the floor, so the role can never conjure a capability). The two
  boundary cases are **distinct by design** and carried by an explicit `RoleScopeTemplate.Present`
  flag rather than Go slice-nilness (the wrong carrier): a **NULL** template (`Present=false` —
  unknown role, nil resolver, empty `role_ref`, or the recorded de-risking `default` role) applies
  **no narrowing**, the full envelope, and is **byte-identical** to a bare `MintGrants` (the existing
  GrantRef goldens stay green); an **EMPTY** `services:[]` (`Present=true`, no services) is an empty
  intersection that **mints nothing** (roles/SCHEMA.md rule 4). Strict mode surfaces a role naming
  an absent capability as an `UnknownRoleScopeError` (the service + `role_ref` named, wrapping the
  `errUnknownRoleScope` sentinel) so a mis-specified role is loud at mint time; the default
  (non-strict) path drops it silently — either way the grant set is never widened. The template
  **never carries credential material** (D39, never enters the VM per D8) — it is a pure
  service_id filter (D52). The catalog-backed successor to `DefaultRoleTemplateResolver` (doc 18 §8)
  installs behind the same hook unchanged: the consumption keys on the resolved template, not on
  which resolver produced it. This is the doc 18 §8 graceful degradation — "until the doc 19
  attenuable-token pass lands, the template degrades to a grant-narrowing filter over the existing
  D22/D39 machinery" — and preserves the reserved seam where the same template becomes the *initial
  attenuation* for the scoped tokens.
- **Token lineage on audit events (doc 19 §9 / P-T1 → D104, `lineage.go`):** `TokenLineage` is
  the FINGERPRINT-ONLY LOG-5 join payload `ValidationResult` carries — per-block fingerprints
  (SHA-256 of each revocation id, never the raw id or the token bytes), the full root→leaf
  `parent_session` hops, the attenuation depth, the inherited `launching_user`, the leaf
  `task_ref`, and the originating `root_session`. `DeriveChildSessionWithLineage` derives a child
  and threads its full hop chain in one pure, zero-mint call. The lineage **field numbers** were
  reserved on `IdentityMinted` / `ValidationResult` before the Stage-0 freeze (`reserved 16-19`,
  RESERVE-ONLY); this populates the typed Go-side record the audit pipeline projects onto them —
  **no proto edit**. A test asserts ZERO token / raw-revocation-id bytes ever ride the serialized
  record.
- **Verification (doc 19 §5/§8):** rides the existing `Validate` seam unchanged. Signature =
  the substrate chain check; freshness = the token's expiry; **per-child** session liveness keys
  on the presented `session_uuid`, and **whole-chain** liveness keys on the inherited
  `root_session` claim — the chain's originating session is pinned on the base token and carried
  unchanged through every hop, so `RevokeSession` on the **root** fails every descendant token
  closed at once (doc 19 §7; an unknown root is not a local failure — the descendant's own
  liveness governs and cross-host revocation rides the fleet list). Grant lookup = the session
  grant **intersected with the token's attenuated service scope** — an attenuated child can never
  exercise a grant outside its blocks.
- **Read-path golden guard (doc 19 §6, `sessiontoken_biscuit_golden_test.go`):** biscuit-go v2.2.0
  surfaces an **appended** block only through its debug `Code()` renderer, so the read path parses
  the deepest block's `session_token_claims(depth, payload)` fact off that render. The render shape
  is therefore a load-bearing parse contract; a committed synthetic golden
  (`testdata/biscuit-block-render-golden.json`) pins the exact scaffold + base64url payload, so a
  biscuit-go upgrade that changes block rendering fails **loudly** at test time instead of
  mis-parsing a token. The biscuit-go version stays **pinned at v2.2.0** (`go.mod`); this golden is
  the tripwire if it moves.

## Substrate progression — pure swaps behind ONE proto

**M0 throwaway shim → M1 own minimal CA → M3 SPIFFE/SPIRE.** Every substrate (plus customer IdP-backed identities) satisfies the same frozen `Validate` contract — "a substrate swap behind a frozen contract, not a rebuild" (doc 05 §7 edge 5; doc 16 §2). The SPIFFE-compatible SAN naming adopted now is what makes the M3 SPIRE migration a pure substrate change. Cloud IAM/STS is an integration where present, never a requirement (D33: vanilla-Linux installable).

Revocation: **no CRL/OCSP** in the minimal CA — TTL-as-revocation plus active eviction; `Validate`'s session-liveness check makes a stolen still-valid cert fail immediately (doc 16 §5.4).

## What must NOT live here

- **No `.proto` bodies** — the `IdentityMint`/`IdentityValidation` services freeze in `proto/dreamserpent/identity/v1/` (the §4 skeleton in doc 16 is the freeze input).
- **No enforcement** — verdicts execute in ds-tlsproxy, never here.
- **No long-lived credential storage** — that is the D39 key store's job (see `../kv-client/`); the mint holds signing roots, off-host.
- Free (unbound) per doc 16 §12: own-CA internals pre-SPIFFE, cert library, renewal mechanics, storage/HSM choice — bounded by the frozen seam + D39 custody + hierarchy separation.

## Residuals

- **Wire coverage gap (deliberate):** `MintWorkloadIdentity` and `RevokeSession`
  are RESERVED-only in `proto/dreamserpent/identity/v1/ca_mint.proto`, so they run
  natively here with no grpc/conformance coverage. The D111 additive promotion must
  be authored as a diff on top of this module, with the `.proto` change routed
  through `proto/FREEZE.md`.
- **CI:** this module is compiled/vetted/tested by the `off-workspace-modules`
  job in `.github/workflows/go.yml` (`GOWORK=off`) — it cannot silently rot outside
  `go.work`.
- **`MintGrants`:** the §5.1 grant model, deterministic issuance, the placeholder
  token, and `ISSUED{service_id}` derivation are in `grants.go`. The grant-record
  proto is **not** frozen in `identity.v1` (`ca_mint.proto` carries `MintGrants`
  RESERVED-only), so grants are **internal Go types** here; the proto-freeze rider
  that promotes the grant-record contract is a **proposed follow-up routed through
  `proto/FREEZE.md`** at the M1 credential-swap window. The fetch-and-cache half of
  the §9 grant-fetch row lives in the sibling `../grant-service/`.
- **`MintSessionToken`:** the doc 19 §3 scoped base token, offline attenuation
  (`AttenuateSessionToken`), and the `Validate`-side session-token leg are in
  `sessiontoken.go` / `sessiontoken_biscuit.go` / `sessiontoken_stdlib.go`. The
  default substrate is **Biscuit** (biscuit-go v2.2.0, Apache-2.0, a pinned
  dependency in this standalone `GOWORK=off` module — see "The scoped session token"
  above), with a stdlib-only fallback behind the same `SubstrateSigner` seam.
  The session-token / `MintSessionToken` proto is **not** frozen in `identity.v1`
  (`ca_mint.proto` carries `MintSessionToken` RESERVED-only), so the token claim record is
  an **internal Go type** here; the proto-freeze rider that promotes it is a **proposed
  follow-up routed through `proto/FREEZE.md`** at the M1 credential-swap window,
  alongside the doc 19 §13 conformance rows joining the D51 public package.
- **Consumer-side fan-out leg:** the orchestrator's in-process
  `CreateChildSession` (`orchestrator/internal/sessions/childsession.go`, doc 15 §5.3
  / D18) derives one strictly-narrower child token per subagent through a
  `ChildTokenDeriver` seam this library satisfies natively across the proto seam
  (carried as DATA — no cross-tree import), appends each child's `session_uuid` as the
  next hop, and NEVER round-trips a mint. It lives in that tree, not this one.

## The GrantRef contract (the cross-module seam)

`grant_ref` is the **only** string this module and the standalone `../grant-service`
module agree on: this side **writes** it (`FormatGrantRef` → `GrantSet` →
`RegisterSession`), the grant-service side **reads** it (`Service.Fetch` keys the D39
store lookup on it). Two separate `GOWORK=off` modules, no compile- or test-time link.

**Contract mechanism — a committed golden round-trip fixture** (a shared Go type is
impossible across two modules with no shared dependency). `testdata/grantref-golden.json`
carries canonical `{session, service, ref}` triples **byte-identical** to
`../grant-service/testdata/grantref-golden.json`. `grants.go` exports
`FormatGrantRef`/`ParseGrantRef` (an inverse pair; the format lives in exactly one
place — `grantRef` delegates to it). `grants_test.go`'s
`TestGrantRef_GoldenContract_WriterSide` asserts the **writer** half
(`FormatGrantRef(session, service) == golden ref`) and that issuance emits the contract
format; the grant-service side asserts the **reader** half. **If either side edits its
format functions unilaterally, that side's own suite fails against the shared golden** —
the drift breaks loudly at test time instead of silently at fetch time.

`TestComposition_MintGrantsToIssuedDigestTag` is the §6.1 composition conformance test:
a synthetic `GrantSet` via `MintGrants` carries exactly the `{grant_ref, service_id,
expiry}` the grant-service `RegisterSession`/`Fetch` consume, and `IssuedDigestTag`
derives from the **grant record** (a digest's intended service is a grant fact, §5.1) —
the proven seam the production digest producer builds on, not that producer.
