# identity/grant-service/ — Grant service

**Owner workstream:** Identity & credentials · **OSS** (swap mechanics ship OSS per D85)
**Status:** **M0 grant-fetch substrate landed; the OpenBao-compatible KV backend + the config-driven selector are now wired.** Standalone **Go** module (`go.mod`, deliberately OUTSIDE `go.work` — the `../mint` + `../fakes/digest-publisher` precedent). The OSS local file/KV fake backend and the per-session cache are stdlib-only; the higher-tier `KVBackend` adapter consumes the standalone `../kv-client/` transport, and `wire.go` repoints the in-process grant-fetch model onto the **already-frozen** `dreamserpent.identity.v1` `GrantFetchService` generated types (`proto/gen/go`, the one legal cross-tree import per D80) — so the module imports `../kv-client/` + `proto/gen/go` via require+replace, with grpc/protobuf arriving transitively. No other third-party deps.

## Charter (what this is)

The Identity-owned service the ds-tlsproxy **swap executor** fetches grants from, fronting the D39 key store (at higher tiers the customer's OpenBao-compatible KV via `../kv-client/`). A **grant** is a typed record: identity × service × scope × TTL — issued at mint time from the session's env spec (D7) + the org `services[]` registry; the typed grant model + issuance live in `../mint` (doc 16 §5.1). This module is the **fetch-and-cache half**: the per-session protocol over the D39 store.

## What the M0 substrate implements

| Surface | Behavior |
|---|---|
| `Backend` seam (`backend.go`) | The D39 key-store seam — `Fetch(grant_ref) → Credential`. KV-v2-read-only posture (§11.3): no write path, no lease lifecycle. Two implementations sit behind it — the OSS file fake (`FileKVBackend`) and the OpenBao-compatible KV adapter (`KVBackend`). |
| `FileKVBackend` (the OSS fake) | The local file/KV fake (D85): loads a **synthetic** JSON `grant_ref → {secret, location}` fixture (D50); `SetAvailable(false)` models a store outage. **Never a live Vault/OpenBao** — that is `KVBackend` over `../kv-client/` behind the same `Backend` seam. |
| `KVBackend` (`kvbackend.go`) | The OpenBao-compatible KV-v2 **adapter** (D55/D85): the higher-tier sibling of `FileKVBackend`. It is the thin adapter mapping the `../kv-client/` transport's `ReadSecret` onto `Backend.Fetch` — a KV-v2 read → `Credential{Secret, Location}`; store unreachable / login fail / permission deny → `ErrStoreUnavailable`; KV-v2 404 → `ErrGrantNotFound`. **Read-only by construction** (§11.3): the adapter only ever calls `ReadSecret`, and `../kv-client/` exposes no write/lease/dynamic method. Driven against an httptest fake OpenBao/Vault — **never a live store** (D50). |
| `SelectBackend` (`selector.go`) | The deploy-time **config-driven factory** (D19/D26/D51): env/flags (`GRANT_BACKEND_*` / `-grant-backend-*`) select `file` mode → `NewFileKVBackend(path)` or `kv` mode → the `../kv-client/` transport (addr/mount/auth) → `NewKVBackend`. So **a tier swap is a CONFIG change** — the OSS hosted file-fake vs the customer's OpenBao/Vault choice is selectable without a grant-service rewrite. Fail-closed: an ambiguous config selects **no** backend (`ErrInvalidConfig`). The selector only ever wires `ReadSecret` (read-only posture, §11.3). |
| `Service.Fetch` | **Per-session fetch, never per-request** (§9): a cache HIT serves from memory and never touches the backend, so steady-state requests pay zero added RTT. |
| Outage semantics | A store outage stalls **NEW** grant fetches only — an in-flight session whose grant is cached **rides its cache** through the outage (§5.1, the D39 availability dependency). |
| `Service.Suspend` | **Eviction on the suspend signal** (§5.4): drops the session cache entirely; a subsequent fetch fails closed. |
| `Service.Park` / `Service.Resume` | Park keeps the cache (**grants survive snapshot+park**); resume **re-validates against session liveness + TTL** (§5.4) — an expired cached grant is dropped so the caller re-mints; a session past its deadline is not resumed (fail-closed). |

The fetched credential is held **in memory ≤ session** — the bounded D76 exposure; it never enters the VM and never sits on the virtual-metal host (D8/D39).

## Test evidence (the done-when, mapped to tests)

| Assurance row (doc 16) | Test |
|---|---|
| **Per-session fetch, never per-request** (§9) — N requests hit the backend exactly once | `TestFetch_PerSessionNeverPerRequest` |
| **Cache rides the outage** (§5.1) — an in-flight session serves through a store outage; a NEW fetch stalls with `ErrStoreUnavailable`; recovery succeeds | `TestFetch_CacheRidesOutage` |
| **Eviction on suspend** (§5.4) — suspend evicts the cache; post-suspend fetch fails closed | `TestSuspend_EvictsGrants` |
| **Park/resume TTL re-validation** (§5.4) — grants survive park, a parked session fetches no new grants, resume drops a grant past its TTL | `TestParkResume_SurvivesAndReValidates` |
| **Dead session not resumed** (§5.4) — a session past its lifetime deadline fails closed on resume | `TestResume_DeadSessionFailsClosed` |
| Missing grant is a definitive deny (not an outage stall) | `TestFetch_GrantNotFound` |
| The OSS local file/KV fake loads a synthetic fixture (D50) | `TestFileKVBackend_LoadsSyntheticFixture` |
| **§9 GrantRef contract, READER side** — `ParseGrantRef(golden ref) == {session, service}`, byte-identical golden to `../mint` (see "The GrantRef contract" below) | `TestGrantRef_GoldenContract_ReaderSide` |
| **§9 GrantRef guard is load-bearing** — `Fetch` rejects a ref that does not parse to the (session, service) being fetched with `ErrGrantRefMismatch` (fail-closed, never a silently-wrong store lookup) | `TestFetch_GrantRefMismatchFailsClosed` |
| **§6.1 composition (reader half)** — synthetic `GrantSet` → `RegisterSession` → `Fetch` keyed on the `GrantSet`'s `grant_ref` resolves the credential; the `ISSUED{service_id}` tag recovers from the same ref | `TestComposition_GrantSetToRegisterSessionToFetch` |

### KVBackend — the OpenBao-compatible KV-v2 adapter (httptest fake, D50)

The `KVBackend` adapter (`kvbackend.go`) is driven against an httptest fake OpenBao/Vault server (`kvbackend_test.go`) speaking the documented KV-v2 wire shapes — **no live store** (D50).

| Assurance row (doc 16) | Test |
|---|---|
| KV-v2 read → `Credential{Secret, Location}` (the §9 happy path); read-only posture — only GET+login verbs reach the store | `TestKVBackend_FetchMapsReadToCredential` |
| A stored secret with no location → the frozen generic Authorization-header seam (D83) | `TestKVBackend_DefaultLocationFallback` |
| KV-v2 404 (no secret at the grant's path) → `ErrGrantNotFound` (a definitive deny, not a stall) | `TestKVBackend_MissingKeyIsGrantNotFound` |
| Store unreachable (transport failure) → `ErrStoreUnavailable` (the §5.1 availability stall), **not** `ErrGrantNotFound` | `TestKVBackend_StoreUnreachableIsStoreUnavailable` |
| Permission deny (Vault 403, role unscoped) → `ErrStoreUnavailable` (fail closed, never a wrong deny) | `TestKVBackend_PermissionDenyIsStoreUnavailable` |
| Login rejection (wrong JWT) → `ErrStoreUnavailable` (auth/availability failure, not a missing grant) | `TestKVBackend_AuthFailureIsStoreUnavailable` |
| An unparseable `grant_ref` → `ErrGrantNotFound` **before any store I/O** (no login, no read) | `TestKVBackend_UnparseableRefIsGrantNotFound` |
| A stored secret missing the designated field → `ErrGrantNotFound` (malformed payload is a definitive miss) | `TestKVBackend_MalformedSecretIsGrantNotFound` |
| Path layout + field names are FREE (§12) — a deployment maps its own KV layout and field names | `TestKVBackend_ConfigurableFieldsAndPath` |
| Construction fails closed on a nil reader | `TestKVBackend_NilReaderRejected` |
| **Selectable BESIDE `FileKVBackend`** — `Service.New` takes a `KVBackend` exactly where it takes the file fake; the same per-session protocol (§9) runs over both (a tier swap is a backend swap) | `TestKVBackend_SelectableBesideFileKVBackend` |
| The per-fetch context hook is honored (a deployment wraps a deadline/cancel around the context-free `Backend.Fetch`) | `TestKVBackend_NewContextHookUsed` |

### SelectBackend — the config-driven backend factory (file fake + httptest KV-v2 fake, D50)

The `SelectBackend` factory (`selector.go`) is driven against the OSS file fake (a synthetic JSON fixture) and the in-package httptest fake OpenBao/Vault (`selector_test.go`) — **no live store** (D50).

| Assurance row (doc 16) | Test |
|---|---|
| Empty/`file` mode → `*FileKVBackend` (the OSS default tier, the Backend `service.go` takes today) | `TestSelector_EmptyModeSelectsFileBackend` |
| File mode wires the service end to end — `New(SelectBackend(cfg)…)` runs the per-session protocol over the OSS fake | `TestSelector_FileModeWiresService` |
| `kv` mode → `*KVBackend` over the **real** `../kv-client/` transport (addr/mount/auth from config) | `TestSelector_KVModeSelectsKVBackend` |
| **A tier swap is a CONFIG change** (D19/D51) — the same `New(SelectBackend(cfg)…)` wiring runs the OpenBao tier when only `cfg.Mode` flips to `kv`; second fetch is a cache HIT | `TestSelector_KVModeWiresServiceAsTierSwap` |
| AppRole auth (§11.3 fallback) is selectable by config — same principal, only the credential shape differs | `TestSelector_KVModeAppRoleAuth` |
| `SecretField`/`LocationField` from config flow through to the KV adapter (the §12-free layout) | `TestSelector_ConfigurableKVFields` |
| Every ambiguous/incomplete config → `ErrInvalidConfig` (fail-closed: NO backend, never a partial/wrong one) | `TestSelector_InvalidConfigsFailClosed` |
| The `GRANT_BACKEND_*` environment maps onto a `SelectorConfig` | `TestSelector_LoadConfigEnv` |
| env seeds defaults, a `-grant-backend-*` flag overrides (the documented env+flag layering) | `TestSelector_BindFlagsOverrideEnv` |
| File mode surfaces a missing/garbled fixture as a loud construction error | `TestSelector_FileFixtureMissingFailsLoud` |

**Build (standalone module — `GOWORK=off`, like `../mint`):** `cd identity/grant-service && GOWORK=off go build ./... && GOWORK=off go test ./...`.

## Already-frozen facts this honors

- **Grant-fetch protocol freezes with the M1 credential-swap design, alongside the D55 Vault spec** (doc 16 §9) — so the **wire** contract (a `.proto`) is deferred; this module is the OSS in-process substrate behind it.
- D39 trust-zone placement: store + this service off-host; the executor inside ds-tlsproxy holds fetched creds in memory ≤ session (the bounded D76 exposure).
- **Per-grant fetch, never per-request**; a store outage stalls *new* grant fetches only (doc 16 §5.1).
- The frozen swap seam shape is the **generic Authorization-header substitution** (D83) — credential-type-agnostic; the `Credential.Location` default is `Authorization`.
- **No Cedar in v0** — the grant decision is a deterministic lookup, not a policy evaluation (D52; the typed grant model is in `../mint`).
- Grants evict on the suspend signal; they survive park/resume with liveness + TTL re-validation (doc 16 §5.4).

## What must NOT live here

- **No swap execution** — the executor is a ds-tlsproxy module (`dataplane/services/ds-tlsproxy/`, doc 16 §5.2); this service only fetches+caches.
- **No expression language** in grant records (D52).
- **No live store** — the OSS backend is a local file/KV fake (D50). The OpenBao-compatible KV-v2 **transport** is the standalone `../kv-client/` module (consumed here via `go.mod` require+replace, not vendored into this tree); `kvbackend.go` is the thin **adapter** that maps its `ReadSecret` onto the `Backend` seam, and `selector.go` is the config-driven factory that wires either backend at deploy time. Both the adapter and the selector are exercised against an httptest fake OpenBao/Vault — **never a live store** (D50).
- **No `.proto` bodies** — the grant-fetch wire contract lands in `proto/dreamserpent/identity/v1/` via a freeze PR at the M1 window (the proto-freeze rider for the grant-record contract is the proposed follow-up routed through `proto/FREEZE.md`).

## The GrantRef contract (the cross-module seam)

`grant_ref` is the **only** string this module and the standalone `../mint` module
agree on: the mint side **writes** it (`mint.FormatGrantRef` → `GrantSet` →
`RegisterSession`), this side **reads** it (`Service.Fetch` keys the D39 store lookup
on it). Two separate `GOWORK=off` modules, no compile- or test-time link — so a
unilateral format change would otherwise break the per-session fetch silently.

**Contract mechanism — a committed golden round-trip fixture** (chosen over a shared
Go type, which is impossible across two modules with no shared dependency).
`testdata/grantref-golden.json` carries canonical `{session, service, ref}` triples
**byte-identical** to `../mint/testdata/grantref-golden.json`. `grantref.go` vendors
`FormatGrantRef`/`ParseGrantRef` (the inverse pair, identical to the mint side's), and
`grantref_test.go`'s `TestGrantRef_GoldenContract_ReaderSide` asserts the **reader**
half: `ParseGrantRef(golden ref) == {session, service}`. The mint side's
`TestGrantRef_GoldenContract_WriterSide` asserts the **writer** half. **If either side
edits its format functions unilaterally, that side's own suite fails against the shared
golden** — the drift breaks loudly at test time instead of silently at fetch time.
`Service.Fetch` now keys on `ParseGrantRef` (rejecting a ref that does not parse to the
session×service being fetched with `ErrGrantRefMismatch`), so the contract function is
load-bearing on the read path, not decorative.

## §6.1 composition seam (consumed here)

The doc 16 §6.1 mint sub-sequence (identity mint → CA mint → grant issuance →
`RegisterSession` → `ISSUED{service_id}` derivation) composes across the seam because
both sides key on the same `grant_ref`.
`TestComposition_GrantSetToRegisterSessionToFetch` proves the grant-service half: a
synthetic `GrantSet` (as `MintGrants` emits) → `RegisterSession` → `Fetch` keyed on the
`GrantSet`'s `grant_ref` resolves the credential, and the `ISSUED{service_id}` tag is
recovered from the same `grant_ref` (a digest's intended service is a **grant fact**,
§5.1). This is the **proven seam**, not the production digest producer, which consumes it.

## Residuals

- **Wire contract:** the grant-record proto rider goes through `proto/FREEZE.md` at
  the M1 credential-swap window. Until it lands, grants stay internal Go types and
  the cross-module `grant_ref` shape is enforced by the golden fixture above (not a
  frozen proto).

