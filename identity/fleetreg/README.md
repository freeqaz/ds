# identity/fleetreg/ — D84 fleet-scope secret-digest registration (control plane)

**Owner workstream:** Identity & credentials · **OSS** (the registration surface is part of the OSS digest path; the OSS/paid line is the D80 service boundary, never a flag inside a binary — D85)
**Status:** Real module — the control-plane API + CLI half of the D84 designation flow. Go module, outside `go.work` (`GOWORK=off`).
**D-numbers:** D84 (mount/path-prefix opt-in, default none, per-secret escape hatch, authority defaults), D55 (OpenBao KV integration; order yields to the first signed partner), D85 (OSS line: generic KV client + digest producer are OSS), D72 (fleet = policy artifact, no third channel — the POL-4 revocation bar), D50 (synthetic fixtures only).

## What this is

The **registration surface** of doc 16 §6.4 / §9 / §11.3: the security team designates Vault mounts / path prefixes during 2c onboarding, everything under a designated prefix is digested automatically, new secrets inherit protection, and explicit per-secret registration is the manual escape hatch. This module owns the **API + CLI** (the dashboard is later); it decides **which** Vault trees the [`../digest/`](../digest/README.md) producer may read — the designated-prefix set **is** the consent surface bounding the producer's plaintext-read scope (D84, the D23 2c motion) — and turns each register/revoke into a **fleet-scope digest policy artifact**.

It introduces **no new proto and no new RPC**. Registration rides the **existing** `policy_log`/`PolicySink` seam (D72, "two cadences, no third channel"): `Manager.Register`/`Revoke` build the fleet credential set with the digest producer and append it through [`../digest/`](../digest/README.md)'s `PublishFleetPolicy` / `RevokeFleetPolicy` — a Go interface onto `orchestrator.v1.PolicyService`'s append path, never a second wire surface.

## Files

| File | Role |
|---|---|
| `registration.go` | The registration **model**: `Registry` (the consent surface — prefix designation + per-secret escape hatch + **inheritance** + **default-none**), `Coverage`/`CoverageOf`/`Covers` (the plaintext-read consent predicate, longest-prefix match at segment boundaries), the D84 authority model (`Ownership`, `Principal`, `Authorizer.Authorize` — org admin for org credentials, owner for owned), and the `DigestSource` seam onto the kv-client read surface. |
| `policyartifact.go` | The registration **API**: `Manager` sequences authority check → consent-surface mutation → plaintext read (only of `Covers`-approved paths) → fleet-scope policy_log append via `../digest/`. `DesignatePrefix` / `RegisterSecret` / `Revoke` / `Sync` (the inheritance refresh). Fail-closed: an unauthorized actor writes nothing; an uncommitted policy-apply surfaces as an error. |
| `cmd/fleetreg/main.go` | The **stdlib-only** CLI (cobra-free, one `flag.FlagSet` per subcommand): `designate` / `register` / `revoke` / `list`. Default path runs against a synthetic in-memory fixture (a fake KV tree + a fake policy sink) so every verb is demonstrable with no live store. Holds the `kvSourceAdapter` projecting `identity/kv-client.Client` onto the `DigestSource` seam (the live path). |
| `doc.go` | Package doc citing doc 16 §6.4/§9/§11.3 and the D-numbers. |
| `*_test.go` | Table-driven: default-none posture, prefix designation + inheritance, per-secret escape hatch, authority-default enforcement (org-admin vs owner), register/revoke ride the policy_log artifact shape (FLEET-scope FORBIDDEN entries under the producer key id; empty-entry retire), read-scope bound to consent, fail-closed legs; the CLI lifecycle; and the kv-client adapter against an httptest fake OpenBao server (the cross-module seam proof). |

## The D84 designation flow (doc 16 §11.3, end to end)

1. **Default: none.** A fresh `Registry` covers nothing — an unconfigured surface designates nothing, so the producer touches zero plaintext.
2. **Prefix designation (the 2c motion).** `Manager.DesignatePrefix` records the single auditable scoping decision and digests every leaf under it as one fleet artifact.
3. **Auto-digest under the prefix.** Everything under a designated prefix is covered automatically — no per-secret action.
4. **Inheritance.** A secret newly written under a designated prefix is picked up by `Manager.Sync` without re-designation — the property per-secret-only registration cannot give (coverage does not rot).
5. **Per-secret escape hatch.** `Manager.RegisterSecret` joins one path *outside* any designated prefix to the feed without designating its whole tree.

The producer's read scope is exactly the union of designated prefixes + per-secret registrations — never broader (`Registry.Covers`), the in-process analogue of the Vault-role scoping that bounds the platform-service auth (doc 16 §11.3).

## What does NOT live here (scope fence)

- **The digest math** (keyed HMAC variants, key lifecycle/rotation) — [`../digest/`](../digest/README.md)'s. This module decides *which* credentials become fleet digests and drives the existing verbs; it computes no digest.
- **The KV transport** (Vault HTTP, auth, read-only posture) — [`../kv-client/`](../kv-client/README.md)'s. This module consumes the `DigestSource` seam an adapter satisfies over `ListKeys`/`ReadSecret`; it edits no kv-client file.
- **The policy_log RPC + the per-host `WatchPolicies` fan-out** — the orchestrator's. This module appends through the `digest.PolicySink` interface; an in-process fake satisfies it in tests.
- **A new proto or RPC** — none. Registration is a policy artifact over the existing append path (D72).
- **The AWS Secrets Manager second store and the dashboard** — explicitly out of scope; both slot behind the same `DigestSource` / registration seam later (doc 16 §11.3).
- **Real credentials / a live store** — synthetic `ds-synth-*` only (D50). The live-Vault path is **env-gated (`FLEETREG_VAULT_ADDR`) and off by default**; it is a deferred manual step (it needs a reachable OpenBao/Vault + platform-service auth) and is never exercised in this wave.

## Build & test

```sh
cd identity/fleetreg
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./...
gofmt -l . | (! grep .)
```
