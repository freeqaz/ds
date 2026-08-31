# roles/ — session role bundles (skeleton landed 2026-06-11)

**Status: machine validator landed** — `SCHEMA.md` and the four built-in role YAMLs
(`default`, `developer`, `researcher`, `security-engineer`) were committed 2026-06-11.
**Doc 18's role rows were ratified 2026-06-12** (→ D89–D96; P-T1 = D94).
The `role/v0` machine validator + parse-time rejections + `role_content_hash` now live in
[`policy-core::role`](../dataplane/crates/policy-core/src/role.rs) (the document home stays here;
the validation code path lives where POL-1 validation lives, doc 18 §5), with the doc 18 §11
assurance suite in
[`policy-core/tests/role_validation.rs`](../dataplane/crates/policy-core/tests/role_validation.rs).
All four built-ins round-trip parse→validate; the roles concept, Orchestrator stewardship,
narrow-by-default model, and OSS packaging are ratified decisions.

**Owner workstream:** Orchestrator (doc 05 §3;
stewardship per doc 18 §4 — the orchestrator pins the role `(name, version, content_hash)`
into the never-recycled session record (doc 15 §5.6, D66) as one more D7-class create-time
input — distinct from the env config (doc 18 §3) — and serves the catalog).
**License:** OSS (Apache-2.0, D25) — role bundles parameterize the open data plane's
guardrails; D15's run-it-without-us promise requires them to be inspectable (doc 18 §5).
**Governing decisions:** D7, D35, D80 (existing); doc 18 §10 P-R1–P-R5/P-T1–P-T3
ratified 2026-06-12 → **D89–D96**.

## Charter

The schema and the built-in catalog for **session roles**: named, versioned, declarative
bundles selected at session create — default, developer, researcher, security-engineer —
each composing tool/image layers, installed skills, a POL-1 session-layer policy posture, a
credential-scope template, and optional runtime config (doc 18 §2). Every axis **references
artifacts other workstreams own**; this tree holds compositions, never contents. Hosted
catalogs seed from these files; orgs add custom roles via the catalog API
(`proto/dreamserpent/roles/v1`, RESERVED).

- `SCHEMA.md` — the role/v0 schema strawman (commented-YAML, doc 13 §3 style).
- `SKILL-ARTIFACTS.md` — the skill-artifact reference shape & install contract for axis (b)'s
  `skills:` refs (proposed/pending-ratification; settles the doc 18 OQ2 named gap).
- `default.yaml`, `developer.yaml`, `researcher.yaml`, `security-engineer.yaml` — the four
  built-ins, all strawmen pending the design build.

Safety posture (ratified D91, doc 18 §9): session create only narrows; a role's widenings are
inert until org-admin catalog ratification; blocklists, rung caps, and the empty
pass-through list are floors nothing here overrides.

## What must NOT live here

- **An env-spec schema or repo build content** — env-spec is UNOWNED (doc 15 OQ10,
  `images/README.md`); a role never substitutes for the D56 second key (doc 18 §3).
- **Image build definitions** — `images/golden/`; roles reference layers by content address.
- **Skill implementations** — roles reference skill bundles; the registry is a named gap
  (doc 18 OQ2).
- **POL-1 layer documents for any layer other than the role's compiled session layer** —
  schema and evaluator live with `ds-contracts`/policy-core (doc 13 §1 rule 1).
- **Credential material, digests, keys** (D39) — scope *templates* only (doc 18 §8).
- **`.proto` bodies** — contracts live in `proto/` (D24); `roles/v1` is README-reserved.
- **attack/redteam vocabulary** in role names or skill refs (doc 06 §3c) — the review role
  is `security-engineer`, a guardrail-assurance posture.

## Neighbors

| Tree | Relation |
|---|---|
| `orchestrator/` | Resolves `role_ref` at create, pins `(name, version, content_hash)` into the session record (doc 15 §5.6), compiles axis (c) into the policy composition |
| `images/` | Owns the tool layers axis (a) references; image identity question doc 18 OQ3 |
| `identity/` | Consumes the scope template at `MintGrants` (doc 16 §5.1); attenuable-token seam per doc 18 §8 / doc 19 §11 |
| `vm/`, `client/` | Skill install + runtime-config axes (b)/(e); the D38 contract keeps the orchestrator runtime-ignorant |
| `proto/dreamserpent/roles/v1/` | The reserved catalog seam (`ListRoles`/`GetRole` now-shaped; write path with the M2 product band) |
