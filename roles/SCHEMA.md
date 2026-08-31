# role/v0 schema

**Status: ratified — doc 18's role rows landed 2026-06-12 (→ D89–D96).** Field names are free;
the shapes and invariants below are the frozen contract the machine validator enforces. Style
follows the POL-1 strawman (doc 13 §3).

**Machine validator.** The validation code path lives in
[`policy-core::role`](../dataplane/crates/policy-core/src/role.rs) — the home rule of doc 18 §5
("if role validation ever needs `policy-core` (it does, for axis (c)'s projection), the
validation code path lives where POL-1 validation lives"). The *document* home stays here. The
`role/v0` parser (`parse_role`) is stdlib-only (no serde / serde_yaml — the workspace dep-free
fence) and enforces every rule below at parse time; the doc 18 §11 assurance suite lives in
[`policy-core/tests/role_validation.rs`](../dataplane/crates/policy-core/tests/role_validation.rs)
(synthetic fixtures only, D50). The rung-cap check DELEGATES to the doc 13 §7 suite
(`ds_contracts::pol1::validate_layer`) — one rung-cap machinery, not two. `role_content_hash`
rides the SAME canonical-serialization machinery the PolicySnapshot `content_hash` uses (doc 18
§7; doc 15 OQ3 / doc 13 OQ2 — one canonicalization spec, not two): SHA-256 (full 32 bytes) over
the produce-once RFC 8785 (JCS) canonical-JSON payload of the role document, via the shared
`ds_contracts::snapshot_verify::sha256` — cross-checked against the `role_document` golden
fixture in `ds-contracts/testdata/snapshot-goldens.json`.

Validation rules (all enforced at parse time by `policy-core::role`; doc 18 §11):

1. **References only** — `image.layers[]` and `skills.install[]` are artifact refs (the
   `images:` / `skills:` prefixes), never inline content; an inline entry is a parse-time
   rejection (`InlineArtifact`). Unknown refs fail session create, fail-closed.
2. **Policy block is a restricted projection** that compiles to ONE POL-1 *session-layer*
   document; it **may not declare `passthrough`** — any `passthrough` key, even an empty list,
   is rejected at parse (`PassThrough`): the empty-by-default pass-through list is the POL-1
   floor's, a role cannot add to it (doc 18 §9 point 3, D74). It may not mint escape hatches,
   and its `guardrails[]` obey the doc 13 rung caps (generic content rules capped `block+log`)
   — the cap check delegates to the doc 13 §7 suite (`RungCap`). Composition is deny-overrides
   (doc 13 §1 rule 2) — org blocklists always win.
3. **Widening is inert until ratified** (doc 18 §9): `allowlist[]` entries and
   `pack_families` tier flips beyond the org envelope carry no effect pre-ratification —
   logged warning, never silent admission (the doc 13 §1 rule-7 pattern).
4. **Credential block is a template** — narrows the env-spec × `services[]` grant envelope
   by intersection; **never credential material** (D39). A role embedding a secret value —
   a `credential` / `secret` / `token` / `api_key` / `password` / `private_key` /
   `authorization` (or similar) key anywhere in the document — is rejected at parse
   (`CredentialMaterial`): axis (d) carries `services[]` + `mode` only. The template is
   **nullable**, and the two boundary cases are distinct: `scope_template: null` = no
   narrowing — the full doc 16 §5.1 env-spec × `services[]` envelope applies unchanged (the
   `default` role); `services: []` = empty intersection — mint nothing (the `researcher`
   role). Consumed at doc 15 §4.1 step 5; the attenuable-token caveat vocabulary belongs to
   the identity scoped-token pass (doc 18 §8).
5. **`version` is a content identifier** (doc 13 §1 rule 3 analog); `role_content_hash` uses
   the doc 15 OQ3 / doc 13 OQ2 canonical serialization (SHA-256 over the produce-once JCS
   payload, the shared `ds_contracts::snapshot_verify::sha256` — one spec, not two). Pinned
   per session in the never-recycled record as `(name, version, role_content_hash)`.

   **Catalog content_hash (landed 2026-06-13, M0).** The orchestrator-side producer —
   `orchestrator/internal/sessions.CatalogRoleResolver` — computes `role_content_hash` over the
   built-in `roles/*.yaml` via the SAME canonical-serialization machinery the PolicySnapshot
   `content_hash` uses (the Go `nftbridge` JCS path, the produce-once-then-hash discipline of doc 13
   §5.1), and ANCHORS the committed `content-hash-goldens.json` to those exact bytes (the
   orchestrator anchor test). The canonical role document is the deterministic projection
   `{credentials.scope_template (null | {mode, services}), name, policy.{allowlist, pack_families,
   posture}, schema_version, version}`, JCS-key-sorted, with the `scope_template` **null** (no
   narrowing) vs **present-empty `services: []`** (mint nothing) boundary surviving as distinct
   bytes → distinct hashes (rule 4). The `identity/mint` catalog resolver reads the SAME anchored
   golden (it is a separate GOWORK=off module whose only legal cross-tree import is `proto/gen/go`,
   so it cannot import the canonicalizer) — both seams therefore agree on one `role_content_hash`
   per role, proven by the cross-module agreement test. A catalog update to the same `(name,
   version)` that changes any hashed field is a DISTINCT pin in both trees.

```yaml
# role/v0 — full field inventory (commented strawman)
schema_version: role/v0
name: <string>                    # catalog key, [a-z0-9-]; never attack/redteam vocabulary
version: "<content-identifier>"   # e.g. "2026.06.11-v1"; cited in provenance, never a
                                  # second version namespace (validation rule 5)
description: <string>
                                  # NOTE: no inheritance in v0 — `extends` is deliberately
                                  # absent (deep inheritance chains are a named non-feature);
                                  # adding any inheritance needs doc 18 design first

image:                            # axis (a) — Image & cache builder
  layers:                         # content-addressed tool layers atop the env-spec image
    - "images:layer/<name>@<digest>"   # ref format STRAWMAN (doc 18 OQ2/OQ3)

skills:                           # axis (b) — VM & runtime / Attach & client
  install:
    - "skills:<bundle>@<version>" # registry is a NAMED GAP (doc 18 OQ2) — strawman refs
                                  # only; no install path is built until the gap closes

policy:                           # axis (c) — compiles to a POL-1 session-layer document
  posture: standard               # locked | standard | open (doc 13 §2) — may be NARROWER
                                  # than the org default; never effectively wider (rule 3)
  pack_families: {}               # tier-flip requests, e.g. { binary-cdn: enabled } —
                                  # widening => inert until catalog ratification
  allowlist: []                   # extra domain entries — same ratification gate
  guardrails: []                  # D52-class rules, doc 13 rung caps apply (rule 2)

credentials:                      # axis (d) — template only (validation rule 4)
  scope_template:                 # NULLABLE: null = no narrowing, full envelope (rule 4)
    services: []                  # subset of the org services[] registry keys;
                                  #   [] = empty intersection, mint nothing (rule 4)
    mode: read-write              # read-only | read-write — strawman vocabulary; the
                                  # caveat language is the identity pass's (doc 18 §8)

runtime:                          # axis (e) — opaque to the orchestrator (D38/D20)
  entrypoint_config_overlay_ref: null   # passed inside entrypoint_config_ref; the
                                        # orchestrator never inspects it
```
