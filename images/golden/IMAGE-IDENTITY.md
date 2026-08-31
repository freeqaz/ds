# images/golden/ — image identity × role layers (doc 18 OQ3 composition) — RATIFIED (D133)

**Owner:** Image & cache builder · **OSS** (D25) · **Status:** **RATIFIED 2026-06-16**
(ratified; D133, Option A).
The §"Recommendation" direction (Option A) is now binding: `image_id =
content_hash(repo, ref, env-spec hash, role-layer-set hash)` over the shared
RFC-8785(JCS)/SHA-256 canonicalizer, empty role-layer-set tail for the roleless
M0 case. Downstream consumers (the `roles/` resolver, the orchestrator `image_id`
recording, doc 15 §4.1 step 7) implement against it; `prebake.sh` step-3 commit
stamps the ID (taskdb `01KTZS6F7V`).

## What this settles, and what it does not

The `hypervisor.v1` **freeze-gate** half of doc 18 OQ3 is already discharged:
**D107** (ratified
2026-06-12) **explicitly waives** any role-layer field on the hypervisor seam —
no new `VmSpec`/`CloneFromImageRequest` field, the image ID carries the
role-layer set, and the orchestrator's content-address surface
(`(repo, ref, env-spec hash) → image ID`, doc 15 §5.1)
does the carrying. D107 deliberately left the **composition details open, owned
by Image & cache** (this tree — `images/README.md` Neighbors row).

This note settles those composition details: **how** the role-layer set folds
into the content-addressed identity, computed in `golden/`, so the image ID a
session resolves through `CloneFromImage` already binds the role's tool layers
without spending a contract field. It is the missing-half answer D107 named.

It does **not** reopen D107, define the `images:layer/...@<digest>` artifact ref
format (that is doc 18 OQ2 + the image/cache contract gap, doc 15 §6 — still a
gap), nor add any proto field (the seam is waived). It binds nothing until
ratified.

## The fork (doc 18 OQ3, verbatim)

> Does the content-addressed image ID become
> `(repo, ref, env-spec hash, role-layer-set hash)`, or do role layers stay a
> separate overlay input to `CloneFromImage`?

### Option A — role-layer set joins the content address (the cheap default)

The image ID tuple widens to
`(repo, ref, env-spec hash, role-layer-set hash)`. The role's `image.layers[]`
(doc 18 §5 axis (a)) are resolved to their content-addressed digests, the set is
canonicalized and hashed into one `role-layer-set hash`, and that hash is a
fourth content-address input. One image ID = one fully-equipped base disk
(env-spec image **with** the role's tool layers already baked/stacked). The
orchestrator records this single ID per D7 (doc 15 §9); `CloneFromImage` clones
one overlay over it.

- **(+)** Honors D107's literal direction (the `(repo, ref, env-spec hash,
  role-layer-set hash)` shape D107 names) with **zero new contract surface** —
  the existing `image_id` string already carries it.
- **(+)** One artifact = one identity = one supply-chain integrity statement
  (the `golden/` charter: the image "is the supply-chain integrity statement for
  everything baked into it"). Role tool layers are *in* that statement, not a
  side input that escapes it.
- **(+)** Cache locality (the doc 15 §7 filter-(4) scheduler preference) keys off
  one ID that already accounts for role layers — a host warm for `developer` on
  this repo+ref is genuinely warm, no post-clone layer fetch on the create path.
- **(+)** Pinning convention reuse: a role+repo image pins `tag@sha256:<digest>`
  identically to every other image in this tree (`images/README.md` "Image
  pinning convention") — the digest binds the whole stack including role layers.
- **(−)** Image **fan-out**: `R` roles × `E` env-spec images = up to `R·E`
  distinct base images per repo, each a build/cache/evict unit. Mitigated by
  layer sharing in the store (the role layers are content-addressed and
  deduplicated across images that reference them) and by roles being a small
  built-in set (four) at v0 — but the *identity* count multiplies even when bytes
  are shared.
- **(−)** A role catalog edit that changes `image.layers[]` mints a new image ID
  for every (repo, ref) that uses the role — a rebuild/cache-warm event, not just
  a session-record field change.

### Option B — role layers stay a separate overlay input to `CloneFromImage`

The image ID stays `(repo, ref, env-spec hash)` — env-spec image only. The role's
tool layers are passed as a **separate, additional overlay input** at clone time:
`CloneFromImage` stacks the role-layer overlay(s) on top of the shared env-spec
base, per session.

- **(+)** No image fan-out: one env-spec base image per (repo, ref) serves every
  role; role layers are thin per-session overlay deltas.
- **(+)** A role-layer change does not invalidate the base image cache — only the
  (small, content-addressed) role-layer overlays change.
- **(−)** **Requires a new contract field** on the hypervisor seam to carry the
  separate role-layer input into `CloneFromImage` — which is **exactly what D107
  waived** (a missed/added field on the one-shot M0 freeze is a v2-package
  event). Option B is contradicted by a ratified decision; it cannot be the
  recommendation without reopening D107.
- **(−)** Identity leak: the image ID no longer fully describes the disk the
  agent runs on — the supply-chain integrity statement splits across the image ID
  *and* an out-of-band role-layer set, and the orchestrator must record both to
  reproduce a session (the `golden/` "one artifact = one statement" property is
  lost).
- **(−)** Cache locality (doc 15 §7 filter-(4)) keys off an ID blind to role
  layers, so a "warm" host may still pay a per-create role-layer stack cost.

## Recommendation (PROPOSED)

**Adopt Option A — the role-layer set joins the content-addressed image
identity:** `image_id = content_hash(repo, ref, env-spec hash, role-layer-set
hash)`, computed in `golden/`, `VmSpec`/`CloneFromImage` unchanged. This is the
cheap default doc 18 OQ3 already records and the direction D107 ratified at the
freeze gate; settling the composition this way keeps the freeze-gate waiver
self-consistent — Option B would reopen D107 by re-introducing the very field it
waived.

Composition mechanics (the open half D107 left to this tree):

1. **`role-layer-set hash` derivation.** Resolve the role's `image.layers[]`
   (doc 18 §5 axis (a)) to their content-addressed layer digests
   (`images:layer/<name>@sha256:<digest>` — the ref *format* itself is doc 18
   OQ2, still a gap; this note assumes only that a layer resolves to a stable
   digest). Canonicalize the **resolved digest set** — order-independent (a set,
   not a list: two roles naming the same layers in different order MUST hash
   equal) by sorting digests lexicographically — and hash with the **same
   produce-once RFC 8785 (JCS) / SHA-256 machinery** that backs the policy
   snapshot `content_hash` (doc 15 §"OQ3 canonical-serialization", doc 13 §5.1)
   and the role document's own `role_content_hash`
   (`dataplane/crates/policy-core/src/role.rs`, doc 18 §7). **One
   canonicalization spec across all three hashes, not three** — the explicit
   non-goal of every prior identity row in this system. An **empty** layer set
   (a role with no `image.layers[]`, e.g. `default`) hashes to a fixed
   empty-set digest, so the role axis is **inert** on the image ID: a roleless
   or layerless create resolves to the *same* image ID it resolves to today
   (`(repo, ref, env-spec hash)` with the empty-set tail) — Option A is
   backward-identity-compatible for the no-tool-layer case.

2. **Fold into the image ID.** The image ID is `content_hash` over the ordered
   tuple `(repo, ref, env-spec hash, role-layer-set hash)` under the same pinned
   proto→JSON mapping (absent ≡ default ≡ omitted; the empty-set tail above is
   the explicit-presence worked example, mirroring `dns.negative_ttl: 0`). The
   orchestrator records this single ID per D7 (doc 15 §9 `RecordEnvConfig` stores
   "the resolved content-addressed image ID"); the role's `(name, version,
   role_content_hash)` pin (doc 18 §7) and this image ID are **separate** pinned
   facts in the session record — the role document hash is *not* the image ID
   (a role carries four other axes that never touch the disk), and the image ID
   is *not* the role hash (env-spec layers join it too).

3. **No contract surface, no skill axis.** `VmSpec.image_id` (doc 15 §5.1) stays
   a single opaque content-address string; the derivation lives entirely in
   `golden/`'s build/identity path and the orchestrator's image-ID recording.
   The **skills** axis (doc 18 §5 axis (b)) is **out of scope here**: skills are
   injected into the per-session overlay pre-boot (doc 18 §6 step 7), not baked
   into the base disk, so they do **not** join the image ID — a skills change is
   an overlay-injection change, not a new image identity. Only axis (a) tool
   layers fold into the address.

4. **Cache / build implications (accept the fan-out, mitigate by dedup).** Each
   distinct `(repo, ref, env-spec hash, role-layer-set hash)` is a build/cache
   unit; the multiplicative fan-out (Option A's main cost) is bounded by (i) the
   small built-in role set at v0, (ii) content-addressed **layer-store dedup** so
   shared role layers cost bytes once across images, and (iii) the empty-set
   identity-compat rule (no extra image for roleless/layerless creates). Nightly
   rebuild cadence (the `golden/` charter) rolls role-layer images on the same
   schedule as env-spec images. Eviction/pre-positioning policy for the widened
   identity space is Image-workstream-owned tuning, not a contract question.

## What downstream consumers should assume

- **doc 15 §5.1 `image_id` comment** — the "cheap default" it records (role
  layers join the content-addressed identity, `VmSpec` unchanged) is now the
  **recommended composition**, detailed here. The comment points at this note;
  the field stays waived (D107).
- **doc 18 OQ3 / §3** — the composition recommendation is drafted (this note);
  OQ3's composition half is **proposed-resolved, not ratified**. Roles assume
  the role-layer set folds into the image ID (Option A) and that the **skills**
  axis stays an overlay input outside the image ID.
- **`roles/` resolver + the orchestrator image-ID path** — resolve `image.layers[]`
  to digests, derive the `role-layer-set hash` via the shared canonicalizer, fold
  into the image ID; no `CloneFromImage` field for role layers (waived).

Until ratified through the
round-4 packet, this is a
strawman binding nothing; it does not flip any status and does not enter doc 04
§6.

## Implementation note — the prebake step-3 image_id stamp (taskdb 01KTZS6F7V)

`prebake.sh` step-3 commit stamps the D133/Option A image_id alongside the
committed golden, as a sidecar `<golden_path>.image-id` (one line: the 64-char
lowercase-hex digest). The rotation/identity path reads it back; `golden_path`
remains the single source of truth for the golden filename, and the sidecar path
is derived from it (`image_id_sidecar_path`). The stamp is computed in both
`emit_plan` (the `--dry-run` `step 3 stamp …` line) and `live_bake` (the actual
write after the golden is published) from one shared resolution, so plan and bake
stay in **lockstep**; the `DS_GOLDEN_BAKE_LIVE` gating is untouched — the
`--dry-run` plan prints the ID it *would* stamp, only the gated live leg writes
the sidecar.

**The stamp:**
`image_id = SHA-256(JCS({env_spec_hash, ref, repo, role_layer_set_hash}))`, the
RFC-8785 (JCS) canonical JSON object over the ordered tuple under the pinned
mapping (keys lexicographically sorted — already `env_spec_hash`, `ref`, `repo`,
`role_layer_set_hash`; no insignificant whitespace; strings JCS-escaped; integers
bare). `role_layer_set_hash = SHA-256(JCS([<sorted resolved layer digests>]))` —
the resolved layer-digest set canonicalized **order-independently** by sorting
digests lexicographically (a *set*, not a list) and rendered as a JCS array.

**Empty-set worked example (roleless / layerless M0).** With no resolved
`image.layers[]` the set is empty: `JCS([]) = "[]"`, and
`role_layer_set_hash = SHA-256("[]") =
4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` — a **fixed
empty-set digest**, so the role axis is **inert**. A roleless create therefore
stamps the same image_id it would resolve to from `(repo, ref, env-spec hash)`
alone (with the empty-set tail) — **backward-identity-compatible**. The orchestrator
records this same ID independently (D7, doc 15 §9), so the bake's stamp must equal
what the shared canonicalizer produces.

**Cross-language agreement (load-bearing).** There is **one** canonicalization
spec across `image_id`, the policy-snapshot `content_hash`, and the role document's
`role_content_hash` — RFC 8785 (JCS) + SHA-256 (doc 13 §5.1;
`dataplane/crates/policy-core/src/role.rs`). `prebake.sh` reproduces that JCS
canonical form for this fixed-shape tuple in self-contained shell + `sha256sum`
(no build dependency): the canonical bytes are byte-identical to what role.rs's
`JcsValue::to_jcs` emits for an all-string sorted-key object, and `sha256sum` /
the hand-rolled `ds_contracts::snapshot_verify::sha256` compute FIPS-180-4 SHA-256
bit-for-bit identically — so a Go/Rust producer forming the same bytes lands on
the same digest by construction. To guard against any drift of the reproduced form
from the shared spec, `--self-test` pins a **committed test vector** and asserts it
**offline**:

| input | value |
| --- | --- |
| repo | `github.com/acme/monorepo` |
| ref | `main` |
| env-spec hash | `0000…0000` (64 zeros) |
| role-layer-set | empty → `4f53cda1…b945` |
| canonical payload | `{"env_spec_hash":"0…0","ref":"main","repo":"github.com/acme/monorepo","role_layer_set_hash":"4f53cda1…b945"}` |
| **image_id** | `7111af2208b612a6783c8861d3482d41ef7b1d5e01cfd5291e3a792f0c4636c6` |

The self-test asserts the canonical payload bytes, the full image_id, the fixed
empty-set digest, role-layer-set order-independence, and the M0 backward-compat
identity — any change to key order, escaping, tuple shape, or the empty-set tail
flips the digest and fails the self-test before a divergent stamp can ship.

**env-spec hash input.** The third content-address input (the env-spec digest the
orchestrator surface resolves, doc 15 §5.1) is supplied to the bake via
`DS_GOLDEN_ENV_SPEC_HASH` or `defaults.env_spec_hash` in the prebake config; absent
both, a documented 64-zero sentinel keeps the stamp deterministic and the plan
inspectable offline (a real bake supplies the resolved hash). This is consumed,
not minted, here — the env-spec schema is owned upstream (doc 15 §9, OQ10).
