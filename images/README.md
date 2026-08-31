# images/ — Image & cache builder

**Owner workstream:** Image & cache builder (doc 05 §3)
**License:** OSS tooling (Apache-2.0, D25)
**Governing decisions:** D17, D23, D41, D49 (doc 04 §6); source design doc 03 §6

## Charter

The CI integration that turns a repo+branch into a **golden image** — deps
running, node_modules on disk, warm build — so a session starts working
*instantly* (doc 02 §5 "ephemeral, pre-built environments"), plus the
site-local package/image **cache** deployment that backs it. Nightly rebuild
cadence dissolves the dev-box patching problem: when a CVE drops you roll the
image, and no instance lives long enough to drift (doc 03 §6). Pre-bake is
primary; the cache is the fallback for what isn't baked (D41). Per doc 03 §6
the first version stays **dynamic** (no golden-image requirement) — pre-baking
is the optimization path, landing as a product band at M2 (doc 05 §5).

- `golden/` — image build definitions + the nightly pipeline (D17 trust-store
  injection hook, D49 CC pin). The hand-built **M0 base image** precedes this
  pipeline and is VM & runtime's (doc 05 §3 seam statement); `golden/`
  industrializes that same image from M1 when this workstream joins.
- `cache/` — Nexus CE pull-through **deploy config only** (D41 is a buy).

## Image pinning convention

Every production image reference in this tree is pinned `tag@sha256:<digest>`:
the human-readable **tag survives** (so a deploy is legible at a glance) and the
**digest binds** (so the resolved image cannot change underneath us). This is
the same posture as the golden image — bumps are explicit, reviewed diffs,
**never registry-side drift**. A cache or mirror host must not be able to
silently roll its image; a bare `:latest` or a tag without a digest is a
deploy-config defect. The convention is stated here **once** and applies to
every deploy path identically:

| Image | Pinned in (every path identical) |
|---|---|
| `docker.io/sonatype/nexus3` (Nexus CE, D41 cache) | `cache/deploy/nexus.container` · `cache/deploy/compose.yaml` |
| `docker.io/alpine/git` (git-http-backend serve face) | `mirror/deploy/ds-mirror.env` (`DS_MIRROR_IMAGE`) · `mirror/deploy/ds-mirror-serve.container` (`Image=`) |

The mirror's `DS_MIRROR_IMAGE` env value and the quadlet `Image=` generator-key
literal are a hand-maintained pair (the generator does not expand
`EnvironmentFile=`); they must stay **byte-for-byte equal**, including the
digest. `mirror/lint-env-drift.sh` enforces that equality and fails closed on
divergence.

### Bumping a pin

To roll an image, change the tag, re-resolve the digest, and update **every**
path that references it in the same reviewed diff — both cache files
(`nexus.container` + `compose.yaml`) or both mirror files
(`ds-mirror.env` + `ds-mirror-serve.container`). The mirror pair is guarded by
`mirror/lint-env-drift.sh`; the **cache pair has no equality lint yet**, so its
two references must be kept identical by hand (and re-checked in review) until
one is added. Resolve with `crane digest`
(or `skopeo inspect --format '{{.Digest}}'`):

```sh
crane digest docker.io/sonatype/nexus3:3.70.1
crane digest docker.io/alpine/git:latest
```

Point-in-time resolution of the digests currently pinned, recorded when they
were set (`crane` v0.21.6, 2026-06-12) — re-run the commands above to confirm
or to bump:

```
$ crane digest docker.io/sonatype/nexus3:3.70.1
sha256:00ecf29c4a3a43d677aec9ff07966e942c4356d9c16a275d94110f6e1e5aca94
$ crane digest docker.io/alpine/git:latest
sha256:4a0e72d49596a1f5d3701aeedafdadc5c0da4062be4657c7bdc4017387f591cc
```

## UNOWNED: env-spec schema (doc 15 OQ10)

The env-spec schema — what "build/env config travels with the request or
lives in the repo" (doc 03 §6) actually looks like — has **no owning design
doc** (doc 15 OQ10: "missing artifact";
doc 15 freezes only the reference shape `RecordEnvConfig` stores, and the
image ID is content-addressed over `(repo, ref, env-spec hash)`).
**Deliberately, there is no directory for it here** — creating one would
fake an ownership decision nobody has made. When an owning doc lands, add
the directory, a CODEOWNERS line, and a `proto/`/schema home per the
"how to add a component" recipe (design Part 5). Also flagged in
`proto/README.md` as an unowned seam.

Relationship note (doc 18 §3, proposed): a **session
role** is the task-shaped axis, the env spec the repo-shaped one — a role adds tool layers
*atop* the env-spec-resolved image and never substitutes for the D56 second key. The OQ10
flag stands regardless of roles.

## What must NOT live here

- **Registry-protocol code** — D41 is buy-not-build; see `cache/README.md`.
- **An env-spec schema home** — unowned, see above (OQ10).
- **The CA mint** — `identity/mint/` (D82); `golden/` only *injects* the
  trust anchor it is handed (D17).
- **Runtime adapter code** — `client/wrapper/adapters/`; this tree only
  *pins the version* the image ships (D49).
- **`.proto` bodies** — contracts live in `proto/` (no image/cache contract
  exists yet; doc 15 §6 marks image identity + cache inventory as a gap).

## Neighbors

| Tree | Relation |
|---|---|
| `orchestrator/` | Consumes `(repo, ref, spec-hash) → image ID`; cache inventory rides the heartbeat for locality placement (doc 15 §6 — contract gap, not yet in proto/) |
| `identity/mint/` | Mints the per-session interception CA whose anchor `golden/` injects (D17/D82) |
| `client/` | The D49 CC pin baked here is what the adapter + goldentrace canary key off |
| `vm/` | Golden image is the raw base under the per-session qcow2 overlay (D29); bakes the entrypoint |
| `paid/onboarding/` | The D54 autodetect agent *drafts* env specs; recording is the orchestrator's |
| `roles/` | Role bundles *reference* content-addressed tool layers built in `golden/` (doc 18 §2 axis a — proposed); whether role layers join the image ID address is doc 18 OQ3, owned here — freeze-gate waived (D107, no `CloneFromImage` field), composition **PROPOSED** in [`golden/IMAGE-IDENTITY.md`](golden/IMAGE-IDENTITY.md) (Option A: role-layer set folds into the content-addressed ID) |
