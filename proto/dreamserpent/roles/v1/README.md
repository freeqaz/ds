# dreamserpent.roles.v1 — READ path FROZEN (write path M2-deferred + reserved)

**Status: READ path FROZEN 2026-06-13** (freeze PR `roles-readpath`; [FREEZE.md](../../../FREEZE.md)
roles.v1 row). This package was reserved by docs/18
(P-T2 → **D95**, ratified 2026-06-12). The read path — `RoleCatalogService` with
`ListRoles` / `GetRole` — is now frozen; `catalog.proto` carries the `Role` message set
that mirrors the [`roles/SCHEMA.md`](../../../../roles/SCHEMA.md) role/v0 schema. The
**write path** (`PutRole` + the widening-ratification verbs) is **DEFERRED to the M2
product band** (doc 18 OQ5; doc 15 §5.3, beside enrollment and policy authoring) and is
**RESERVED**, not implemented — reserved-RPC comments on the service plus generous
field-number reservations on every message, so it lands ADDITIVELY without a v2.

**Owner workstream:** Orchestrator (doc 18 §4/§7 — the orchestrator pins the role
`(name, version, content_hash)` into the never-recycled session record (doc 15 §5.6, D66,
D92) and serves the catalog). **License:** [OSS] public contract (D58/D93): orchestrator-lite
(OSS) and the paid fleet control plane implement the SAME package.

**What is frozen (the read path, doc 18 §4/§6):**

- `service RoleCatalogService` — `ListRoles` (enumerate the catalog + name the recorded
  default, doc 18 §7) and `GetRole` (read one role by `<name>` / `<name>@<version>` /
  empty = recorded default; unknown ref = NotFound). Needed by M0's orchestrator-lite (the
  OSS single-host all-in-one, **D80**) and the CLI — served wherever `CreateSession` is.
- `message Role` — the wire projection of one `roles/SCHEMA.md` (role/v0) document: the
  pinned identity triple `(name, version, content_hash)` (D92; `content_hash` = the ONE
  canonical-serialization spec, roles/SCHEMA.md rule 5) + all five composition axes
  (`image` / `skills` as REFERENCES; `policy` posture + the §9 widening posture;
  `scope_template` as a credential TEMPLATE — services + mode, NEVER material, D39 — with
  the §8 null-vs-present-empty boundary carried by `scope_template_present`; `runtime` as
  an opaque overlay ref).

**Backing store (M0).** The read path is backed by the checked-in
[`roles/`](../../../../roles/) catalog (the four built-in strawmen — default / developer /
researcher / security-engineer); the control-plane server is
`orchestrator/internal/controlplane.RoleCatalogService`, projecting
`sessions.LoadCatalogRoleDocuments` onto `Role`. The `role_content_hash` is anchored to
[`roles/content-hash-goldens.json`](../../../../roles/content-hash-goldens.json) — the
same golden both catalog resolvers read (the cross-module agreement). The doc 18 §11
read-path validation suite lives in
`orchestrator/internal/controlplane/rolecatalog_test.go`.

**The write path stays out (M2-deferred, RESERVED):** `PutRole` (publish/update a role
version into the org catalog — the actor-recorded mutation, doc 18 §7) and the
widening-ratification verb (org-admin ratification flipping a role version's widenings from
inert to admitted, doc 18 §9, D91) design + freeze with the **M2 product band**, not now.
Nothing in `catalog.proto` pre-ratifies that design — the reservations only keep room.

**Deliberately NOT in this package:** the `role_ref` field on `CreateSessionRequest` —
that is one optional field in [`orchestrator.v1`](../../orchestrator/v1/) (D95/D106,
INCLUDED there at its M0 freeze), not a `roles.v1` message.

**What must NOT live here:** POL-1 schema fields (`ds-contracts`, doc 13 §3); skill or
image artifact registries (named gaps, doc 18 OQ2/OQ3 — they get their own seams when
owned; the role carries only the strawman REFS); anything carrying credential material
rather than scope templates (D39, doc 18 §8); human-RBAC messages (org-model doc, doc 17
OQ7); the catalog WRITE verbs (M2-deferred, reserved above).
