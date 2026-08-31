# skill-artifact reference shape & install contract (proposed — pending ratification)

**Status: proposed / pending-ratification — settles the axis (b) named gap that
doc 18 §2 and OQ2 leave open; binds nothing.** Mints no
D-numbers. This is the missing owning contract for the skill bundles a role's `skills:` block
references — the registry doc 18 OQ2 calls "a named gap of
the same class as image identity + cache inventory (doc 15 §6)." It is **ready for the three
stakeholder workstreams to ratify** (Agent roles, VM & runtime, Attach & client — §6 below);
until they do, the role YAMLs' `skills:` entries remain strawmen and no install path is built
(doc 18 OQ2; doc 18 TODO "Define the skill-artifact reference shape … until then `skills:`
blocks are strawmen and install paths are not built"). Style follows
[`SCHEMA.md`](SCHEMA.md) (the role/v0 strawman) and the doc 13 §3 commented-YAML convention.

**Governing source:** doc 18 §2 axis (b) (the skills axis
references skill bundles; owner = VM & runtime / Attach & client; enforced by "overlay
injection pre-boot at v0; pre-baked golden path at M2, D12") and
doc 18 OQ2 (the registry gap). The
identity/content-addressing discipline is grounded in the
doc 15 §6 **image-identity precedent** (content-addressed
artifacts built ahead of create, shared across sessions, resolved at
doc 15 §4.1 step 7) and the **D73 digest-ack** pattern
(produce-before-egress, ack-gated, fail-closed) — applied where each genuinely fits, not by
analogy alone (§1, §4 below). This doc designs **none** of the bundle *contents* (a skill's
files, manifest format, or runtime adapter wiring belong to VM & runtime / Attach & client);
it designs the **reference shape, content addressing, install mechanics, and failure
semantics** — the seam, the way doc 18 §8 designs only the credential-template seam.

---

## 1. Reference shape — `name@version` → content-addressed digest

A role's `skills:` entries (e.g. `skills:code-review@1`, the strawman in
[`developer.yaml`](developer.yaml)) are **catalog references, never inline content** — the
same references-only invariant the role schema enforces ([`SCHEMA.md`](SCHEMA.md) rule 1:
"`image.layers[]` and `skills.install[]` are artifact refs, never inline content"). The
reference shape is a three-level address that **resolves at create to a content digest**,
exactly parallel to how a `images:layer/<name>@<digest>` ref resolves through the Image
workstream's content-addressed identity (doc 18 §6 step 7):

```
skills:<name>@<version>   →   resolve against catalog   →   skill bundle @ <digest>
   (role-authored ref)         (orchestrator, create)        (pinned, immutable)
```

1. **`<name>`** — the catalog key (`[a-z0-9-]`, never attack/redteam vocabulary — the doc 06
   §3c constraint the role schema already carries). Names a skill *family*, not a build.
2. **`<version>`** — a **content identifier, never a second version namespace** — the
   doc 13 §1 rule 3 analog the role schema
   applies to `version` ([`SCHEMA.md`](SCHEMA.md) rule 5) and that doc 18 §7 applies to
   `role_version`. `@1` in the strawmen is a human-citable label (provenance may cite
   `skill code-review@1` the way doc 18 §7 cites `role developer@2026.06.11-v1`); it is **not**
   what guarantees immutability. The catalog **pins** each `<name>@<version>` to exactly one
   content digest — the resolution `code-review@1 → sha256:…` is recorded, and a published
   `(name, version)` pair never re-points (§3).
3. **`<digest>`** — the content hash of the bundle (§2). This is the artifact actually
   injected and the value **pinned into the never-recycled session record** alongside the
   role's own `(role_name, role_version, role_content_hash)` (doc 18 §7; doc 15 §5.6, D66).
   A role pinned at create carries a frozen skill set for its whole life — a catalog update
   re-points `code-review@1` for **new creates only**, exactly the doc 18 §7 / doc 13 §1
   rule-8 "changing live state is the policy plane's job" philosophy.

**Where the D73 digest-ack pattern applies, and where it does not.** D73's digest discipline
(produce the artifact in the trust zone, write-before-first-egress, ack-gate routability,
fail-closed) is the *create-sequencing* precedent here: a skill bundle is resolved and its
digest pinned **before boot** (§3), and a resolution failure **fails the create** (§4) — the
mint-before-attach shape. What does **not** carry over is D73's *trust* posture: D73 digests
guard credential egress (a security invariant), whereas skill bundles are **availability-
critical, not trust-critical** — doc 18 §6 step 7 states this distinction explicitly
("missing artifact fails the create — fail-closed like step 7's CA injection, **though skills
are availability-critical, not trust-critical**"). So a skill digest mismatch is a
**fail-closed create refusal** (an artifact-integrity failure), not a policy-plane suspend
event; it never rides the `policy_log`, the D73 SecretMatcher feed, or the D72 distribution
channel. The role's compiled session-layer policy (axis c) is the only thing a role contributes
to the policy plane; skills are session-overlay content.

## 2. Content addressing — what is hashed, where it lives, how immutability holds

**What is hashed.** The digest covers the **entire skill bundle as a sealed artifact** — its
manifest plus all packaged files — under the **same canonical-serialization machinery the role
`content_hash` uses** ([`SCHEMA.md`](SCHEMA.md) rule 5; doc 15 OQ3 / doc 13 OQ2: "one
canonicalization spec, not two"). One canonicalization discipline across the role tree means
the round-4 content-hash canonical-serialization pass
(sessions/round4/01)
covers skill bundles too — this doc adds **no second hashing spec**. The bundle's *internal*
manifest format (what a skill declares it provides to the runtime adapter) is **owned by VM &
runtime / Attach & client**, not specified here — this contract only requires that whatever
that format is, the digest is taken over its canonical serialization so identity is stable.

**Where it lives at v0.** Skill bundles are **content-addressed artifacts built ahead of
session create and shared across sessions** — structurally the doc 15 §6 image story ("images
are built ahead of session create and shared across sessions … pre-baked golden images are the
M2 optimization path, D12"). At v0 the store is **a content-addressed bundle store the
orchestrator can read at create**, fetched into the session overlay during injection (§3); the
concrete backend (a directory of digest-named bundles beside the checked-in role YAMLs at v0,
an OCI-style content store later) is a **free implementation choice bounded by one rule**: the
fetch path must be reachable from wherever `CreateSession` runs — including `orchestrator-lite`,
the OSS single-host all-in-one (D80) — the same constraint doc 18 §4 places on catalog reads.
**No registry *service* is built at v0** (doc 18 OQ2 — "no install path is built until the gap
closes"); the v0 store is checked-in/file-backed, and a `proto`-fronted skill catalog is a
later seam reserved the way `proto/dreamserpent/roles/v1` is reserved for the role catalog
(doc 18 §6) — this doc reserves **no proto** and mints **no FREEZE.md row**.

**How immutability is guaranteed.** Three layers, weakest to strongest:
1. The `(name, version)` → digest binding in the catalog **never re-points once published** —
   re-pointing is a *new* version (the doc 13 §1 rule-3 content-identifier discipline; the same
   never-recycle posture as the session record, D66).
2. The artifact is addressed **by its own content** — fetching `@<digest>` and re-hashing must
   reproduce `<digest>`, or the fetch is rejected (§4). Content addressing makes immutability
   structural, not policy: a mutated bundle has a different address.
3. The resolved digest is **pinned into the never-recycled session record** at create
   (§1; doc 15 §5.6, D66), so the exact skill artifacts a session ran are an auditable fact for
   the flow-log retention window — the same audit posture doc 18 §7 gives the role itself.

## 3. Install mechanics at v0 — injection into the session overlay, pre-boot

Install is **overlay injection pre-boot at v0** — verbatim the axis (b) mechanism doc 18 §2
names and doc 18 §6 step 7 sequences ("skill bundles injected into the overlay pre-boot at
v0"). It rides the **existing** doc 15 §4.1 create choreography — **no new precedence
constraint, no new step** (doc 18 §6: "the role adds inputs to existing steps"):

| doc 15 §4.1 step | Skill-bundle touchpoint |
|---|---|
| 1–2 | Role resolved; each `skills:` entry resolved `name@version → digest` against the catalog and the **digest pinned** into the session record beside the role identity. An unknown or unresolvable skill ref is a **structural create refusal** (§4) — same posture as the doc 18 §6 step 1–2 unknown-role refusal and the D56 two-key check. |
| 7 | **`CloneFromImage` creates the per-session qcow2 overlay (D29); the resolved skill bundles are injected into that overlay before boot, fail-closed** — the *same per-create overlay-injection slot* as the D17/D82 interception-CA injection (doc 15 §4.1 step 7: "injected into the overlay's trust store before boot, fail-closed; injection failure fails the create"). Skills and the CA share the mechanism and the fail-closed posture; they differ only in criticality class (§1 — availability vs trust). Injection failure for any pinned skill bundle **fails the create** and unwinds per the doc 15 §4.1 step 7–8 rollback (destroy the domain, dispose the overlay). |
| 8 | Boot + entrypoint (D38): the guest entrypoint and the per-runtime adapter (Attach & client) find the injected bundles already present on the overlay filesystem at a path the runtime contract names; **the orchestrator never executes or inspects skill contents** (the D38/D20 runtime-ignorance posture). |

This keeps the orchestrator's role purely **resolve-and-pin-and-inject**: it addresses,
fetches by digest, verifies, and lays the sealed bundles into the overlay. **Activation** — how
the runtime entrypoint and the runtime adapter make an injected skill available to the agent
loop — is **VM & runtime / Attach & client's**, behind the D38 entrypoint contract; this doc
stops at "the bytes are present on the overlay, by digest, before boot." The **M2 path**
(pre-baked into the golden image rather than per-session injected, D12) is the same
optimization doc 18 §2 names for axis (b) and doc 15 §6 names for images — it changes *where*
the bytes are baked, not the reference shape, the addressing, or the failure semantics; v0 is
per-session injection.

## 4. Failure semantics — missing/unresolvable artifact fails the create, fail-closed

A skill artifact that is **missing, unresolvable, or fails content verification FAILS the
session create, fail-closed** — this is the load-bearing safety rule of the contract and
matches every counterpart in the design set:

- **Unresolvable reference** (`name@version` not in the catalog, or no digest pinned for it) →
  **structural create refusal**, the doc 18 §6 step 1–2 "unknown role, schema-invalid role, or
  an unresolvable ref = structural refusal" posture, and the [`SCHEMA.md`](SCHEMA.md) rule 1
  "unknown refs fail session create, fail-closed."
- **Fetch failure / artifact absent from the store** → **create refusal** (the bytes the role
  pinned cannot be laid into the overlay). Fail-closed: a session never boots silently missing a
  skill its role declared.
- **Digest mismatch** (fetched bytes do not re-hash to the pinned `<digest>`) → **create
  refusal** — an artifact-integrity failure (§2 immutability layer 2). The session is never
  given a substituted or mutated bundle.
- **Injection failure** (overlay write fails) → **create refusal**, the doc 15 §4.1 step 7
  CA-injection failure posture; rollback drives the destroy path (dispose overlay, unwind).

This is fail-**closed** in the availability sense (refuse the create), distinguished from the
trust sense (§1): there is **no degraded-mode boot** that proceeds with a skill missing — a
role's `skills:` block is a contract about what the session is equipped with, and a session that
cannot meet it does not exist. The contrast with doc 18 §9's **inert-widening** posture is
deliberate and worth stating: an *unratified policy widening* in a role rides inert and the
create proceeds (admitting nothing — the doc 13 §1 rule-7 pattern), because a widening that
admits nothing is safe to defer; a *missing skill artifact* is **not** safe to defer, because
the session would silently lack a declared capability — so it refuses. (Mirrors doc 18: an
unratified widening is not a refusal, but an unresolvable artifact ref is.) These two failure
modes belong to different axes and resolve oppositely by design.

## 5. The condensed reference-shape strawman

Full field discipline is §§1–4; this is the citable strawman, in the `SCHEMA.md` /
doc 13 §3 commented-YAML style. It is the **resolution target** the role YAMLs' `skills:`
blocks point at — it adds **no fields** to the role schema itself.

```yaml
# skill-artifact reference — the resolution target of a role's skills.install[] entry.
# STRAWMAN (doc 18 OQ2); proposed/pending-ratification. No proto, no FREEZE row, no D-number.

# In a role YAML (unchanged from roles/SCHEMA.md — reference only, never content):
skills:
  install:
    - "skills:code-review@1"          # <name>@<version>: catalog ref, never inline content
                                      #   <name>    — [a-z0-9-]; no attack/redteam vocab (doc 06 §3c)
                                      #   <version> — CONTENT IDENTIFIER (doc 13 §1 rule 3 analog),
                                      #               human-citable label; NOT the immutability guarantee

# Resolved at create (orchestrator), pinned into the session record (doc 15 §5.6, D66):
resolved_skill:                       # one per skills.install[] entry — NOT authored in the role
  name: code-review                   # the catalog key
  version: "1"                        # the cited content identifier
  digest: "sha256:<...>"              # CONTENT ADDRESS over the canonical bundle serialization
                                      #   (doc 15 OQ3 / doc 13 OQ2 — one canonicalization spec).
                                      #   (name,version)→digest never re-points once published (§2).
  store: content-addressed            # v0: checked-in / file-backed store the orchestrator reads;
                                      #   reachable from orchestrator-lite (D80). No registry SERVICE
                                      #   at v0 (doc 18 OQ2). M2: pre-baked golden path (D12).

# Install = overlay injection pre-boot (doc 15 §4.1 step 7; doc 18 §2 axis b):
#   resolve → fetch by digest → verify (re-hash == digest) → inject into per-session qcow2
#   overlay (D29) BEFORE boot, fail-closed. Same slot as the D17/D82 CA injection;
#   availability-critical, not trust-critical (doc 18 §6 step 7).
# Failure (unresolvable ref | fetch fail | digest mismatch | injection fail) => CREATE REFUSAL,
#   fail-closed (§4). No degraded boot. Contrast: an unratified policy widening rides INERT
#   (doc 18 §9) — a missing skill artifact does NOT.
```

## 6. Per-workstream constraints — collected from the design docs (the ratification ask)

This contract is **ready for the three stakeholder workstreams to ratify**. The constraints
below are **collected from their documented positions**, not invented obligations — each cites
the doc/decision that already states it. Ratification means each workstream confirms the
constraint it owns is met, not that this doc imposes a new one.

| Workstream | Tree | Documented constraint this contract must honor | Source |
|---|---|---|---|
| **Agent roles** | [`roles/`](README.md) | (1) References only — `skills.install[]` is artifact refs, never inline content, and **unknown refs fail session create, fail-closed**. (2) `<version>` is a **content identifier, never a second version namespace**. (3) The resolved skill identity is **pinned in the never-recycled session record** beside the role's `(name, version, content_hash)`. (4) Names carry **no attack/redteam vocabulary**. (5) Skills add **no new field** to the role schema — the role YAML stays as `SCHEMA.md` defines it. | [`SCHEMA.md`](SCHEMA.md) rules 1 & 5; doc 18 §2 / §7; doc 06 §3c |
| **VM & runtime** | [`vm/`](../vm/README.md) | (1) Install is **overlay injection pre-boot at v0** into the **per-session qcow2 overlay (D29)** — the guest **entrypoint** (`vm/entrypoint/`, the `dreamserpent.runtime.v1` launch/supervise/**inject** contract, D38) is the injection consumer. (2) Injection is **fail-closed** in the doc 15 §4.1 step 7 slot; injection failure fails the create. (3) The bundle's **internal manifest format is VM & runtime's to define**, not this doc's — this contract only fixes that the digest is taken over its canonical serialization. (4) **Pre-baked golden path is the M2 optimization (D12)**; v0 is per-session injection. | doc 18 §2 axis (b); doc 15 §4.1 step 7 (D29/D17/D12); [`vm/README.md`](../vm/README.md) (D20/D29/D38) |
| **Attach & client** | [`client/`](../client/README.md) | (1) **Runtime adapter awareness** (doc 18 §2 axis b) — the per-runtime adapter (the only runtime-specific code, D38/D20, sanctioned home `wrapper/adapters/`) is what makes an injected skill available to the agent loop; the orchestrator stays runtime-ignorant. (2) **Activation is the adapter's**, behind the D38 contract — this doc stops at "bytes present on the overlay by digest, pre-boot." (3) The runtime/CC version the adapter targets is **pinned in the golden image (D49)**; a skill bundle and the pinned runtime must agree, so skill-vs-runtime compatibility is a property the adapter asserts, not the orchestrator. | doc 18 §2 axis (b); [`client/README.md`](../client/README.md) (D18/D20/D38/D49); D49 |

**What ratification does NOT touch (out of scope here):** the skill bundle's internal manifest
schema and packaging format (VM & runtime / Attach & client), how a runtime adapter activates a
skill in the agent loop (Attach & client), and any `proto`-fronted skill-catalog service (a
later reserved seam, not built at v0 — doc 18 OQ2). This doc owns the **reference shape,
content addressing, install/injection mechanics, and failure semantics** — the seam — and
nothing inside the bundle.

---

*Ratification-vehicle note (updated 2026-06-12): the round-4 packet
ratified and fully disposed 2026-06-12 (doc 04 §6 D89–D121) **without** collating this
proposal — the packet's §1 edit list leaves doc 18 OQ2 open regardless of ratification, so
this contract remains proposed and the pending ratification above is the **three-workstream
ratification (§6)**, recorded through a future doc 04 §6 decision row, never this doc. This
doc mints no D-number and adds no P-row to doc 18; on ratification the integration pass
assigns identity through doc 04 §6, never here.*
