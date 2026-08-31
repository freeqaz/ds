# ds-admission-shm

**Charter.** The survivable shared-memory DNS-2b admission map — the **D131
Candidate A** storage body behind the frozen `ds-contracts`
`AdmissionMap`/`ReverseIndex` traits. A host-agent-owned shared-memory segment
with a **per-entry seqlock** so `ds-tlsproxy`'s synchronous TLS-1/TLS-4 reads are
lock-free (the 2026-06-15 contention benchmark forcing function) and so the map's
backing **outlives the `ds-dnsgate` writer process** (warm-restart collapses from
*reconstruct* to *re-attach + bounded reconcile* — doc 11 §8.4 / §8.4.1).

**Owner.** Boundary (`/dataplane/ @dream-serpent/boundary`; CODEOWNERS +
`guardrail-map.yaml` `dataplane/**` already cover this path — no edits owed here).

**Mark / license.** OSS, Apache-2.0 (workspace), listed under `dataplane/` in
`oss-manifest.yaml`.

**D-numbers.**
- **D131** — storage-mechanism choice: shared-memory segment + per-entry seqlock,
  chosen over the UDS sidecar; warm-restart = tolerate-then-preserve.
- **D67 / D68** — the FROZEN `ds-contracts` admission API this crate is a *body*
  for (single shared deadline, insert-then-answer fail-closed, expiry-gates-new,
  reverse-index from day one). The API version, entry shape, and reverse-index
  shape are unchanged — this is a storage body, **not** a contract change.
- **D40 / D67** — no framework type crosses the contract; addresses are the
  family-agnostic `AdmittedAddr`, never a stdlib/framework address type.

**The segment layout is a cross-process contract.** Both the `ds-dnsgate` writer
and the `ds-tlsproxy` reader map the *same bytes*, so the byte layout (header +
entry table + reverse-index table, all fixed-size POD) is versioned by a
`layout_version` **distinct from `ADMISSION_API_VERSION`**. A `layout_version` or
`api_version` mismatch on attach is not a re-attach: it surfaces
`AdmissionError::VersionMismatch` and the caller falls back to the (floor)
start-empty tier (doc 11 §8.4). Any non-additive change to the on-segment layout
bumps `LAYOUT_VERSION`.

## Shape

- `ShmAdmissionMap` — the **single writer** (`admit`/`revoke` take `&mut self`,
  which is what enforces single-writer at the type level). Owns the in-segment
  reverse index. Implements the frozen `AdmissionMap`.
- `ShmAdmissionReader` — the **read-only** `ds-tlsproxy` shape: maps the segment
  `PROT_READ` and only does seqlock `lookup` (`&self`). A separate type (not an
  `AdmissionMap` impl) so a reader cannot even *name* `admit`/`revoke` — the
  read-only mapping is enforced by the kernel and the absence of the methods.
- `Segment` — the mmap backing (named POSIX shm for production survivability; an
  anonymous `MAP_SHARED` backing for tests/bench that exercises the real
  cross-process code paths over threads).
- `KernelDeadlineSource` — the reconcile seam (production body = ds-nft kernel
  set-dump, out of scope here); `reconcile` prunes any entry whose kernel
  deadline is absent or in the past (kernel deadline authoritative, W2).

See `docs/11-ds-dnsgate-design.md` §8.4 / §8.4.1 for the authoritative design.
