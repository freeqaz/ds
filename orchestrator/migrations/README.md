# orchestrator/migrations — control-plane Postgres schema

Schema migrations for the control plane's **external Postgres** (D6 — state never
lives on hosts). Empty at skeleton time by design: migration contents are
**owner-landed** with the implementation, not scaffolded, because the schema's
load-bearing shapes are frozen by contracts that have not published yet
(`proto/FREEZE.md` rows are all OPEN).

## Scope (what the schema will hold — doc 15 §2, §5.6)

| Table family | Frozen shape it must encode |
|---|---|
| `sessions` | The session record: the never-recycled SessionRef quartet (D66/D44), env-config ref + resolved image ID (D7/D74), identity/CA/digest refs (D22/D17/D73), the **lifecycle state column** whose value vocabulary is the doc 15 §3 frozen M0 state machine — the twelve states `PENDING → CREATING → READY → ATTACHED ⇄ WORKING` plus `SNAPSHOTTING`, `MIGRATING`, first-class `PARKED`, `SUSPENDED(reason)`, `RESUMING`, and `DESTROYING → DESTROYED`; the schema never declares a competing vocabulary; the `CHECK` transcribes §3 verbatim, and a vocabulary change reopens the §3 contract set, not a migration. Plus policy posture + live grants, attach/writer-seat/attendedness state (D18/D78), parent link, the **pinned-role triple** `(role_name, role_version, role_content_hash)` + the §9 widening-gate posture (doc 18 §7, D89–D96; `0009`, additive — `role_content_hash` is the one canonical-serialization hash, roles/SCHEMA.md rule 5), lifecycle timestamps, **per-host index history** (park/migration joins are per-host-epoch). Retained — never deleted within the flow-log retention window (D66; 90-day strawman, tier-tunable) |
| `policy_log` | Append-only; **bigserial seq is THE single policy version namespace**; actor recorded on every row — the log IS the audit trail (D36). Ask-grants are TTL'd rows under the same seq (doc 15 §4.3). The `kind` `CHECK` transcribes the persisted `store.PolicyKind` vocabulary: `append` / `ask_grant` (`0002`) widened additively to admit `deny_memo` (`0013`, the D118 deny memo, doc 16 §8.2) — a widening only, never a rewrite (D36) |
| env configs | `RecordEnvConfig` reference shape: env-spec (repo ref + hash, or inline), resolved content-addressed image ID, coupled invariants (CC pin ↔ pack exclusion, D74/D49) — doc 15 §9. Only the *reference shape* is owned here; the env-spec document format is UNOWNED (doc 15 OQ10) |
| plans, metering | Plan store rows (M2); D57 metering as an idempotent event stream + short-retention D37 sample rollups, wired from M0 |
| `principals` | The minimal human-principal record (doc 16 §3.2, D45/D56/D57): IdP subject + org (`UNIQUE(idp_subject, org)`) + the five-role set (`launcher / viewer / approver / org-admin / repo-admin`) under a role `CHECK` that mirrors `store.PrincipalRole.Valid()`. Deliberately minimal — the full seat/viewer taxonomy lives with billing/multiplayer (D57/D61); only the **linkage shape** is reserved here: a nullable `sessions.launching_principal` column (1:1, the doc 04 §5 attribution promise — `launching_user` is the single root claim), NULL until the identity is minted. `MintWorkloadIdentity` resolving the claim and ask-event approver attribution are out of scope (separate tasks). The doc 16 §3.3 agent-inventory READ PATH lands additively on top in `0007`, re-declaring nothing from `0006`: the `agent_inventory` VIEW (the D62 "who launched what, attributed to the launching user, joined to the D7 env config" obligation) is `sessions ⋈ principals ⋈ env_configs` with both joins **LEFT** — an unlinked (pre-mint / system) session and a session whose env config was pruned still list — and exposes attribution columns only (no credential / CA / digest refs); plus a composite `sessions (launching_principal, created_at DESC)` index serving the per-principal newest-first drill-down |
| `prompts`, `session_context` | The M2 **queryable session-context / prompt store** (doc 02 §8; doc 05 §5 M2; doc 15 §5.6) — "Seeding and saving session context/prompts… should be queryable, associated with outputs". Both rows are **session-attributed** (FK to `sessions(session_uuid)`): `prompts` are recorded artifacts ordered per-session by `(seq, id)` with an optional reuse `label`; `session_context` is one blob per `(session_uuid, kind)` where the `kind` tag is the queryable facet and a save **replaces** the prior blob of that kind (preserving `created_at`, advancing `updated_at`). Fronted by the `store.ContextStore` seam (in-memory reference impl pinned to a `database/sql` impl by a shared conformance suite, D33), beside — not inside — the §5.6 `Repository`. **Live read shape (read-only):** the canvas plan-card projection + console D61 boards read through `store.PlanStoreReader` over the existing plan rows (no write-back, doc 17 §3.3/OQ8); the wire home is RESERVED `dreamserpent.planstore.v1` (proto/FREEZE.md row 23) |

## Rules

- Migration **tooling choice is free** (doc 15 §10), bounded by the D19 tier swap:
  everything must run identically against managed RDS-class Postgres (hosted /
  bring-compute) and customer-run Postgres (on-prem), via `internal/store`'s
  repository interface (D33).
- No host-side state ever migrates here; host agents persist their monotonic
  index counters locally and recover via `RecoverSessions`.
- policy_log rows are audit: no migration may rewrite or delete them.
- The lifecycle-state vocabulary has a **machine-readable mirror**:
  `orchestrator/internal/sessions` (the §3 transition table + conformance test;
  the §3 diagram stays normative). A migration `CHECK` that enumerates the
  states transcribes §3 verbatim, and every Go consumer of the vocabulary wires
  into the conformance test, so drift from §3 **fails the build** rather than
  waiting on a review grep (a 10-state enum once built green against the
  12-state freeze). The store tree carries its own build-time tie to that
  freeze: `orchestrator/internal/store/vocabpin` imports both the persisted
  `store.SessionState` set and the §3 table and pins them token-for-token
  (per-token compile-time length braces + a load-time count/membership check),
  so a dropped, added, or renamed persisted state — the exact MIGRATING/RESUMING
  omission — refuses to compile.

## Apply contract

The migrations land as raw `0001_sessions.sql … 0005_metering_events.sql` — plain
DDL with no embedded apply mechanism — and `internal/store/postgres_test.go`
assumes "migrations already applied". Migration **tooling is free** (doc 15 §10),
bounded by the D19 tier swap; this section pins the contract every applier
(the bundled `apply.sh`, or an external runner) must honor.

- **Ordering — lexical by filename.** Apply files in ascending filename order.
  The zero-padded `NNNN_` sequence prefix makes lexical order identical to
  numeric order, and the set is dense from `0001` (asserted by the no-database
  smoke test). A new migration takes the next free `NNNN`; files are never
  renumbered or reordered after landing.
- **Idempotency / re-run posture.** The raw `.sql` is **not** individually
  idempotent — each file is plain `CREATE TABLE` / `CREATE INDEX` / `CREATE
  TRIGGER` with no `IF NOT EXISTS`, so re-applying an already-applied file
  errors on the existing object. Re-runnability is the **runner's** job, not the
  schema's: an applier records applied versions in a `schema_migrations` ledger
  (a runner concern, deliberately absent from the owner-landed `.sql`) and skips
  files already present, so re-running the runner over a populated database is a
  safe no-op. The supported path is applying the whole set, in order, to a
  **fresh** database; partial/repair application is an operator action under the
  same ledger.
- **Failure posture — stop on first error.** Apply each file in a single
  transaction with `ON_ERROR_STOP` (psql `-1 -v ON_ERROR_STOP=1`); the first
  error aborts the run with a non-zero exit and applies nothing from the failing
  file (never continue-past-error). The ledger insert rides the file's own
  transaction, so a half-applied file never records as done and the run is
  resumable from exactly the failed version.
- **D19 tier posture (managed vs on-prem).** The same files, the same lexical
  order, the same runner must apply identically across both tiers, behind
  `internal/store`'s repository interface (D6/D33):
  - **Managed (hosted + bring-compute)** — we operate the control plane, so the
    target is **managed RDS-class Postgres**; apply runs from the control-plane
    side (CI/CD or a one-shot job) against the managed endpoint. No host-side
    state ever migrates here.
  - **On-prem** — the customer runs everything, including a **customer-run
    Postgres**; the operator runs the same applier against their own instance.
    No managed-service assumptions (extensions, superuser-only DDL) may leak in;
    the DDL stays portable Postgres.
- **Live application is an env-gated step — never in the build sandbox, but wired
  as a dedicated CI lane.** Applying against a live database never runs in the
  ordinary `go test ./...` pass or the wave build sandbox. `apply.sh` connects
  only when `DS_PG_DSN` is set; with `DRY_RUN=1` (and no `DS_PG_DSN`) it prints
  the lexical plan and exits without touching a database. The matching live
  verification — the `DS_PG_DSN`-gated `TestPostgres*` entrypoints in
  `internal/store` (the §5.6 Repository suite `TestPostgres_Conformance`, plus
  the `0007` inventory/resolver/approver and `0008` session-context cases) — is
  skipped unless `DS_PG_DSN` is set (and a Postgres driver is registered via
  `DS_PG_DRIVER`, imported **outside** this module). The **`pg-conformance`
  GitHub Actions workflow** (`.github/workflows/pg-conformance.yml`) is the one
  place that supplies both: it stands up an ephemeral `postgres:16` service,
  applies the migrations through this `apply.sh` contract, registers a driver
  **CI-side only** (`go mod edit -require` + `go get`, plus a build-tagged
  blank-import shim under `pg_conformance_ci`), and runs the live-Postgres suite
  (`-run '^TestPostgres'`) against the live engine. The lane defaults to `lib/pq` (`DS_PG_DRIVER=postgres`)
  and documents the `pgx` alternative in its `env:` comments. It triggers on
  changes under `internal/store/**`, `migrations/**`, `go.work`, or the workflow
  itself; the normal `go test ./...` pass still exercises only the
  **no-database** smoke checks below.
  - **The stdlib-only invariant protects the COMMITTED tree, not the ephemeral
    checkout.** The CI driver injection deliberately mutates the runner's
    throwaway `go.mod`/`go.sum` for the duration of the run; what must never
    happen is any of it being committed back. The lane's leak guard is therefore
    ordered to be provably non-self-defeating (an earlier attempt asserted
    `git diff --exit-code go.mod` *after* the in-place injection and so failed by
    construction): a dedicated fresh-checkout
    `committed-tree-guard` job — and a pre-injection check in the conformance job
    — assert the committed `go.mod` carries **zero non-stdlib requires** and that
    `go.sum` is **untracked**, *before* any injection; the post-injection check
    asserts only that **nothing is staged/committed back** and that the
    ephemeral require set is exactly the one pinned driver. The committed-tree
    assertions precede or are isolated from the injection; the after-injection
    assertion never demands the working tree be unchanged.

### Reference runner & smoke check

`apply.sh` is the bundled reference applier. It is **non-Go on purpose**, so it
lives **outside** `orchestrator/go.mod`'s stdlib-only import graph (no module in
the orchestrator ever compiles or imports it; `go.mod`/`go.sum` are untouched).
Operators may substitute any external runner that honors the contract above
(e.g. `migrate`, `dbmate`, `flyway`, or `psql` in a loop) — pin its ordering to
lexical-by-filename, its failure mode to stop-on-first-error, and its
re-run/idempotency to a version ledger.

The contract is guarded without a database by `apply_smoke_test.go` (the
package's only Go, test-only), which runs in the ordinary `go test ./...`:

- `TestApplyOrderingIsLexicalAndDense` — the file set is dense from `0001` and
  lexical order equals numeric order. **Numbers are pre-assigned so parallel work
  stays disjoint:** e.g. `0007_principal_roles.sql` and `0008_session_context.sql`
  were authored on separate branches. A branch carrying only one of a co-land pair
  carries a sequence gap and is RED in isolation by construction; it goes green
  once both land together. A gap surviving past co-land is a real defect, not that
  expected interleaving.
- `TestApplyRunnerSyntax` — `sh -n apply.sh` (no DB, no connection).
- `TestApplyRunnerDryRunPlan` — `DRY_RUN=1 apply.sh` (with `DS_PG_DSN` unset)
  emits the migrations in lexical order, proving the runner's enumeration cannot
  drift from the documented ordering.
- `TestMigration0007And0008CoLand` — the `0007↔0008` merge group (below) is
  whole: `0007_principal_roles.sql` and `0008_session_context.sql` are
  **both present or both absent**, never exactly one.

```sh
DRY_RUN=1 ./apply.sh                                  # print the lexical plan, no DB
DS_PG_DSN='postgres://user:pw@host:5432/db' ./apply.sh  # DEFERRED manual step (live)
```

### Merge group: 0007↔0008 co-land

`0007_principal_roles.sql` (the principal-roles record/role model) and
`0008_session_context.sql` (the M2 session-context/prompt store) are a **single
merge group**: **principal-roles must land before-or-with context-store**, never
after, and a tree must never carry `0008` without `0007`. The session-context
store records rows attributed to the principal-roles set `0007` introduces, so
`0008`-without-`0007` is a broken half-landing, not a runnable schema.

This is mechanized, not just documented, so no future single-unit re-run or
cherry-pick can land `0008` without `0007`:

- **A planning dependency edge** — the context-store work *depends on*
  principal-roles, so principal-roles is never scheduled after context-store.
- **A build-time RED gate** — `TestMigration0007And0008CoLand` in
  `apply_smoke_test.go` asserts co-presence by enumerating the migrations
  directory by filename (it imports neither `.sql`), so any tree carrying exactly
  one of the pair fails `go test ./...`. This is the **same failure** the
  dense-ordering smoke test already produces: `TestApplyOrderingIsLexicalAndDense`
  fails RED on a `0008`-without-`0007` tree because the missing `0007` leaves a
  **gap at `0007`** in the dense-from-`0001` sequence (empirically verified). The
  co-land test makes that gap explicit and named at the migration-pair level, and
  additionally catches the mirror half-landing (`0007` present, `0008` absent),
  which dense-ordering permits (a `0007` dense tail) but is still an incomplete
  merge group.
