-- 0006_principals.sql — the minimal human-principal record (doc 16 §3.2) and
-- the nullable session→launching_principal linkage (the doc 04 §5 attribution
-- promise). Control-plane state in external Postgres only (D6). D45/D56/D57.
--
-- Apply-contract posture (orchestrator/migrations/README.md): this file is raw
-- DDL with NO `IF NOT EXISTS` and NO embedded apply mechanism — re-applying an
-- already-applied file errors on the existing object by design; re-runnability
-- is the runner's job via its `schema_migrations` ledger, not the schema's. The
-- supported path is the whole set applied in lexical order to a fresh database.
-- `0006` is the next free zero-padded prefix after `0005_metering_events.sql`,
-- so lexical order equals numeric order and the set stays dense from `0001`.

CREATE TABLE principals (
    -- Stable handle the session linkage references; not the IdP subject, so a
    -- subject rename at the IdP never breaks attribution joins.
    id            text PRIMARY KEY,

    -- The OIDC subject claim (doc 16 §11.2) + the org it is asserted within.
    -- (idp_subject, org) is the unique business key: one human, asserted by an
    -- org's IdP, is one principal IN THAT ORG — the same subject in two orgs is
    -- two principals (orgs do not share an identity namespace).
    idp_subject   text NOT NULL,
    org           text NOT NULL,

    -- The §3.2 role SET (D45/D56/D57). Stored as jsonb (not text[]) so the
    -- database/sql impl encodes/decodes it with encoding/json — the SAME
    -- driver-agnostic path sessions.grants uses — keeping orchestrator/go.mod
    -- stdlib-only (no Postgres array driver). An empty set ('[]') is legal: a
    -- principal with no roles yet is a valid record (roles granted post-create).
    roles         jsonb NOT NULL DEFAULT '[]'::jsonb
        -- Role-vocabulary CHECK — the SQL mirror of store.PrincipalRole.Valid()
        -- in internal/store/principals.go. Every element of the jsonb array must
        -- be one of the EXACTLY FIVE §3.2 roles. The full seat/viewer billing
        -- taxonomy is deliberately NOT here (D57/D61) — adding a role reopens the
        -- §3.2 role contract (D45/D56/D57) and must change Valid() in lockstep,
        -- exactly as the conformance suite's role-CHECK-parity case pins.
        --
        -- Expressed as jsonb containment (<@): every element of `roles` must
        -- appear in the allowed-set array. Postgres forbids subqueries in CHECK
        -- constraints (the first live pg-conformance run, 2026-06-13, rejected
        -- the original NOT EXISTS form with SQLSTATE 0A000), and <@ is the
        -- subquery-free equivalent: empty arrays and duplicates pass, any
        -- out-of-vocabulary element fails — identical semantics to Valid().
        -- The jsonb_typeof guard stays: a bare scalar would otherwise satisfy
        -- scalar-in-array containment.
        CHECK (
            jsonb_typeof(roles) = 'array'
            AND roles <@ '["launcher","viewer","approver","org-admin","repo-admin"]'::jsonb
        ),

    display_name  text NOT NULL DEFAULT '',

    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,

    -- A single human is one principal per org: the §3.2 uniqueness invariant.
    -- The repository surfaces a collision here as ErrConflict (SQLSTATE 23505).
    UNIQUE (idp_subject, org)
);

CREATE INDEX principals_org_idx ON principals (org);

-- Session → launching_principal linkage (the doc 04 §5 attribution promise:
-- "per-workload identity, minted at session start, attributed to the launching
-- user"). The persisted referent of the workload identity's `launching_user`
-- claim (doc 16 §3.1/§3.2).
--
-- LINKAGE-SHAPE DECISION (nullable column vs. join table) — nullable column.
--   The attribution relation is 1:1: a session has at most ONE launching
--   principal (D44/D99 — `launching_user` is the single ROOT attribution claim,
--   never a set), and a principal launches many sessions. A 1:1 reference is a
--   nullable foreign-key COLUMN on the many side (sessions), not a join table —
--   a join table would model a many-to-many the attribution contract explicitly
--   forbids (one root claim) and would let a session accumulate two launchers,
--   which is exactly the ambiguity attribution exists to prevent.
--   NULLABLE because the link is genuinely optional: a session created before
--   its identity is minted (the §4.1 create choreography mints at step 5, after
--   the record exists), or a system/internal session, legitimately has no
--   launching principal. The column therefore defaults to NULL and the store's
--   GetSessionLaunchingPrincipal returns "" for the unset case — never a
--   fabricated principal. This is the LINKAGE SHAPE ONLY: MintWorkloadIdentity
--   resolving the claim FROM this column is a separate, out-of-scope task.
--   ON DELETE is omitted (no cascade): principal rows are retained like session
--   rows, and a soft REFERENCES keeps the FK without coupling lifecycles.
ALTER TABLE sessions
    ADD COLUMN launching_principal text REFERENCES principals(id);

CREATE INDEX sessions_launching_principal_idx ON sessions (launching_principal);
