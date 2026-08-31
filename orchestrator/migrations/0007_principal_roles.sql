-- 0007_principal_roles.sql — the INCREMENTAL schema the doc 16 §3.3 agent-inventory
-- READ PATH and the `launching_user` resolver seam need, on top of the principal
-- record + role vocabulary + linkage column that 0006_principals.sql already
-- landed. D45/D56/D57/D62. Control-plane state in external Postgres only (D6).
--
-- This file is DELIBERATELY ADDITIVE and DELIBERATELY MINIMAL. The principal
-- table, its five-role CHECK, the UNIQUE(idp_subject, org) business key, and the
-- nullable sessions.launching_principal linkage column are ALREADY in 0006 — this
-- migration does NOT re-declare any of them. It carries only the read-path
-- affordances the inventory query + resolver need: a supporting index for the
-- org-scoped inventory sweep and a named inventory VIEW that pins the §3.3 join
-- shape (sessions ⋈ principals ⋈ env_configs) in one place.
--
-- Apply-contract posture (orchestrator/migrations/README.md): raw DDL, NO
-- `IF NOT EXISTS`, NO embedded apply mechanism — re-applying an already-applied
-- file errors on the existing object by design; re-runnability is the runner's
-- job via its `schema_migrations` ledger. `0007` is the next free zero-padded
-- prefix after `0006_principals.sql`, so lexical order equals numeric order and
-- the set stays dense from `0001`.

-- Inventory read-path index. The §3.3 inventory is surfaced through the paid
-- dashboard layer "scoped to an org" — the dashboard reads per-org, joining a
-- principal's sessions. The 0006 principals_org_idx already supports the
-- principal-side org filter; this composite index supports the join's hot path:
-- "the sessions a given launching principal owns, newest first" (the per-row
-- drill-down the dashboard issues after the org sweep). It mirrors the 0006
-- sessions_launching_principal_idx but carries created_at so the ORDER BY in the
-- inventory query is index-served rather than a post-join sort.
CREATE INDEX sessions_launching_principal_created_idx
    ON sessions (launching_principal, created_at DESC);

-- Agent-inventory VIEW (doc 16 §3.3, the D62 obligation: "who launched what,
-- attributed to the launching user, joined to the D7 env config"). The read path
-- is "a query over control-plane Postgres sessions+identities tables, surfaced
-- through the paid dashboard layer" — this VIEW is that query, named once so the
-- store's inventory method and any future dashboard reader share ONE join shape
-- instead of re-deriving it. A dedicated inventory API is a v0 non-goal (§3.3),
-- so this is a read-path VIEW, not a new write surface.
--
-- The join is a LEFT JOIN on launching_principal: a session with no launching
-- principal (the nullable pre-mint / system-session case — 0006 linkage notes)
-- still appears in the inventory, with NULL principal columns, rather than being
-- dropped. env_config_ref is a soft reference (no FK, 0001 sessions), so the
-- env-config join is also LEFT — a session whose env config was pruned still
-- lists. The VIEW exposes ONLY attribution-relevant columns (no credential / CA /
-- digest refs): the inventory answers "who launched what under which env", not
-- the credential mechanics, which are the §4/§5 swap-path concern.
--
-- RESERVED-shape note (M4 multiplayer, D57/D61): this VIEW surfaces the SINGLE
-- launching principal (1:1, the doc 04 §5 single-root-claim attribution promise).
-- The full seat/viewer roster a multiplayer session carries (D61 one-writer /
-- N-reader, D57 seats) is NOT joined here — that taxonomy lives with
-- billing/multiplayer and would extend this VIEW additively at M4, never retrofit
-- the 1:1 launching-principal shape this inventory pins.
CREATE VIEW agent_inventory AS
SELECT
    s.session_uuid          AS session_uuid,
    s.host_id               AS host_id,
    s.host_session_index    AS host_session_index,
    s.state                 AS state,
    s.parent_session_uuid   AS parent_session_uuid,
    s.created_at            AS session_created_at,
    s.launching_principal   AS launching_principal_id,
    p.idp_subject           AS launching_user,       -- the §3.1 `launching_user` claim value
    p.org                   AS org,
    p.display_name          AS launching_display_name,
    s.env_config_ref        AS env_config_ref,
    e.image_id              AS image_id              -- the D7 resolved env-config image
FROM sessions s
LEFT JOIN principals  p ON s.launching_principal = p.id
LEFT JOIN env_configs e ON s.env_config_ref = e.ref;
