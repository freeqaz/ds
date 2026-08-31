-- 0012_park_join.sql — the DURABLE session<->question join for the D46 rung-2
-- ask park (doc 16 §8.2; internal/parkstore). This is the table the parkstore
-- database/sql twin of parkstore.Store writes through, so a genuine rung-2 ask
-- that PARKS survives a control-plane restart and resumes on a human answer —
-- never timing out into allow or kill (D46/D77). ADDITIVE: a NEW table only.
--
-- WHY THIS MIGRATION. internal/parkstore ships the in-memory `Memory` reference
-- impl behind the narrow `Store` seam (RecordParked / ClearParked / Lookup /
-- List); the database/sql twin (`SQL`, parkstore/sql.go) makes the same reads
-- hit a table that genuinely outlives the process. The §3 crash matrix's
-- restart re-adoption (doc 15 §3 / D35) needs the join to PERSIST: on restart
-- the control plane re-reads the outstanding parks from this table (List) and
-- resumes each on answer (Lookup) exactly as before. The map-backed reference
-- impl stands in for this row in tests; this is the row.
--
-- Apply-contract posture (orchestrator/migrations/README.md): raw DDL with NO
-- `IF NOT EXISTS` and NO embedded apply mechanism — re-applying an already-
-- applied file errors on the existing object by design; re-runnability is the
-- runner's job via its `schema_migrations` ledger, not the schema's. The
-- supported path is the whole set applied in lexical order to a fresh database.
-- `0012` is the next free zero-padded prefix after
-- `0011_session_epoch_overlay_path.sql`, so lexical order equals numeric order
-- and the set stays dense from `0001`.
--
-- ADDITIVE-ONLY. This adds ONE table (park_join) and touches no existing table,
-- column, CHECK, or index, so every pre-existing row and the conformance suite
-- stay byte-for-byte valid.

CREATE TABLE park_join (
    -- The parked session's UUID — the JOIN KEY to the pending question, and the
    -- restart-survival lookup key. ONE outstanding park per session (a ClearParked
    -- deletes the row on resume), so the session UUID is the natural primary key:
    -- a RecordParked UPSERTs onto it (re-recording a still-parked session
    -- overwrites in place rather than duplicating). Mirrors parkstore.Memory's
    -- map keyed by SessionUUID.
    session_uuid       text PRIMARY KEY,

    -- The pending question (askhold.Ask). Stored as the resource triple + the
    -- POL-3 matched-rule id + the rung-2 flag, the exact fields Ask carries —
    -- flat columns (not jsonb) because the shape is fixed and small, and a flat
    -- row is the cheapest restart-survival read. `rung2` is ALWAYS true for a
    -- recorded park (only a genuine rung-2 ask parks, askhold/park.go), but the
    -- column is carried so the re-read Ask round-trips faithfully.
    resource_kind      text    NOT NULL DEFAULT '',  -- askhold.Ask.ResourceKind
    resource_name      text    NOT NULL DEFAULT '',  -- askhold.Ask.ResourceName
    matched_rule_id    text    NOT NULL DEFAULT '',  -- askhold.Ask.MatchedRuleID (POL-3 "why asked")
    rung2              boolean NOT NULL DEFAULT true, -- askhold.Ask.Rung2 (the class that PARKS, D46/D77)

    -- When the ask parked: the D46 pause-clock origin. A re-read park is still
    -- PARKED no matter how long ago this is — the park NEVER times out (D46/D77),
    -- so this is carried for transparency, not for an expiry the store enforces.
    parked_at          timestamptz NOT NULL
);

-- The bulk restart-survival re-adoption read (List, the doc 15 §3 RecoverSessions
-- shape) enumerates outstanding parks in deterministic session-UUID order; the
-- PRIMARY KEY index already serves that ORDER BY, so no extra index is needed.
