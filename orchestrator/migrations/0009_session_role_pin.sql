-- 0009_session_role_pin.sql — the pinned-role triple on the never-recycled
-- session record (doc 18 §7, D66/D89–D96; doc 15 §5.6). ADDITIVE columns only.
--
-- WHY THIS MIGRATION. The doc 15 §4.1 steps-1–2 role stage (sessions/roleref.go:
-- ResolveAndPinRole) resolves the requested role_ref against the org catalog and
-- PINS the immutable (role_name, role_version, role_content_hash) triple for the
-- session lifetime (doc 18 §7: "Pinned at create, never retro-applied"). Until
-- this migration that pin rode only in-package (CreateSpineResult.PinnedRole)
-- because internal/store was frozen this wave; the doc 18 §11 pin-and-audit row
-- ("every session record carries role fields") and the D66 never-recycled record
-- need the triple to actually PERSIST. This is the sanctioned store-seam unfreeze
-- for exactly that persistence.
--
-- ADDITIVE-ONLY (the unfreeze discipline). Three nullable-or-defaulted columns on
-- the existing sessions table — no existing column, CHECK, or index is touched, so
-- every pre-existing row and the conformance suite stay byte-for-byte valid. A row
-- written before this migration (or by a caller that resolves no role) carries the
-- recorded-default-or-empty posture: role_name/role_version/role_content_hash
-- default to '' (the "no pin recorded yet" state), and the create choreography
-- writes the explicit `default@<current>` triple when it resolves the recorded
-- default (doc 18 §7: "Default is recorded, not null" — the EMPTY column is the
-- pre-pin state, never the recorded-default state).
--
-- THE TRIPLE (doc 18 §7, roles/SCHEMA.md rule 5):
--   role_name         — the role's catalog name (`default` for the recorded
--                       de-risking default). Empty only before the pin is written.
--   role_version      — the role's content identifier (e.g. `2026.06.11-v1`),
--                       NEVER a second version namespace (roles/SCHEMA.md rule 5).
--   role_content_hash — the role's `role_content_hash`: SHA-256 (hex) over the
--                       produce-once JCS canonical payload of the role document,
--                       the SAME canonical-serialization machinery the
--                       PolicySnapshot content_hash uses (one spec, not two —
--                       roles/SCHEMA.md rule 5, doc 15 OQ3 / doc 13 OQ2). Pins the
--                       EXACT role bytes, so a catalog update to the same
--                       (name, version) is still a DISTINCT pin.
--
-- The inert-widening posture (doc 18 §9) rides as the role_widenings_inert flag:
-- true means the pinned role version carried UNRATIFIED widenings that rode INERT
-- at create (logged warning, admitting nothing — the doc 13 §1 rule-7 pattern,
-- D91). The widening SET itself is the catalog's (the actor-recorded ratification
-- event, doc 18 §9), not duplicated onto every session row; the record carries
-- only the boolean posture for the §11 widening-gate audit row.

ALTER TABLE sessions
    ADD COLUMN role_name            text    NOT NULL DEFAULT '',   -- doc 18 §7 role_name ('' = pin not yet written)
    ADD COLUMN role_version         text    NOT NULL DEFAULT '',   -- doc 18 §7 role_version (content identifier, rule 5)
    ADD COLUMN role_content_hash    text    NOT NULL DEFAULT '',   -- doc 18 §7 role_content_hash (JCS canonical, rule 5)
    ADD COLUMN role_widenings_inert boolean NOT NULL DEFAULT false; -- doc 18 §9 widening-gate posture (inert at create)
