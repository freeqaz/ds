-- 0004_plans.sql — plan-store rows. planstore.v1 is the M2 plan store →
-- D61 read-only plan boards (doc 15 §5.6); the table is reserved so the schema
-- is complete from M0.

CREATE TABLE plans (
    id           text PRIMARY KEY,
    session_uuid text REFERENCES sessions(session_uuid),  -- owning session when scoped
    title        text NOT NULL DEFAULT '',
    body         bytea,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL
);

CREATE INDEX plans_session_idx ON plans (session_uuid) WHERE session_uuid IS NOT NULL;
