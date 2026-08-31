-- 0008_session_context.sql — the M2 queryable session-context / prompt store
-- (doc 02 §8; doc 05 §5 M2 "Queryable session context/prompts"; doc 15 §5.6).
--
-- Seeding and saving session context/prompts is wanted and must be QUERYABLE
-- and ATTRIBUTED to the session that produced them (doc 02 §8 — "associated with
-- outputs"). Plans already have their reserved table (0004_plans.sql); this
-- migration adds the prompt and free-form context rows beside them, all three
-- keyed back to sessions(session_uuid) so every recorded artifact is
-- session-attributed.
--
-- NOTE on the migration sequence: 0007_* is reserved for principal-roles
-- (a sibling unit in this wave); this branch carries 0008 without 0007, so the
-- dense-sequence apply smoke test (migrations/apply_smoke_test.go) is satisfied
-- only once the two units land together. The gap is a cross-unit coordination
-- point, not a defect in this file.

-- prompts — the recorded prompt text a session ran with (doc 02 §8). Each row is
-- attributed to its owning session; the (session_uuid, role, seq) ordering lets
-- a reader replay a session's prompt history in order. Prompts are append-style
-- records (a prompt the session actually used), never edited in place; an id is
-- the stable handle a future planstore.v1 read path returns.
CREATE TABLE prompts (
    id           text PRIMARY KEY,
    session_uuid text NOT NULL REFERENCES sessions(session_uuid),  -- attribution (doc 02 §8)
    role         text NOT NULL DEFAULT 'user',                     -- user | system | assistant
    seq          bigint NOT NULL DEFAULT 0,                        -- per-session ordering
    label        text NOT NULL DEFAULT '',                         -- optional reuse label ("I reuse that stuff")
    body         bytea,                                            -- the prompt text, opaque here
    created_at   timestamptz NOT NULL
);

CREATE INDEX prompts_session_idx ON prompts (session_uuid, seq);

-- session_context — free-form, queryable seedable/savable session context keyed
-- by a kind tag (doc 02 §8: "Seeding and saving session context… should be
-- queryable, associated with outputs"). One row per (session_uuid, kind) so a
-- save replaces the prior context of that kind for the session; the kind tag is
-- what makes the store queryable by facet (e.g. "init-script", "task", "notes").
CREATE TABLE session_context (
    session_uuid text NOT NULL REFERENCES sessions(session_uuid),  -- attribution (doc 02 §8)
    kind         text NOT NULL,                                    -- context facet, queryable
    body         bytea,                                            -- the context blob, opaque here
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (session_uuid, kind)
);

CREATE INDEX session_context_kind_idx ON session_context (kind);
