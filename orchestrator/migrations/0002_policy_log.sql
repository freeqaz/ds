-- 0002_policy_log.sql — the append-only policy_log (D36). The bigserial seq is
-- THE single policy version namespace end to end (doc 15 §5.3); the log IS the
-- audit trail. Ask-grants are TTL'd rows under the same seq (doc 15 §4.3).
--
-- Append-only is enforced by trigger: no UPDATE, no DELETE may touch this table.
-- A migration may never rewrite or delete a policy_log row (migrations README).

CREATE TABLE policy_log (
    seq          bigserial PRIMARY KEY,           -- the single policy version namespace
    kind         text NOT NULL DEFAULT 'append'
        CHECK (kind IN ('append','ask_grant')),
    actor        text NOT NULL CHECK (actor <> ''),  -- recorded on EVERY row (D36)
    content_hash text NOT NULL DEFAULT '',          -- snapshot identity component
    payload      bytea,                              -- composed policy doc, or grant body

    -- Ask-grant fields (kind='ask_grant'): session-scoped, TTL'd; the grant dies
    -- with the session. NULL for ordinary appends.
    session_uuid text,
    expires_at   timestamptz,

    created_at   timestamptz NOT NULL
);

CREATE INDEX policy_log_session_idx ON policy_log (session_uuid) WHERE session_uuid IS NOT NULL;
CREATE INDEX policy_log_kind_idx    ON policy_log (kind);

-- Append-only enforcement: reject any UPDATE or DELETE. The seq stays
-- monotonically increasing because bigserial never reuses a value.
CREATE OR REPLACE FUNCTION policy_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_log is append-only (D36): % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER policy_log_no_update
    BEFORE UPDATE OR DELETE ON policy_log
    FOR EACH ROW EXECUTE FUNCTION policy_log_append_only();
