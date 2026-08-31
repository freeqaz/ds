-- 0003_env_configs.sql — the RecordEnvConfig reference shape (doc 15 §9).
-- Only the reference shape is owned here; the env-spec document format itself is
-- UNOWNED (doc 15 OQ10). The coupled invariants are recorded so the CC-pin ↔
-- pack-exclusion coupling cannot silently split (D74/D49).

CREATE TABLE env_configs (
    ref            text PRIMARY KEY,                 -- stable handle (EnvConfigRef)
    repo_ref       text NOT NULL DEFAULT '',         -- repo ref + hash, or empty when inline
    spec_hash      text NOT NULL DEFAULT '',         -- env-spec hash
    inline_spec    bytea,                            -- inline spec body when not repo-referenced
    image_id       text NOT NULL DEFAULT '',         -- resolved content-addressed image ID

    -- Coupled invariants (D74/D49), recorded together so they cannot split.
    coupled_pin    text NOT NULL DEFAULT '',         -- CC pin (≥ 2.1.116)
    pack_version   text NOT NULL DEFAULT '',         -- session-pack version
    pack_exclusion text NOT NULL DEFAULT '',         -- downloads.claude.ai excluded-from-pack invariant

    created_at     timestamptz NOT NULL
);
