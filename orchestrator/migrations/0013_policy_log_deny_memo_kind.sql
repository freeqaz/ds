-- 0013_policy_log_deny_memo_kind.sql — widen the policy_log kind CHECK to ADMIT
-- the D118 deny memo (doc 16 §8.2; internal/store/denymemo.go PolicyKindDenyMemo
-- = 'deny_memo'). The D118 deny memo already lands in-memory via AppendPolicy and
-- surfaces through LiveDenyMemos, but a live-Postgres INSERT of a 'deny_memo' row
-- is REJECTED by 0002_policy_log.sql's `CHECK (kind IN ('append','ask_grant'))`,
-- so the memo is non-functional on the Postgres-backed control plane. This
-- migration adds 'deny_memo' to that enumerated set so the live INSERT is
-- accepted, with no other change.
--
-- ADDITIVE-ONLY (D36, policy_log is APPEND-ONLY). This WIDENS the kind vocabulary
-- — it adds 'deny_memo' to the allowed set and removes nothing. It touches NO
-- existing row: dropping and re-adding a table-level CHECK constraint is a schema
-- (catalog) operation, not a row UPDATE/DELETE, so the append-only trigger
-- (policy_log_no_update) is not engaged and every pre-existing 'append' /
-- 'ask_grant' row stays byte-for-byte valid (the widened set is a strict
-- superset, so no existing row could fail the new CHECK). No payload, actor, seq,
-- or any other column is rewritten. This transcribes the EXISTING deny_memo
-- contract (denymemo.go) into the persisted CHECK; it mints no new D-number.
--
-- WHY A NEW MIGRATION, NOT AN EDIT TO 0002. Migrations are never renumbered or
-- reordered after landing (README "Ordering"): 0002 already applied to live
-- databases, so the vocabulary change rides a NEW next-free file that ALTERs the
-- constraint forward. A fresh database applies 0001..0013 in lexical order and
-- ends with the widened CHECK; an already-migrated database gets the widening
-- when the runner applies this one new file.
--
-- Apply-contract posture (orchestrator/migrations/README.md): raw DDL with NO
-- `IF NOT EXISTS` and no embedded apply mechanism — re-applying an already-applied
-- file errors on the missing/duplicate object by design; re-runnability is the
-- runner's job via its `schema_migrations` ledger, not the schema's. The
-- supported path is the whole set applied in lexical order to a fresh database.
-- `0013` is the next free zero-padded prefix after `0012_park_join.sql`, so
-- lexical order equals numeric order and the set stays dense from `0001`.
--
-- Postgres has no "ADD VALUE to an inline CHECK"; the portable, on-prem-safe form
-- (no managed-service-only DDL, README D19 posture) is DROP the named constraint
-- and ADD the widened one. The constraint name `policy_log_kind_check` is the
-- name Postgres assigns to the inline column CHECK in 0002 (table_column_check),
-- so the DROP targets exactly that constraint.

ALTER TABLE policy_log DROP CONSTRAINT policy_log_kind_check;

ALTER TABLE policy_log ADD CONSTRAINT policy_log_kind_check
    CHECK (kind IN ('append','ask_grant','deny_memo'));
