-- ONE-TIME server provisioning for the taskdb shared lock server.
--
-- Creates a dedicated, isolated Postgres database `taskdb`, owned by a
-- non-superuser `devteam` login, to hold the lock registry (see lockserver.sql).
-- Keep it separate from any application database on the same server: no app
-- data ever mixes with lock rows, and dropping/rebuilding it can never touch
-- the app.
--
-- Why a superuser step: the `devteam` login should not have CREATEDB, so
-- creating the database must be done once by the postgres superuser. After
-- this runs, `devteam` owns the database and `taskdb lockserver migrate`
-- (run as devteam through the SSH tunnel) creates the tables — no further
-- superuser action is ever needed.
--
-- Run once, as an admin on the lock-server host. Feed the file on STDIN rather
-- than via psql -f: psql runs AS the postgres user, which may not be able to
-- read a file under your home directory — your own shell opens it and postgres
-- just reads the pipe:
--
--     sudo -u postgres psql -v ON_ERROR_STOP=1 < scripts/taskdb/lockserver-provision.sql
--
-- Idempotent: re-running is a no-op once the database exists.

-- CREATE DATABASE cannot run inside a transaction or take IF NOT EXISTS, so
-- generate the statement only when the database is absent and \gexec it.
SELECT format('CREATE DATABASE taskdb OWNER %I', 'devteam')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'taskdb')
\gexec

-- Belt-and-suspenders: ensure devteam can connect and (as owner / via the
-- public schema) create the lock tables. On PG15+ the database owner is a
-- member of pg_database_owner, which owns the public schema, so CREATE there
-- already works; these grants make it explicit and survive an owner change.
GRANT ALL PRIVILEGES ON DATABASE taskdb TO devteam;

\connect taskdb
GRANT ALL ON SCHEMA public TO devteam;

-- Create the lock table here too so the single sudo step leaves a fully usable
-- server (no separate migrate needed). This DDL mirrors lockserver.sql, which
-- `taskdb lockserver migrate` re-applies idempotently (CREATE TABLE IF NOT
-- EXISTS) — migrate stays the canonical schema source for later repairs. The
-- ALTER ... OWNER hands the objects to devteam so it has full DML over them.
CREATE TABLE IF NOT EXISTS task_locks (
    task_id    TEXT PRIMARY KEY,
    locked_by  TEXT NOT NULL,
    host       TEXT NOT NULL DEFAULT '',
    locked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    note       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_task_locks_locked_at ON task_locks (locked_at);
ALTER TABLE task_locks OWNER TO devteam;

\echo 'provisioned: database taskdb (owner devteam) with task_locks ready.'
\echo 'verify from a dev box:  taskdb lockserver tunnel  (then, in another shell)  taskdb lockserver status'
