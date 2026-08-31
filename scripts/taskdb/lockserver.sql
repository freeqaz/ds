-- taskdb shared lock registry — applied by `taskdb lockserver migrate`.
--
-- This is the ONLY state that lives in Postgres. The git repo (tasks/*.json)
-- remains the single authority for task content, dependencies, and the DAG;
-- Postgres holds nothing but advisory lock rows so concurrent agents on
-- different machines don't double-claim the same task. Losing this database
-- loses no durable work — every row is reconstructable by simply re-locking.
--
-- Lives in the dedicated `taskdb` database (see lockserver-provision.sql),
-- public schema. The file is embedded into the taskdb binary (//go:embed) so
-- `lockserver migrate` always applies exactly this committed text; it is also
-- committed standalone so the schema is reviewable in git.

CREATE TABLE IF NOT EXISTS task_locks (
    -- The task ULID (full 26-char form). No FK: the tasks themselves live in
    -- SQLite/git, not here. A lock for an unknown id is harmless and self-heals.
    task_id    TEXT PRIMARY KEY,
    -- The claiming session id (same value as the local SQLite locked_by).
    locked_by  TEXT NOT NULL,
    -- Human triage: which dev/machine holds it (hostname or $TASKDB_DEV).
    host       TEXT NOT NULL DEFAULT '',
    -- Server-clock acquisition time. now() here means staleness is judged by
    -- the shared server's clock, not each dev's possibly-skewed laptop.
    locked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Optional free-text reason (e.g. set by a release that re-locks).
    note       TEXT NOT NULL DEFAULT ''
);

-- Reap scans by age; index the column it filters on.
CREATE INDEX IF NOT EXISTS idx_task_locks_locked_at ON task_locks (locked_at);

-- ---------------------------------------------------------------------------
-- Wave telemetry (added 2026-06-13). PURELY ADDITIVE: these tables are new and
-- the task_locks table above is untouched, so an OLD lock-server client (another
-- machine on the prior taskdb binary) keeps working unchanged against this
-- migrated DB — it simply never reads or writes these tables. Like task_locks,
-- this is disposable coordination state: the git repo (tasks/*.json) remains the
-- sole authority for task content and the DAG; losing these tables loses no
-- durable work (the next wave re-emits its own events).
--
-- Two tables, written together by `taskdb wave-event`:
--   wave_events     — an append-only stream of intra-workflow transitions so the
--                     dashboard can show live per-wave / per-unit / per-step
--                     progress, joined to tasks by task_id.
--   lock_heartbeats — one upserted row per (session, task_id) the wave touches,
--                     carrying last_activity. The staleness signal reads THIS
--                     (no heartbeat in N minutes) instead of pure lock-age, so an
--                     actively-progressing wave stops being flagged ⚠ STALE.

CREATE TABLE IF NOT EXISTS wave_events (
    -- Surrogate id so the stream is append-only and orderable even when several
    -- events share a millisecond timestamp.
    id          BIGSERIAL PRIMARY KEY,
    -- The wave label (task-wave waveLabel) — the branch/integration prefix.
    wave        TEXT NOT NULL DEFAULT '',
    -- A per-dispatch run id so two runs of the same wave label don't interleave.
    run_id      TEXT NOT NULL DEFAULT '',
    -- The unit key (slug) this event belongs to; '' for wave-level events
    -- (wave-start / gate / wave-end) that aren't scoped to a single unit.
    unit_key    TEXT NOT NULL DEFAULT '',
    -- The task ULID this event advances; '' for wave-level events. No FK — tasks
    -- live in git/SQLite, not here (same rationale as task_locks).
    task_id     TEXT NOT NULL DEFAULT '',
    -- The pipeline phase: scope|implement|review|gate|plan|wave2|merge|finalize|land
    -- (free text; the dashboard groups on it but does not constrain it).
    phase       TEXT NOT NULL DEFAULT '',
    -- The agent label the engine assigned (e.g. impl:foo, review:foo, merge).
    agent_label TEXT NOT NULL DEFAULT '',
    -- start | end | status-change | heartbeat.
    event       TEXT NOT NULL DEFAULT '',
    -- The task's status at this transition (open|in-progress|done|blocked) when
    -- the event carries one; '' otherwise.
    status      TEXT NOT NULL DEFAULT '',
    -- The claiming session id (matches task_locks.locked_by) so an event can be
    -- attributed to a holder and drive its heartbeat.
    session     TEXT NOT NULL DEFAULT '',
    -- Which dev/machine emitted it (hostname or $TASKDB_DEV).
    host        TEXT NOT NULL DEFAULT '',
    -- Output tokens spent so far this turn (budget.spent proxy), -1 when unknown.
    tokens      BIGINT NOT NULL DEFAULT -1,
    -- Optional free-text detail.
    note        TEXT NOT NULL DEFAULT '',
    -- Server-clock event time (shared clock, not a possibly-skewed laptop).
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The dashboard reads the live tail by wave/run, newest first.
CREATE INDEX IF NOT EXISTS idx_wave_events_wave_run ON wave_events (wave, run_id, ts);
-- And joins per-task progress.
CREATE INDEX IF NOT EXISTS idx_wave_events_task ON wave_events (task_id);

CREATE TABLE IF NOT EXISTS lock_heartbeats (
    -- Keyed by the lock holder pair so each (session, task) has exactly one
    -- freshness row, upserted on every telemetry write.
    session       TEXT NOT NULL DEFAULT '',
    task_id       TEXT NOT NULL DEFAULT '',
    -- The most recent transition's wave/run/phase, for display.
    wave          TEXT NOT NULL DEFAULT '',
    run_id        TEXT NOT NULL DEFAULT '',
    phase         TEXT NOT NULL DEFAULT '',
    host          TEXT NOT NULL DEFAULT '',
    -- Server-clock time of the last telemetry event for this holder. The
    -- staleness signal compares now() against THIS (not task_locks.locked_at):
    -- a lock with a fresh heartbeat is NOT stale even past the 30m age cutoff.
    last_activity TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session, task_id)
);

-- Staleness scans heartbeats by recency.
CREATE INDEX IF NOT EXISTS idx_lock_heartbeats_last_activity ON lock_heartbeats (last_activity);

-- ---------------------------------------------------------------------------
-- Serialized landing queue (added 2026-06-14, doc 27 Lever 3). PURELY ADDITIVE:
-- one new table beside task_locks/wave_events, and the tables above are untouched,
-- so an OLD lock-server client (another machine on the prior taskdb binary) keeps
-- working unchanged against this migrated DB — it simply never reads or writes
-- land_queue (it falls back to landing 'main' directly, today's behavior). Like
-- task_locks, this is disposable coordination state: the git repo (tasks/*.json +
-- the branch refs) is the SOLE authority; losing these rows loses no durable work
-- — the next wave re-enqueues its own row. Leader election needs NO schema here: a
-- single landing writer is elected by INSERT..ON CONFLICT DO NOTHING of the literal
-- task_id '__land_leader__' sentinel into task_locks above, and a dead leader's
-- sentinel is reaped by age exactly like any stale lock.

CREATE TABLE IF NOT EXISTS land_queue (
    id BIGSERIAL PRIMARY KEY,
    branch TEXT NOT NULL,                  -- the gate-green ref to land, pushed to origin
    base_sha TEXT NOT NULL DEFAULT '',     -- main sha it was gated over (fast-path skip + staleness)
    task_ids TEXT NOT NULL DEFAULT '',     -- space-joined owned task ULIDs (tombstone + dedupe targets)
    gate TEXT NOT NULL DEFAULT '',         -- gate command run in the merged worktree before FF-push; '' = fall back to the runner's static --gate
    wave TEXT NOT NULL DEFAULT '', run_id TEXT NOT NULL DEFAULT '',
    priority INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'queued', -- queued|landing|landed|conflict|failed|cancelled
    requested_by TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
    runner TEXT NOT NULL DEFAULT '', attempts INT NOT NULL DEFAULT 0,
    merge_commit TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT now(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ
);
-- One active landing per branch (idempotent re-enqueue is a no-op while in flight).
-- Dedup is BRANCH-ONLY and that is INTENTIONAL (#14): a wave's idempotent retry
-- (or a double-enqueue) of the SAME branch must collapse to the one in-flight row,
-- not stack a second land of the same work. The only theoretical collision —
-- different CONTENTS pushed under the same branch NAME — is made rare upstream by
-- the producer minting a unique integration-branch name per wave/run, so same-name
-- reuse essentially does not occur in practice.
CREATE UNIQUE INDEX IF NOT EXISTS uq_land_queue_active ON land_queue (branch) WHERE status IN ('queued','landing');
-- The runner's pick: oldest highest-priority queued row.
CREATE INDEX IF NOT EXISTS idx_land_queue_pick ON land_queue (status, priority DESC, id);
-- Live-DB migration for the per-row gate (added 2026-06-15). Idempotent and
-- additive: on an already-created live land_queue this ADDs the gate column; on a
-- fresh install the CREATE TABLE above already carries it, so this is a no-op. The
-- OLD running runner never SELECTs gate (explicit column lists), so the new column
-- is invisible to it — adding it cannot break an in-flight old binary.
ALTER TABLE land_queue ADD COLUMN IF NOT EXISTS gate TEXT NOT NULL DEFAULT '';

-- ---------------------------------------------------------------------------
-- Done-tombstone registry (added 2026-06-16, docs/23 Proposal A — the
-- status-aware claim). PURELY ADDITIVE: one brand-new table beside
-- task_locks/wave_events/land_queue, none of which is touched, so an OLD
-- lock-server client (another machine on the prior taskdb binary) keeps working
-- unchanged against this migrated DB — it simply never reads or writes task_done
-- (its claim path has no tombstone consult, exactly today's behavior). And a NEW
-- binary on an UN-migrated DB degrades to "no tombstone data" (tombstonedTasks()
-- returns an empty map on a missing-table query error, mirroring
-- heartbeatAgesByTask), so neither direction breaks.
--
-- WHY: in the per-clone-DB topology a clone can redo a task another clone already
-- finished, in the window before it has `git pull`ed + thawed the terminal state
-- (docs/23 §1.1, risk #2). A terminal completion (release to done/dropped, or the
-- landing queue FF-landing the branch) upserts a SHORT-LIVED tombstone keyed by
-- task_id; `claim` consults it and SKIPS (auto-claim) or REFUSES (explicit
-- `claim <id>`/`lock <id>`) a candidate the local clone has not yet pulled,
-- closing that redo window. Like task_locks, this is DISPOSABLE soft coordination
-- state: the git repo (tasks/*.json) remains the SOLE authority for task content
-- and the DAG; a tombstone is NEVER frozen to tasks/*.json, is reconstructable
-- (the next terminal write re-asserts it), and is reaped by age.
--
-- RESOLVED design decisions (docs/23 OQ-A1/A2/A3 — DECIDED, see lockserver.go):
--   OQ-A1: an AUTO-claim SILENTLY SKIPS a tombstoned candidate; an EXPLICIT
--          claim/lock of one REFUSES loudly.
--   OQ-A2: TTL defaults to 24h (env-tunable TASKDB_TOMBSTONE_TTL); reaped by age
--          on the standing reap path + opportunistically on claim.
--   OQ-A3: a deliberate REOPEN (done -> open/in-progress) DELETEs the tombstone so
--          claim offers the task again (and the freshness comparison self-heals
--          even before the DELETE fires, once the local updated_at passes `at`).
CREATE TABLE IF NOT EXISTS task_done (
    -- The task ULID (full 26-char form). No FK: tasks live in SQLite/git, not here
    -- (same rationale as task_locks). PRIMARY KEY so an upsert collapses repeated
    -- completions of the same id to one tombstone row.
    task_id TEXT PRIMARY KEY,
    -- The terminal status recorded (done|dropped) — surfaced in the loud refuse.
    status  TEXT NOT NULL,
    -- The session/identity that completed it, for human triage in the refuse.
    by      TEXT NOT NULL DEFAULT '',
    -- Which dev/machine completed it (hostname or $TASKDB_DEV).
    host    TEXT NOT NULL DEFAULT '',
    -- Server-clock completion time. The claim consult gates a candidate only when
    -- this is NEWER than the candidate's local updated_at (the clone has not yet
    -- pulled the terminal state); reap scans by this column.
    at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Reap scans by age; index the column it filters on (like idx_task_locks_locked_at).
CREATE INDEX IF NOT EXISTS idx_task_done_at ON task_done (at);
