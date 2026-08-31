-- 0005_metering_events.sql — the D57 idempotent metering event stream (wired
-- from M0). Billing derives from session-record state transitions: active states
-- accrue per second; SUSPENDED/PARKED ≈ free; socket-hold counts active. The
-- event_id is the idempotency key — re-emitting the same id is a no-op.

CREATE TABLE metering_events (
    event_id     text PRIMARY KEY,                 -- idempotency key (D57)
    session_uuid text NOT NULL,
    kind         text NOT NULL DEFAULT '',         -- e.g. state_transition, sample
    state        text NOT NULL DEFAULT '',         -- the entered state for transition events
    occurred_at  timestamptz NOT NULL,
    payload      bytea                             -- e.g. the D37 RSS/CPU/IO sample, opaque
);

CREATE INDEX metering_events_session_idx ON metering_events (session_uuid, occurred_at);
