-- 0001_sessions.sql — the session record (doc 15 §5.6) and its per-host index
-- history. Control-plane state in external Postgres only (D6); retained, never
-- deleted within the flow-log retention window (D66).

CREATE TABLE sessions (
    -- Stage-0-frozen SessionRef quartet (D66/D44): the authoritative index→UUID
    -- join key. host_session_index is burned-never-recycled (enforced via the
    -- index-epoch history, not a per-row unique on this current binding, because
    -- migration/park rebinds it).
    session_uuid          text   PRIMARY KEY,
    host_id               text   NOT NULL,
    host_session_index    bigint NOT NULL,   -- uint64 in Go; non-negative
    tap_name              text   NOT NULL,   -- dstap-<idx>, ≤15 chars IFNAMSIZ

    -- Environment & image (D7/D74). env_config_ref points at env_configs.ref;
    -- left as a soft reference (no FK) so a record outlives a pruned env config.
    env_config_ref        text   NOT NULL DEFAULT '',
    image_id              text   NOT NULL DEFAULT '',

    -- Identity / CA / digest references (D22/D17/D73). Opaque here.
    identity_ref          text    NOT NULL DEFAULT '',
    ca_ref                text    NOT NULL DEFAULT '',
    digest_ref            text    NOT NULL DEFAULT '',
    digest_acked          boolean NOT NULL DEFAULT false,  -- §4.1 step-6 routability gate

    -- Policy posture (D72 sweep visibility). policy_applied_seq is the host
    -- applied_seq the create choreography placed against; grants is the resolved
    -- live grant view (authoritative rows live in policy_log).
    policy_applied_seq    bigint  NOT NULL DEFAULT 0,
    grants                jsonb   NOT NULL DEFAULT '[]'::jsonb,

    -- Attach / writer-seat / attendedness state (D18/D78/D61).
    writer_seat           text    NOT NULL DEFAULT '',
    writer_role           text    NOT NULL DEFAULT '',   -- ''|WRITER|READER
    attended              boolean NOT NULL DEFAULT false,
    attach_state          text    NOT NULL DEFAULT '',   -- last issued seat class

    -- Parent-session link (D18 fan-out, D61 hierarchy). NULL for root sessions.
    parent_session_uuid   text REFERENCES sessions(session_uuid),

    -- Lifecycle (D57 metering derives from these transitions). The state
    -- vocabulary is the doc 15 §3 frozen machine — exactly twelve states,
    -- transcribed VERBATIM here (incl. MIGRATING and RESUMING); the schema
    -- never declares a competing vocabulary, and a state change reopens the §3
    -- contract set, not a migration. suspend_reason is meaningful only in
    -- SUSPENDED.
    state                 text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING','CREATING','READY','ATTACHED','WORKING',
                         'SNAPSHOTTING','MIGRATING','PARKED','SUSPENDED','RESUMING',
                         'DESTROYING','DESTROYED')),
    suspend_reason        text
        CHECK (suspend_reason IS NULL OR suspend_reason IN ('user','policy_breach','rebalance')),
    -- A reason is set iff the session is SUSPENDED. RESUMING (and every other
    -- non-SUSPENDED state) therefore forces a NULL reason: SUSPENDED→RESUMING
    -- clears it as part of leaving SUSPENDED.
    CHECK ((state = 'SUSPENDED') = (suspend_reason IS NOT NULL)),

    created_at            timestamptz NOT NULL,
    ready_at              timestamptz,
    attached_at           timestamptz,
    destroyed_at          timestamptz,   -- teardown finalization (§4.2 step 6); row retained
    updated_at            timestamptz NOT NULL
);

CREATE INDEX sessions_host_id_idx        ON sessions (host_id);
CREATE INDEX sessions_state_idx          ON sessions (state);
CREATE INDEX sessions_parent_idx         ON sessions (parent_session_uuid);

-- Per-host index history (doc 15 §5.6): migration/park re-placement gives a new
-- host index/tap on the target; flow-log joins are per-host-epoch, so every
-- binding the session ever held is recorded. The burned-never-recycled guard
-- (D66) is a presence check against THIS table across current+historical rows,
-- which is why the per-host index uniqueness lives here, not on sessions.
CREATE TABLE session_index_epochs (
    id                  bigserial PRIMARY KEY,
    session_uuid        text   NOT NULL REFERENCES sessions(session_uuid),
    host_id             text   NOT NULL,
    host_session_index  bigint NOT NULL,
    tap_name            text   NOT NULL,
    guest_ip            bytea,                       -- family-agnostic bytes (D75)
    guest_ip_family     text NOT NULL DEFAULT ''     -- ''|v4|v6
        CHECK (guest_ip_family IN ('','v4','v6')),
    started_at          timestamptz NOT NULL,
    ended_at            timestamptz,                 -- NULL = current epoch
    -- An index, once bound on a host, is never bound again on that host: this is
    -- the structural never-recycle enforcement (D66).
    UNIQUE (host_id, host_session_index)
);

CREATE INDEX session_index_epochs_session_idx ON session_index_epochs (session_uuid);
