package store

// SQL text for the Postgres implementation. PostgreSQL dialect ($N placeholders,
// ON CONFLICT, RETURNING). The columns mirror orchestrator/migrations/*.sql.

const sqlInsertSession = `
INSERT INTO sessions (
  session_uuid, host_id, host_session_index, tap_name,
  env_config_ref, image_id, identity_ref, ca_ref, digest_ref, digest_acked,
  policy_applied_seq, grants,
  writer_seat, writer_role, attended, attach_state,
  parent_session_uuid, state, suspend_reason,
  role_name, role_version, role_content_hash, role_widenings_inert,
  mint_expiry,
  created_at, ready_at, attached_at, destroyed_at, updated_at
) VALUES (
  $1,$2,$3,$4, $5,$6,$7,$8,$9,$10, $11,$12,
  $13,$14,$15,$16, $17,$18,$19, $20,$21,$22,$23,
  $24,
  $25,$26,$27,$28,$29
)`

const sqlGetSession = `
SELECT session_uuid, host_id, host_session_index, tap_name,
       env_config_ref, image_id, identity_ref, ca_ref, digest_ref, digest_acked,
       policy_applied_seq, grants,
       writer_seat, writer_role, attended, attach_state,
       parent_session_uuid, state, suspend_reason,
       role_name, role_version, role_content_hash, role_widenings_inert,
       mint_expiry,
       created_at, ready_at, attached_at, destroyed_at, updated_at
FROM sessions WHERE session_uuid = $1`

const sqlUpdateSession = `
UPDATE sessions SET
  env_config_ref=$1, image_id=$2, identity_ref=$3, ca_ref=$4, digest_ref=$5, digest_acked=$6,
  policy_applied_seq=$7, grants=$8,
  writer_seat=$9, writer_role=$10, attended=$11, attach_state=$12,
  state=$13, suspend_reason=$14,
  role_name=$15, role_version=$16, role_content_hash=$17, role_widenings_inert=$18,
  mint_expiry=$19,
  ready_at=$20, attached_at=$21, destroyed_at=$22, updated_at=$23
WHERE session_uuid=$24`

const sqlUpdateSessionRef = `
UPDATE sessions SET host_id=$1, host_session_index=$2, tap_name=$3, updated_at=$4
WHERE session_uuid=$5`

// sqlListSessions is the §5.3 console read as a KEYSET SCAN (the in-process page-walk
// pushed down to ONE bounded query). Parameters:
//
//	$1 host filter, $2 state filter, $3 parent filter (NULL = no filter on each),
//	$4 include-destroyed flag,
//	$5 launching_user filter (NULL = fleet-wide; else the session's launching principal
//	   must resolve to this idp_subject — the §3.1 attribution narrowing, an EXISTS over
//	   principals so a NULL/dangling launching_principal is excluded, never leaked),
//	$6 keyset-cursor SET flag, $7 cursor created_at, $8 cursor session_uuid (when SET the
//	   page returns only rows STRICTLY AFTER the cursor in the newest-first order),
//	$9 page LIMIT (< 0 = no limit, the back-compat single-shot path).
//
// The (created_at DESC, session_uuid DESC) order + the keyset WHERE + the $5
// launching-principal scoping are served by the composite covering index
// sessions_keyset_idx (launching_principal, created_at DESC, session_uuid DESC) —
// migration 0014_sessions_keyset_idx.sql: the scoped page is a bounded index
// range-scan (leading equality on launching_principal, the two order keys carried
// DESC so no post-scan sort), and the fleet-wide page (no $5 scope) rides the same
// index's ordering suffix. The page is the newest-first prefix past the cursor,
// bounded by $9.
const sqlListSessions = `
SELECT session_uuid, host_id, host_session_index, tap_name,
       env_config_ref, image_id, identity_ref, ca_ref, digest_ref, digest_acked,
       policy_applied_seq, grants,
       writer_seat, writer_role, attended, attach_state,
       parent_session_uuid, state, suspend_reason,
       role_name, role_version, role_content_hash, role_widenings_inert,
       mint_expiry,
       created_at, ready_at, attached_at, destroyed_at, updated_at
FROM sessions
WHERE ($1::text IS NULL OR host_id = $1)
  AND ($2::text IS NULL OR state = $2)
  AND ($3::text IS NULL OR parent_session_uuid = $3)
  AND ($4 OR state <> 'DESTROYED')
  AND ($5::text IS NULL OR EXISTS (
        SELECT 1 FROM principals pr
        WHERE pr.id = sessions.launching_principal AND pr.idp_subject = $5))
  AND (NOT $6::boolean
        OR created_at < $7::timestamptz
        OR (created_at = $7::timestamptz AND session_uuid < $8::text))
ORDER BY created_at DESC, session_uuid DESC
` + sessionLimitClause

// sessionLimitClause bounds sqlListSessions to $9 rows, or no limit when $9 < 0 (the
// back-compat single-shot path). Mirrors limitClause's CASE-to-NULL idiom (policy_log).
const sessionLimitClause = `
FETCH FIRST (CASE WHEN $9 < 0 THEN NULL ELSE $9 END) ROWS ONLY`

// --- index epochs (per-host index history) ---

const sqlInsertEpoch = `
INSERT INTO session_index_epochs (
  session_uuid, host_id, host_session_index, tap_name,
  guest_ip, guest_ip_family, overlay_path, started_at, ended_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`

const sqlListEpochs = `
SELECT host_id, host_session_index, tap_name, guest_ip, guest_ip_family, overlay_path, started_at, ended_at
FROM session_index_epochs WHERE session_uuid = $1 ORDER BY started_at, id`

const sqlCloseOpenEpoch = `
UPDATE session_index_epochs SET ended_at=$1
WHERE session_uuid=$2 AND ended_at IS NULL`

// sqlIndexBurned counts every binding (current or historical) of an index on a
// host across the epoch history — the burned-never-recycled guard (D66).
const sqlIndexBurned = `
SELECT COUNT(*) FROM session_index_epochs WHERE host_id=$1 AND host_session_index=$2`

// --- policy_log (append-only; bigserial seq RETURNING) ---

const sqlInsertPolicy = `
INSERT INTO policy_log (kind, actor, content_hash, payload, session_uuid, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING seq`

const sqlListPolicy = `
SELECT seq, kind, actor, content_hash, payload, session_uuid, expires_at, created_at
FROM policy_log
WHERE seq > $1
ORDER BY seq
` + limitClause

// limitClause applies $2 as a LIMIT, or no limit when $2 < 0.
const limitClause = `
FETCH FIRST (CASE WHEN $2 < 0 THEN NULL ELSE $2 END) ROWS ONLY`

const sqlLiveGrants = `
SELECT seq, kind, actor, content_hash, payload, session_uuid, expires_at, created_at
FROM policy_log
WHERE session_uuid = $1 AND kind = $2
  AND (expires_at IS NULL OR expires_at > $3)
ORDER BY seq`

// --- env_configs ---

const sqlUpsertEnv = `
INSERT INTO env_configs (ref, repo_ref, spec_hash, inline_spec, image_id, coupled_pin, pack_version, pack_exclusion, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (ref) DO UPDATE SET
  repo_ref=EXCLUDED.repo_ref, spec_hash=EXCLUDED.spec_hash, inline_spec=EXCLUDED.inline_spec,
  image_id=EXCLUDED.image_id, coupled_pin=EXCLUDED.coupled_pin,
  pack_version=EXCLUDED.pack_version, pack_exclusion=EXCLUDED.pack_exclusion`

const sqlGetEnv = `
SELECT ref, repo_ref, spec_hash, inline_spec, image_id, coupled_pin, pack_version, pack_exclusion, created_at
FROM env_configs WHERE ref = $1`

// --- plans ---

const sqlUpsertPlan = `
INSERT INTO plans (id, session_uuid, title, body, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET
  session_uuid=EXCLUDED.session_uuid, title=EXCLUDED.title, body=EXCLUDED.body,
  updated_at=EXCLUDED.updated_at`

const sqlGetPlan = `
SELECT id, session_uuid, title, body, created_at, updated_at FROM plans WHERE id = $1`

const sqlListPlans = `
SELECT id, session_uuid, title, body, created_at, updated_at
FROM plans
WHERE ($1::text IS NULL OR session_uuid = $1)
ORDER BY id`

// --- metering_events (idempotent on event_id) ---

const sqlGetMetering = `
SELECT event_id, session_uuid, kind, state, occurred_at, payload
FROM metering_events WHERE event_id = $1`

const sqlInsertMetering = `
INSERT INTO metering_events (event_id, session_uuid, kind, state, occurred_at, payload)
VALUES ($1,$2,$3,$4,$5,$6)`

const sqlListMetering = `
SELECT event_id, session_uuid, kind, state, occurred_at, payload
FROM metering_events
WHERE ($1::text IS NULL OR session_uuid = $1)
ORDER BY occurred_at, event_id`

// --- principals (doc 16 §3.2; roles stored as jsonb of the §3.2 role set, the
// same driver-agnostic encoding sessions.grants uses — see scanPrincipalFrom) ---

const sqlInsertPrincipal = `
INSERT INTO principals (id, idp_subject, org, roles, display_name, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)`

const sqlGetPrincipal = `
SELECT id, idp_subject, org, roles, display_name, created_at, updated_at
FROM principals WHERE id = $1`

const sqlGetPrincipalByIdP = `
SELECT id, idp_subject, org, roles, display_name, created_at, updated_at
FROM principals WHERE idp_subject = $1 AND org = $2`

const sqlUpdatePrincipalRoles = `
UPDATE principals SET roles = $1, updated_at = $2 WHERE id = $3`

// --- session → launching_principal linkage (nullable column on sessions) ---

const sqlSetLaunchingPrincipal = `
UPDATE sessions SET launching_principal = $1, updated_at = $2 WHERE session_uuid = $3`

const sqlGetLaunchingPrincipal = `
SELECT launching_principal FROM sessions WHERE session_uuid = $1`

const sqlPrincipalExists = `
SELECT 1 FROM principals WHERE id = $1`
