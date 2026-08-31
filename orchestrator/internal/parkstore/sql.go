// SPDX-License-Identifier: Apache-2.0

package parkstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
)

// SQL is the database/sql twin of Memory: the DURABLE backing for the D46
// session<->question join, behind the SAME parkstore.Store seam Memory
// satisfies. Where Memory's "durable" map is re-read by Lookup/List within the
// process, SQL's reads hit a table (orchestrator/migrations/0012_park_join.sql)
// that genuinely OUTLIVES the process — so a parked rung-2 ask survives a real
// control-plane restart and resumes on a human answer, never timing out into
// allow or kill (D46/D77; doc 16 §8.2). A caller wired against Store gets either
// backing without knowing which, and the two are held to the same behavior.
//
// It takes an INJECTED *sql.DB (D33: the driver choice is the operator's — this
// package imports no driver, so orchestrator/go.mod stays stdlib-only). The
// owner wires a driver at the binary boundary and hands the open pool here;
// live-Postgres integration is exercised only behind DS_PG_DSN (a deferred
// manual step, never run in the sandbox — sql_test.go SKIPS without it), so the
// `go test ./...` gate stays green with no live DB (D50). SQL is written for
// PostgreSQL ($N placeholders, ON CONFLICT, timestamptz).
//
// ADDITIVE fault posture, inherited from askhold (identical to Memory). A
// record/clear/read FAULT here never un-parks or re-parks the ask — askhold
// already holds the safe state (a record error leaves the ask PARKED, a clear
// error leaves it RESUMED, askhold/park.go) — so SQL simply SURFACES the IO
// fault through the same error returns for the caller to retry; it performs no
// compensating write of its own.
type SQL struct {
	db *sql.DB
}

// NewSQL wraps an already-open *sql.DB. It is the database/sql constructor twin
// of NewMemory; the caller supplies a pool opened against a schema carrying
// 0012_park_join.sql.
func NewSQL(db *sql.DB) *SQL { return &SQL{db: db} }

// Compile-time assertions: *SQL satisfies the SAME narrow Store seam and the
// askhold.ParkRecorder contract Memory does — so any Memory/SQL conformance
// assertion agrees, and a caller swaps one backing for the other unchanged.
var (
	_ Store                = (*SQL)(nil)
	_ askhold.ParkRecorder = (*SQL)(nil)
)

// SQL statements. The columns mirror orchestrator/migrations/0012_park_join.sql.
const (
	// RecordParked is an UPSERT keyed on the session UUID: re-recording a
	// still-parked session overwrites the row in place (one outstanding park per
	// session), exactly as Memory's map overwrites a key.
	sqlUpsertPark = `
INSERT INTO park_join (session_uuid, resource_kind, resource_name, matched_rule_id, rung2, parked_at)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (session_uuid) DO UPDATE SET
  resource_kind=EXCLUDED.resource_kind, resource_name=EXCLUDED.resource_name,
  matched_rule_id=EXCLUDED.matched_rule_id, rung2=EXCLUDED.rung2,
  parked_at=EXCLUDED.parked_at`

	// ClearParked is an idempotent DELETE: removing an absent join affects zero
	// rows and is a no-op success, so a re-driven clear after a partial write is
	// retry-safe (matching Memory's delete-of-absent).
	sqlDeletePark = `DELETE FROM park_join WHERE session_uuid = $1`

	// Lookup is the keyed restart-survival read.
	sqlLookupPark = `
SELECT session_uuid, resource_kind, resource_name, matched_rule_id, rung2, parked_at
FROM park_join WHERE session_uuid = $1`

	// List is the bulk restart-survival read, in deterministic session-UUID order
	// (the doc 15 §3 RecoverSessions re-adoption shape), matching Memory's sort.
	sqlListParks = `
SELECT session_uuid, resource_kind, resource_name, matched_rule_id, rung2, parked_at
FROM park_join ORDER BY session_uuid`
)

// queryTimeout bounds each restart-survival read/write so a stalled backing
// surfaces as a context fault the caller retries, rather than hanging the resume
// path. It is generous (the join is tiny) and applies only when the caller did
// not already bound the work — the Store methods carry no ctx, so SQL provides
// its own, like the rest of internal/store's deferred-manual paths.
const queryTimeout = 5 * time.Second

// RecordParked UPSERTs the session<->question join when an ask enters
// ParkPhaseParked (askhold calls this from NewParked). The single write-shape
// fault is an empty session UUID (no join key) — returned as the SAME
// errEmptySession Memory returns, so a caller cannot tell the backings apart. A
// backing IO fault surfaces as-is; per the askhold contract neither un-parks the
// ask (askhold already holds the PARKED safe state), so the caller simply
// retries.
func (s *SQL) RecordParked(p askhold.Parked) error {
	if p.SessionUUID == "" {
		return errEmptySession
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	_, err := s.db.ExecContext(ctx, sqlUpsertPark,
		p.SessionUUID, p.Ask.ResourceKind, p.Ask.ResourceName, p.Ask.MatchedRuleID, p.Ask.Rung2, p.ParkedAt,
	)
	return err
}

// ClearParked DELETEs the join when a park RESUMES on answer (askhold calls this
// from Resume). Clearing an absent join is a no-op success (idempotent
// retry-safe), matching Memory. The empty-UUID write-shape fault returns
// errEmptySession; a backing IO fault surfaces as-is and never re-parks the ask
// (askhold already holds the RESUMED safe state).
func (s *SQL) ClearParked(p askhold.Parked) error {
	if p.SessionUUID == "" {
		return errEmptySession
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	// A DELETE of an absent row affects zero rows and returns no error — exactly
	// the no-op-success idempotency Memory's delete gives.
	_, err := s.db.ExecContext(ctx, sqlDeletePark, p.SessionUUID)
	return err
}

// Lookup re-reads the durable join for one session (the keyed restart-survival
// read). The bool reports presence; a cleared/never-recorded session is absent
// (false, nil — sql.ErrNoRows is the absence signal, not a fault). An empty
// session UUID is the same write-shape fault Memory returns. A genuine query
// fault surfaces through the error, the signature Memory reserved for exactly
// this twin.
func (s *SQL) Lookup(sessionUUID string) (askhold.Parked, bool, error) {
	if sessionUUID == "" {
		return askhold.Parked{}, false, errEmptySession
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	p, err := scanPark(s.db.QueryRowContext(ctx, sqlLookupPark, sessionUUID))
	if errors.Is(err, sql.ErrNoRows) {
		return askhold.Parked{}, false, nil
	}
	if err != nil {
		return askhold.Parked{}, false, err
	}
	return p, true, nil
}

// List enumerates every outstanding park in deterministic session-UUID order
// (the bulk restart-survival re-adoption read). The returned slice is freshly
// allocated per call, so a caller iterating it never races the backing. A query
// fault surfaces through the error.
func (s *SQL) List() ([]askhold.Parked, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, sqlListParks)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]askhold.Parked, 0)
	for rows.Next() {
		p, err := scanPark(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// rowScanner is the read surface common to *sql.Row and *sql.Rows, so scanPark
// serves both the keyed Lookup and the bulk List from one place.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanPark materializes one park_join row into an askhold.Parked. A re-read park
// is ALWAYS still PARKED with NO verdict — the table holds only outstanding
// (not-yet-cleared) joins, and a resumed ask is DELETEd, so a re-read never
// surfaces a timeout-derived allow/kill. Phase is therefore set to
// ParkPhaseParked unconditionally; ResumedAt / Verdict / GrantScope / DenyReason
// stay zero, exactly the restart-survival shape the resume path expects.
func scanPark(sc rowScanner) (askhold.Parked, error) {
	var p askhold.Parked
	if err := sc.Scan(
		&p.SessionUUID,
		&p.Ask.ResourceKind,
		&p.Ask.ResourceName,
		&p.Ask.MatchedRuleID,
		&p.Ask.Rung2,
		&p.ParkedAt,
	); err != nil {
		return askhold.Parked{}, err
	}
	p.Phase = askhold.ParkPhaseParked
	return p, nil
}
