// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

// TestLandQueueSchemaPresent: the embedded schema carries the land_queue DDL and
// both of its indexes (cheap guard that the additive block reached lockserver.sql
// and //go:embed wired it in). The partial-unique WHERE clause is the load-bearing
// single-active-landing invariant the serial runner depends on, so assert on it
// verbatim — a silent drift to a plain unique index would let two rows land the
// same branch concurrently.
func TestLandQueueSchemaPresent(t *testing.T) {
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS land_queue",
		"uq_land_queue_active",
		"idx_land_queue_pick",
		"WHERE status IN ('queued','landing')",
		"(status, priority DESC, id)",
	} {
		if !strings.Contains(lockSchemaSQL, want) {
			t.Errorf("embedded lockserver.sql missing land_queue DDL %q", want)
		}
	}
}

// TestLandQueueGateColumn pins the per-row gate column in BOTH apply paths: the
// CREATE TABLE body (fresh installs) and the idempotent live-DB ALTER (an
// already-migrated DB the running runner is reading). A drift to either would mean
// a fresh install or the live DB silently lacks the column the runner needs to run
// each branch's own compose-build, regressing landing=queue to the static --gate.
func TestLandQueueGateColumn(t *testing.T) {
	for _, want := range []string{
		"gate TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE land_queue ADD COLUMN IF NOT EXISTS gate TEXT NOT NULL DEFAULT ''",
	} {
		if !strings.Contains(lockSchemaSQL, want) {
			t.Errorf("embedded lockserver.sql missing gate migration %q", want)
		}
	}
}

// TestLandQueueSchemaAdditive: the land_queue migration is backwards-compatible —
// it adds one table + two indexes with IF NOT EXISTS and NEVER alters/drops/
// renames task_locks, wave_events, or lock_heartbeats. An old lock-server client
// on the prior binary keeps reading/writing those tables unchanged after this
// migrated DB. Guards against a future edit slipping a destructive statement into
// the same idempotent apply path (mirrors TestTelemetrySchemaAdditive).
func TestLandQueueSchemaAdditive(t *testing.T) {
	lc := strings.ToLower(lockSchemaSQL)
	for _, forbidden := range []string{
		"alter table task_locks", "drop table task_locks",
		"alter table wave_events", "drop table wave_events",
		"alter table lock_heartbeats", "drop table lock_heartbeats",
		"drop column", "alter column", "rename ",
	} {
		if strings.Contains(lc, forbidden) {
			t.Errorf("lockserver.sql contains a NON-additive statement %q — old lock-server clients would break", forbidden)
		}
	}
}

// TestLandLeaderSentinel pins the election sentinel literal: leader election
// reuses task_locks via this exact task_id, so the value is a cross-machine
// contract (a drift would re-elect the leader on every binary version).
func TestLandLeaderSentinel(t *testing.T) {
	if landLeaderSentinel != "__land_leader__" {
		t.Errorf("landLeaderSentinel=%q want %q", landLeaderSentinel, "__land_leader__")
	}
}

// TestLandSchemaPresentLive is the live-DB check: it runs migrate() (additive,
// idempotent) and asserts landSchemaPresent() is then true. It routes its server
// setup through landqServerForTest (the B7 isolation gate), so with
// DS_LANDQ_EPHEMERAL_PG UNSET it SKIPS IMMEDIATELY — before resolving any config
// or opening any connection — and never touches the SHARED production lock server
// (the prior Enabled/reachable-only skip did NOT fire when lockserver.json is
// enabled and the tunnel is up, so this otherwise opened shared prod). With the
// gate SET it runs migrate() against a throwaway Postgres; it inserts ZERO rows,
// and landqServerForTest already runs migrate() and registers cleanup.
func TestLandSchemaPresentLive(t *testing.T) {
	ls := landqServerForTest(t)
	present, err := ls.landSchemaPresent()
	if err != nil {
		t.Fatalf("landSchemaPresent() error: %v", err)
	}
	if !present {
		t.Errorf("land_queue absent after migrate() — additive DDL did not apply")
	}
}
