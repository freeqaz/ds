// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDSNBuild checks the keyword/value DSN, including single-quote/backslash
// escaping of the password (the one field that can carry pq-special chars).
func TestDSNBuild(t *testing.T) {
	c := &lockConfig{Postgres: pgConfig{
		Host: "127.0.0.1", Port: 5433, DBName: "taskdb",
		User: "devteam", Password: "p'a\\ss", SSLMode: "disable", ConnectTimeout: 3,
	}}
	dsn := c.dsn()
	for _, want := range []string{
		"host='127.0.0.1'", "port=5433", "dbname='taskdb'", "user='devteam'",
		`password='p\'a\\ss'`, "sslmode='disable'", "connect_timeout=3",
	} {
		if !strings.Contains(dsn, want) {
			t.Errorf("dsn() missing %q\n got: %s", want, dsn)
		}
	}
}

// TestDSNDefaults fills sslmode and connect_timeout when omitted.
func TestDSNDefaults(t *testing.T) {
	c := &lockConfig{Postgres: pgConfig{Host: "h", Port: 1, DBName: "d", User: "u", Password: "pw"}}
	dsn := c.dsn()
	if !strings.Contains(dsn, "sslmode='disable'") {
		t.Errorf("missing default sslmode: %s", dsn)
	}
	if !strings.Contains(dsn, "connect_timeout=5") {
		t.Errorf("missing default connect_timeout: %s", dsn)
	}
}

// TestDSNOverride returns the raw override verbatim.
func TestDSNOverride(t *testing.T) {
	c := &lockConfig{dsnOverride: "postgres://x:y@h:1/d?sslmode=disable"}
	if got := c.dsn(); got != "postgres://x:y@h:1/d?sslmode=disable" {
		t.Errorf("override not used verbatim: %s", got)
	}
}

// TestRedactedDSN masks the password in both the structured and override forms.
func TestRedactedDSN(t *testing.T) {
	c := &lockConfig{Postgres: pgConfig{Host: "h", Port: 1, DBName: "d", User: "u", Password: "SECRET123"}}
	if r := c.redactedDSN(); strings.Contains(r, "SECRET123") {
		t.Errorf("redactedDSN leaked password: %s", r)
	}
	o := &lockConfig{dsnOverride: "host=h password=SECRET123 dbname=d"}
	if r := o.redactedDSN(); strings.Contains(r, "SECRET123") {
		t.Errorf("redactedDSN(override kv) leaked password: %s", r)
	}
	u := &lockConfig{dsnOverride: "host=h password='SECRET123' dbname=d"}
	if r := u.redactedDSN(); strings.Contains(r, "SECRET123") {
		t.Errorf("redactedDSN(override quoted) leaked password: %s", r)
	}
}

// TestTunnelCmd derives the ssh command and fills missing fields with defaults.
func TestTunnelCmd(t *testing.T) {
	c := &lockConfig{SSH: sshConfig{Host: "lock-server.example.com", User: "tunnel", RemotePGHost: "127.0.0.1", RemotePGPort: 5432, LocalPort: 5433}}
	if got, want := c.tunnelCmd(), "ssh -N -L 5433:127.0.0.1:5432 tunnel@lock-server.example.com"; got != want {
		t.Errorf("tunnelCmd()=%q want %q", got, want)
	}
	def := &lockConfig{SSH: sshConfig{Host: "h", User: "tunnel"}}
	if got, want := def.tunnelCmd(), "ssh -N -L 5433:127.0.0.1:5432 tunnel@h"; got != want {
		t.Errorf("tunnelCmd() defaults=%q want %q", got, want)
	}
}

func TestTruthyEnv(t *testing.T) {
	cases := map[string]bool{"": false, "0": false, "false": false, "no": false, "off": false,
		"1": true, "true": true, "yes": true, "on": true, "anything": true}
	for v, want := range cases {
		t.Setenv("TASKDB_PROBE_TRUTHY", v)
		if got := truthyEnv("TASKDB_PROBE_TRUTHY"); got != want {
			t.Errorf("truthyEnv(%q)=%v want %v", v, got, want)
		}
	}
}

// TestResolveConfigDisable: TASKDB_LOCK_DISABLE forces local-only regardless of
// the committed config.
func TestResolveConfigDisable(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	cfg, err := resolveLockConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Errorf("expected disabled with TASKDB_LOCK_DISABLE=1")
	}
}

// TestResolveConfigDSNOverride: TASKDB_LOCK_DSN opts in and is used verbatim.
func TestResolveConfigDSNOverride(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "")
	t.Setenv("TASKDB_LOCK_DSN", "host=example dbname=d user=u password=pw")
	cfg, err := resolveLockConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Errorf("TASKDB_LOCK_DSN should enable remote locking")
	}
	if cfg.dsn() != "host=example dbname=d user=u password=pw" {
		t.Errorf("override DSN not used: %s", cfg.dsn())
	}
}

// TestEmbeddedConfigValid: the committed lockserver.json embeds and parses, is
// DISABLED by default (a fresh clone locks locally and never dials out), and
// points at the dedicated taskdb database (guards against a fat-fingered edit
// landing a broken — or, worse, silently dialing — default in every clone).
func TestEmbeddedConfigValid(t *testing.T) {
	var cfg lockConfig
	if err := json.Unmarshal(defaultLockConfigJSON, &cfg); err != nil {
		t.Fatalf("embedded lockserver.json does not parse: %v", err)
	}
	if cfg.Enabled {
		t.Errorf("embedded config should be disabled by default (local-only locking out of the box)")
	}
	if cfg.Postgres.DBName != "taskdb" {
		t.Errorf("embedded config dbname=%q, want taskdb (the dedicated lock DB)", cfg.Postgres.DBName)
	}
	if cfg.Postgres.Password != "" {
		t.Errorf("embedded config must not carry a password; use TASKDB_LOCK_DSN or a local edit")
	}
}

// TestEmbeddedSchemaApplies: the embedded schema is non-empty and creates the
// lock table (cheap guard that //go:embed wired the file in).
func TestEmbeddedSchemaPresent(t *testing.T) {
	if !strings.Contains(lockSchemaSQL, "CREATE TABLE IF NOT EXISTS task_locks") {
		t.Errorf("embedded lockserver.sql missing task_locks DDL")
	}
}

// TestTelemetrySchemaAdditive: the migration is backwards-compatible — it adds
// the two telemetry tables with IF NOT EXISTS and NEVER alters/drops/renames the
// existing task_locks table or its columns (other machines' running lock-server
// code reads/writes task_locks unchanged). Guards against a future edit slipping
// a destructive statement into the same idempotent apply path.
func TestTelemetrySchemaAdditive(t *testing.T) {
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS wave_events",
		"CREATE TABLE IF NOT EXISTS lock_heartbeats",
	} {
		if !strings.Contains(lockSchemaSQL, want) {
			t.Errorf("embedded lockserver.sql missing additive DDL %q", want)
		}
	}
	// Fail closed on any statement that would mutate an existing client's view of
	// task_locks. The whole migration must be CREATE … IF NOT EXISTS only.
	lc := strings.ToLower(lockSchemaSQL)
	for _, forbidden := range []string{
		"alter table task_locks",
		"drop table task_locks",
		"drop column",
		"rename ",
		"alter column",
	} {
		if strings.Contains(lc, forbidden) {
			t.Errorf("lockserver.sql contains a NON-additive statement %q — old lock-server clients would break", forbidden)
		}
	}
}

// TestLockStale exercises the activity-aware staleness rule the dashboard and
// `taskdb status` / `lockserver status` share: a lock past the age cutoff is
// stale ONLY when it also has no recent telemetry heartbeat. No heartbeat
// (hbAge<=0) falls back to pure lock-age (legacy behavior).
func TestLockStale(t *testing.T) {
	old := staleLockThreshold + time.Minute    // past the cutoff
	recent := staleLockThreshold - time.Minute // within the cutoff
	cases := []struct {
		name      string
		age, hb   time.Duration
		hasBeat   bool
		wantStale bool
	}{
		{"no heartbeat, young lock → not stale", recent, 0, false, false},
		{"no heartbeat, old lock → stale (legacy fallback)", old, 0, false, true},
		{"old lock but FRESH heartbeat → NOT stale (the fix)", old, recent, true, false},
		{"old lock, SUB-SECOND fresh heartbeat → NOT stale (hbAge≈0, hasBeat true)", old, 0, true, false},
		{"old lock AND old heartbeat → stale", old, old, true, true},
		{"young lock with old heartbeat → not stale (age gates first)", recent, old, true, false},
		{"young lock, fresh heartbeat → not stale", recent, recent, true, false},
	}
	for _, c := range cases {
		if got := lockStale(c.age, c.hb, c.hasBeat); got != c.wantStale {
			t.Errorf("%s: lockStale(%v,%v,%v)=%v want %v", c.name, c.age, c.hb, c.hasBeat, got, c.wantStale)
		}
	}
}

// TestTrackDisableSilences: TASKDB_TRACK_DISABLE makes wave-event a quiet no-op
// (exit 0) even with the lock server enabled — the telemetry-only opt-out that
// keeps locking on. cmdWaveEvent must return nil without attempting a connection.
func TestTrackDisableSilences(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "")
	t.Setenv("TASKDB_TRACK_DISABLE", "1")
	if err := cmdWaveEvent(nil, []string{"--wave", "w", "--phase", "scope", "--event", "start"}); err != nil {
		t.Errorf("wave-event with TASKDB_TRACK_DISABLE=1 should no-op (nil err); got %v", err)
	}
}
