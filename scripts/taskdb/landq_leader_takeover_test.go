// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
	"time"
)

// The __land_leader__ sentinel is the ONE lock reap() deliberately refuses to age
// out, so before takeover existed a hard kill (SIGKILL / crash / power loss /
// reboot) stranded it permanently: the deferred releaseLandLeader never runs, no
// sweep reclaims it, and every candidate reports "another runner holds it" and
// exits 0. That is exactly what happened on 2026-08-18 — the box rebooted at
// 21:14 while a leader held the sentinel, and the queue sat dead for 11h41m while
// the 2-minute election timer reported the same healthy-looking message all night.
//
// These tests pin the two pure decision functions that gate the reclaim. Both are
// deliberately clock-injected (no time.Now() inside) so the boundaries are exact
// rather than flaky.

func TestLandLeaderTakeoverEligible(t *testing.T) {
	now := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	lockAt := func(d time.Duration) *RemoteLock {
		return &RemoteLock{TaskID: landLeaderSentinel, LockedBy: "peer", LockedAt: now.Add(-d)}
	}

	cases := []struct {
		name       string
		holder     *RemoteLock
		staleAfter time.Duration
		want       bool
		why        string
	}{
		{
			name: "nil holder is not a takeover", holder: nil, staleAfter: time.Hour, want: false,
			why: "an unlocked sentinel is won by plain acquire(); takeover must not claim to have stolen anything",
		},
		{
			name: "disabled by zero threshold", holder: lockAt(99 * time.Hour), staleAfter: 0, want: false,
			why: "0 means the operator turned takeover OFF; even an ancient sentinel must be left alone",
		},
		{
			name: "disabled by negative threshold", holder: lockAt(99 * time.Hour), staleAfter: -time.Minute, want: false,
			why: "a negative duration must not underflow into 'everything is stale'",
		},
		{
			name: "fresh heartbeat is never stolen", holder: lockAt(2 * time.Second), staleAfter: 45 * time.Minute, want: false,
			why: "the live-leader case: a 30s heartbeat keeps locked_at seconds old",
		},
		{
			name: "exactly at the threshold is NOT yet eligible", holder: lockAt(45 * time.Minute), staleAfter: 45 * time.Minute, want: false,
			why: "strict > keeps the boundary unambiguous; ties favour the incumbent",
		},
		{
			name: "one nanosecond past the threshold is eligible", holder: lockAt(45*time.Minute + time.Nanosecond), staleAfter: 45 * time.Minute, want: true,
			why: "the boundary must actually be crossable, or takeover would never fire",
		},
		{
			name: "the real outage: 11h41m silent", holder: lockAt(11*time.Hour + 41*time.Minute), staleAfter: 45 * time.Minute, want: true,
			why: "the 2026-08-18 reboot strand must be reclaimed automatically",
		},
		{
			name: "a leader mid-gate is NOT stolen at the default floor", holder: lockAt(19 * time.Minute), staleAfter: 40 * time.Minute, want: false,
			why: "an old-binary leader with no mid-gate heartbeat ages up to --gate-timeout (20m); the 2x floor must cover it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := landLeaderTakeoverEligible(tc.holder, now, tc.staleAfter); got != tc.want {
				t.Errorf("landLeaderTakeoverEligible = %v, want %v\n  why this matters: %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestResolveLandLeaderTakeover pins the clamp. The floor exists for the ROLLOUT
// case: a leader already running an older binary has no mid-gate heartbeat, so
// its locked_at legitimately ages for the full length of a gate. Stealing it
// would put two writers on main.
func TestResolveLandLeaderTakeover(t *testing.T) {
	cases := []struct {
		name          string
		requested     time.Duration
		gateTimeout   time.Duration
		wantEffective time.Duration
		wantClamped   bool
		why           string
	}{
		{
			name:      "disabled passes through untouched",
			requested: 0, gateTimeout: 20 * time.Minute,
			wantEffective: 0, wantClamped: false,
			why: "an operator turning takeover off must not have it clamped back ON by the floor",
		},
		{
			name:      "negative is treated as disabled, not clamped up",
			requested: -time.Hour, gateTimeout: 20 * time.Minute,
			wantEffective: 0, wantClamped: false,
			why: "a negative must not become a live 40m threshold",
		},
		{
			name:      "default 45m clears the default floor of 2x20m",
			requested: landqDefaultTakeoverAfter, gateTimeout: 20 * time.Minute,
			wantEffective: 45 * time.Minute, wantClamped: false,
			why: "the shipped default must not trip its own clamp warning on every start",
		},
		{
			name:      "an over-eager 5m is raised to 2x the gate timeout",
			requested: 5 * time.Minute, gateTimeout: 20 * time.Minute,
			wantEffective: 40 * time.Minute, wantClamped: true,
			why: "5m is shorter than a single gate run — this is the double-writer footgun the floor exists to stop",
		},
		{
			name:      "a tiny gate timeout still respects the absolute floor",
			requested: time.Minute, gateTimeout: time.Minute,
			wantEffective: landqTakeoverMinFloor, wantClamped: true,
			why: "2x1m = 2m would be only ~4 missed heartbeats; the 10m absolute floor takes over",
		},
		{
			name:      "a long gate timeout raises the floor above the default",
			requested: landqDefaultTakeoverAfter, gateTimeout: 60 * time.Minute,
			wantEffective: 120 * time.Minute, wantClamped: true,
			why: "a 60m gate means locked_at can legitimately be 60m old; 45m would steal a live leader",
		},
		{
			name:      "an explicit generous value is honoured as-is",
			requested: 6 * time.Hour, gateTimeout: 20 * time.Minute,
			wantEffective: 6 * time.Hour, wantClamped: false,
			why: "the floor is a minimum, never a maximum",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, clamped := resolveLandLeaderTakeover(tc.requested, tc.gateTimeout)
			if got != tc.wantEffective || clamped != tc.wantClamped {
				t.Errorf("resolveLandLeaderTakeover(%s, %s) = (%s, %v), want (%s, %v)\n  why this matters: %s",
					tc.requested, tc.gateTimeout, got, clamped, tc.wantEffective, tc.wantClamped, tc.why)
			}
		})
	}
}

// TestLandLeaderTakeoverClampIsSafeForAnyGateTimeout is the property the two
// tables above only sample: whatever an operator asks for, an ENABLED takeover
// threshold always ends up strictly greater than the gate timeout. If this ever
// fails, some (requested, gateTimeout) pair can steal the sentinel from a leader
// that is merely running a slow gate — a double writer on main.
func TestLandLeaderTakeoverClampIsSafeForAnyGateTimeout(t *testing.T) {
	gates := []time.Duration{
		0, time.Second, 30 * time.Second, time.Minute, 5 * time.Minute,
		20 * time.Minute, time.Hour, 3 * time.Hour,
	}
	requests := []time.Duration{
		time.Nanosecond, time.Second, time.Minute, 10 * time.Minute,
		landqDefaultTakeoverAfter, 24 * time.Hour,
	}
	for _, g := range gates {
		for _, r := range requests {
			effective, _ := resolveLandLeaderTakeover(r, g)
			if effective <= 0 {
				t.Fatalf("enabled request %s became disabled at gate=%s", r, g)
			}
			if effective <= g {
				t.Errorf("UNSAFE: gate=%s request=%s -> effective=%s, which is not greater than the gate timeout; "+
					"a leader running a full-length gate could be stolen", g, r, effective)
			}
			if effective < landqTakeoverMinFloor {
				t.Errorf("gate=%s request=%s -> effective=%s, below the absolute floor %s",
					g, r, effective, landqTakeoverMinFloor)
			}
		}
	}
}

// --- DB-level CAS tests (ephemeral Postgres only) ---------------------------
//
// These pin takeoverLandLeader's compare-and-swap against a real server, where
// the staleness predicate is evaluated by Postgres' own clock. They manipulate
// the fixed __land_leader__ sentinel, so like their siblings they run ONLY
// against a throwaway instance and never the shared production registry.

// TestTakeoverLandLeader_ReclaimsAProvablyDeadLeader is the regression for the
// 2026-08-18 strand: a sentinel whose holder is gone must be reclaimable without
// an operator running `lockserver unlock --force`.
func TestTakeoverLandLeader_ReclaimsAProvablyDeadLeader(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const dead = "landq-runner-rebooted-box"
	const fresh = "landq-runner-new-candidate"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	if won, _, err := ls.acquireLandLeader(dead, "old-host"); err != nil || !won {
		t.Fatalf("seeding the incumbent: won=%v err=%v", won, err)
	}
	// The box rebooted 11h41m ago and never released.
	ageForeignLock(t, ls, landLeaderSentinel, 11*time.Hour+41*time.Minute)

	// A plain acquire still loses — this is the behavior that stranded the queue.
	if won, holder, err := ls.acquireLandLeader(fresh, "new-host"); err != nil {
		t.Fatalf("acquireLandLeader: %v", err)
	} else if won {
		t.Fatalf("acquire() unexpectedly won a held sentinel — the single-writer guarantee changed")
	} else if holder == nil || holder.LockedBy != dead {
		t.Fatalf("holder = %+v, want the dead incumbent %q", holder, dead)
	}

	stole, err := ls.takeoverLandLeader(fresh, "new-host", dead, 45*time.Minute)
	if err != nil {
		t.Fatalf("takeoverLandLeader: %v", err)
	}
	if !stole {
		t.Fatalf("takeover did NOT reclaim a sentinel silent for 11h41m — the queue would stay stranded")
	}
	h, err := ls.holder(landLeaderSentinel)
	if err != nil || h == nil {
		t.Fatalf("holder after takeover: %+v err=%v", h, err)
	}
	if h.LockedBy != fresh {
		t.Errorf("sentinel holder = %q, want %q", h.LockedBy, fresh)
	}
	if time.Since(h.LockedAt) > 5*time.Minute {
		t.Errorf("locked_at was not refreshed on takeover (age %s) — the new leader would look stale immediately",
			time.Since(h.LockedAt).Round(time.Second))
	}
}

// TestTakeoverLandLeader_RefusesALiveLeader is the safety half: a leader whose
// heartbeat is current must never be stolen, or two writers race onto main.
func TestTakeoverLandLeader_RefusesALiveLeader(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const live = "landq-runner-alive"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	if won, _, err := ls.acquireLandLeader(live, devHost()); err != nil || !won {
		t.Fatalf("seeding the incumbent: won=%v err=%v", won, err)
	}
	// Mid-gate: locked_at is 19 minutes old, just under a 20m gate timeout.
	ageForeignLock(t, ls, landLeaderSentinel, 19*time.Minute)

	stole, err := ls.takeoverLandLeader("challenger", "other-host", live, 40*time.Minute)
	if err != nil {
		t.Fatalf("takeoverLandLeader: %v", err)
	}
	if stole {
		t.Fatalf("STOLE the sentinel from a leader only 19m silent under a 40m threshold — double writer on main")
	}
	if h, _ := ls.holder(landLeaderSentinel); h == nil || h.LockedBy != live {
		t.Fatalf("incumbent lost its sentinel: holder=%+v want %q", h, live)
	}
}

// TestTakeoverLandLeader_OnlyOneChallengerWins pins the CAS guard. Two candidates
// racing the same dead leader must not both conclude they are the leader.
func TestTakeoverLandLeader_OnlyOneChallengerWins(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const dead = "landq-runner-dead"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	if won, _, err := ls.acquireLandLeader(dead, "old-host"); err != nil || !won {
		t.Fatalf("seeding the incumbent: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, landLeaderSentinel, 2*time.Hour)

	// Both challengers observed the SAME dead holder, as two racing candidates would.
	first, err := ls.takeoverLandLeader("challenger-a", "host-a", dead, 45*time.Minute)
	if err != nil {
		t.Fatalf("first takeover: %v", err)
	}
	second, err := ls.takeoverLandLeader("challenger-b", "host-b", dead, 45*time.Minute)
	if err != nil {
		t.Fatalf("second takeover: %v", err)
	}
	if !first {
		t.Fatalf("the first challenger failed to take over a 2h-silent sentinel")
	}
	if second {
		t.Fatalf("BOTH challengers won the sentinel — the compare-and-swap on locked_by is not holding")
	}
}

// TestTakeoverLandLeader_DisabledAndGuardArgs: the disabled switch and the empty
// prevHolder guard must short-circuit BEFORE touching the DB, so a misconfigured
// caller can never issue an unguarded UPDATE against the sentinel row.
func TestTakeoverLandLeader_DisabledAndGuardArgs(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const held = "landq-runner-incumbent"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	if won, _, err := ls.acquireLandLeader(held, "a-host"); err != nil || !won {
		t.Fatalf("seeding the incumbent: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, landLeaderSentinel, 99*time.Hour)

	for _, tc := range []struct {
		name       string
		prevHolder string
		staleAfter time.Duration
	}{
		{"takeover disabled by zero threshold", held, 0},
		{"takeover disabled by negative threshold", held, -time.Hour},
		{"empty prevHolder is not an unguarded update", "", 45 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stole, err := ls.takeoverLandLeader("challenger", "host-c", tc.prevHolder, tc.staleAfter)
			if err != nil {
				t.Fatalf("takeoverLandLeader: %v", err)
			}
			if stole {
				t.Fatalf("took over the sentinel with %s", tc.name)
			}
			if h, _ := ls.holder(landLeaderSentinel); h == nil || h.LockedBy != held {
				t.Fatalf("incumbent displaced: holder=%+v want %q", h, held)
			}
		})
	}
}

// --- resource-exhaustion classification -------------------------------------
//
// A gate that dies because the BOX ran out of disk/quota/memory exits non-zero
// cleanly, so without this classification it parks the row [failed] and reads as
// "this branch is red". Row #6658 did exactly that in 10s — and the identical
// gate on the identical commit went green the moment TMPDIR moved off the full
// tmpfs. Misattributing a machine problem to the code sends the next reader to
// debug something that was never broken, so it is worse than a loud abort.

func TestGateOutputIndicatesExhaustion(t *testing.T) {
	cases := []struct {
		name       string
		out        string
		wantMarker string
		wantHit    bool
	}{
		{
			name:       "the real #6658 output",
			out:        "# github.com/dream-serpent/dream-serpent/client/cmd/ds-tui\n/usr/lib/go/pkg/tool/linux_amd64/link: mapping output file failed: disk quota exceeded\ncompile: writing output: write $WORK/b199/_pkg_.a: disk quota exceeded\n",
			wantMarker: "disk quota exceeded", wantHit: true,
		},
		{
			name:       "ENOSPC from a cargo build",
			out:        "error: failed to write /home/x/target/debug/deps/foo: No space left on device (os error 28)",
			wantMarker: "no space left on device", wantHit: true,
		},
		{
			name:       "ENOMEM from the linker",
			out:        "ld: final link failed: Cannot allocate memory",
			wantMarker: "cannot allocate memory", wantHit: true,
		},
		{
			name:       "an ordinary RED gate is NOT exhaustion",
			out:        "./main.go:12:2: undefined: doesNotExist\nFAIL\tgithub.com/x/y [build failed]\n",
			wantMarker: "", wantHit: false,
		},
		{
			name:       "a failing test is NOT exhaustion",
			out:        "--- FAIL: TestThing (0.00s)\n    thing_test.go:9: got 1, want 2\nFAIL\n",
			wantMarker: "", wantHit: false,
		},
		{
			name: "empty output is not exhaustion",
			out:  "", wantMarker: "", wantHit: false,
		},
		{
			name:       "matching is case-insensitive",
			out:        "WRITE FAILED: DISK QUOTA EXCEEDED",
			wantMarker: "disk quota exceeded", wantHit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker, hit := gateOutputIndicatesExhaustion(tc.out)
			if hit != tc.wantHit || marker != tc.wantMarker {
				t.Errorf("gateOutputIndicatesExhaustion = (%q, %v), want (%q, %v)",
					marker, hit, tc.wantMarker, tc.wantHit)
			}
		})
	}
}

// TestRunGate_ExhaustionIsTransientNotRed is the end-to-end classification: a
// gate that exits non-zero AND names an exhaustion errno must come back
// transient (requeue + honest detail), never a red gate (park the branch).
func TestRunGate_ExhaustionIsTransientNotRed(t *testing.T) {
	wt := t.TempDir()

	red := runGate(wt, `echo "./main.go:12:2: undefined: nope"; exit 1`, 30*time.Second)
	if red.ok {
		t.Fatalf("control gate unexpectedly passed")
	}
	if red.transient {
		t.Errorf("an ordinary compile error was classified TRANSIENT — real red gates would requeue forever instead of parking")
	}
	if red.exhausted != "" {
		t.Errorf("exhausted=%q on an ordinary compile error", red.exhausted)
	}

	full := runGate(wt, `echo "link: mapping output file failed: disk quota exceeded"; exit 1`, 30*time.Second)
	if full.ok {
		t.Fatalf("exhaustion gate unexpectedly passed")
	}
	if !full.transient {
		t.Errorf("a disk-quota failure was classified as a RED gate — the branch gets blamed for the box being full (this is #6658)")
	}
	if full.exhausted != "disk quota exceeded" {
		t.Errorf("exhausted = %q, want %q so the row detail can name the real cause", full.exhausted, "disk quota exceeded")
	}
	if full.exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 (exhaustion still exits cleanly — that is why it needs output inspection)", full.exitCode)
	}
}

// TestGateScratchDir_NamesTheDirectoryGoWillActuallyUse: the operator message is
// only useful if it points at the right directory, and GOTMPDIR wins over TMPDIR
// for Go's $WORK.
func TestGateScratchDir_NamesTheDirectoryGoWillActuallyUse(t *testing.T) {
	t.Setenv("TMPDIR", "/home/u/tmp/landq/gobuild")
	t.Setenv("GOTMPDIR", "/home/u/tmp/landq/go-override")
	if got := gateScratchDir(); got != "/home/u/tmp/landq/go-override" {
		t.Errorf("gateScratchDir = %q, want the GOTMPDIR override", got)
	}

	t.Setenv("GOTMPDIR", "")
	if got := gateScratchDir(); got != "/home/u/tmp/landq/gobuild" {
		t.Errorf("gateScratchDir = %q, want the TMPDIR value when GOTMPDIR is empty", got)
	}

	t.Setenv("TMPDIR", "")
	got := gateScratchDir()
	if !strings.Contains(got, "/tmp") {
		t.Errorf("gateScratchDir = %q, want it to name /tmp when both are unset", got)
	}
	if !strings.Contains(got, "unset") {
		t.Errorf("gateScratchDir = %q — with both unset the message should SAY so; a bare %q reads like a deliberate setting", got, "/tmp")
	}
}
