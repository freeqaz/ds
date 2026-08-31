package sessions

import (
	"expvar"
	"fmt"
	"os"
	"testing"
)

// TestResolveDegradeHostCap_EnvKnob proves the §4.1 step-9 per-host degrade-map LRU cap
// is the env-gated DS_ORCH_DEGRADE_HOST_CAP operator knob (D72), read ONCE at
// construction: unset → the 1024 default; a valid positive value → that exact cap; an
// invalid/zero/negative value → fail-safe fallback to the 1024 default. The cap only
// becomes env-driven; the orch25 eviction/overflow policy is unchanged (exercised by the
// guard tests in sessioncreate_test.go, which stay green with the default).
func TestResolveDegradeHostCap_EnvKnob(t *testing.T) {
	cases := []struct {
		name   string
		set    bool // whether the env var is present at all
		value  string
		expect int
	}{
		{name: "unset_defaults_1024", set: false, expect: defaultMaxDegradeHostKeys},
		{name: "empty_defaults_1024", set: true, value: "", expect: defaultMaxDegradeHostKeys},
		{name: "valid_value_used", set: true, value: "16", expect: 16},
		{name: "valid_one", set: true, value: "1", expect: 1},
		{name: "valid_large", set: true, value: "65536", expect: 65536},
		{name: "zero_clamped_to_default", set: true, value: "0", expect: defaultMaxDegradeHostKeys},
		{name: "negative_clamped_to_default", set: true, value: "-7", expect: defaultMaxDegradeHostKeys},
		{name: "non_integer_clamped_to_default", set: true, value: "lots", expect: defaultMaxDegradeHostKeys},
		{name: "trailing_garbage_clamped_to_default", set: true, value: "16x", expect: defaultMaxDegradeHostKeys},
		{name: "whitespace_clamped_to_default", set: true, value: "  16  ", expect: defaultMaxDegradeHostKeys},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(degradeHostCapEnv, tc.value)
			} else {
				// t.Setenv first registers a cleanup that restores the original value, so
				// the subsequent os.Unsetenv (which makes the var absent for this subtest,
				// regardless of the ambient environment / CI) leaks no env state: the
				// cleanup undoes it after the subtest.
				t.Setenv(degradeHostCapEnv, "sentinel")
				if err := os.Unsetenv(degradeHostCapEnv); err != nil {
					t.Fatalf("unset %s: %v", degradeHostCapEnv, err)
				}
			}
			if got := resolveDegradeHostCap(); got != tc.expect {
				t.Fatalf("resolveDegradeHostCap() with %q (set=%v) = %d, want %d", tc.value, tc.set, got, tc.expect)
			}
		})
	}
}

// TestResolveDegradeHostCap_DrivesGuardBound proves the resolved env cap is the bound the
// constructed guard ACTUALLY enforces (the knob is load-bearing, not cosmetic): a guard
// built with resolveDegradeHostCap()'s value retains exactly that many distinct per-host
// keys (the active set) before evicting the least-recently-degraded host into the
// "__other__" overflow bucket — the orch25 eviction policy, now under the env-driven cap.
func TestResolveDegradeHostCap_DrivesGuardBound(t *testing.T) {
	t.Setenv(degradeHostCapEnv, "3")
	cap := resolveDegradeHostCap()
	if cap != 3 {
		t.Fatalf("resolveDegradeHostCap() = %d, want 3", cap)
	}
	m := expvar.NewMap(fmt.Sprintf("test_degrade_cap_knob_bound_%s", t.Name()))
	g := newDegradeHostGuard(m, cap)

	// Degrade cap+2 distinct hosts; only the cap most-recent stay as exact keys, the rest
	// fold into the overflow bucket. Active-set keys + the overflow bucket = cap+1 keys.
	for i := 0; i < cap+2; i++ {
		g.recordDegradeByHost(fmt.Sprintf("host-%d", i))
	}
	distinct := 0
	m.Do(func(expvar.KeyValue) { distinct++ })
	if distinct != cap+1 {
		t.Fatalf("guard under env cap=%d retained %d keys, want %d (active set + overflow)", cap, distinct, cap+1)
	}
	// The two earliest hosts were evicted into the overflow bucket (no degrade lost).
	if got := overflowValue(m); got != 2 {
		t.Fatalf("overflow bucket = %d, want 2 (the two least-recently-degraded hosts folded)", got)
	}
}

// overflowValue reads the reserved overflow bucket's accumulated count from a map.
func overflowValue(m *expvar.Map) int64 {
	if v, ok := m.Get(degradeOverflowKey).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

// TestDegradeHostCapSelfReport_PublishesResolvedCap proves the startup expvar SELF-REPORT
// of the §4.1 step-9 per-host degrade-map cap (D72) reflects the RESOLVED value an
// operator would read off /debug/vars — the default when the env is unset, the env value
// when set, and the clamp floor when the env (or a direct cap) is non-positive. The
// global self-report (step9DegradeHostCapReported) is published ONCE at package init from
// the resolved-and-clamped step9DegradeGuard.max, so it equals that bound; the
// per-resolution cases drive publishDegradeHostCap against a fresh expvar.Int (the same
// fresh-var-per-test discipline TestResolveDegradeHostCap_DrivesGuardBound uses for the
// map) so the published value can be asserted across env/clamp inputs without
// re-registering the stable global name.
func TestDegradeHostCapSelfReport_PublishesResolvedCap(t *testing.T) {
	// The process-global self-report equals the guard's effective (resolved + clamped) cap,
	// the value an operator confirms via /debug/vars.
	if got, want := step9DegradeHostCapReported(), int64(step9DegradeGuard.max); got != want {
		t.Fatalf("step9DegradeHostCapReported() = %d, want guard cap %d (the resolved self-report)", got, want)
	}

	cases := []struct {
		name   string
		cap    int   // the cap as resolveDegradeHostCap / newDegradeHostGuard would yield it
		expect int64 // the value the self-report must publish
	}{
		{name: "default_1024", cap: defaultMaxDegradeHostKeys, expect: int64(defaultMaxDegradeHostKeys)},
		{name: "env_value", cap: 16, expect: 16},
		{name: "env_one", cap: 1, expect: 1},
		{name: "large", cap: 65536, expect: 65536},
		{name: "nonpositive_clamped_to_one", cap: guardCap(0), expect: 1},
		{name: "negative_clamped_to_one", cap: guardCap(-7), expect: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := expvar.NewInt(fmt.Sprintf("test_degrade_host_cap_selfreport_%s", t.Name()))
			if got := publishDegradeHostCap(v, tc.cap).Value(); got != tc.expect {
				t.Fatalf("publishDegradeHostCap(%d) published %d, want %d", tc.cap, got, tc.expect)
			}
		})
	}
}

// guardCap returns the effective cap newDegradeHostGuard would enforce for a raw cap,
// so the self-report cases assert against the SAME clamp floor the guard applies (a
// non-positive cap floors to 1 — the bound is never unbounded or zero).
func guardCap(raw int) int {
	return newDegradeHostGuard(expvar.NewMap(fmt.Sprintf("test_guardcap_floor_%d", raw)), raw).max
}
