package sessions

import (
	"expvar"
	"fmt"
	"testing"
)

// TestStep9StalenessBudgetSelfReport_PublishesResolvedBudget proves the startup expvar
// SELF-REPORT of the §4.1 step-9 D72 STALENESS BUDGET (the re-check window) reflects the
// RESOLVED value an operator would read off /debug/vars: the negative-input clamp to 0 (the
// strictest budget), a zero/exact-match budget, and a positive window are each published
// verbatim. The package-init var is SET (not re-registered) at every NewSessionCreator, so a
// constructed coordinator's resolved stalenessBudget equals the published self-report; the
// per-resolution cases drive publishStep9StalenessBudget against a fresh expvar.Int (the same
// fresh-var-per-test discipline the degrade-cap self-report test uses) so the published value
// is asserted across resolved inputs without re-registering the stable global name.
func TestStep9StalenessBudgetSelfReport_PublishesResolvedBudget(t *testing.T) {
	// A constructed coordinator publishes its RESOLVED budget to the operator-visible var.
	// NewSessionCreator clamps a negative input to 0; the self-report must equal what the
	// coordinator actually enforces (c.stalenessBudget), the value an operator confirms via
	// /debug/vars.
	budgetCases := []struct {
		name   string
		input  int64 // the budget passed to NewSessionCreator
		expect int64 // the resolved value (post-clamp) the self-report must publish
	}{
		{name: "exact_match_zero", input: 0, expect: 0},
		{name: "positive_window", input: 7, expect: 7},
		{name: "large_window", input: 4096, expect: 4096},
		{name: "negative_clamped_to_zero", input: -5, expect: 0},
	}
	for _, tc := range budgetCases {
		t.Run("constructed_"+tc.name, func(t *testing.T) {
			h := newHarness(t, true)
			c, err := NewSessionCreator(h.seams, tc.input, nil)
			if err != nil {
				t.Fatalf("NewSessionCreator(budget=%d): %v", tc.input, err)
			}
			// The coordinator resolved the budget to expect…
			if c.stalenessBudget != tc.expect {
				t.Fatalf("c.stalenessBudget = %d, want %d (resolved from input %d)", c.stalenessBudget, tc.expect, tc.input)
			}
			// …and the operator-visible self-report tracks it.
			if got := step9StalenessBudgetReported(); got != tc.expect {
				t.Fatalf("step9StalenessBudgetReported() = %d, want %d (the resolved self-report after construction)", got, tc.expect)
			}
		})
	}

	// The publish helper writes the resolved budget verbatim to a fresh var across inputs —
	// the same single publish path NewSessionCreator drives — so the publish logic is pinned
	// without re-registering the global stable name.
	publishCases := []struct {
		name   string
		budget int64
	}{
		{name: "zero", budget: 0},
		{name: "one", budget: 1},
		{name: "window", budget: 16},
		{name: "large", budget: 65536},
	}
	for _, tc := range publishCases {
		t.Run("publish_"+tc.name, func(t *testing.T) {
			v := expvar.NewInt(fmt.Sprintf("test_step9_staleness_budget_selfreport_%s", t.Name()))
			if got := publishStep9StalenessBudget(v, tc.budget).Value(); got != tc.budget {
				t.Fatalf("publishStep9StalenessBudget(%d) published %d, want %d", tc.budget, got, tc.budget)
			}
		})
	}
}
