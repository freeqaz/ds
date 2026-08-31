// state_test.go — owned by impl-state. Table-driven unit tests feeding
// hand-rolled NDJSON record lines through a fresh Adapter with a deterministic
// clock, asserting the ATTACHED⇄WORKING latch, SessionAccounted (closed-set
// outcome, terminal_reason absent on budget, never stop_reason), and the
// QuotaUpdated passthrough. These do NOT depend on client/fixtures/ cassettes
// (those are integration-level, via the golden test).
package claudecode

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// fixedClock returns the replay-style deterministic clock: a base time plus
// one second per call, so seq/observed_at are stable across runs.
func fixedClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := int64(0)
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// feed runs the given raw NDJSON lines through one fresh adapter (deterministic
// clock) and returns the concatenated projection. A line decode error fails the
// test immediately — these are hand-authored, well-formed records.
func feed(t *testing.T, lines ...string) (*Adapter, []attach.Event) {
	t.Helper()
	a := New(WithClock(fixedClock()))
	var out []attach.Event
	for i, line := range lines {
		evs, err := a.Feed([]byte(line))
		if err != nil {
			t.Fatalf("Feed line %d returned error: %v\nline: %s", i, err, line)
		}
		out = append(out, evs...)
	}
	return a, out
}

// types extracts the ordered list of event types, for ordering assertions.
func types(evs []attach.Event) []attach.Type {
	out := make([]attach.Type, len(evs))
	for i, ev := range evs {
		out[i] = ev.Type
	}
	return out
}

func typesEqual(got []attach.Event, want ...attach.Type) bool {
	g := types(got)
	if len(g) != len(want) {
		return false
	}
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

const (
	statusRequesting = `{"type":"system","subtype":"status","uuid":"u-status-1","session_id":"s1","status":"requesting"}`
	resultSuccess    = `{"type":"result","subtype":"success","uuid":"u-result-1","session_id":"s1","is_error":false,"num_turns":2,"stop_reason":"end_turn","terminal_reason":"completed","total_cost_usd":0.0123,"duration_ms":4200,"usage":{"input_tokens":10,"output_tokens":20},"modelUsage":{"sonnet":{"costUSD":0.0123}}}`
)

// TestStatusToWorkingTransition: a requesting ping latches WORKING with reason
// "requesting"; the terminal result returns to ATTACHED with "turn_complete".
func TestStatusToWorkingTransition(t *testing.T) {
	a, evs := feed(t, statusRequesting, resultSuccess)

	if !typesEqual(evs, attach.TypeSessionState, attach.TypeSessionAccounted, attach.TypeSessionState) {
		t.Fatalf("unexpected event types: %v", types(evs))
	}

	if got := evs[0].SessionState.State; got != attach.StateWorking {
		t.Errorf("first transition state = %q, want WORKING", got)
	}
	if got := evs[0].SessionState.Reason; got != "requesting" {
		t.Errorf("WORKING reason = %q, want \"requesting\"", got)
	}
	if got := evs[2].SessionState.State; got != attach.StateAttached {
		t.Errorf("final transition state = %q, want ATTACHED", got)
	}
	if got := evs[2].SessionState.Reason; got != "turn_complete" {
		t.Errorf("ATTACHED reason = %q, want \"turn_complete\"", got)
	}
	if a.working {
		t.Errorf("latch left WORKING after terminal result")
	}

	// Source stamping + monotonic seq from 1.
	if len(evs[0].Source) != 1 || evs[0].Source[0] != "u-status-1" {
		t.Errorf("status event Source = %v, want [u-status-1]", evs[0].Source)
	}
	for i, ev := range evs {
		if ev.Seq != uint64(i+1) {
			t.Errorf("event %d Seq = %d, want %d", i, ev.Seq, i+1)
		}
		if ev.SessionID != "s1" {
			t.Errorf("event %d SessionID = %q, want s1", i, ev.SessionID)
		}
	}
}

// TestStatusNoDuplicateTransition: two requesting pings in a row latch WORKING
// once; SessionState is emitted on transitions only.
func TestStatusNoDuplicateTransition(t *testing.T) {
	_, evs := feed(t, statusRequesting, statusRequesting)
	if !typesEqual(evs, attach.TypeSessionState) {
		t.Fatalf("want exactly one SessionState, got %v", types(evs))
	}
	if evs[0].SessionState.State != attach.StateWorking {
		t.Errorf("state = %q, want WORKING", evs[0].SessionState.State)
	}
}

// TestStatusOpenTaskKeepsWorking: with a task already open, a non-requesting
// status must NOT drop the latch back to ATTACHED (an open task is itself a
// WORKING signal, P9), and is recorded as an unexpected status value.
func TestStatusOpenTaskKeepsWorking(t *testing.T) {
	a := New(WithClock(fixedClock()))
	a.working = true
	a.openTasks["task-x"] = struct{}{}

	rec := &statusRecord{Status: "idle", UUID: "u-idle"}
	evs, err := a.handleStatus(rec)
	if err != nil {
		t.Fatalf("handleStatus error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("expected no transition (latch stays WORKING), got %v", types(evs))
	}
	if !a.working {
		t.Errorf("latch dropped to ATTACHED despite open task")
	}
	if len(a.Warnings()) == 0 {
		t.Errorf("expected a warning for the unobserved status value")
	}
}

// TestResultSuccessAccounting: a success terminal emits SessionAccounted with
// the verbatim closed-set outcome, integer/float scalars, raw usage/modelUsage
// passthrough, and denial_count 0; then the ATTACHED transition.
func TestResultSuccessAccounting(t *testing.T) {
	// Latch WORKING first (requesting ping) so the terminal genuinely fires
	// the ATTACHED transition — the baseline-chat cassette flow.
	_, evs := feed(t, statusRequesting, resultSuccess)

	if !typesEqual(evs, attach.TypeSessionState, attach.TypeSessionAccounted, attach.TypeSessionState) {
		t.Fatalf("unexpected event types: %v", types(evs))
	}
	if evs[2].SessionState.State != attach.StateAttached {
		t.Errorf("final transition state = %q, want ATTACHED", evs[2].SessionState.State)
	}
	acc := evs[1].SessionAccounted
	if acc.Outcome != "success" {
		t.Errorf("Outcome = %q, want success", acc.Outcome)
	}
	if acc.IsError {
		t.Errorf("IsError = true, want false")
	}
	if acc.NumTurns != 2 {
		t.Errorf("NumTurns = %d, want 2", acc.NumTurns)
	}
	if acc.DurationMS != 4200 {
		t.Errorf("DurationMS = %d, want 4200", acc.DurationMS)
	}
	if acc.TotalCostUSD != 0.0123 {
		t.Errorf("TotalCostUSD = %v, want 0.0123", acc.TotalCostUSD)
	}
	if acc.TerminalReason != "completed" {
		t.Errorf("TerminalReason = %q, want completed", acc.TerminalReason)
	}
	if acc.DenialCount != 0 {
		t.Errorf("DenialCount = %d, want 0", acc.DenialCount)
	}
	if len(acc.Errors) != 0 {
		t.Errorf("Errors = %v, want empty", acc.Errors)
	}
	// usage/modelUsage are raw passthrough — verify they round-trip as JSON,
	// never reinterpreted.
	var usage map[string]int
	if err := json.Unmarshal(acc.Usage, &usage); err != nil {
		t.Fatalf("Usage not valid JSON: %v", err)
	}
	if usage["input_tokens"] != 10 || usage["output_tokens"] != 20 {
		t.Errorf("Usage = %v, want input_tokens=10 output_tokens=20", usage)
	}
	if len(acc.ModelUsage) == 0 {
		t.Errorf("ModelUsage passthrough is empty")
	}
}

// TestResultBudgetTerminal: the budget terminal carries is_error true, free-text
// errors[], NO terminal_reason, and an arbitrary stop_reason — the adapter must
// pass the closed-set subtype through and NEVER branch on stop_reason.
func TestResultBudgetTerminal(t *testing.T) {
	// stop_reason is deliberately "tool_use" here (nondeterministic on this
	// terminal, P9) — the projection must ignore it entirely.
	const budget = `{"type":"result","subtype":"error_max_budget_usd","uuid":"u-budget","session_id":"s1","is_error":true,"num_turns":5,"stop_reason":"tool_use","errors":["budget of $0.01 exceeded"],"total_cost_usd":0.0101}`
	_, evs := feed(t, statusRequesting, budget)

	if !typesEqual(evs, attach.TypeSessionState, attach.TypeSessionAccounted, attach.TypeSessionState) {
		t.Fatalf("unexpected event types: %v", types(evs))
	}
	acc := evs[1].SessionAccounted
	if acc.Outcome != "error_max_budget_usd" {
		t.Errorf("Outcome = %q, want error_max_budget_usd", acc.Outcome)
	}
	if !acc.IsError {
		t.Errorf("IsError = false, want true")
	}
	if acc.TerminalReason != "" {
		t.Errorf("TerminalReason = %q, want empty (absent on budget terminal)", acc.TerminalReason)
	}
	if len(acc.Errors) != 1 || acc.Errors[0] != "budget of $0.01 exceeded" {
		t.Errorf("Errors = %v, want the free-text budget message", acc.Errors)
	}
}

// TestResultMaxTurnsKeepsTerminalReason: the max-turns terminal keeps
// terminal_reason="max_turns" (it is only dropped on the budget terminal, P13),
// and the outcome is the verbatim subtype.
func TestResultMaxTurnsKeepsTerminalReason(t *testing.T) {
	const maxTurns = `{"type":"result","subtype":"error_max_turns","uuid":"u-turns","session_id":"s1","is_error":true,"num_turns":9,"stop_reason":"tool_use","terminal_reason":"max_turns","errors":["max turns reached"]}`
	_, evs := feed(t, maxTurns)
	acc := evs[0].SessionAccounted
	if acc.Outcome != "error_max_turns" {
		t.Errorf("Outcome = %q, want error_max_turns", acc.Outcome)
	}
	if acc.TerminalReason != "max_turns" {
		t.Errorf("TerminalReason = %q, want max_turns", acc.TerminalReason)
	}
}

// TestResultWithDenialsCount: result.permission_denials[] sets DenialCount on
// the accounting event (the per-denial AskResolved emission belongs to ask.go,
// which state.go hands off to — not asserted here).
func TestResultWithDenialsCount(t *testing.T) {
	const denied = `{"type":"result","subtype":"success","uuid":"u-denied","session_id":"s1","is_error":false,"num_turns":1,"stop_reason":"end_turn","terminal_reason":"completed","permission_denials":[{"tool_name":"Bash","tool_use_id":"toolu_SYNTH1","tool_input":{"command":"rm"}},{"tool_name":"Bash","tool_use_id":"toolu_SYNTH2","tool_input":{"command":"ls"}}]}`
	_, evs := feed(t, denied)
	acc := evs[0].SessionAccounted
	if acc.DenialCount != 2 {
		t.Errorf("DenialCount = %d, want 2", acc.DenialCount)
	}
	// Outcome stays success even with denials present (a denial keeps
	// subtype==success, P8/P13).
	if acc.Outcome != "success" {
		t.Errorf("Outcome = %q, want success (denials keep subtype success)", acc.Outcome)
	}
}

// TestResultWhileTaskOpenStaysWorking: a terminal result with an open task does
// NOT emit the ATTACHED transition — only a result with no open tasks returns to
// ATTACHED (P9).
func TestResultWhileTaskOpenStaysWorking(t *testing.T) {
	a := New(WithClock(fixedClock()))
	a.working = true
	a.openTasks["task-open"] = struct{}{}

	var rec resultRecord
	if err := json.Unmarshal([]byte(resultSuccess), &rec); err != nil {
		t.Fatalf("decode resultSuccess: %v", err)
	}
	a.sessionID = "s1"
	evs, err := a.handleResult(&rec)
	if err != nil {
		t.Fatalf("handleResult error: %v", err)
	}
	if !typesEqual(evs, attach.TypeSessionAccounted) {
		t.Fatalf("want only SessionAccounted (no ATTACHED transition), got %v", types(evs))
	}
	if !a.working {
		t.Errorf("latch dropped to ATTACHED despite open task")
	}
}

// TestRateLimitPassthrough: QuotaUpdated is a verbatim passthrough of
// rate_limit_info with Semantics fixed to provisional and ResetsAt carried raw.
func TestRateLimitPassthrough(t *testing.T) {
	const rl = `{"type":"rate_limit_event","uuid":"u-rl","session_id":"s1","rate_limit_info":{"rateLimitType":"tokens","status":"allowed","resetsAt":1893456000,"isUsingOverage":true,"overageStatus":"active","overageDisabledReason":""}}`
	_, evs := feed(t, rl)

	if !typesEqual(evs, attach.TypeQuotaUpdated) {
		t.Fatalf("want exactly one QuotaUpdated, got %v", types(evs))
	}
	q := evs[0].QuotaUpdated
	if q.Semantics != attach.QuotaSemanticsProvisional {
		t.Errorf("Semantics = %q, want provisional", q.Semantics)
	}
	if q.RateLimitType != "tokens" {
		t.Errorf("RateLimitType = %q, want tokens", q.RateLimitType)
	}
	if q.Status != "allowed" {
		t.Errorf("Status = %q, want allowed", q.Status)
	}
	if !q.IsUsingOverage {
		t.Errorf("IsUsingOverage = false, want true")
	}
	if q.OverageStatus != "active" {
		t.Errorf("OverageStatus = %q, want active", q.OverageStatus)
	}
	// ResetsAt is raw passthrough — wire type unpinned (P18); here a number.
	if string(q.ResetsAt) != "1893456000" {
		t.Errorf("ResetsAt = %s, want raw 1893456000", q.ResetsAt)
	}
	if len(evs[0].Source) != 1 || evs[0].Source[0] != "u-rl" {
		t.Errorf("Source = %v, want [u-rl]", evs[0].Source)
	}
}

// TestResultStandaloneNoTransition: a result with the latch already ATTACHED
// (no prior WORKING) emits SessionAccounted but no spurious SessionState — the
// transition only fires when the latch actually changes.
func TestResultStandaloneNoTransition(t *testing.T) {
	a := New(WithClock(fixedClock()))
	a.sessionID = "s1"
	// working defaults to false (ATTACHED).
	var rec resultRecord
	if err := json.Unmarshal([]byte(resultSuccess), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	evs, err := a.handleResult(&rec)
	if err != nil {
		t.Fatalf("handleResult error: %v", err)
	}
	if !typesEqual(evs, attach.TypeSessionAccounted) {
		t.Fatalf("want only SessionAccounted (already ATTACHED), got %v", types(evs))
	}
}
