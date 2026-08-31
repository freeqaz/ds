// state.go — owned by impl-state: the ATTACHED⇄WORKING latch, terminal
// classification (closed-set outcome, never stop_reason), session.accounted,
// and quota passthrough.
//
// Only ATTACHED and WORKING have a CC-wire source (P9 / PHASE3 §2); the
// adapter must never synthesize the orchestrator-owned doc 15 §3 states. The
// WORKING latch is driven by two signals — a status=="requesting" ping OR any
// open task_* (tree.go maintains Adapter.openTasks) — and SessionState is
// emitted on transitions only.
package claudecode

import "github.com/dream-serpent/dream-serpent/client/wrapper/attach"

// setWorking moves the ATTACHED⇄WORKING latch to want and, on a transition,
// returns the single SessionState event carrying reason. No transition ⇒ no
// event (SessionState emits on transitions only, P9). source is the uuid of
// the CC record that drove the change, for Source stamping.
func (a *Adapter) setWorking(want bool, reason, source string) []attach.Event {
	if a.working == want {
		return nil
	}
	a.working = want
	state := attach.StateAttached
	if want {
		state = attach.StateWorking
	}
	ev := a.emit(attach.Event{
		Type: attach.TypeSessionState,
		SessionState: &attach.SessionState{
			State:  state,
			Reason: reason,
		},
	}, source)
	return []attach.Event{ev}
}

// handleStatus toggles WORKING on status.status == "requesting" (P9: the only
// print-mode value — a request-in-flight signal, not a state enum), reading
// Adapter.openTasks (maintained by tree.go). Emit SessionState on transitions
// only; never synthesize orchestrator-owned states.
//
// Desired latch = requesting-ping OR any open task; a non-requesting ping with
// no open task drops back to ATTACHED. Open tasks keep WORKING latched
// regardless of the ping value (an open task is itself a WORKING signal, P9).
func (a *Adapter) handleStatus(rec *statusRecord) ([]attach.Event, error) {
	requesting := rec.Status == "requesting"
	if !requesting {
		// Unobserved in print mode (only "requesting" was ever seen, P9): a
		// non-requesting status value carries no state meaning the adapter can
		// trust. Record it and leave the latch to the open-task signal.
		a.warnf("unexpected status %q (uuid %s): only \"requesting\" is print-mode observed (P9)", rec.Status, rec.UUID)
	}
	want := requesting || len(a.openTasks) > 0
	// reason describes the transition the status ping drives: "requesting" only
	// when a requesting ping enters WORKING; "task_open" when an open task holds
	// WORKING under a non-requesting ping; "turn_complete" when a non-requesting
	// ping with no open task drops back to ATTACHED ("requesting" would mislabel
	// a WORKING→ATTACHED edge). Only the requesting value is observed in print
	// mode (P9), so the latter two are reached only by an unobserved richer enum.
	var reason string
	switch {
	case requesting:
		reason = "requesting"
	case want:
		reason = "task_open"
	default:
		reason = "turn_complete"
	}
	return a.setWorking(want, reason, rec.UUID), nil
}

// handleResult emits SessionAccounted (closed-set outcome per P13; optional
// terminal_reason — absent on the budget terminal; NEVER branch on
// stop_reason), returns to ATTACHED when no tasks remain open, and hands
// permission_denials[] to ask.go's handleDenials for unresolved-denial
// emission and terminal cancellation of open asks.
//
// Emission order: SessionAccounted first (the terminal accounting), then any
// ask resolutions the denial handover produces, then the ATTACHED transition
// (the turn has fully closed once accounting and ask cleanup are done).
func (a *Adapter) handleResult(rec *resultRecord) ([]attach.Event, error) {
	var events []attach.Event

	// Outcome is result.subtype verbatim — the closed set
	// {success, error_during_execution, error_max_turns, error_max_budget_usd,
	// error_max_structured_output_retries} (P13). terminal_reason passes
	// through as-is (empty/absent on the budget terminal, max_turns on
	// error_max_turns); NEVER branch on stop_reason (P9: nondeterministic).
	events = append(events, a.emit(attach.Event{
		Type: attach.TypeSessionAccounted,
		SessionAccounted: &attach.SessionAccounted{
			Outcome:        rec.Subtype,
			IsError:        rec.IsError,
			NumTurns:       rec.NumTurns,
			DurationMS:     rec.DurationMS,
			TotalCostUSD:   rec.TotalCostUSD,
			TerminalReason: rec.TerminalReason,
			Errors:         rec.Errors,
			Usage:          rec.Usage,
			ModelUsage:     rec.ModelUsage,
			DenialCount:    len(rec.PermissionDenials),
		},
	}, rec.UUID))

	// Hand permission_denials[] to ask.go: emit AskResolved for denials whose
	// ask is still open, and cancel any asks left unanswered at terminal.
	denialEvents, err := a.handleDenials(rec.PermissionDenials, rec.UUID)
	if err != nil {
		return events, err
	}
	events = append(events, denialEvents...)

	// A result with no open task returns the run loop to ATTACHED (P9). The
	// terminal is per-invocation, not per-session — the orchestrator owns any
	// re-drive — so the adapter only reports the local loop returning to idle.
	if len(a.openTasks) == 0 {
		events = append(events, a.setWorking(false, "turn_complete", rec.UUID)...)
	}

	return events, nil
}

// handleRateLimit emits QuotaUpdated 1:1 — a verbatim passthrough of
// rate_limit_info with Semantics fixed to provisional (P18 open). ResetsAt is
// carried as raw JSON: its wire type is unpinned (P18), so the adapter never
// reinterprets it.
func (a *Adapter) handleRateLimit(rec *rateLimitRecord) ([]attach.Event, error) {
	info := rec.RateLimitInfo
	ev := a.emit(attach.Event{
		Type: attach.TypeQuotaUpdated,
		QuotaUpdated: &attach.QuotaUpdated{
			RateLimitType:         info.RateLimitType,
			Status:                info.Status,
			ResetsAt:              info.ResetsAt,
			IsUsingOverage:        info.IsUsingOverage,
			OverageStatus:         info.OverageStatus,
			OverageDisabledReason: info.OverageDisabledReason,
			Semantics:             attach.QuotaSemanticsProvisional,
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}
