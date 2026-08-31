package tui

import (
	"fmt"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// format.go turns one attach.v1 payload into a single transcript-line string.
// These are pure functions of the wire fields — no clocks, no I/O — so the
// model fold and the renderer are deterministic and golden-testable. They
// render only fields that exist on the (unfrozen) attach Go shape; a field the
// renderer wants but the shape lacks is a freeze-checklist gap, recorded as a
// taskdb note, never invented here.

// excerptLimit bounds an inline excerpt; the wire already trims most to 256
// runes, this is a render-side safety clamp.
const excerptLimit = 200

func formatInit(s *attach.SessionInit) string {
	if s == nil {
		return "session attached"
	}
	parts := []string{"session attached"}
	if s.Model != "" {
		parts = append(parts, "model="+s.Model)
	}
	if s.RuntimeVersion != "" {
		parts = append(parts, "runtime="+s.RuntimeVersion)
	}
	if s.PermissionMode != "" {
		parts = append(parts, "perm="+s.PermissionMode)
	}
	if s.CWD != "" {
		parts = append(parts, "cwd="+s.CWD)
	}
	if len(s.Tools) > 0 {
		parts = append(parts, "tools=["+strings.Join(s.Tools, ",")+"]")
	}
	return strings.Join(parts, "  ")
}

func formatState(s *attach.SessionState) string {
	if s.Reason != "" {
		return fmt.Sprintf("state -> %s (%s)", s.State, s.Reason)
	}
	return "state -> " + s.State
}

func formatThinking(msg *attach.ChatMessage, b attach.ChatBlock) string {
	return "thinking: " + clamp(b.Text)
}

func formatChat(msg *attach.ChatMessage, b attach.ChatBlock) string {
	role := msg.Role
	if role == "" {
		role = "assistant"
	}
	return role + ": " + clamp(b.Text)
}

func formatTool(t *attach.ToolInvoked) string {
	name := t.Name
	switch t.Kind {
	case "mcp":
		if t.Server != "" || t.Tool != "" {
			name = fmt.Sprintf("%s (mcp %s/%s)", t.Name, t.Server, t.Tool)
		}
	case "skill":
		if t.Skill != "" {
			name = fmt.Sprintf("%s (skill %s)", t.Name, t.Skill)
		}
	}
	line := "tool " + name
	if in := compactInput(t.Input); in != "" {
		line += "  " + in
	}
	return line
}

func formatToolCompleted(t *attach.ToolCompleted) string {
	if t.DenialMessage != "" {
		return "tool denied: " + clamp(t.DenialMessage)
	}
	if t.IsError {
		return "tool error: " + clamp(t.OutputExcerpt)
	}
	if t.OutputExcerpt != "" {
		return "tool ok: " + clamp(t.OutputExcerpt)
	}
	return "tool ok"
}

func formatSubagent(s *attach.SubagentSpawned) string {
	label := s.SubagentType
	if label == "" {
		label = "subagent"
	}
	line := "spawn " + label
	if s.Description != "" {
		line += ": " + clamp(s.Description)
	}
	if s.ParentConfidence == "inferred" {
		line += " [parent inferred]"
	}
	return line
}

func formatSubProgress(s *attach.SubagentProgress) string {
	line := "  ... working"
	if s.LastToolName != "" {
		line += " (" + s.LastToolName + ")"
	}
	// UsageRaw is Uncharacterized — never rendered as token burn (attach.go).
	return line
}

func formatSubCompleted(s *attach.SubagentCompleted) string {
	status := s.Status
	if status == "" {
		status = "completed"
	}
	line := "subagent " + status
	if s.Summary != "" {
		line += ": " + clamp(s.Summary)
	}
	return line
}

func formatSubAccounted(s *attach.SubagentAccounted) string {
	parts := []string{"subagent accounted"}
	if s.SubagentTokens > 0 {
		parts = append(parts, fmt.Sprintf("tokens=%d", s.SubagentTokens))
	}
	if s.ToolUses > 0 {
		parts = append(parts, fmt.Sprintf("tools=%d", s.ToolUses))
	}
	if s.DurationMS > 0 {
		parts = append(parts, fmt.Sprintf("dur=%dms", s.DurationMS))
	}
	if s.OutputExcerpt != "" {
		parts = append(parts, "out="+clamp(s.OutputExcerpt))
	}
	// Continuation is display-only and gated in headless runs — never present
	// it as actionable (attach.go Continuation doc).
	return strings.Join(parts, " ")
}

func formatAsk(a *Ask) string {
	tool := a.ToolName
	if tool == "" {
		tool = "operation"
	}
	line := "ASK: approve " + tool
	if a.Pending {
		line += " (re-armed)"
	}
	if in := compactInput(a.Input); in != "" {
		line += "  " + in
	}
	line += "  [allow-once / allow-always(PROPOSAL) / deny]"
	return line
}

func formatAskResolved(a *Ask) string {
	switch a.Behavior {
	case "allow":
		return "ask resolved: ALLOW " + a.ToolName
	case "deny":
		msg := a.Message
		if msg == "" {
			msg = a.ToolName
		}
		return "ask resolved: DENY " + clamp(msg)
	case "cancelled":
		return "ask resolved: CANCELLED " + a.ToolName + " (never answered; session was parked)"
	default:
		return "ask resolved: " + a.Behavior
	}
}

func formatAskResolvedOrphan(r *attach.AskResolved) string {
	return fmt.Sprintf("ask resolved (no surfaced ask %s): %s", r.AskID, r.Behavior)
}

// formatPlanDelta renders one plan-delta line (§6.1 row 6). A TodoWrite/Task*
// delta summarizes the full-list snapshot as a count + status breakdown and
// names the active (in_progress) item; an ExitPlanMode delta renders the plan
// body + approval state. Pure function of the wire fields — golden-testable.
func formatPlanDelta(p *attach.PlanDelta) string {
	if p == nil {
		return "plan updated"
	}
	if p.Kind == attach.PlanDeltaKindExitPlanMode || (len(p.Todos) == 0 && p.Plan != "") {
		line := "plan proposed"
		if p.ApprovalState != "" {
			line = "plan " + p.ApprovalState
		}
		if p.Plan != "" {
			line += ": " + clamp(p.Plan)
		}
		return line
	}
	if len(p.Todos) == 0 {
		return "plan cleared"
	}
	var done, inProgress, pending int
	active := ""
	for _, t := range p.Todos {
		switch t.Status {
		case "completed":
			done++
		case "in_progress":
			inProgress++
			if active == "" {
				active = t.ActiveForm
				if active == "" {
					active = t.Content
				}
			}
		default:
			pending++
		}
	}
	line := fmt.Sprintf("plan: %d task(s) [%d done, %d in-progress, %d pending]", len(p.Todos), done, inProgress, pending)
	if active != "" {
		line += " -> " + clamp(active)
	}
	return line
}

func formatQuota(q *attach.QuotaUpdated) string {
	parts := []string{"quota"}
	if q.RateLimitType != "" {
		parts = append(parts, q.RateLimitType)
	}
	if q.Status != "" {
		parts = append(parts, q.Status)
	}
	if q.IsUsingOverage {
		parts = append(parts, "overage")
	}
	// Semantics is always provisional (P18 open) — render as a hedge, not a
	// commitment.
	parts = append(parts, "("+q.Semantics+")")
	return strings.Join(parts, " ")
}

func formatAccounted(s *attach.SessionAccounted) string {
	parts := []string{"session " + s.Outcome}
	if s.NumTurns > 0 {
		parts = append(parts, fmt.Sprintf("turns=%d", s.NumTurns))
	}
	if s.DurationMS > 0 {
		parts = append(parts, fmt.Sprintf("dur=%dms", s.DurationMS))
	}
	if s.DenialCount > 0 {
		parts = append(parts, fmt.Sprintf("denials=%d", s.DenialCount))
	}
	if s.TerminalReason != "" {
		parts = append(parts, "reason="+s.TerminalReason)
	}
	return strings.Join(parts, " ")
}

// compactInput renders a tool/ask input JSON blob to a short single line for
// display. It tries to surface the human-meaningful keys (command/description)
// and otherwise falls back to a clamped one-line form of the raw JSON.
func compactInput(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	// Cheap single-line collapse: the wire JSON is already small (synthetic
	// fixtures); replace newlines/tabs and clamp. We deliberately do not
	// re-decode into invented field names — surface the wire shape as-is.
	s := string(raw)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	return clamp(s)
}

// clamp trims a string to excerptLimit runes with an ellipsis.
func clamp(s string) string {
	r := []rune(s)
	if len(r) <= excerptLimit {
		return s
	}
	return string(r[:excerptLimit]) + "..."
}
