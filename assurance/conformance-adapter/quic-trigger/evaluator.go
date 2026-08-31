// SPDX-License-Identifier: Apache-2.0

package quictrigger

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	quiccanary "github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/quic-canary"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// evaluator.go — the D70 standing trigger-evaluation runner (doc 12 §7,
// doc 14 §10). It combines the three flip-to-inspect triggers into one
// timestamped, queryable FlipDecision:
//
//	(1) the nightly canary Report (quiccanary.Report — trigger 1, owned by u1),
//	(2) the D64 baseline-endpoint posture (trigger 2),
//	(3) H3-bound workload features evidenced by task failures JOINED to LOG-1
//	    FlowRecord udp/443 QUIC_BLOCKED reject events per session (trigger 3).
//
// The verdict (Evaluate → FlipDecision.Flip) is a PURE function the offline half
// asserts against planted scenarios; the scheduled half (RunWeekly) collects the
// previous week's real inputs and feeds them to the same Evaluate.

// LiveEnvVar is the single switch for the scheduled (live-collector) half. UNSET
// (or any value other than "1") keeps it disabled: LiveEnabled() returns false,
// RunWeekly is never driven, and the offline verdict tests run deterministically
// with no network. CI never sets it.
const LiveEnvVar = "DS_QUIC_TRIGGER_LIVE"

// LiveEnabled reports whether the operator opted into the scheduled runner via
// LiveEnvVar=1. The default (unset) is false — CI is offline and deterministic.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// ── The flip reasons (doc 12 §7 — the three triggers, five named codes) ───────

// FlipReason is one stable, queryable cause the standing check can record for a
// flip-to-inspect decision. The five codes are the doc 12 §7 trigger conditions
// (trigger 1 splits into the canary-failure and latency-regression rows; trigger
// 2 splits into the H3-only and TCP-degraded rows; trigger 3 is the single
// H3-bound-feature row). The string values are the canonical audit tokens an
// off-box query filters on, so they are load-bearing, not descriptive.
type FlipReason string

const (
	// ReasonCanaryFailure — trigger 1a: the nightly canary reported a cooperative
	// client's first-contact FAILURE to the baseline domain (a developer-value
	// endpoint unreachable over the transport DNS-4 steers clients onto), OR a
	// raw-QUIC boundary hole. Sourced from the quiccanary.Report.
	ReasonCanaryFailure FlipReason = "canary-failure"
	// ReasonLatencyRegression — trigger 1b: the nightly canary reported a
	// cooperative client's p95 first-contact latency REGRESSED beyond budget
	// (absolute ceiling or relative margin over the TCP-direct control). Sourced
	// from the quiccanary.Report.
	ReasonLatencyRegression FlipReason = "latency-regression"
	// ReasonBaselineH3Only — trigger 2a: a D64 baseline endpoint became H3-ONLY —
	// it no longer answers over TCP 443 at all, so block-with-fallback can no
	// longer reach it.
	ReasonBaselineH3Only FlipReason = "baseline-h3-only"
	// ReasonBaselineTCPDegraded — trigger 2b: a D64 baseline endpoint measurably
	// DEGRADED its TCP 443 service (still answers, but its TCP path regressed
	// beyond budget — the H3 path it offers is now the fast one).
	ReasonBaselineTCPDegraded FlipReason = "baseline-tcp-degraded"
	// ReasonH3BoundFeature — trigger 3: a required workload feature is H3-bound
	// (WebTransport, MASQUE/connect-udp, an H3-only gRPC API), EVIDENCED BY task
	// failures JOINED to per-session udp/443 QUIC_BLOCKED reject events.
	ReasonH3BoundFeature FlipReason = "h3-bound-feature"
)

// AllReasons is the canonical FlipReason universe, audit order. The offline half
// reconciles this list against the const block in source (the go/ast self-check)
// so a new reason can't be added without a planted scenario AND a row here.
func AllReasons() []FlipReason {
	return []FlipReason{
		ReasonCanaryFailure,
		ReasonLatencyRegression,
		ReasonBaselineH3Only,
		ReasonBaselineTCPDegraded,
		ReasonH3BoundFeature,
	}
}

// ── Trigger-2 input: D64 baseline-endpoint posture ────────────────────────────

// BaselineBudget is the TCP-443 latency ceiling a D64 baseline endpoint's
// measured TCP service must stay under before it counts as "degraded" (trigger
// 2b). Like the canary latency budget, it is a FREE cell (doc 12 §9 / §13 free
// column) — build guidance the standing-check owner tunes, not a frozen
// contract. The zero value disables the TCP-degraded check (only H3-only trips).
type BaselineBudget struct {
	// TCP443Ceiling is the absolute p95 TCP-443 first-contact ceiling for a
	// baseline endpoint. A measured TCP p95 above this (while still answering) is
	// trigger 2b. Zero disables the degraded check.
	TCP443Ceiling time.Duration
}

// DefaultBaselineBudget returns the build-guidance default: the same generous
// absolute ceiling the canary uses for cooperative TCP first-contact, so the
// two halves of the latency story agree on what "degraded" means.
func DefaultBaselineBudget() BaselineBudget {
	return BaselineBudget{TCP443Ceiling: quiccanary.DefaultP95Budget}
}

// BaselineStatus is the measured posture of ONE D64 baseline endpoint for the
// evaluation window. The scheduled half fills it from real probes (sharing the
// quic-canary BaselineDomain / workload matrix); the offline half plants it.
type BaselineStatus struct {
	// Domain is the D64 baseline endpoint (joins to a quiccanary baseline domain).
	Domain string
	// AnswersTCP443 reports whether the endpoint still answers over TCP 443 at
	// all in the window. False ⇒ H3-only ⇒ trigger 2a (ReasonBaselineH3Only).
	AnswersTCP443 bool
	// TCP443P95 is the measured p95 TCP-443 first-contact latency in the window
	// (0 when not measured, e.g. an H3-only endpoint). A non-zero value above the
	// BaselineBudget ceiling is trigger 2b (ReasonBaselineTCPDegraded).
	TCP443P95 time.Duration
}

// ── Trigger-3 inputs: LOG-1 FlowRecords + reported task failures ──────────────

// TaskFailure is one reported workload (task) failure in the evaluation window
// that NAMES an H3-bound feature as its suspected cause. It is evidence ONLY
// when JOINED to per-session udp/443 QUIC_BLOCKED reject events (doc 12 §7
// trigger 3: "evidenced by task failures joined to udp/443 reject events").
type TaskFailure struct {
	// Session is the session the failing task ran in — the join key to the LOG-1
	// FlowRecord reject events. The join is by SessionRef identity (the session
	// UUID), NEVER the mark_session_index disambiguator (doc 14 §4): two live
	// sessions can share a mark_session_index, so a mark-keyed join would
	// mis-attribute rejects across sessions.
	Session *boundaryv1.SessionRef
	// Feature names the H3-bound feature the failing task needed (WebTransport,
	// MASQUE/connect-udp, an H3-only gRPC API). Carried into the evidence summary.
	Feature string
	// TaskID is the failing task's identifier (for the audit trail).
	TaskID string
}

// SessionKey is the canonical per-session join key derived from a SessionRef:
// the session UUID. The mark_session_index is a 14-bit disambiguator and MUST
// NOT be the join key (doc 14 §4) — this function enforces that by keying on the
// UUID, falling back to host_id+tap_name when the UUID is absent. A nil ref
// returns "" (an unkeyable record, dropped from the join, never matched).
func SessionKey(s *boundaryv1.SessionRef) string {
	if s == nil {
		return ""
	}
	if u := s.GetSessionUuid(); u != "" {
		return u
	}
	// Fall back to the interface-anchored identity (host + tap) — still NOT the
	// mark_session_index (the disambiguator that can collide).
	if host, tap := s.GetHostId(), s.GetTapName(); host != "" || tap != "" {
		return host + "/" + tap
	}
	return ""
}

// QUICRejectCounts counts udp/443 QUIC_BLOCKED reject events PER SESSION from a
// LOG-1 FlowRecord stream (the previous week's log). It is the D70 per-session
// reject counter (doc 12 §7, doc 14 §2: the QUIC_BLOCKED reason code "is what
// makes the D70 flip-to-inspect trigger queryable off-box"). Only records whose
// reject_reason is REJECT_REASON_QUIC_BLOCKED are counted — a generic
// default-deny reject (REJECT_REASON_DEFAULT_DENY) is explicitly NOT a QUIC
// signal and must not inflate the count (the whole point of the distinct reason
// code, doc 14 §2). Records with no keyable session are dropped (they cannot
// join a task failure). The map is keyed by SessionKey.
func QUICRejectCounts(records []*boundaryv1.FlowRecord) map[string]int {
	counts := make(map[string]int)
	for _, r := range records {
		if r == nil {
			continue
		}
		if r.GetRejectReason() != boundaryv1.RejectReason_REJECT_REASON_QUIC_BLOCKED {
			continue
		}
		key := SessionKey(r.GetSession())
		if key == "" {
			continue
		}
		counts[key]++
	}
	return counts
}

// ── The evaluation inputs ─────────────────────────────────────────────────────

// Inputs is the full set the standing weekly check evaluates: the nightly canary
// Report (trigger 1), the D64 baseline posture (trigger 2), and the LOG-1
// FlowRecord stream + reported task failures (trigger 3). The scheduled half
// collects these from a running deployment; the offline half plants them.
type Inputs struct {
	// Canary is the nightly QUIC conformance canary Report (trigger 1). A zero
	// Report (no verdicts) means the canary did not run this window — that is NOT
	// a flip on its own (the canary's own absence is a separate ops alarm), so a
	// zero Report contributes no trigger-1 reasons.
	Canary quiccanary.Report
	// Baselines is the measured posture of each D64 baseline endpoint (trigger 2).
	Baselines []BaselineStatus
	// BaselineBudget is the TCP-degraded ceiling for trigger 2b (DefaultBaselineBudget()
	// when zero — a zero ceiling disables the degraded check, H3-only still trips).
	BaselineBudget BaselineBudget
	// RejectRecords is the previous week's LOG-1 FlowRecord stream, from which the
	// per-session udp/443 QUIC_BLOCKED counter is derived (trigger 3 join, doc 14 §2).
	RejectRecords []*boundaryv1.FlowRecord
	// TaskFailures are the reported H3-bound-feature task failures (trigger 3
	// evidence). A failure is evidence ONLY when its session has ≥1 QUIC_BLOCKED
	// reject in RejectRecords.
	TaskFailures []TaskFailure
	// WindowStart / WindowEnd bound the evaluation window (the "previous week"),
	// carried into the audit record for queryability. Zero values are tolerated
	// (the decision Timestamp is always set); set them for a complete audit trail.
	WindowStart time.Time
	WindowEnd   time.Time
}

// ── The decision (the audit artifact) ─────────────────────────────────────────

// ReasonEvidence pairs a fired FlipReason with its human-readable supporting
// metrics (doc 12 §7: "evidence summary … + supporting metrics"). Each is one
// line of the queryable audit record.
type ReasonEvidence struct {
	Reason FlipReason
	// Summary is the actionable, secret-free description an on-call reads: the
	// specific client/endpoint/session and the metric that tripped the trigger.
	Summary string
}

// FlipDecision is the standing trigger-evaluation outcome — the queryable audit
// artifact emitted each run (doc 12 §7: "produces a boolean flip decision logged
// with timestamp and evidence"). It is recorded whether or not it flips, so the
// audit trail is continuous.
type FlipDecision struct {
	// Flip is the boolean verdict: true ⇒ flip QUIC posture from
	// block-with-fallback to must-inspect. true iff ANY trigger fired.
	Flip bool
	// Reasons is the set of distinct FlipReason codes that fired, AllReasons()
	// order (stable for diffing across runs). Empty when Flip is false.
	Reasons []FlipReason
	// Evidence is the per-reason supporting-metrics summary (doc 12 §7), in the
	// same order as Reasons. Empty when Flip is false.
	Evidence []ReasonEvidence
	// Timestamp is the UTC instant the evaluation ran (RFC3339Nano in AuditLine).
	// Always set, even on a no-flip run, so "when did the standing check last
	// run" is queryable.
	Timestamp time.Time
	// WindowStart / WindowEnd echo the evaluated window for the audit trail.
	WindowStart time.Time
	WindowEnd   time.Time
}

// HasReason reports whether the decision fired a specific reason — the
// fine-grained audit query ("did we ever flip on an H3-bound feature?").
func (d FlipDecision) HasReason(r FlipReason) bool {
	for _, got := range d.Reasons {
		if got == r {
			return true
		}
	}
	return false
}

// AuditLine renders the single canonical, secret-free log line the standing
// check emits each run — the queryable audit record (doc 12 §7: "the log entry
// is timestamped and queryable for audit"). A flip is loud and lists its
// reasons; a no-flip run still records that the check ran and found nothing, so
// the trail is continuous.
func (d FlipDecision) AuditLine() string {
	ts := d.Timestamp.UTC().Format(time.RFC3339Nano)
	if !d.Flip {
		return fmt.Sprintf("quic-trigger ts=%s flip=false reasons=[] window=[%s..%s] decision=keep-block-with-fallback",
			ts, fmtTime(d.WindowStart), fmtTime(d.WindowEnd))
	}
	rs := make([]string, len(d.Reasons))
	for i, r := range d.Reasons {
		rs[i] = string(r)
	}
	return fmt.Sprintf("quic-trigger ts=%s flip=true reasons=[%s] window=[%s..%s] decision=flip-to-must-inspect",
		ts, strings.Join(rs, ","), fmtTime(d.WindowStart), fmtTime(d.WindowEnd))
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ── The pure verdict ──────────────────────────────────────────────────────────

// Evaluate is the standing trigger-evaluation verdict (doc 12 §7: "a standing
// weekly/nightly check, not a judgment call"). It combines all three triggers
// over the planted/collected Inputs and produces the timestamped, queryable
// FlipDecision. `now` is injected (not time.Now()) so the verdict is pure and
// the offline tests are deterministic; the scheduled half passes time.Now().
//
// The verdict flips iff ANY trigger fired. Each fired trigger contributes its
// distinct FlipReason exactly once (the reasons are deduplicated and emitted in
// AllReasons() order) with a secret-free evidence summary carrying the specific
// supporting metric.
func Evaluate(in Inputs, now time.Time) FlipDecision {
	budget := in.BaselineBudget
	// Note: a zero TCP443Ceiling deliberately DISABLES the degraded check (only
	// H3-only trips) — DefaultBaselineBudget() is opt-in, not silently forced, so
	// a caller can run H3-only-only.

	// Collect evidence per reason; dedupe reasons, keep all evidence lines.
	evByReason := make(map[FlipReason][]string)
	add := func(r FlipReason, summary string) {
		evByReason[r] = append(evByReason[r], summary)
	}

	// ── Trigger 1: the nightly canary (sourced from the u1 Report) ────────────
	// The canary already split its verdict into named per-client causes; map each
	// triggered verdict's cause onto canary-failure vs latency-regression. A
	// latency regression is its own reason; everything else the canary flags
	// (first-contact failure, a raw-QUIC hole, a missing/unknown measurement) is
	// a canary-failure for the standing check's coarser two-row trigger-1 split.
	for _, v := range in.Canary.TriggeredVerdicts() {
		if errors.Is(v.Err, quiccanary.ErrLatencyRegression) {
			add(ReasonLatencyRegression, fmt.Sprintf("canary[%s]: %s", v.Client, summarizeErr(v.Err)))
			continue
		}
		add(ReasonCanaryFailure, fmt.Sprintf("canary[%s]: %s", v.Client, summarizeErr(v.Err)))
	}

	// ── Trigger 2: D64 baseline-endpoint posture ──────────────────────────────
	for _, b := range in.Baselines {
		if !b.AnswersTCP443 {
			add(ReasonBaselineH3Only, fmt.Sprintf("baseline[%s]: no longer answers over TCP 443 (H3-only) — block-with-fallback can no longer reach it", b.Domain))
			continue // an H3-only endpoint has no meaningful TCP p95 to degrade-check
		}
		if budget.TCP443Ceiling > 0 && b.TCP443P95 > budget.TCP443Ceiling {
			add(ReasonBaselineTCPDegraded, fmt.Sprintf("baseline[%s]: TCP-443 p95 %s exceeds ceiling %s — TCP service measurably degraded", b.Domain, b.TCP443P95, budget.TCP443Ceiling))
		}
	}

	// ── Trigger 3: H3-bound workload feature, joined to udp/443 rejects ───────
	// A task failure is evidence ONLY when its session has ≥1 QUIC_BLOCKED reject
	// in the same window (doc 12 §7: "evidenced by task failures JOINED to udp/443
	// reject events"). The join is by SessionKey (the UUID, never the mark
	// disambiguator, doc 14 §4). A failure with no co-session QUIC reject is not
	// evidence and never trips the trigger.
	rejectCounts := QUICRejectCounts(in.RejectRecords)
	for _, f := range in.TaskFailures {
		key := SessionKey(f.Session)
		if key == "" {
			continue // unkeyable failure cannot join the reject stream
		}
		n := rejectCounts[key]
		if n == 0 {
			continue // failed, but NOT while racking up udp/443 rejects ⇒ not H3 evidence
		}
		add(ReasonH3BoundFeature, fmt.Sprintf("task[%s] feature=%q session=%s failed with %d co-session udp/443 QUIC_BLOCKED reject(s) — feature is H3-bound", f.TaskID, f.Feature, key, n))
	}

	// ── Assemble the decision in AllReasons() order ───────────────────────────
	d := FlipDecision{
		Timestamp:   now,
		WindowStart: in.WindowStart,
		WindowEnd:   in.WindowEnd,
	}
	for _, r := range AllReasons() {
		lines, ok := evByReason[r]
		if !ok {
			continue
		}
		d.Flip = true
		d.Reasons = append(d.Reasons, r)
		// Stable evidence order within a reason.
		sort.Strings(lines)
		for _, l := range lines {
			d.Evidence = append(d.Evidence, ReasonEvidence{Reason: r, Summary: l})
		}
	}
	return d
}

// summarizeErr renders a canary error as a single secret-free line for the
// evidence summary (the canary errors carry only client name + metric, never any
// payload byte — never-log-the-secret holds trivially here, but we keep the
// rendering to the error's own message which the canary authored to be safe).
func summarizeErr(err error) string {
	if err == nil {
		return "triggered (no detail)"
	}
	return err.Error()
}

// ── The scheduled runner (env-gated, fails loud until wired) ──────────────────

// ErrRunnerNotWired fires from the scheduled half until an operator wires the
// real input collectors (the canary Report fetch, the baseline probes, and the
// previous-week LOG-1 FlowRecord + task-failure join) against a running
// deployment — so DS_QUIC_TRIGGER_LIVE=1 fails LOUDLY rather than reporting a
// false green over an unimplemented collector. The verdict logic (Evaluate) is
// unchanged when the collectors land; only the input-gathering body is replaced.
var ErrRunnerNotWired = errors.New("quictrigger: scheduled trigger-evaluation runner not wired — DS_QUIC_TRIGGER_LIVE=1 requires a running boundary + the previous-week LOG-1 FlowRecord stream, the nightly canary Report, and the D64 baseline probes the wave sandbox lacks; this is a DEFERRED MANUAL step (doc 12 §7, doc 14 §10 Stage-2 NFT-4 rig extension)")

// CollectInputs is the input-gathering seam the scheduled half calls before
// Evaluate: it collects the previous window's canary Report, baseline posture,
// LOG-1 FlowRecord stream, and reported task failures from a running deployment.
// Until an operator wires the real collectors it returns ErrRunnerNotWired so a
// scheduled run never reports a false green over empty (vacuously no-flip)
// inputs. The window [start,end) bounds what it collects.
func CollectInputs(start, end time.Time) (Inputs, error) {
	if !LiveEnabled() {
		// Caller must gate on LiveEnabled(); returning the sentinel here keeps a
		// misuse from silently producing empty (vacuously no-flip) inputs.
		return Inputs{}, fmt.Errorf("%w: scheduled half not enabled (%s != 1)", ErrRunnerNotWired, LiveEnvVar)
	}
	return Inputs{}, ErrRunnerNotWired
}

// RunWeekly is the scheduled runner entry point a weekly/nightly CI job
// (.github/workflows) invokes. It collects the previous window's inputs
// (CollectInputs) and evaluates them with the SAME Evaluate the offline half
// asserts, returning the timestamped FlipDecision. Until the collectors are
// wired it surfaces ErrRunnerNotWired (a loud, deferred-manual failure, never a
// vacuous green). `now` is the run instant (the scheduled job passes
// time.Now().UTC()); the window is [now-7d, now) by default when the caller does
// not narrow it.
func RunWeekly(now time.Time) (FlipDecision, error) {
	start := now.Add(-7 * 24 * time.Hour)
	in, err := CollectInputs(start, now)
	if err != nil {
		return FlipDecision{Timestamp: now, WindowStart: start, WindowEnd: now}, err
	}
	return Evaluate(in, now), nil
}
