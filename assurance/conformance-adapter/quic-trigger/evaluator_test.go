// SPDX-License-Identifier: Apache-2.0

package quictrigger

// evaluator_test.go — the OFFLINE half of the D70 standing trigger-evaluation
// check. Always runs, no network: it drives the PURE verdict logic (Evaluate,
// QUICRejectCounts, FlipDecision.AuditLine) against PLANTED scenarios — each of
// the three triggers in isolation, the combinations, the all-clear baseline that
// must NOT flip, and the per-session LOG-1 reject-counter join (including the two
// cases that distinguish real evidence from noise: a task failure with no
// co-session QUIC reject, and a generic default-deny reject that must not inflate
// the QUIC count). The scheduled real-deployment run is the env-gated half
// (RunWeekly, DS_QUIC_TRIGGER_LIVE=1), deferred to CI as a manual step.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	quiccanary "github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/quic-canary"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// fixedNow is the deterministic evaluation instant the offline verdict uses.
var fixedNow = time.Date(2026, 6, 15, 3, 0, 0, 0, time.UTC)

// ── helpers ───────────────────────────────────────────────────────────────────

func ms(d int) time.Duration { return time.Duration(d) * time.Millisecond }

// session builds a SessionRef with a distinct UUID and a DELIBERATELY COLLIDING
// mark_session_index, so any join that wrongly keyed on the mark disambiguator
// (instead of the UUID, doc 14 §4) would mis-attribute across the two sessions.
func session(uuid string, markIdx uint32) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{
		SessionUuid:      uuid,
		HostId:           "host-a",
		HostSessionIndex: uint64(markIdx),
		TapName:          "dstap-" + uuid,
	}
}

// quicReject builds a LOG-1 FlowRecord for a udp/443 QUIC_BLOCKED reject in the
// given session — the D70 per-session reject counter's input (doc 14 §2).
func quicReject(s *boundaryv1.SessionRef) *boundaryv1.FlowRecord {
	return &boundaryv1.FlowRecord{
		Session:      s,
		IpProtocol:   17, // UDP
		DstPort:      443,
		RejectReason: boundaryv1.RejectReason_REJECT_REASON_QUIC_BLOCKED,
	}
}

// defaultDenyReject builds a generic default-deny reject — NOT a QUIC signal; it
// must never inflate the per-session QUIC reject count (doc 14 §2: the distinct
// reason code is exactly what keeps this from happening).
func defaultDenyReject(s *boundaryv1.SessionRef) *boundaryv1.FlowRecord {
	return &boundaryv1.FlowRecord{
		Session:      s,
		IpProtocol:   6, // TCP
		DstPort:      443,
		RejectReason: boundaryv1.RejectReason_REJECT_REASON_DEFAULT_DENY,
	}
}

// allClearCanary builds a canary Report with no triggered verdicts — every
// cooperative client succeeded within budget and the raw-QUIC probe fast-failed.
// This is the no-trigger baseline for trigger 1.
func allClearCanary(t *testing.T) quiccanary.Report {
	t.Helper()
	var ms []quiccanary.Measurement
	for _, c := range quiccanary.CooperativeClients() {
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportTCP, FirstContactOK: true,
			Latencies: []time.Duration{100 * time.Millisecond, 120 * time.Millisecond, 140 * time.Millisecond},
		})
	}
	for _, c := range quiccanary.RawQUICClients() {
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportQUIC, FirstContactOK: false,
			Latencies: []time.Duration{50 * time.Millisecond},
		})
	}
	r := quiccanary.Evaluate(ms, quiccanary.DefaultBudget(), 0)
	if r.FlipToInspect() {
		t.Fatalf("all-clear canary must NOT flip; triggered: %+v", r.TriggeredVerdicts())
	}
	return r
}

// allClearInputs is the no-trigger baseline the negative cases perturb one
// trigger at a time: a clean canary, a healthy TCP-answering baseline, no task
// failures, no QUIC rejects.
func allClearInputs(t *testing.T) Inputs {
	t.Helper()
	return Inputs{
		Canary: allClearCanary(t),
		Baselines: []BaselineStatus{
			{Domain: quiccanary.BaselineDomain, AnswersTCP443: true, TCP443P95: 150 * time.Millisecond},
		},
		BaselineBudget: DefaultBaselineBudget(),
		WindowStart:    fixedNow.Add(-7 * 24 * time.Hour),
		WindowEnd:      fixedNow,
	}
}

// ── The all-clear baseline must NOT flip ──────────────────────────────────────

func TestEvaluate_AllClear_NoFlip(t *testing.T) {
	d := Evaluate(allClearInputs(t), fixedNow)
	if d.Flip {
		t.Fatalf("all-clear inputs must NOT flip; reasons=%v evidence=%+v", d.Reasons, d.Evidence)
	}
	if len(d.Reasons) != 0 || len(d.Evidence) != 0 {
		t.Fatalf("no-flip decision must carry no reasons/evidence; got reasons=%v", d.Reasons)
	}
	// A no-flip run is STILL a recorded audit entry (continuous trail).
	if d.Timestamp.IsZero() {
		t.Fatalf("every decision (even no-flip) must be timestamped for the audit trail")
	}
	line := d.AuditLine()
	if !strings.Contains(line, "flip=false") || !strings.Contains(line, "keep-block-with-fallback") {
		t.Fatalf("no-flip audit line must record the check ran and kept the posture: %q", line)
	}
}

// ── Trigger 1a: canary first-contact failure ──────────────────────────────────

func TestEvaluate_Trigger1_CanaryFailure(t *testing.T) {
	in := allClearInputs(t)
	// Plant a cooperative client whose TCP first-contact FAILED.
	var ms []quiccanary.Measurement
	for _, c := range quiccanary.CooperativeClients() {
		ok := true
		if c.Name == "anthropic-sdk-python" {
			ok = false // the developer-value endpoint is unreachable over TCP
		}
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportTCP, FirstContactOK: ok,
			Latencies: []time.Duration{100 * time.Millisecond},
		})
	}
	for _, c := range quiccanary.RawQUICClients() {
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportQUIC, FirstContactOK: false,
			Latencies: []time.Duration{50 * time.Millisecond},
		})
	}
	in.Canary = quiccanary.Evaluate(ms, quiccanary.DefaultBudget(), 0)

	d := Evaluate(in, fixedNow)
	if !d.Flip {
		t.Fatalf("a canary first-contact failure must flip to inspect (trigger 1)")
	}
	if !d.HasReason(ReasonCanaryFailure) {
		t.Fatalf("expected ReasonCanaryFailure; got %v", d.Reasons)
	}
	if d.HasReason(ReasonLatencyRegression) {
		t.Fatalf("a first-contact failure must NOT also report a latency regression; got %v", d.Reasons)
	}
}

// ── Trigger 1b: canary p95 latency regression (distinct reason) ───────────────

func TestEvaluate_Trigger1_LatencyRegression(t *testing.T) {
	in := allClearInputs(t)
	var ms []quiccanary.Measurement
	for _, c := range quiccanary.CooperativeClients() {
		lat := 120 * time.Millisecond
		if c.Name == "headless-chrome" {
			lat = 5 * time.Second // well over the absolute p95 ceiling
		}
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportTCP, FirstContactOK: true,
			Latencies: []time.Duration{lat},
		})
	}
	for _, c := range quiccanary.RawQUICClients() {
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportQUIC, FirstContactOK: false,
			Latencies: []time.Duration{50 * time.Millisecond},
		})
	}
	in.Canary = quiccanary.Evaluate(ms, quiccanary.DefaultBudget(), 0)

	d := Evaluate(in, fixedNow)
	if !d.Flip || !d.HasReason(ReasonLatencyRegression) {
		t.Fatalf("a canary p95 regression must flip with ReasonLatencyRegression; got flip=%v reasons=%v", d.Flip, d.Reasons)
	}
}

// ── Trigger 2a: a D64 baseline endpoint becomes H3-only ───────────────────────

func TestEvaluate_Trigger2_BaselineH3Only(t *testing.T) {
	in := allClearInputs(t)
	in.Baselines = []BaselineStatus{
		{Domain: quiccanary.BaselineDomain, AnswersTCP443: false}, // H3-only now
	}
	d := Evaluate(in, fixedNow)
	if !d.Flip || !d.HasReason(ReasonBaselineH3Only) {
		t.Fatalf("an H3-only baseline must flip with ReasonBaselineH3Only; got flip=%v reasons=%v", d.Flip, d.Reasons)
	}
	// An H3-only endpoint has no TCP p95 to degrade-check, so the degraded reason
	// must NOT also fire.
	if d.HasReason(ReasonBaselineTCPDegraded) {
		t.Fatalf("an H3-only endpoint has no TCP service to call 'degraded'; got %v", d.Reasons)
	}
}

// ── Trigger 2b: a baseline endpoint's TCP 443 measurably degrades ─────────────

func TestEvaluate_Trigger2_BaselineTCPDegraded(t *testing.T) {
	in := allClearInputs(t)
	in.Baselines = []BaselineStatus{
		{Domain: quiccanary.BaselineDomain, AnswersTCP443: true, TCP443P95: 5 * time.Second}, // over ceiling
	}
	d := Evaluate(in, fixedNow)
	if !d.Flip || !d.HasReason(ReasonBaselineTCPDegraded) {
		t.Fatalf("a degraded TCP baseline must flip with ReasonBaselineTCPDegraded; got flip=%v reasons=%v", d.Flip, d.Reasons)
	}
	if d.HasReason(ReasonBaselineH3Only) {
		t.Fatalf("a still-answering endpoint is not H3-only; got %v", d.Reasons)
	}
}

// A zero BaselineBudget ceiling disables the degraded check (H3-only still trips).
func TestEvaluate_Trigger2_ZeroBudgetDisablesDegraded(t *testing.T) {
	in := allClearInputs(t)
	in.BaselineBudget = BaselineBudget{} // zero ceiling ⇒ degraded check off
	in.Baselines = []BaselineStatus{
		{Domain: quiccanary.BaselineDomain, AnswersTCP443: true, TCP443P95: 9 * time.Second},
	}
	d := Evaluate(in, fixedNow)
	if d.Flip {
		t.Fatalf("a zero budget ceiling must disable the TCP-degraded check; got reasons=%v", d.Reasons)
	}
}

// ── Trigger 3: H3-bound feature, EVIDENCED BY the reject-event join ───────────

func TestEvaluate_Trigger3_H3BoundFeature_WithRejectEvidence(t *testing.T) {
	in := allClearInputs(t)
	s := session("11111111-1111-4000-8000-000000000001", 7)
	// The failing task ran in session s, which racked up udp/443 QUIC_BLOCKED
	// rejects in the same window — that JOIN is the evidence (doc 12 §7 trigger 3).
	in.TaskFailures = []TaskFailure{
		{Session: s, Feature: "WebTransport", TaskID: "task-wt-1"},
	}
	in.RejectRecords = []*boundaryv1.FlowRecord{quicReject(s), quicReject(s), quicReject(s)}

	d := Evaluate(in, fixedNow)
	if !d.Flip || !d.HasReason(ReasonH3BoundFeature) {
		t.Fatalf("an H3-bound task failure joined to udp/443 rejects must flip; got flip=%v reasons=%v", d.Flip, d.Reasons)
	}
	// The evidence summary must carry the supporting metric (reject count) and the
	// feature name (doc 12 §7: evidence summary + supporting metrics).
	var found bool
	for _, e := range d.Evidence {
		if e.Reason == ReasonH3BoundFeature && strings.Contains(e.Summary, "WebTransport") && strings.Contains(e.Summary, "3 co-session") {
			found = true
		}
	}
	if !found {
		t.Fatalf("trigger-3 evidence must name the feature and the reject count; got %+v", d.Evidence)
	}
}

// The join is what makes it evidence: a task failure with NO co-session QUIC
// reject is NOT evidence and must NOT trip trigger 3.
func TestEvaluate_Trigger3_FailureWithoutRejectIsNotEvidence(t *testing.T) {
	in := allClearInputs(t)
	s := session("22222222-2222-4000-8000-000000000002", 9)
	in.TaskFailures = []TaskFailure{
		{Session: s, Feature: "MASQUE/connect-udp", TaskID: "task-masque-1"},
	}
	// No reject records at all for s ⇒ the failure has some OTHER cause.
	in.RejectRecords = nil

	d := Evaluate(in, fixedNow)
	if d.Flip {
		t.Fatalf("a task failure with no co-session udp/443 reject is not H3 evidence and must NOT flip; reasons=%v", d.Reasons)
	}
}

// A generic default-deny reject must NOT inflate the per-session QUIC count — the
// whole point of the distinct QUIC_BLOCKED reason code (doc 14 §2).
func TestEvaluate_Trigger3_DefaultDenyDoesNotCountAsQUIC(t *testing.T) {
	in := allClearInputs(t)
	s := session("33333333-3333-4000-8000-000000000003", 11)
	in.TaskFailures = []TaskFailure{
		{Session: s, Feature: "h3-only-grpc", TaskID: "task-grpc-1"},
	}
	// The session has rejects, but they are GENERIC default-deny, not QUIC.
	in.RejectRecords = []*boundaryv1.FlowRecord{defaultDenyReject(s), defaultDenyReject(s)}

	d := Evaluate(in, fixedNow)
	if d.Flip {
		t.Fatalf("default-deny rejects must not count as QUIC evidence; reasons=%v", d.Reasons)
	}
}

// The per-session join must NOT cross sessions: a reject in session A must not
// supply evidence for a failure in session B, even when they share a colliding
// mark_session_index (doc 14 §4 — the join is by UUID, never the disambiguator).
func TestEvaluate_Trigger3_RejectJoinDoesNotCrossSessions(t *testing.T) {
	in := allClearInputs(t)
	const sharedMark = 42
	a := session("aaaaaaaa-aaaa-4000-8000-00000000000a", sharedMark)
	b := session("bbbbbbbb-bbbb-4000-8000-00000000000b", sharedMark) // same mark idx, different UUID
	// b is the failing task; the rejects belong to A.
	in.TaskFailures = []TaskFailure{{Session: b, Feature: "WebTransport", TaskID: "task-b"}}
	in.RejectRecords = []*boundaryv1.FlowRecord{quicReject(a), quicReject(a)}

	d := Evaluate(in, fixedNow)
	if d.Flip {
		t.Fatalf("a reject in session A must not be evidence for a failure in session B (mark-index collision must not bridge them); reasons=%v", d.Reasons)
	}
}

// ── QUICRejectCounts: the per-session counter unit (D70, doc 14 §2) ───────────

func TestQUICRejectCounts_PerSessionOnlyQUICBlocked(t *testing.T) {
	a := session("aaaaaaaa-0000-4000-8000-000000000001", 1)
	b := session("bbbbbbbb-0000-4000-8000-000000000002", 2)
	records := []*boundaryv1.FlowRecord{
		quicReject(a), quicReject(a), // a: 2 QUIC
		quicReject(b),        // b: 1 QUIC
		defaultDenyReject(a), // not counted
		defaultDenyReject(b), // not counted
		nil,                  // nil-safe
		{RejectReason: boundaryv1.RejectReason_REJECT_REASON_QUIC_BLOCKED}, // no session ⇒ dropped
	}
	got := QUICRejectCounts(records)
	if got[SessionKey(a)] != 2 {
		t.Fatalf("session a must count 2 QUIC rejects; got %d", got[SessionKey(a)])
	}
	if got[SessionKey(b)] != 1 {
		t.Fatalf("session b must count 1 QUIC reject; got %d", got[SessionKey(b)])
	}
	if len(got) != 2 {
		t.Fatalf("only keyable QUIC_BLOCKED records count; got %d keys: %v", len(got), got)
	}
}

// ── Combined triggers: all reasons fire, deduped, in AllReasons() order ───────

func TestEvaluate_AllTriggersTogether(t *testing.T) {
	// Canary: one first-contact failure AND one latency regression.
	var ms []quiccanary.Measurement
	for _, c := range quiccanary.CooperativeClients() {
		ok, lat := true, 120*time.Millisecond
		switch c.Name {
		case "anthropic-sdk-python":
			ok = false
		case "headless-chrome":
			lat = 5 * time.Second
		}
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportTCP, FirstContactOK: ok,
			Latencies: []time.Duration{lat},
		})
	}
	for _, c := range quiccanary.RawQUICClients() {
		ms = append(ms, quiccanary.Measurement{
			Client: c.Name, Transport: quiccanary.TransportQUIC, FirstContactOK: false,
			Latencies: []time.Duration{50 * time.Millisecond},
		})
	}
	s := session("99999999-9999-4000-8000-000000000009", 5)
	in := Inputs{
		Canary: quiccanary.Evaluate(ms, quiccanary.DefaultBudget(), 0),
		Baselines: []BaselineStatus{
			{Domain: "h3only.example", AnswersTCP443: false},
			{Domain: "degraded.example", AnswersTCP443: true, TCP443P95: 6 * time.Second},
		},
		BaselineBudget: DefaultBaselineBudget(),
		TaskFailures:   []TaskFailure{{Session: s, Feature: "WebTransport", TaskID: "task-x"}},
		RejectRecords:  []*boundaryv1.FlowRecord{quicReject(s)},
		WindowStart:    fixedNow.Add(-7 * 24 * time.Hour),
		WindowEnd:      fixedNow,
	}
	d := Evaluate(in, fixedNow)
	if !d.Flip {
		t.Fatalf("all triggers planted must flip")
	}
	// Every one of the five reasons must fire, exactly once, in AllReasons() order.
	want := AllReasons()
	if len(d.Reasons) != len(want) {
		t.Fatalf("expected all %d reasons, got %d: %v", len(want), len(d.Reasons), d.Reasons)
	}
	for i, r := range want {
		if d.Reasons[i] != r {
			t.Fatalf("reasons must be in AllReasons() order; pos %d want %s got %s (full %v)", i, r, d.Reasons[i], d.Reasons)
		}
	}
	// Audit line lists all five reason tokens and the flip verdict.
	line := d.AuditLine()
	if !strings.Contains(line, "flip=true") || !strings.Contains(line, "flip-to-must-inspect") {
		t.Fatalf("flip audit line malformed: %q", line)
	}
	for _, r := range want {
		if !strings.Contains(line, string(r)) {
			t.Fatalf("audit line must list reason %s: %q", r, line)
		}
	}
}

// ── The audit record is timestamped and queryable (doc 12 §7) ─────────────────

func TestFlipDecision_AuditLineTimestampedAndQueryable(t *testing.T) {
	in := allClearInputs(t)
	in.Baselines = []BaselineStatus{{Domain: quiccanary.BaselineDomain, AnswersTCP443: false}}
	d := Evaluate(in, fixedNow)

	line := d.AuditLine()
	// The timestamp is RFC3339Nano UTC and present in the line (queryable by time).
	if !strings.Contains(line, fixedNow.UTC().Format(time.RFC3339Nano)) {
		t.Fatalf("audit line must carry the RFC3339Nano timestamp for queryability: %q", line)
	}
	// The window is carried for the audit trail.
	if d.WindowStart.IsZero() || d.WindowEnd.IsZero() {
		t.Fatalf("a flip decision must carry the evaluated window for the audit trail")
	}
	// Reason is queryable both via the structured accessor and the rendered line.
	if !d.HasReason(ReasonBaselineH3Only) {
		t.Fatalf("HasReason must answer the structured audit query")
	}
	if !strings.Contains(line, string(ReasonBaselineH3Only)) {
		t.Fatalf("the rendered audit line must carry the reason token for off-box query: %q", line)
	}
}

// ── The scheduled half is env-gated and fails loud until wired ────────────────

func TestRunWeekly_DefaultDisabled_FailsLoud(t *testing.T) {
	t.Setenv(LiveEnvVar, "") // default CI posture
	if LiveEnabled() {
		t.Fatalf("the scheduled half must be disabled by default")
	}
	_, err := RunWeekly(fixedNow)
	if !errors.Is(err, ErrRunnerNotWired) {
		t.Fatalf("disabled RunWeekly must fail with ErrRunnerNotWired (never a vacuous green); got %v", err)
	}
}

func TestRunWeekly_EnabledButUnwired_FailsLoud(t *testing.T) {
	t.Setenv(LiveEnvVar, "1") // operator opts in, but no collectors are wired
	if !LiveEnabled() {
		t.Fatalf("LiveEnvVar=1 must enable the scheduled half")
	}
	d, err := RunWeekly(fixedNow)
	if !errors.Is(err, ErrRunnerNotWired) {
		t.Fatalf("an enabled-but-unwired RunWeekly must fail LOUDLY with ErrRunnerNotWired, never a vacuous no-flip green; got err=%v decision=%+v", err, d)
	}
	// Even on the error path the decision carries the timestamp/window (the run
	// was attempted), so the failure itself is an auditable event.
	if d.Timestamp.IsZero() {
		t.Fatalf("the error-path decision must still be timestamped (an attempted run is an audit event)")
	}
}

func TestCollectInputs_DefaultDisabled_FailsLoud(t *testing.T) {
	t.Setenv(LiveEnvVar, "")
	_, err := CollectInputs(fixedNow.Add(-7*24*time.Hour), fixedNow)
	if !errors.Is(err, ErrRunnerNotWired) {
		t.Fatalf("disabled CollectInputs must fail with ErrRunnerNotWired; got %v", err)
	}
}

// ── FlipReason universe reconciled against source (the canary/tlsproxyinspect
// self-check) — a new reason can't be added without a planted scenario ─────────

func TestAllReasons_ReconciledAgainstSource(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "evaluator.go", nil, 0)
	if err != nil {
		t.Fatalf("parse evaluator.go: %v", err)
	}

	// Collect every `Reason* FlipReason = "..."` const declared in source.
	sourceReasons := map[string]string{} // const name -> string value
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Only typed FlipReason consts.
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "FlipReason" {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				bl, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				sourceReasons[name.Name] = strings.Trim(bl.Value, `"`)
			}
		}
		return true
	})

	if len(sourceReasons) == 0 {
		t.Fatalf("found no FlipReason consts in source — the self-check parser broke")
	}

	// Every source const must appear in AllReasons() (by value), and AllReasons()
	// must carry no value absent from source. This forces a new reason to be
	// listed in AllReasons() (and so exercised by the combined-triggers test).
	inAll := map[string]bool{}
	for _, r := range AllReasons() {
		inAll[string(r)] = true
	}
	for name, val := range sourceReasons {
		if !inAll[val] {
			t.Errorf("FlipReason %s (%q) declared in source is missing from AllReasons()", name, val)
		}
	}
	if len(inAll) != len(sourceReasons) {
		t.Errorf("AllReasons() has %d values but source declares %d FlipReason consts — they must match exactly", len(inAll), len(sourceReasons))
	}
}

// ── Guard: the offline suite never touches the network (env hygiene) ──────────

func TestMain(m *testing.M) {
	// Belt-and-suspenders: the offline suite must run with the live gate OFF so a
	// developer's ambient DS_QUIC_TRIGGER_LIVE never accidentally enables the
	// scheduled half mid-suite. Each live test sets it explicitly via t.Setenv.
	_ = os.Unsetenv(LiveEnvVar)
	os.Exit(m.Run())
}
