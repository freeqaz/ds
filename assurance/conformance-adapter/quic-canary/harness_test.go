// SPDX-License-Identifier: Apache-2.0

package quiccanary

// harness_test.go — the OFFLINE half of the D70 QUIC conformance canary. Always
// runs, no network: it drives the PURE verdict/trigger logic (VerdictFor,
// Evaluate, Report.FlipToInspect, Percentile) against SYNTHETIC measurements,
// proving each named trigger/hole condition fires (and the happy paths do not).
// The over-the-wire real-client runs are the env-gated live half (RunLive,
// DS_QUIC_CANARY_LIVE=1), deferred to CI as a manual step.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

func ms(d int) time.Duration { return time.Duration(d) * time.Millisecond }

// okTCP builds a successful cooperative TCP leg with the given per-sample
// latencies (in ms).
func okTCP(client string, latMs ...int) Measurement {
	m := Measurement{Client: client, Transport: TransportTCP, FirstContactOK: true}
	for _, l := range latMs {
		m.Latencies = append(m.Latencies, ms(l))
	}
	return m
}

// fastFailQUIC builds a raw-QUIC leg that failed FAST (the correct reject).
func fastFailQUIC(client string, latMs int) Measurement {
	return Measurement{Client: client, Transport: TransportQUIC, FirstContactOK: false, Latencies: []time.Duration{ms(latMs)}}
}

// allCooperativeOK returns a TCP-leg measurement set in which every cooperative
// client succeeds well within budget — the no-trigger baseline that the negative
// cases perturb one row at a time.
func allCooperativeOK() []Measurement {
	var out []Measurement
	for _, c := range CooperativeClients() {
		out = append(out, okTCP(c.Name, 100, 120, 140))
	}
	for _, c := range RawQUICClients() {
		out = append(out, fastFailQUIC(c.Name, 50))
	}
	return out
}

// ── Matrix shape (doc 12 §7 pinned set) ──────────────────────────────────────

func TestMatrix_PinnedSetComplete(t *testing.T) {
	// doc 12 §7 / doc 14 §10 enumerate the pinned client set explicitly. Every
	// named family must appear so a future matrix edit that DROPS a client (and
	// thus stops testing its first-contact) fails here.
	wantSubstrings := []string{
		"curl", "git", "node", "npm", "python-requests", "python-httpx",
		"go-nethttp", "rust-reqwest", "grpc",
		"anthropic-sdk-python", "anthropic-sdk-ts", "headless-chrome",
	}
	names := map[string]bool{}
	for _, c := range Matrix() {
		if c.Name == "" {
			t.Error("every matrix client must have a stable Name")
		}
		if c.Version == "" {
			t.Errorf("client %q must carry a pinned latest-stable Version (doc 12 §7)", c.Name)
		}
		if c.Why == "" {
			t.Errorf("client %q must tie back to the spec via Why", c.Name)
		}
		names[c.Name] = true
	}
	joined := strings.Join(keys(names), " ")
	for _, want := range wantSubstrings {
		if !strings.Contains(joined, want) {
			t.Errorf("pinned set is missing a %q-family client (doc 12 §7); have: %s", want, joined)
		}
	}
}

func TestMatrix_TwoPopulationsPresentAndDistinct(t *testing.T) {
	// The two-populations framing (doc 12 §7) requires BOTH a cooperative
	// population AND a raw-QUIC probe — never merged.
	coop := CooperativeClients()
	raw := RawQUICClients()
	if len(coop) == 0 {
		t.Fatal("no cooperative clients — DNS-4-steered population missing")
	}
	if len(raw) == 0 {
		t.Fatal("no raw-QUIC clients — the NFT-4-reject validation probe (curl --http3-only) is missing")
	}
	// The raw-QUIC probe must be a QUIC-forced posture (curl --http3-only),
	// never a happy-eyeballs client miscategorized.
	for _, c := range raw {
		if c.Posture != PostureQUICForced {
			t.Errorf("raw-QUIC client %q must have PostureQUICForced (the no-fallback probe), got %q", c.Name, c.Posture)
		}
	}
	// Cooperative clients must never be QUIC-forced (that would have no TCP pass).
	for _, c := range coop {
		if c.Posture == PostureQUICForced {
			t.Errorf("cooperative client %q must not be PostureQUICForced", c.Name)
		}
	}
}

func TestMatrix_GoldenImageNeutrality_ChromeDefaultQUICEnabled(t *testing.T) {
	// doc 12 §7 golden-image neutrality: headless Chrome runs default-QUIC-enabled
	// (happy-eyeballs), NOT with a forcing/disabling flag baked in.
	var chrome *Client
	for i := range Matrix() {
		if Matrix()[i].Name == "headless-chrome" {
			c := Matrix()[i]
			chrome = &c
		}
	}
	if chrome == nil {
		t.Fatal("headless-chrome row missing (doc 12 §7 pinned set)")
	}
	if chrome.Posture != PostureHappyEyeballs {
		t.Errorf("headless Chrome must be PostureHappyEyeballs (default-QUIC-enabled, no --disable-quic), got %q", chrome.Posture)
	}
	if strings.Contains(strings.ToLower(chrome.Invocation), "--disable-quic") {
		t.Error("headless Chrome invocation must NOT ship --disable-quic (it is a documented knob, not a default)")
	}
}

// ── Percentile / p95 ─────────────────────────────────────────────────────────

func TestP95_NearestRank(t *testing.T) {
	cases := []struct {
		name    string
		samples []int // ms
		p       int
		want    int // ms
	}{
		{"empty", nil, 95, 0},
		{"single", []int{42}, 95, 42},
		{"twenty-sequential-p95", seq(1, 20), 95, 19}, // ceil(0.95*20)=19th
		{"ten-sequential-p95", seq(1, 10), 95, 10},    // ceil(0.95*10)=10th
		{"p50-median-odd", []int{10, 20, 30}, 50, 20}, // ceil(0.5*3)=2nd
		{"p100-max", []int{5, 1, 3}, 100, 5},
		{"p0-clamps-to-first", []int{5, 1, 3}, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ds []time.Duration
			for _, s := range tc.samples {
				ds = append(ds, ms(s))
			}
			got := Percentile(ds, tc.p)
			if got != ms(tc.want) {
				t.Errorf("Percentile(%v, %d) = %s, want %s", tc.samples, tc.p, got, ms(tc.want))
			}
		})
	}
}

func TestP95_DoesNotMutateInput(t *testing.T) {
	in := []time.Duration{ms(30), ms(10), ms(20)}
	snapshot := append([]time.Duration(nil), in...)
	_ = Percentile(in, 95)
	for i := range in {
		if in[i] != snapshot[i] {
			t.Fatalf("Percentile mutated its input at %d: %v != %v", i, in, snapshot)
		}
	}
}

// ── Cooperative population verdict (TCP success within budget) ────────────────

func TestEvaluate_AllCooperativeWithinBudget_NoTrigger(t *testing.T) {
	r := Evaluate(allCooperativeOK(), DefaultBudget(), ms(150))
	if r.FlipToInspect() {
		t.Fatalf("all clients in budget + raw-QUIC fast-failed must NOT flip to inspect; triggered: %+v", r.TriggeredVerdicts())
	}
	if len(r.Verdicts) != len(Matrix()) {
		t.Errorf("verdict count = %d, want one per matrix client (%d)", len(r.Verdicts), len(Matrix()))
	}
}

func TestEvaluate_CooperativeFirstContactFailure_Triggers(t *testing.T) {
	target := CooperativeClients()[0].Name
	set := allCooperativeOK()
	for i := range set {
		if set[i].Client == target && set[i].Transport == TransportTCP {
			set[i].FirstContactOK = false // the developer-value endpoint is unreachable
		}
	}
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a cooperative TCP first-contact failure must flip to inspect (doc 12 §7 trigger 1)")
	}
	assertVerdict(t, r, target, ErrFirstContactFailed)
}

func TestEvaluate_CooperativeAbsoluteBudgetExceeded_Triggers(t *testing.T) {
	target := CooperativeClients()[0].Name
	set := allCooperativeOK()
	for i := range set {
		if set[i].Client == target && set[i].Transport == TransportTCP {
			// p95 well over the 2s absolute ceiling.
			set[i].Latencies = []time.Duration{ms(2500), ms(2600), ms(2700)}
		}
	}
	r := Evaluate(set, DefaultBudget(), 0) // no control ⇒ absolute ceiling governs
	if !r.FlipToInspect() {
		t.Fatal("a cooperative TCP p95 over the absolute ceiling must flip to inspect")
	}
	assertVerdict(t, r, target, ErrLatencyRegression)
}

func TestEvaluate_CooperativeRelativeRegressionVsControl_Triggers(t *testing.T) {
	target := CooperativeClients()[0].Name
	set := allCooperativeOK()
	for i := range set {
		if set[i].Client == target && set[i].Transport == TransportTCP {
			// 300ms p95 — under the 2s absolute ceiling, but >1.5x a 100ms control.
			set[i].Latencies = []time.Duration{ms(300), ms(300), ms(300)}
		}
	}
	r := Evaluate(set, DefaultBudget(), ms(100)) // control 100ms ⇒ limit 150ms
	if !r.FlipToInspect() {
		t.Fatal("a cooperative TCP p95 >1.5x the TCP-direct control must flip to inspect even under the absolute ceiling (doc 12 §7: regress vs a TCP-direct control)")
	}
	assertVerdict(t, r, target, ErrLatencyRegression)
}

func TestEvaluate_CooperativeQUICFailure_IsExpected_NotATrigger(t *testing.T) {
	// The crux of the two-populations framing: a COOPERATIVE client failing over
	// QUIC is the EXPECTED H3-suppression outcome (DNS-4 steered it to TCP). As
	// long as its TCP leg succeeds in budget, NO trigger fires.
	target := "" // first cooperative client that has a QUIC leg
	for _, c := range CooperativeClients() {
		if !c.NoQUICLeg {
			target = c.Name
			break
		}
	}
	if target == "" {
		t.Skip("no cooperative client with a measurable QUIC leg in the matrix")
	}
	set := allCooperativeOK()
	// Add a FAILED QUIC leg for the cooperative client (H3 suppressed) on top of
	// its successful TCP leg.
	set = append(set, Measurement{Client: target, Transport: TransportQUIC, FirstContactOK: false, Latencies: []time.Duration{ms(800)}})
	r := Evaluate(set, DefaultBudget(), ms(150))
	if r.FlipToInspect() {
		t.Fatalf("a cooperative QUIC first-contact failure with a healthy TCP leg must NOT trigger (it is the expected H3-suppression outcome); triggered: %+v", r.TriggeredVerdicts())
	}
}

func TestEvaluate_CooperativeMissingTCPLeg_TriggersNotVacuous(t *testing.T) {
	// Drop a cooperative client's TCP leg entirely — a missing required leg must
	// fire, never pass vacuously.
	target := CooperativeClients()[0].Name
	var set []Measurement
	for _, m := range allCooperativeOK() {
		if m.Client == target && m.Transport == TransportTCP {
			continue
		}
		set = append(set, m)
	}
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a cooperative client missing its TCP leg must trigger, never pass vacuously")
	}
	assertVerdict(t, r, target, ErrMissingMeasurement)
}

// ── Raw-QUIC population verdict (fast-fail = reject validated) ────────────────

func TestEvaluate_RawQUICFastFail_NoTrigger(t *testing.T) {
	// The baseline already fast-fails the raw-QUIC probe; confirm it is the pass.
	r := Evaluate(allCooperativeOK(), DefaultBudget(), ms(150))
	for _, v := range r.Verdicts {
		if v.Population == PopulationRawQUIC && v.Triggered {
			t.Fatalf("a raw-QUIC fast-fail validates the reject and must NOT trigger; got %v", v.Err)
		}
	}
}

func TestEvaluate_RawQUICSucceeds_IsBoundaryHole(t *testing.T) {
	// curl --http3-only SUCCEEDING means udp/443 reached upstream — the NFT-4
	// reject is not controlling. This is a hole, surfaced with its own sentinel.
	target := RawQUICClients()[0].Name
	set := allCooperativeOK()
	for i := range set {
		if set[i].Client == target && set[i].Transport == TransportQUIC {
			set[i].FirstContactOK = true // reject bypassed
			set[i].Latencies = []time.Duration{ms(120)}
		}
	}
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a raw-QUIC client that SUCCEEDS over udp/443 is a boundary hole and must fire")
	}
	assertVerdict(t, r, target, ErrRawQUICNotRejected)
}

func TestEvaluate_RawQUICSlowFail_SignalsSilentDrop(t *testing.T) {
	// A raw-QUIC FAILURE that took >1s signals a SILENT DROP, not the fast ICMP
	// port-unreachable reject D70 requires.
	target := RawQUICClients()[0].Name
	set := allCooperativeOK()
	for i := range set {
		if set[i].Client == target && set[i].Transport == TransportQUIC {
			set[i].FirstContactOK = false
			set[i].Latencies = []time.Duration{ms(5000)} // multi-second hang
		}
	}
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a raw-QUIC slow failure (>1s) signals a silent drop and must fire (doc 12 §7 reject-not-drop)")
	}
	assertVerdict(t, r, target, ErrRawQUICSlowFail)
}

func TestEvaluate_RawQUICMissingQUICLeg_TriggersNotVacuous(t *testing.T) {
	target := RawQUICClients()[0].Name
	var set []Measurement
	for _, m := range allCooperativeOK() {
		if m.Client == target && m.Transport == TransportQUIC {
			continue
		}
		set = append(set, m)
	}
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a raw-QUIC client missing its QUIC leg must trigger, never pass vacuously")
	}
	assertVerdict(t, r, target, ErrMissingMeasurement)
}

// ── Matrix drift ─────────────────────────────────────────────────────────────

func TestEvaluate_UnknownClientMeasurement_Triggers(t *testing.T) {
	set := append(allCooperativeOK(), okTCP("curl-quux-removed", 100))
	r := Evaluate(set, DefaultBudget(), ms(150))
	if !r.FlipToInspect() {
		t.Fatal("a measurement naming a client outside the pinned matrix must fire (matrix drift)")
	}
	found := false
	for _, v := range r.TriggeredVerdicts() {
		if v.Client == "curl-quux-removed" && errors.Is(v.Err, ErrUnknownClient) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an ErrUnknownClient verdict for the drifted client; triggered: %+v", r.TriggeredVerdicts())
	}
}

// ── Env-gate contract ────────────────────────────────────────────────────────

func TestLiveGate_DefaultOff(t *testing.T) {
	t.Setenv(LiveEnvVar, "")
	if LiveEnabled() {
		t.Fatal("live half must be OFF by default (DS_QUIC_CANARY_LIVE unset)")
	}
	t.Setenv(LiveEnvVar, "0")
	if LiveEnabled() {
		t.Fatal("DS_QUIC_CANARY_LIVE=0 must NOT enable the live half")
	}
	t.Setenv(LiveEnvVar, "1")
	if !LiveEnabled() {
		t.Fatal("DS_QUIC_CANARY_LIVE=1 must enable the live half")
	}
}

func TestLiveBaseline_DefaultAndOverride(t *testing.T) {
	t.Setenv(BaselineEnvVar, "")
	if got := LiveBaseline(); got != BaselineDomain {
		t.Errorf("default baseline = %q, want %q", got, BaselineDomain)
	}
	t.Setenv(BaselineEnvVar, "baseline.test.example")
	if got := LiveBaseline(); got != "baseline.test.example" {
		t.Errorf("override baseline = %q, want the env value", got)
	}
}

func TestRunLive_NotWired_FailsLoud(t *testing.T) {
	// Even with the gate ON, the live driver must fail LOUDLY until wired — never
	// a vacuous (empty-measurements) green.
	t.Setenv(LiveEnvVar, "1")
	_, _, err := RunLive()
	if !errors.Is(err, ErrLiveDriverNotWired) {
		t.Fatalf("RunLive with the gate on must return ErrLiveDriverNotWired; got %v", err)
	}
}

func TestRunLive_GateOff_StillSentinel(t *testing.T) {
	t.Setenv(LiveEnvVar, "")
	_, _, err := RunLive()
	if !errors.Is(err, ErrLiveDriverNotWired) {
		t.Fatalf("RunLive with the gate off must not silently produce an empty run; got %v", err)
	}
}

// TestLive_QUICCanary is the env-gated live runner: the over-the-wire real-client
// matrix. It SKIPS by default (gate off) and fails loudly when the gate is on but
// the driver is unwired, so the gate never reports a false green.
func TestLive_QUICCanary(t *testing.T) {
	if !LiveEnabled() {
		t.Skipf("live QUIC canary disabled; set %s=1 to run against a deployment (%s=%s)", LiveEnvVar, BaselineEnvVar, LiveBaseline())
	}
	ms, control, err := RunLive()
	if err != nil {
		t.Fatalf("live driver: %v (DEFERRED MANUAL — wire the real pinned-client drivers, doc 14 §10 Stage-2)", err)
	}
	r := Evaluate(ms, DefaultBudget(), control)
	if r.FlipToInspect() {
		t.Fatalf("live canary fired the flip-to-inspect trigger: %+v", r.TriggeredVerdicts())
	}
}

// ── Exported-sentinel-universe completeness (mirrors tlsproxyinspect) ─────────
//
// Every exported reject/trigger cause is an `Err<Name> = errors.New("quiccanary:
// …")` var enumerated here. This test reconciles the table against source by
// parsing exactly the `Err* = errors.New(...)` var specs in the non-_test.go
// files, so a sentinel added to source but not the universe (or vice versa)
// fails — keeping the named-cause convention honest.

var exportedSentinelUniverse = map[string]error{
	"ErrFirstContactFailed": ErrFirstContactFailed,
	"ErrLatencyRegression":  ErrLatencyRegression,
	"ErrRawQUICNotRejected": ErrRawQUICNotRejected,
	"ErrRawQUICSlowFail":    ErrRawQUICSlowFail,
	"ErrUnknownClient":      ErrUnknownClient,
	"ErrMissingMeasurement": ErrMissingMeasurement,
	"ErrLiveDriverNotWired": ErrLiveDriverNotWired,
}

func TestExportedSentinelUniverseComplete(t *testing.T) {
	inSource := scanExportedErrVars(t)
	for name := range inSource {
		if _, ok := exportedSentinelUniverse[name]; !ok {
			t.Errorf("exported error var %q is in source but missing from exportedSentinelUniverse — add it (and assert its trigger condition)", name)
		}
	}
	for name := range exportedSentinelUniverse {
		if !inSource[name] {
			t.Errorf("exportedSentinelUniverse names %q but no `%s = errors.New(...)` var exists in source", name, name)
		}
	}
}

func TestExportedSentinelsAreNamespaced(t *testing.T) {
	for name, err := range exportedSentinelUniverse {
		if err == nil {
			t.Errorf("sentinel %q is nil", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "quiccanary:") {
			t.Errorf("sentinel %q message must be namespaced `quiccanary: …`; got %q", name, err.Error())
		}
	}
}

// scanExportedErrVars parses the package's non-_test.go source and returns the
// set of exported var names assigned `errors.New(...)`. Mirrors the
// tlsproxyinspect by-name scan.
func scanExportedErrVars(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if !id.IsExported() || !strings.HasPrefix(id.Name, "Err") {
						continue
					}
					if i >= len(vs.Values) {
						continue
					}
					if isErrorsNewCall(vs.Values[i]) {
						out[id.Name] = true
					}
				}
			}
		}
	}
	return out
}

func isErrorsNewCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}

// ── small test utilities ─────────────────────────────────────────────────────

func assertVerdict(t *testing.T, r Report, client string, want error) {
	t.Helper()
	for _, v := range r.Verdicts {
		if v.Client != client {
			continue
		}
		if !v.Triggered {
			t.Fatalf("verdict for %q did not trigger; want %v", client, want)
		}
		if !errors.Is(v.Err, want) {
			t.Fatalf("verdict for %q: err = %v, want errors.Is(_, %v)", client, v.Err, want)
		}
		return
	}
	t.Fatalf("no verdict found for client %q", client)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func seq(lo, hi int) []int {
	var out []int
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}
