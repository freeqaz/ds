// SPDX-License-Identifier: Apache-2.0

package quiccanary

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// harness.go — the D70 nightly QUIC conformance canary harness (doc 12 §7,
// doc 14 §10). It executes the pinned-client workload matrix against a baseline
// domain over QUIC and a TCP-direct control, measures p95 first-contact latency,
// and evaluates the FLIP-TO-INSPECT trigger: any first-contact failure to an
// allowed domain OR any p95 latency regression beyond budget fires the trigger.
//
// # The verdict, by population (doc 12 §7 two-populations framing)
//
//   - Cooperative clients (curl --http3, Chrome, git, Node, Python, Go, Rust,
//     gRPC, the Anthropic SDKs): pass when TCP first-contact SUCCEEDS within the
//     p95 latency budget. DNS-4 steers them onto TCP, so a QUIC first-contact
//     "failure" for a cooperative client is the EXPECTED outcome, NOT a trigger.
//   - Raw-QUIC clients (curl --http3-only): pass when QUIC first-contact FAILS
//     FAST (the NFT-4 reject ⇒ ICMP port-unreachable ⇒ ECONNREFUSED in <1s). A
//     raw-QUIC client that SUCCEEDS is the boundary hole — that flips the
//     verdict, because it means udp/443 is reachable.
//
// # The harness split — offline verdict logic + env-gated live driver
//
// The verdict/trigger logic (LatencyBudget, p95, VerdictFor, Evaluate) is PURE
// and offline-evaluable: harness_test.go drives it against SYNTHETIC measurements
// (no network), exactly as resolverlock asserts the NFT-4 shape offline before
// the live tier lands. The LIVE half (env-gated behind LiveEnvVar, default
// SKIPPED) drives the REAL pinned clients over the wire against a running
// boundary; until an operator wires the real drivers it fails LOUDLY per
// workload (the notYetWired scaffold), so the gate never reports a false green.
//
// This is the doc 06 (c)/(d) rig extension that lands WITH NFT-4 at Stage 2
// (doc 14 §10 TODO): the canary attaches to the doc 06 (c) guardrail-assurance
// framework on a nightly schedule and gates the flip-to-inspect trigger.

// LiveEnvVar is the single switch for the live half. UNSET (or any value other
// than "1") keeps the live half disabled — LiveEnabled() returns false and the
// live runners SKIP naming this var, so the default `go test ./...` is offline
// and deterministic. CI never sets it. Set to "1" to opt into the live run
// (which fails LOUDLY until the real client drivers are wired).
const LiveEnvVar = "DS_QUIC_CANARY_LIVE"

// BaselineEnvVar points the live run at a deployment's baseline domain (the
// api.anthropic.com-shaped endpoint). It only resolves WHERE the live half would
// connect — it does not by itself enable the live half; LiveEnvVar still governs.
const BaselineEnvVar = "DS_QUIC_CANARY_BASELINE"

// LiveEnabled reports whether the operator opted into the live half via
// LiveEnvVar=1. The default (unset) is false — CI is offline and deterministic.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// LiveBaseline returns the live baseline domain (BaselineEnvVar override, else
// the BaselineDomain default). It does not enable the live half.
func LiveBaseline() string {
	if v := os.Getenv(BaselineEnvVar); v != "" {
		return v
	}
	return BaselineDomain
}

// ── Latency budget ─────────────────────────────────────────────────────────
//
// The canary latency budget is a FREE cell (doc 12 §9 "QUIC … canary latency
// budget" / §13 free column; doc 14 §10 "canary latency budget is free"). We set
// it here as build guidance, not a frozen contract: a generous absolute p95
// ceiling for first-contact to the baseline domain over TCP, plus a relative
// regression margin over the TCP-direct control. Both are tunable knobs the
// nightly job owner adjusts as the baseline is characterized.

// DefaultP95Budget is the absolute p95 first-contact latency ceiling for a
// cooperative client over TCP to the baseline domain. First contact includes
// DNS resolution through ds-dnsgate, the TLS-1 SNI admission + termination, and
// the upstream re-origination — so it is deliberately generous. Exceeding it is
// a latency regression that fires the flip-to-inspect trigger.
const DefaultP95Budget = 2 * time.Second

// DefaultRegressionMargin is the relative p95 ceiling over the TCP-direct
// control: a client's measured p95 over the boundary may exceed the direct
// control by up to this factor before it counts as a regression. The canary's
// whole framing is "boundary TCP vs TCP-direct control" (doc 12 §7), so the
// relative margin is the primary regression signal; the absolute budget is the
// backstop for when no control measurement is available.
const DefaultRegressionMargin = 1.5

// LatencyBudget is the (absolute p95 ceiling, relative regression margin) pair
// the canary evaluates each cooperative client against. The zero value is NOT
// usable; use DefaultBudget() or construct explicitly.
type LatencyBudget struct {
	// P95Ceiling is the absolute p95 first-contact ceiling over TCP.
	P95Ceiling time.Duration
	// RegressionMargin is the multiplier the boundary-leg p95 may exceed the
	// TCP-direct control p95 by before it counts as a regression (e.g. 1.5 ⇒ 50%
	// over the control). Ignored when a case carries no control measurement.
	RegressionMargin float64
}

// DefaultBudget returns the build-guidance default budget (the FREE-cell values).
func DefaultBudget() LatencyBudget {
	return LatencyBudget{P95Ceiling: DefaultP95Budget, RegressionMargin: DefaultRegressionMargin}
}

// ── Measurements ───────────────────────────────────────────────────────────

// Measurement is one client's observed first-contact result on one transport
// leg over a set of probe samples. The live half fills this in from real client
// runs; the offline half synthesizes it to assert the verdict logic.
type Measurement struct {
	// Client is the pinned-client name (joins to a Matrix() row).
	Client string
	// Transport is the leg this measurement covers (TCP or QUIC).
	Transport Transport
	// FirstContactOK reports whether first contact to the baseline domain
	// SUCCEEDED on this leg. For a cooperative TCP leg, true is the pass
	// condition; for a raw-QUIC leg, true is the FAILURE (the reject was bypassed).
	FirstContactOK bool
	// Latencies are the per-sample first-contact latencies. p95 is computed from
	// these. May be empty when first contact failed outright (a refused QUIC leg
	// carries the single fast-fail latency so the "fails fast" property is
	// checkable).
	Latencies []time.Duration
}

// P95 returns the 95th-percentile first-contact latency over the samples using
// the nearest-rank method (the smallest sample at or above the 95% rank). It
// returns 0 for an empty sample set. Nearest-rank is the standard, dependency-
// free p95 for the small nightly sample counts (no interpolation, no float
// surprises).
func (m Measurement) P95() time.Duration { return Percentile(m.Latencies, 95) }

// Percentile computes the p-th percentile of the durations via nearest-rank.
// p is clamped to [0,100]. An empty input returns 0. Exposed so the live half
// and the D74 baseline-discovery sessions compute percentiles identically.
func Percentile(samples []time.Duration, p int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// Nearest-rank: rank = ceil(p/100 * N), 1-based; index = rank-1.
	rank := (p*len(sorted) + 99) / 100 // ceil division
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// FastFailThreshold is the ceiling under which a raw-QUIC client's first-contact
// FAILURE must land for the NFT-4 reject to count as "fails fast" (doc 12 §7,
// doc 12 §13.5: <1s ECONNREFUSED, never a multi-second silent-drop hang). A
// raw-QUIC leg that fails SLOWLY signals a silent drop — itself a boundary
// defect, distinct from the reject working correctly.
const FastFailThreshold = time.Second

// ── Named verdict failure modes ────────────────────────────────────────────
//
// Each names ONE doc 12 §7 / doc 14 §10 canary row a measurement must satisfy.
// A regression or failure surfaces the SPECIFIC sentinel (loud, actionable) so a
// nightly failure tells the on-call exactly which property broke and that the
// flip-to-inspect trigger fired. Tests assert the specific error via errors.Is;
// the universe is reconciled against source the same way tlsproxyinspect does.

var (
	// ErrFirstContactFailed fires when a COOPERATIVE client's TCP first-contact
	// to the allowed baseline domain FAILED — the doc 12 §7 trigger-1 condition
	// ("fail first-contact to a baseline domain"). The boundary must let the
	// developer-value endpoint through over TCP; a failure flips to inspect.
	ErrFirstContactFailed = errors.New("quiccanary: cooperative client TCP first-contact to the baseline domain FAILED — a developer-value endpoint is unreachable over the transport DNS-4 steers clients onto; this fires the D70 flip-to-inspect trigger (doc 12 §7 trigger 1)")
	// ErrLatencyRegression fires when a cooperative client's TCP p95
	// first-contact latency exceeded the absolute budget OR the relative margin
	// over the TCP-direct control — the doc 12 §7 trigger-1 condition ("regress
	// p95 first-contact latency beyond budget vs a TCP-direct control").
	ErrLatencyRegression = errors.New("quiccanary: cooperative client p95 first-contact latency REGRESSED beyond budget (absolute ceiling or relative margin over the TCP-direct control) — this fires the D70 flip-to-inspect trigger (doc 12 §7 trigger 1)")
	// ErrRawQUICNotRejected fires when a RAW-QUIC client (curl --http3-only)
	// first-contact SUCCEEDED — udp/443 reached an upstream, so the NFT-4 reject
	// is NOT controlling the non-cooperative population. This is a boundary HOLE
	// (the sole control for raw QUIC failed), distinct from a latency trigger.
	ErrRawQUICNotRejected = errors.New("quiccanary: raw-QUIC (curl --http3-only) first-contact SUCCEEDED — udp/443 reached upstream, so the NFT-4 reject is NOT controlling the non-cooperative population; this is a boundary hole, not just a flip trigger (doc 12 §7, two-populations framing)")
	// ErrRawQUICSlowFail fires when a raw-QUIC client's first-contact FAILED but
	// only after FastFailThreshold — a slow failure signals a silent drop, not the
	// fast ICMP-port-unreachable reject D70 requires (the multi-second hang the
	// reject-not-drop verdict exists to prevent).
	ErrRawQUICSlowFail = errors.New("quiccanary: raw-QUIC (curl --http3-only) first-contact failed SLOWLY (> the fast-fail threshold) — a silent drop, not the fast ICMP port-unreachable reject D70 requires; the udp/443 rule must reject-not-drop (doc 12 §7, §13.5)")
	// ErrUnknownClient fires when a Measurement names a client not in Matrix() —
	// a measurement set that drifted from the pinned matrix (a renamed or removed
	// client) would otherwise silently skip its verdict.
	ErrUnknownClient = errors.New("quiccanary: measurement names a client absent from the pinned workload matrix — the measurement set drifted from Matrix() (doc 12 §7 pinned set)")
	// ErrMissingMeasurement fires when a matrix client has no measurement for a
	// leg the harness must evaluate (a cooperative client with no TCP leg, or a
	// raw-QUIC client with no QUIC leg) — a missing measurement must never pass
	// vacuously.
	ErrMissingMeasurement = errors.New("quiccanary: a pinned client is missing the measurement leg its population requires (cooperative⇒TCP, raw-quic⇒QUIC) — a missing leg must never pass vacuously (doc 12 §7)")
	// ErrLiveDriverNotWired fires from the env-gated live half until an operator
	// wires the real client drivers — so DS_QUIC_CANARY_LIVE=1 fails LOUDLY rather
	// than reporting a false green over an unimplemented driver.
	ErrLiveDriverNotWired = errors.New("quiccanary: live client driver not wired — DS_QUIC_CANARY_LIVE=1 requires a running boundary + real pinned-client drivers the wave sandbox lacks; this is a DEFERRED MANUAL step (doc 12 §7, doc 14 §10 Stage-2 NFT-4 rig extension)")
)

// ── Verdict ────────────────────────────────────────────────────────────────

// ClientVerdict is the per-client outcome of one canary run.
type ClientVerdict struct {
	Client     string
	Population Population
	// Triggered reports whether THIS client's measurement fires the
	// flip-to-inspect trigger (or surfaces a boundary hole).
	Triggered bool
	// Err is the specific named cause when Triggered, else nil. Always one of the
	// exported Err* sentinels (wrapped with measurement detail), never an
	// anonymous error, so the on-call gets an actionable cause.
	Err error
	// TCPP95 / QUICP95 are the measured p95 first-contact latencies (0 when the
	// leg was not measured), carried for the nightly report and the D74 sessions.
	TCPP95  time.Duration
	QUICP95 time.Duration
}

// byClient indexes measurements by (client, transport).
type measKey struct {
	client    string
	transport Transport
}

func indexMeasurements(ms []Measurement) map[measKey]Measurement {
	out := make(map[measKey]Measurement, len(ms))
	for _, m := range ms {
		out[measKey{m.Client, m.Transport}] = m
	}
	return out
}

// VerdictFor computes the canary verdict for ONE pinned client from its
// measurements, against the budget. control is the TCP-direct (no-boundary)
// p95 for the relative-regression check (0 ⇒ relative check skipped, absolute
// ceiling still applies). This is the PURE function the offline half asserts and
// the live half cross-checks its real-world observation against, so both halves
// agree on the spec.
func VerdictFor(c Client, idx map[measKey]Measurement, budget LatencyBudget, control time.Duration) ClientVerdict {
	v := ClientVerdict{Client: c.Name, Population: c.Population}

	switch c.Population {
	case PopulationRawQUIC:
		// Raw-QUIC: measured over QUIC ONLY; pass condition is a FAST FAILURE.
		m, ok := idx[measKey{c.Name, TransportQUIC}]
		if !ok {
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s raw-quic client has no QUIC leg", ErrMissingMeasurement, c.Name)
			return v
		}
		v.QUICP95 = m.P95()
		if m.FirstContactOK {
			// udp/443 reached upstream — the reject is not controlling. Boundary hole.
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s succeeded over QUIC", ErrRawQUICNotRejected, c.Name)
			return v
		}
		// Failed (correct) — but it must fail FAST (reject, not silent drop).
		if fastest := minDuration(m.Latencies); fastest > FastFailThreshold {
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s failed in %s (> %s)", ErrRawQUICSlowFail, c.Name, fastest, FastFailThreshold)
			return v
		}
		return v // fast fail — the reject mechanism validated.

	default: // PopulationCooperative
		// Cooperative: pass condition is TCP first-contact success within budget.
		// The QUIC leg (when present) is measured for observability only — a
		// cooperative QUIC failure is the EXPECTED H3-suppression outcome, never a
		// trigger.
		if q, ok := idx[measKey{c.Name, TransportQUIC}]; ok {
			v.QUICP95 = q.P95()
		}
		m, ok := idx[measKey{c.Name, TransportTCP}]
		if !ok {
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s cooperative client has no TCP leg", ErrMissingMeasurement, c.Name)
			return v
		}
		v.TCPP95 = m.P95()
		if !m.FirstContactOK {
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s failed TCP first-contact", ErrFirstContactFailed, c.Name)
			return v
		}
		p95 := m.P95()
		if p95 > budget.P95Ceiling {
			v.Triggered = true
			v.Err = fmt.Errorf("%w: %s TCP p95 %s exceeds absolute ceiling %s", ErrLatencyRegression, c.Name, p95, budget.P95Ceiling)
			return v
		}
		if control > 0 && budget.RegressionMargin > 0 {
			limit := time.Duration(float64(control) * budget.RegressionMargin)
			if p95 > limit {
				v.Triggered = true
				v.Err = fmt.Errorf("%w: %s TCP p95 %s exceeds %.2gx the TCP-direct control %s (limit %s)", ErrLatencyRegression, c.Name, p95, budget.RegressionMargin, control, limit)
				return v
			}
		}
		return v // success within budget — no trigger.
	}
}

// Report is the outcome of one full canary run over the whole matrix.
type Report struct {
	// Verdicts is the per-client verdict, matrix order.
	Verdicts []ClientVerdict
	// Triggered reports whether ANY client fired the flip-to-inspect trigger or
	// surfaced a boundary hole. A nightly run with Triggered=true escalates to the
	// flip-to-inspect evaluation (doc 12 §7 trigger 1).
	Triggered bool
}

// FlipToInspect is the standing-trigger verdict (doc 12 §7: "Trigger evaluation
// is a standing weekly/nightly check, not a judgment call"). It is exactly
// Report.Triggered — any first-contact failure or latency regression to an
// allowed domain, or a raw-QUIC client that was NOT rejected.
func (r Report) FlipToInspect() bool { return r.Triggered }

// TriggeredVerdicts returns just the verdicts that fired (the nightly failure
// list the on-call sees).
func (r Report) TriggeredVerdicts() []ClientVerdict {
	var out []ClientVerdict
	for _, v := range r.Verdicts {
		if v.Triggered {
			out = append(out, v)
		}
	}
	return out
}

// Evaluate runs the verdict logic over the WHOLE pinned matrix given a set of
// measurements and a control p95 (the TCP-direct, no-boundary baseline). It is
// the nightly canary's offline-evaluable core: the live half collects real
// measurements and calls Evaluate; the offline half synthesizes measurements and
// asserts Evaluate's verdicts. An ErrUnknownClient measurement (one not in the
// matrix) is reported as a triggered verdict so matrix drift never passes
// silently.
func Evaluate(ms []Measurement, budget LatencyBudget, control time.Duration) Report {
	idx := indexMeasurements(ms)
	known := make(map[string]bool)
	var report Report

	for _, c := range Matrix() {
		known[c.Name] = true
		v := VerdictFor(c, idx, budget, control)
		report.Verdicts = append(report.Verdicts, v)
		if v.Triggered {
			report.Triggered = true
		}
	}

	// Flag any measurement that names a client outside the pinned matrix — a
	// measurement set that drifted (renamed/removed client) must never silently
	// skip its verdict.
	seen := make(map[string]bool)
	for _, m := range ms {
		if known[m.Client] || seen[m.Client] {
			continue
		}
		seen[m.Client] = true
		report.Verdicts = append(report.Verdicts, ClientVerdict{
			Client:    m.Client,
			Triggered: true,
			Err:       fmt.Errorf("%w: %q", ErrUnknownClient, m.Client),
		})
		report.Triggered = true
	}

	return report
}

// minDuration returns the smallest sample (the fastest first-contact attempt),
// or 0 for an empty set. Used to assert a raw-QUIC failure landed FAST.
func minDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	m := ds[0]
	for _, d := range ds[1:] {
		if d < m {
			m = d
		}
	}
	return m
}

// RunLive is the env-gated live driver entry point. It drives the REAL pinned
// clients over the wire against the baseline (LiveBaseline()) and returns the
// collected measurements + control. Until an operator wires the real client
// drivers it returns ErrLiveDriverNotWired so DS_QUIC_CANARY_LIVE=1 never reports
// a false green. The live half (a DEFERRED MANUAL step) replaces this body with
// the real drivers; the verdict logic (Evaluate) is unchanged.
func RunLive() (ms []Measurement, control time.Duration, err error) {
	if !LiveEnabled() {
		// Caller must gate on LiveEnabled(); returning the sentinel here keeps a
		// misuse from silently producing an empty (vacuously-passing) run.
		return nil, 0, fmt.Errorf("%w: live half not enabled (%s != 1)", ErrLiveDriverNotWired, LiveEnvVar)
	}
	return nil, 0, ErrLiveDriverNotWired
}
