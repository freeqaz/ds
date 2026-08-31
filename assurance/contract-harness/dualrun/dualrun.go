// SPDX-License-Identifier: Apache-2.0

// Package dualrun is the run-the-suite-against-real-AND-fake harness (doc 06
// §2.1, doc 15 §11). A module ships ONE conformance suite; this package runs it
// twice — once dialed at the real implementation, once at the generated fake —
// and fails on any divergence between the two outcome sets.
//
// The contract this package enforces is the linchpin of the parallel-development
// story (D14/D24): if the two runs diverge, either the fake is lying (a
// downstream team is coding against fiction) or the implementation drifted from
// the contract. Both are bugs at the seam, and both are caught per-commit.
//
// A suite is a list of named Scenarios. Each scenario is a pure function of a
// dialed *grpc.ClientConn that returns an Observation — a stable, comparable
// summary of what the scenario observed at the seam (response fields, gRPC
// status codes, stream framing). The harness runs every scenario against both
// ends, compares Observations, and reports the seam green only if every scenario
// observed the same thing on the real impl and the fake.
package dualrun

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc"
)

// Observation is the stable, comparable summary a scenario produces at the seam.
// It is intentionally a flat, ordered key/value view rather than a Go value:
// equality is by canonical string form, so two runs that produced equivalent
// observations compare equal regardless of map iteration order or unexported
// proto internals. Scenarios record only what the CONTRACT promises — never
// implementation-private detail — so a faithful fake and a faithful real impl
// observe identically.
type Observation struct {
	kv map[string]string
}

// NewObservation returns an empty Observation ready to record into.
func NewObservation() *Observation { return &Observation{kv: map[string]string{}} }

// Set records a contract-observable key/value. Later Sets on the same key
// overwrite; this keeps scenario code straight-line.
func (o *Observation) Set(key, value string) *Observation {
	if o.kv == nil {
		o.kv = map[string]string{}
	}
	o.kv[key] = value
	return o
}

// Setf is Set with a format string for the value.
func (o *Observation) Setf(key, format string, args ...any) *Observation {
	return o.Set(key, fmt.Sprintf(format, args...))
}

// Canonical renders the Observation as a deterministic, sorted string. Two
// Observations are equal iff their Canonical forms are equal.
func (o *Observation) Canonical() string {
	if o == nil {
		return "<nil>"
	}
	keys := make([]string, 0, len(o.kv))
	for k := range o.kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(o.kv[k])
	}
	return b.String()
}

// Scenario is one named conformance case. It is run twice — once with a conn
// dialed at the real implementation, once at the generated fake — and must
// produce the SAME Observation both times for the seam to be green. A scenario
// returning an error (a harness-level failure, e.g. an unexpected transport
// error) fails the run for the end it ran against; contract-level outcomes
// (including expected gRPC error statuses) belong in the Observation, not the
// error.
type Scenario struct {
	Name string
	Run  func(ctx context.Context, conn *grpc.ClientConn) (*Observation, error)
}

// Suite is a module's single conformance suite (doc 06 §3a: one suite, run
// against real + fake). Scenarios run in declaration order.
type Suite struct {
	// Seam names the seam under test, e.g. "orchestrator<->hostagent".
	Seam      string
	Scenarios []Scenario
}

// Dialer yields a *grpc.ClientConn dialed at one end of the seam (real impl or
// generated fake), plus a stop func that releases it. Production wiring dials a
// real address; the in-process harness dials a bufconn (see bufconn.go).
type Dialer interface {
	Dial(ctx context.Context) (conn *grpc.ClientConn, stop func(), err error)
}

// Divergence is one scenario whose real and fake Observations disagree.
type Divergence struct {
	Scenario string
	Real     string // Real impl's canonical Observation
	Fake     string // Generated fake's canonical Observation
}

// ScenarioObservation pairs the real and fake Observations a single scenario
// produced during a dual run. It is the per-scenario record the cross-end
// equality check in Suite.Run already computed — exposed so a directed test can
// assert on the ACTUAL observed verdict without re-driving the responder
// out-of-band. Either side is nil when that end failed at the harness level (the
// failure is then in Result.RealErrors / Result.FakeErrors). By construction
// these hold only the contract-observable key/value form a Scenario chose to
// record (Observation), never secret bytes (doc 16 §5.2): the harness retains
// whatever the scenario recorded and nothing more.
type ScenarioObservation struct {
	Scenario string
	Real     *Observation
	Fake     *Observation
}

// Result is the outcome of running a Suite against both ends.
type Result struct {
	Seam        string
	Ran         int
	Divergences []Divergence
	// RealErrors / FakeErrors hold harness-level (non-contract) failures keyed by
	// scenario name — a scenario that could not run cleanly against that end.
	RealErrors map[string]error
	FakeErrors map[string]error

	// perScenario holds, in declaration order, the real+fake Observation each
	// scenario produced (nil on the side that failed at the harness level). It is
	// populated by Suite.Run and read back through PerScenario / ObservationsFor;
	// it is unexported so the public field set (Seam/Ran/Divergences/RealErrors/
	// FakeErrors) stays backward-compatible. Map iteration over RealErrors/
	// FakeErrors is randomized, but this slice preserves Suite.Run ordering.
	perScenario []ScenarioObservation
}

// PerScenario returns the per-scenario real+fake Observations in the order the
// suite ran them (declaration order — the same order Suite.Run walked). The
// returned slice is a copy of the header records, so a caller cannot mutate the
// Result's bookkeeping; the Observations themselves are shared (treat them as
// read-only). Use it to make a directed assertion on the ACTUAL observed verdict
// the dual run already drove, instead of constructing a second responder.
func (r *Result) PerScenario() []ScenarioObservation {
	if r == nil || len(r.perScenario) == 0 {
		return nil
	}
	out := make([]ScenarioObservation, len(r.perScenario))
	copy(out, r.perScenario)
	return out
}

// ObservationsFor returns the real and fake Observation a single named scenario
// produced during the run, and whether that scenario was found. Either returned
// Observation is nil when that end failed at the harness level (see
// Result.RealErrors / Result.FakeErrors). The returned Observations are shared
// with the Result; treat them as read-only.
func (r *Result) ObservationsFor(scenario string) (real, fake *Observation, ok bool) {
	if r == nil {
		return nil, nil, false
	}
	for _, so := range r.perScenario {
		if so.Scenario == scenario {
			return so.Real, so.Fake, true
		}
	}
	return nil, nil, false
}

// OK reports whether the seam is green: every scenario ran cleanly on both ends
// and observed the same thing.
func (r *Result) OK() bool {
	return len(r.Divergences) == 0 && len(r.RealErrors) == 0 && len(r.FakeErrors) == 0
}

// Report renders a human-readable summary suitable for a test failure message.
func (r *Result) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "dual-run seam %q: ran %d scenario(s)", r.Seam, r.Ran)
	if r.OK() {
		b.WriteString(" — real and fake agree on every scenario (green).")
		return b.String()
	}
	b.WriteString(" — DIVERGENCE (a fake is lying or an impl drifted, doc 06 §2.1):\n")
	for _, d := range r.Divergences {
		fmt.Fprintf(&b, "  scenario %q diverged:\n    real: %s\n    fake: %s\n",
			d.Scenario, indent(d.Real), indent(d.Fake))
	}
	for _, name := range sortedKeys(r.RealErrors) {
		fmt.Fprintf(&b, "  scenario %q failed against REAL impl: %v\n", name, r.RealErrors[name])
	}
	for _, name := range sortedKeys(r.FakeErrors) {
		fmt.Fprintf(&b, "  scenario %q failed against generated FAKE: %v\n", name, r.FakeErrors[name])
	}
	return b.String()
}

// Run executes the suite against both ends and returns the comparison Result.
// It never panics on a scenario error; harness-level errors are collected so a
// single broken scenario does not mask the rest of the seam.
func (s Suite) Run(ctx context.Context, real, fake Dialer) (*Result, error) {
	res := &Result{
		Seam:       s.Seam,
		RealErrors: map[string]error{},
		FakeErrors: map[string]error{},
	}
	realConn, stopReal, err := real.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dual-run %q: dial real: %w", s.Seam, err)
	}
	defer stopReal()
	fakeConn, stopFake, err := fake.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dual-run %q: dial fake: %w", s.Seam, err)
	}
	defer stopFake()

	for _, sc := range s.Scenarios {
		res.Ran++
		realObs, realErr := safeRun(ctx, sc, realConn)
		fakeObs, fakeErr := safeRun(ctx, sc, fakeConn)
		// Record the per-scenario real+fake Observations in declaration order so a
		// directed test can read back the ACTUAL observed verdict (PerScenario /
		// ObservationsFor) instead of re-driving the responder. The Observation on
		// a failed end is nil; its harness error rides RealErrors/FakeErrors below.
		res.perScenario = append(res.perScenario, ScenarioObservation{
			Scenario: sc.Name,
			Real:     realObs,
			Fake:     fakeObs,
		})
		if realErr != nil {
			res.RealErrors[sc.Name] = realErr
		}
		if fakeErr != nil {
			res.FakeErrors[sc.Name] = fakeErr
		}
		if realErr != nil || fakeErr != nil {
			continue
		}
		if realObs.Canonical() != fakeObs.Canonical() {
			res.Divergences = append(res.Divergences, Divergence{
				Scenario: sc.Name,
				Real:     realObs.Canonical(),
				Fake:     fakeObs.Canonical(),
			})
		}
	}
	return res, nil
}

// safeRun runs one scenario, converting a panic into an error so one misbehaving
// scenario cannot crash the whole seam run.
func safeRun(ctx context.Context, sc Scenario, conn *grpc.ClientConn) (obs *Observation, err error) {
	defer func() {
		if r := recover(); r != nil {
			obs = nil
			err = fmt.Errorf("scenario panicked: %v", r)
		}
	}()
	obs, err = sc.Run(ctx, conn)
	if err == nil && obs == nil {
		err = fmt.Errorf("scenario returned a nil Observation and no error")
	}
	return obs, err
}

func indent(s string) string {
	return strings.ReplaceAll(s, "\n", "\n          ")
}

// sortedKeys returns the map's keys in deterministic order so Report output is
// stable across runs (Go map iteration is randomized).
func sortedKeys(m map[string]error) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
