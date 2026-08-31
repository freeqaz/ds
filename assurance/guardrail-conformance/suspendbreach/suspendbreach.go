// SPDX-License-Identifier: Apache-2.0

package suspendbreach

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION).
const Tag = "suspend-on-breach-fires"

// PauseBudgetSeconds is the D46 fully-transparent pause budget in seconds: 5 min
// = 300s (doc 04 §6 D46 — "≤5 min fully transparent"). A suspend whose resume
// latency exceeds this is not transparent within budget. A guard test pins it to
// the documented tier so a silent constant drift fails in the test, not in
// production.
const PauseBudgetSeconds = 300

// ── Trip classes (D77 taxonomy, revising D53) ───────────────────────────────
//
// D77 reserves VM suspension for genuine threats: blocklist hits and rules
// explicitly configured action: suspend. Behavioral caps default action: block
// — an in-band error + async notify, never a suspend.

// TripClass names the class of guardrail trip.
type TripClass string

const (
	// ClassBlocklist — a blocklist hit (threat-intel feeds + org-defined entries):
	// a genuine-threat trip that MUST suspend (D77).
	ClassBlocklist TripClass = "blocklist"
	// ClassActionSuspend — a rule explicitly configured action: suspend (an
	// operation the org marks dangerous): MUST suspend (D77).
	ClassActionSuspend TripClass = "action_suspend"
	// ClassActionBlock — a behavioral cap defaulting action: block: serves an
	// in-band error + async notify, MUST NOT suspend (D77).
	ClassActionBlock TripClass = "action_block"
)

// isSuspendClass reports whether a trip class is a genuine-threat class that must
// suspend the VM.
func (c TripClass) isSuspendClass() bool {
	return c == ClassBlocklist || c == ClassActionSuspend
}

// ── Trip outcomes ───────────────────────────────────────────────────────────

// Outcome names what the boundary actually did when the trip fired.
type Outcome string

const (
	// OutcomeSuspended — the VM was suspended mid-action.
	OutcomeSuspended Outcome = "suspended"
	// OutcomeInBandError — an in-band machine-readable error (403/429) was served;
	// the VM kept running.
	OutcomeInBandError Outcome = "in_band_error"
)

// ── The synthetic trip picture ──────────────────────────────────────────────

// Trip is one guardrail trip in the synthetic fixture.
type Trip struct {
	// Name labels the trip for messages (e.g. "C2-domain blocklist hit").
	Name string `json:"name"`
	// Class is the trip class (blocklist | action_suspend | action_block).
	Class TripClass `json:"class"`
	// Outcome is what the boundary produced (suspended | in_band_error).
	Outcome Outcome `json:"outcome"`
	// InBandReason is true iff a machine-readable in-band reason (403/429 body,
	// EDE 15) was served. Required for action:block trips (D77).
	InBandReason bool `json:"in_band_reason"`
	// AsyncNotify is true iff an async human notification fired. Required for
	// action:block trips (D77 — ordinary policy events fire async notify).
	AsyncNotify bool `json:"async_notify"`
	// ResumeLatencySeconds is the resume latency for a suspend outcome (the time
	// the pause lasted before transparent resume). Meaningful only when
	// Outcome==suspended; it must be within PauseBudgetSeconds to be transparent.
	ResumeLatencySeconds int `json:"resume_latency_seconds"`
}

// Picture is a synthetic fixture's full trip picture.
type Picture struct {
	// Name labels the fixture (filled from the filename when loaded via Load).
	Name string `json:"-"`
	// Trips is the set of guardrail trips the fixture covers.
	Trips []Trip `json:"trips"`
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the failure modes this row enumerates.
type ViolationClass string

const (
	// ViolationSuspendClassNotSuspended — (a) a blocklist / action:suspend trip
	// whose outcome was not a suspend (the core negative control).
	ViolationSuspendClassNotSuspended ViolationClass = "suspend-class-trip-did-not-suspend"
	// ViolationResumeOverBudget — (b) a suspend whose resume latency exceeds the
	// D46 fully-transparent pause budget.
	ViolationResumeOverBudget ViolationClass = "resume-latency-over-pause-budget"
	// ViolationBlockClassSuspended — (c) an action:block trip that suspended the
	// VM (D77 reserves suspension for genuine threats).
	ViolationBlockClassSuspended ViolationClass = "block-class-trip-suspended-the-vm"
	// ViolationBlockClassNoInBandReason — (d) an action:block trip that served no
	// machine-readable in-band reason (D77 densest-channel rule).
	ViolationBlockClassNoInBandReason ViolationClass = "block-class-trip-no-in-band-reason"
)

// Violation is a single failure: which rule, which trip, and a reason.
type Violation struct {
	Class  ViolationClass
	Trip   string
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Trip, v.Reason)
}

// ── The mechanical check ────────────────────────────────────────────────────

// Check diffs a synthetic trip picture against the D77/D46 enforcement contract
// and returns every violation, in a stable order. An empty result means the
// picture conforms: every suspend-class trip suspended and resumed within the
// pause budget, and every action:block trip stayed in-band with a
// machine-readable reason + async notify and never suspended.
//
// Per-trip verdict:
//
//   - suspend-class (blocklist | action_suspend):
//     outcome != suspended → SuspendClassNotSuspended (a).
//     outcome == suspended and ResumeLatencySeconds > budget → ResumeOverBudget (b).
//   - action_block:
//     outcome == suspended → BlockClassSuspended (c).
//     !InBandReason → BlockClassNoInBandReason (d).
func Check(p Picture) []Violation {
	var vs []Violation
	for _, t := range p.Trips {
		switch {
		case t.Class.isSuspendClass():
			if t.Outcome != OutcomeSuspended {
				vs = append(vs, Violation{
					Class: ViolationSuspendClassNotSuspended,
					Trip:  t.label(),
					Reason: fmt.Sprintf("trip %s is a suspend-class trip (%s) but its outcome was %q, "+
						"not a suspend; a blocklist hit or an action:suspend rule must SUSPEND the VM "+
						"mid-action (D77, doc 03 §7 BIC)", t.label(), t.Class, t.Outcome),
				})
				continue
			}
			if t.ResumeLatencySeconds > PauseBudgetSeconds {
				vs = append(vs, Violation{
					Class: ViolationResumeOverBudget,
					Trip:  t.label(),
					Reason: fmt.Sprintf("trip %s suspended but resumed after %ds, past the %ds "+
						"fully-transparent pause budget; resume must be transparent within budget "+
						"(D46)", t.label(), t.ResumeLatencySeconds, PauseBudgetSeconds),
				})
			}
		case t.Class == ClassActionBlock:
			if t.Outcome == OutcomeSuspended {
				vs = append(vs, Violation{
					Class: ViolationBlockClassSuspended,
					Trip:  t.label(),
					Reason: fmt.Sprintf("trip %s is an action:block behavioral cap but it SUSPENDED the "+
						"VM; D77 reserves suspension for genuine threats — a behavioral cap serves an "+
						"in-band error + async notify, never a heavyweight suspend", t.label()),
				})
			}
			if !t.InBandReason {
				vs = append(vs, Violation{
					Class: ViolationBlockClassNoInBandReason,
					Trip:  t.label(),
					Reason: fmt.Sprintf("trip %s is an action:block cap but served no machine-readable "+
						"in-band reason; every denial carries a machine-readable reason on the densest "+
						"channel available so the agent self-heals instead of looping (D77)", t.label()),
				})
			}
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Trip < vs[j].Trip
	})
	return vs
}

// label names the trip for messages, with a fallback when blank.
func (t Trip) label() string {
	if t.Name != "" {
		return t.Name
	}
	return "(unnamed trip)"
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored).
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate rejects a picture with no trips or a trip whose class/outcome is
// outside the enumerated set.
func (p Picture) validate() error {
	if len(p.Trips) == 0 {
		return fmt.Errorf("picture %s declares no trips — a trip picture must cover at least one "+
			"guardrail trip", p.Name)
	}
	for _, t := range p.Trips {
		switch t.Class {
		case ClassBlocklist, ClassActionSuspend, ClassActionBlock:
		default:
			return fmt.Errorf("picture %s trip %s declares unknown class %q (want %q, %q, or %q)",
				p.Name, t.label(), t.Class, ClassBlocklist, ClassActionSuspend, ClassActionBlock)
		}
		switch t.Outcome {
		case OutcomeSuspended, OutcomeInBandError:
		default:
			return fmt.Errorf("picture %s trip %s declares unknown outcome %q (want %q or %q)",
				p.Name, t.label(), t.Outcome, OutcomeSuspended, OutcomeInBandError)
		}
	}
	return nil
}

// Load reads a synthetic trip picture from a JSON file and labels it with the
// file's base name for violation messages.
func Load(path string) (Picture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Picture{}, fmt.Errorf("reading trip-picture fixture %s: %w", path, err)
	}
	var p Picture
	if err := json.Unmarshal(data, &p); err != nil {
		return Picture{}, fmt.Errorf("parsing trip-picture fixture %s: %w", path, err)
	}
	p.Name = filepath.Base(path)
	if err := p.validate(); err != nil {
		return Picture{}, err
	}
	return p, nil
}
