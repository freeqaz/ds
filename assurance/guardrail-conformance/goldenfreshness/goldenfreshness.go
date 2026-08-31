// SPDX-License-Identifier: Apache-2.0

package goldenfreshness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ── The rotation window (doc 03 §6 "Package & build caching", "Nightly golden
//    images" bullet / images/golden/README.md) ─────────────────────────────
//
// The rotation policy is a freshness / max-age check: a golden a session clones
// from is never older than the rotation window. The window default is the nightly
// cadence (24h); images/golden/nightly-rebuild.sh exposes it as the
// DS_GOLDEN_MAX_AGE_HOURS env override. We model the policy as DATA carried in
// each fixture (Policy.MaxAgeHours) so a manifest pins the exact window it
// asserts against; DefaultRotationWindow restates the documented default the
// runtime check falls back to, and a guard test pins it to the documented cadence
// so a silent constant drift fails in the test, not in production.

// DefaultRotationWindow is the documented default rotation window in hours: 24h,
// the nightly rebuild cadence (doc 03 §6, images/golden/README.md "Rotation
// window = DS_GOLDEN_MAX_AGE_HOURS (default 24h)"). A golden older than the
// window is STALE and must be rolled before any new session clones from it.
const DefaultRotationWindow = 24

// MaxAgeEnvVar is the documented env override name for the rotation window, named
// here only so the claim text and the runtime contract (nightly-rebuild.sh) stay
// in lockstep; this package never reads it (it diffs DATA, never the environment).
const MaxAgeEnvVar = "DS_GOLDEN_MAX_AGE_HOURS"

// ── The rotation policy ─────────────────────────────────────────────────────

// Policy is the rotation policy a golden manifest is diffed against: the single
// knob is the rotation window (max age, in hours).
type Policy struct {
	// MaxAgeHours is the rotation window: a present golden older than this is
	// STALE. A non-positive value is invalid (the policy must name a real window).
	MaxAgeHours int `json:"max_age_hours"`
}

// resolvedWindow returns the policy's window, falling back to the documented
// default when the fixture left it unset (zero). A negative window is left as-is
// so validate() can reject it.
func (p Policy) resolvedWindow() int {
	if p.MaxAgeHours == 0 {
		return DefaultRotationWindow
	}
	return p.MaxAgeHours
}

// ── The golden manifest (synthetic fixture) ─────────────────────────────────

// GoldenRow is one opted-in (repo, branch)'s golden in the manifest: whether the
// bake has produced it (Present) and, if so, how old it is in hours (AgeHours,
// the mtime-vs-now arithmetic nightly-rebuild.sh's rotation check performs). A
// row with Present=false is an opted-in golden that has never been baked.
type GoldenRow struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	// Present is true iff the per-(repo, branch) golden exists under the config's
	// output_dir. An opted-in row with Present=false is MISSING (violation b).
	Present bool `json:"present"`
	// AgeHours is the golden's age in hours (now − mtime). It is meaningful only
	// when Present is true. A present row whose age is negative is UNROTATABLE
	// (violation c): the verdict cannot be computed.
	AgeHours int `json:"age_hours"`
}

// label names the row for violation messages: "<repo>@<branch>", or a positional
// fallback when either field is blank.
func (r GoldenRow) label() string {
	switch {
	case r.Repo != "" && r.Branch != "":
		return r.Repo + "@" + r.Branch
	case r.Repo != "":
		return r.Repo
	case r.Branch != "":
		return "@" + r.Branch
	default:
		return "(unnamed golden)"
	}
}

// Manifest is a synthetic fixture's full rotation picture: the policy in force
// plus the per-(repo, branch) golden rows it covers.
type Manifest struct {
	// Name labels the fixture for violation messages (filled from the filename
	// when loaded via LoadManifest).
	Name string `json:"-"`
	// Policy is the rotation policy this manifest asserts against.
	Policy Policy `json:"policy"`
	// Goldens is the list of opted-in goldens the manifest covers.
	Goldens []GoldenRow `json:"goldens"`
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the freshness failure modes the rotation row enumerates,
// so each violation reports WHICH rule it tripped (the "fails NAMED" bar).
type ViolationClass string

const (
	// ViolationStale — (a) a present golden older than the rotation window.
	ViolationStale ViolationClass = "golden-stale-past-rotation-window"
	// ViolationMissing — (b) an opted-in golden that has never been baked.
	ViolationMissing ViolationClass = "golden-missing-never-baked"
	// ViolationUnrotatable — (c) a row whose rotation verdict cannot be computed
	// (e.g. a present golden with a negative/undecidable age).
	ViolationUnrotatable ViolationClass = "golden-rotation-verdict-undecidable"
)

// Violation is a single freshness failure: which rule, which golden, and a
// human-readable reason citing the rotation-policy anchor.
type Violation struct {
	Class  ViolationClass
	Golden string
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Golden, v.Reason)
}

// ── The mechanical diff ─────────────────────────────────────────────────────

// Diff diffs a golden manifest against its rotation policy and returns every
// freshness violation, in a stable order (rule class, then golden label). An
// empty result means the manifest conforms: every opted-in golden is present and
// within the rotation window.
//
// Per-row verdict:
//
//   - Present=false → MISSING (b): an opted-in golden never baked cannot back a
//     session.
//   - Present=true, AgeHours < 0 → UNROTATABLE (c): the mtime-vs-now arithmetic
//     yields no usable verdict; an undecidable golden is a breach, not a pass.
//   - Present=true, AgeHours > window → STALE (a): older than the rotation window;
//     it must be rolled before any new session clones from it.
//   - Present=true, 0 ≤ AgeHours ≤ window → FRESH (no violation).
//
// A golden exactly at the window boundary (AgeHours == window) is treated as
// still FRESH — the window is the maximum tolerated age, not the first stale age,
// mirroring the runtime "older than the window is STALE" phrasing.
func Diff(m Manifest, p Policy) []Violation {
	window := p.resolvedWindow()
	var vs []Violation
	for _, g := range m.Goldens {
		if !g.Present {
			vs = append(vs, Violation{
				Class:  ViolationMissing,
				Golden: g.label(),
				Reason: fmt.Sprintf("opted-in golden %s has never been baked (present=false); "+
					"it cannot back a session until the first bake produces it (doc 03 §6 "+
					"\"Package & build caching\", \"Nightly golden images\" bullet)", g.label()),
			})
			continue
		}
		if g.AgeHours < 0 {
			vs = append(vs, Violation{
				Class:  ViolationUnrotatable,
				Golden: g.label(),
				Reason: fmt.Sprintf("golden %s is present but reports age_hours=%d (<0): the "+
					"mtime-vs-now rotation verdict is undecidable; an undecidable golden is a "+
					"breach, never a silent pass", g.label(), g.AgeHours),
			})
			continue
		}
		if g.AgeHours > window {
			vs = append(vs, Violation{
				Class:  ViolationStale,
				Golden: g.label(),
				Reason: fmt.Sprintf("golden %s is %dh old, past the %dh rotation window; it is "+
					"STALE and must be rolled before any new session clones from it (doc 03 §6 "+
					"\"Package & build caching\", \"Nightly golden images\" bullet — the CVE-roll "+
					"SLA)", g.label(), g.AgeHours, window),
			})
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Golden < vs[j].Golden
	})
	return vs
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd — the same technique the
// appinstall corpus uses.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate rejects a manifest that cannot anchor a freshness verdict: no policy
// window at all (after the documented default fallback) or no golden rows.
func (m Manifest) validate() error {
	if m.Policy.resolvedWindow() <= 0 {
		return fmt.Errorf("manifest %s declares max_age_hours=%d — the rotation policy must "+
			"name a positive window (hours)", m.Name, m.Policy.MaxAgeHours)
	}
	if len(m.Goldens) == 0 {
		return fmt.Errorf("manifest %s declares no goldens — a rotation manifest must cover "+
			"at least one opted-in (repo, branch)", m.Name)
	}
	return nil
}

// LoadManifest reads a synthetic golden manifest from a JSON file and labels it
// with the file's base name for violation messages.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading golden manifest fixture %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parsing golden manifest fixture %s: %w", path, err)
	}
	m.Name = filepath.Base(path)
	if err := m.validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
