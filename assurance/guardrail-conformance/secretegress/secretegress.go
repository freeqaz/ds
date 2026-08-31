// SPDX-License-Identifier: Apache-2.0

package secretegress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION).
const Tag = "secret-egress-canary-blocked"

// ── Path classes (doc 12 §5.3, §5; doc 16 §1 non-claims) ────────────────────
//
// The claim is scoped to INSPECTED paths only. TLS-4 pass-through tunnels
// (D17/D74) get no inspection / swap / scanning — a stated, tested NON-CLAIM
// carried in-row.

// PathClass names the egress path an attempt rode.
type PathClass string

const (
	// PathInspected — a TLS-terminated, SecretMatcher-inspected egress path. The
	// canary-never-egresses claim binds here.
	PathInspected PathClass = "inspected"
	// PathPassThrough — a cert-pinned TLS-4 pass-through tunnel (D17/D74): no
	// inspection, no swap, no scanning. Out of scope for the egress claim
	// (non-claim 1).
	PathPassThrough PathClass = "pass_through"
)

// ── Pushed variant tags (doc 14 §7) ─────────────────────────────────────────
//
// The digest producer pushes encoded variants of every forbidden secret; the
// SecretMatcher matches the raw value AND each pushed variant. The claim covers
// "raw + every pushed variant"; an attempt in a variant the feed never pushed is
// undecidable (violation c).

// Variant names a pushed encoding the feed can match.
type Variant string

const (
	VariantRaw    Variant = "RAW"
	VariantBase64 Variant = "BASE64"
	VariantURLEnc Variant = "URLENC"
	VariantHex    Variant = "HEX"
)

// allKnownVariants is the doc 14 §7 pushed-variant set. The conforming control
// proves a canary is caught in each one on an inspected path.
var allKnownVariants = []Variant{VariantRaw, VariantBase64, VariantURLEnc, VariantHex}

// ── The synthetic feed + egress picture ─────────────────────────────────────

// Feed is the keyed digest feed in force for the fixture: the forbidden canary's
// label and the set of variant tags the producer pushed for it (the variants the
// matcher can therefore catch).
type Feed struct {
	// Canary labels the planted forbidden canary credential (a synthetic name,
	// never a real value).
	Canary string `json:"canary"`
	// PushedVariants is the set of variant tags the producer pushed for the
	// canary (doc 14 §7). The matcher can catch a canary observed in any of these.
	PushedVariants []Variant `json:"pushed_variants"`
}

// Attempt is one egress attempt observed in the fixture.
type Attempt struct {
	// Dest labels the destination for messages (e.g. "allowed-domain body").
	Dest string `json:"dest"`
	// Path is the egress path class (inspected | pass_through).
	Path PathClass `json:"path"`
	// CanaryVariant is the variant the canary bytes were observed in on this
	// attempt, or "" if no canary was present in the attempt at all.
	CanaryVariant Variant `json:"canary_variant"`
	// Blocked is true iff the inspected path held/blocked the attempt at the
	// configured rung. Meaningful only when a canary was present on an inspected
	// path; a clean attempt (no canary) need not be blocked.
	Blocked bool `json:"blocked"`
	// CanaryInSpool is true iff the canary VALUE was observed in any log / event /
	// spool byte for this attempt (the fingerprint-only invariant, D73). It must
	// be false on every attempt, blocked or not, on any path class.
	CanaryInSpool bool `json:"canary_in_spool"`
}

// Picture is a synthetic fixture's full feed + egress picture.
type Picture struct {
	// Name labels the fixture (filled from the filename when loaded via Load).
	Name string `json:"-"`
	// Feed is the keyed digest feed in force.
	Feed Feed `json:"feed"`
	// Attempts is the set of egress attempts the fixture covers.
	Attempts []Attempt `json:"attempts"`
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the failure modes this row enumerates.
type ViolationClass string

const (
	// ViolationCanaryEgressedInspected — (a) a canary observed leaving on an
	// INSPECTED path that was not blocked: the planted canary egressed.
	ViolationCanaryEgressedInspected ViolationClass = "canary-egressed-on-inspected-path"
	// ViolationCanaryInSpool — (b) the canary VALUE observed in a log/event/spool
	// byte (the fingerprint-only invariant, D73).
	ViolationCanaryInSpool ViolationClass = "canary-value-observed-in-spool"
	// ViolationUnknownVariant — (c) a canary observed in a variant the feed never
	// pushed: the verdict is undecidable, treated as a breach.
	ViolationUnknownVariant ViolationClass = "canary-variant-not-in-feed"
)

// Violation is a single failure: which rule, which attempt, and a human-readable
// reason citing the anchor.
type Violation struct {
	Class   ViolationClass
	Attempt string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Attempt, v.Reason)
}

// ── The mechanical check ────────────────────────────────────────────────────

// Check scans a synthetic feed + egress picture and returns every violation, in
// a stable order (rule class, then attempt). An empty result means the picture
// conforms: every inspected-path canary attempt was blocked with the canary
// value absent from every spool byte, and pass-through attempts are unflagged
// for egress (the stated non-claim).
//
// Per-attempt verdict:
//
//   - CanaryInSpool=true → CanaryInSpool (b), on ANY path class: the
//     fingerprint-only invariant binds the logging plane regardless of path.
//   - CanaryVariant set and not in the feed's pushed set → UnknownVariant (c):
//     an un-enumerated variant is undecidable.
//   - CanaryVariant set, path INSPECTED, not Blocked → CanaryEgressedInspected
//     (a): the planted canary leaked on an inspected path.
//   - CanaryVariant set, path PASS_THROUGH → NOT flagged for egress (non-claim 1:
//     pass-through gets no scanning). It can still trip (b) via CanaryInSpool.
func Check(p Picture) []Violation {
	pushed := map[Variant]bool{}
	for _, v := range p.Feed.PushedVariants {
		pushed[v] = true
	}
	var vs []Violation
	for _, a := range p.Attempts {
		if a.CanaryInSpool {
			vs = append(vs, Violation{
				Class:   ViolationCanaryInSpool,
				Attempt: a.label(),
				Reason: fmt.Sprintf("attempt %s recorded the canary VALUE in a log/event/spool byte; "+
					"the canary value must appear in zero bytes of any record — fingerprint-only, even "+
					"on a blocked attempt (D73; doc 12 §5.3)", a.label()),
			})
		}
		if a.CanaryVariant == "" {
			continue // no canary present in this attempt's egress bytes
		}
		if !pushed[a.CanaryVariant] {
			vs = append(vs, Violation{
				Class:   ViolationUnknownVariant,
				Attempt: a.label(),
				Reason: fmt.Sprintf("attempt %s observed the canary in variant %q, which the feed never "+
					"pushed (%v); the verdict is undecidable and an undecidable canary is a breach, "+
					"never a silent pass (doc 14 §7)", a.label(), a.CanaryVariant, p.Feed.PushedVariants),
			})
			continue
		}
		switch a.Path {
		case PathInspected:
			if !a.Blocked {
				vs = append(vs, Violation{
					Class:   ViolationCanaryEgressedInspected,
					Attempt: a.label(),
					Reason: fmt.Sprintf("attempt %s carried the canary (variant %q) out on an INSPECTED "+
						"path without being blocked — a planted canary credential must never egress on "+
						"inspected paths (D73; doc 16 §1/§13)", a.label(), a.CanaryVariant),
				})
			}
		case PathPassThrough:
			// Non-claim 1 (doc 12 §5.3, doc 16 §1): TLS-4 pass-through gets no
			// inspection / swap / scanning. A canary on a pass-through path is NOT
			// flagged for egress here. (CanaryInSpool above still binds the logging
			// plane regardless of path class.)
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Attempt < vs[j].Attempt
	})
	return vs
}

// KnownVariants returns the doc 14 §7 pushed-variant set (copy), so a test can
// assert the conforming control proves a catch in EACH pushed variant.
func KnownVariants() []Variant {
	out := make([]Variant, len(allKnownVariants))
	copy(out, allKnownVariants)
	return out
}

// label names the attempt for messages, with a fallback when blank.
func (a Attempt) label() string {
	if a.Dest != "" {
		return a.Dest
	}
	return "(unnamed attempt)"
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

// validate rejects a picture that cannot anchor a verdict: no canary in the
// feed, no attempts, or an attempt with an unknown path class.
func (p Picture) validate() error {
	if p.Feed.Canary == "" {
		return fmt.Errorf("picture %s declares no canary in the feed — a canary-egress picture must "+
			"name the planted forbidden canary", p.Name)
	}
	if len(p.Attempts) == 0 {
		return fmt.Errorf("picture %s declares no egress attempts — a canary-egress picture must "+
			"cover at least one attempt", p.Name)
	}
	for _, a := range p.Attempts {
		switch a.Path {
		case PathInspected, PathPassThrough:
		default:
			return fmt.Errorf("picture %s attempt %s declares unknown path class %q (want %q or %q)",
				p.Name, a.label(), a.Path, PathInspected, PathPassThrough)
		}
	}
	return nil
}

// Load reads a synthetic feed + egress picture from a JSON file and labels it
// with the file's base name for violation messages.
func Load(path string) (Picture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Picture{}, fmt.Errorf("reading canary-egress fixture %s: %w", path, err)
	}
	var p Picture
	if err := json.Unmarshal(data, &p); err != nil {
		return Picture{}, fmt.Errorf("parsing canary-egress fixture %s: %w", path, err)
	}
	p.Name = filepath.Base(path)
	if err := p.validate(); err != nil {
		return Picture{}, err
	}
	return p, nil
}
