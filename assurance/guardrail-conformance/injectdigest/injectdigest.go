// SPDX-License-Identifier: Apache-2.0

package injectdigest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION).
// The guardrail-map.yaml glob for this package points at this exact string, and
// TestTagStable pins it, so the §3c inject-class twin, this package, and the map
// name the SAME row. It is the digest half of the twin whose TTL half credttl
// owns (credttl.Tag = identity-inject-class-ttl-bound).
const Tag = "identity-inject-class-wrong-destination-blocked"

// ── The destination fence (doc 16 §5.1/§6/§10 "issued-to-the-grant-service") ─
//
// An inject-class credential's ISSUED{service_id} digest is tagged with its
// INTENDED service — and that tag is DERIVED FROM THE GRANT RECORD: a digest's
// intended service is a grant fact (doc 16 §5.1). The boundary's SecretMatcher
// therefore knows, for every ISSUED digest, the one destination it is issued to.
// On egress to that INTENDED destination the injected credential fires exactly
// once and is not flagged (the swap/scan filter-ordering interlock, doc 16 §10 /
// §5.5 step 7); on egress to any OTHER destination the digest match is a
// "keyed-issued-to-wrong-destination" event whose rung default is block+log
// (doc 16 §5.5 table). We model the intended service as DATA carried in each
// presentation (IssuedServiceID), so a presentation pins the exact destination
// fence it asserts against; the check never dials the feed or the matcher (D50).

// ── The presentation (synthetic fixture) ────────────────────────────────────

// Presentation is one synthetic ISSUED{service_id}-digest egress attempt: the
// service the digest is ISSUED to (its intended destination, a grant fact,
// doc 16 §5.1) and the destination it was actually presented to on egress, plus
// whether the boundary blocked that egress. A conforming attempt is EITHER an
// egress to the intended service that was NOT blocked (fires exactly once,
// doc 16 §10) OR an egress to a WRONG destination that WAS blocked (the
// keyed-issued-to-wrong-destination block held, doc 16 §5.5).
type Presentation struct {
	// Name labels the presentation for violation messages (filled from the
	// filename via Load only when the fixture leaves it blank).
	Name string `json:"name"`
	// IssuedServiceID is the service the ISSUED{service_id} digest is issued to —
	// its INTENDED egress destination, derived from the grant record (doc 16 §5.1).
	// Empty → UNDECIDABLE: a digest that names no intended service has no
	// destination fence to diff against.
	IssuedServiceID string `json:"issued_service_id"`
	// EgressDestination is the service_id the digest/credential was actually
	// presented to on egress. Empty → UNDECIDABLE: an attempt that names no
	// destination cannot be judged wrong-vs-intended.
	EgressDestination string `json:"egress_destination"`
	// Blocked is true iff the boundary held/blocked this egress. On a WRONG
	// destination it MUST be true (the keyed-issued-to-wrong-destination block);
	// on the INTENDED destination it MUST be false (the injected credential fires
	// exactly once and is not flagged, doc 16 §10).
	Blocked bool `json:"blocked"`
}

// label names the presentation for violation messages, with a fallback when
// blank.
func (p Presentation) label() string {
	if p.Name != "" {
		return p.Name
	}
	return "(unnamed presentation)"
}

// isWrongDestination reports whether the digest was presented to a destination
// OTHER than the service it is issued to. Meaningful only when both service ids
// are non-empty (the undecidable guard runs first in Check).
func (p Presentation) isWrongDestination() bool {
	return p.EgressDestination != p.IssuedServiceID
}

// Picture is a synthetic fixture's full egress picture: the set of
// ISSUED{service_id}-digest egress attempts it covers.
type Picture struct {
	// Name labels the fixture (filled from the filename when loaded via Load).
	Name string `json:"-"`
	// Presentations is the set of ISSUED-digest egress attempts this picture covers.
	Presentations []Presentation `json:"presentations"`
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the wrong-destination failure modes this row enumerates,
// so each violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// two directed classes are DELIBERATELY distinct — a wrong-destination that
// leaked vs an intended-destination that was falsely blocked — so a diff that
// reports one cannot be mistaken for the other.
type ViolationClass string

const (
	// ViolationWrongDestinationEgressed — (a) an ISSUED{service_id} digest
	// presented to a destination OTHER than its issued service was NOT blocked:
	// the credential egressed to the wrong destination. This is the leg the row
	// exists to catch — the keyed-issued-to-wrong-destination block regressing to
	// a silent pass (doc 16 §5.5 block+log rung default).
	ViolationWrongDestinationEgressed ViolationClass = "inject-class-issued-digest-wrong-destination-egressed"
	// ViolationIntendedDestinationBlocked — (b) an ISSUED{service_id} digest
	// presented to its OWN intended service was blocked; the injected credential
	// must fire exactly once and pass on the intended egress (doc 16 §10 /
	// §5.5 step 7), so a block here breaks the swap. Independent of leg (a).
	ViolationIntendedDestinationBlocked ViolationClass = "inject-class-issued-digest-intended-destination-blocked"
	// ViolationUndecidableDestination — (c) an attempt with an empty issued
	// service or an empty egress destination names no destination fence, so the
	// wrong-vs-intended verdict is undecidable and is treated as a breach, never a
	// silent pass (kin to the credttl UNDECIDABLE-TTL verdict).
	ViolationUndecidableDestination ViolationClass = "inject-class-issued-digest-destination-undecidable"
)

// Violation is a single wrong-destination failure: which rule, which
// presentation, and a human-readable reason citing the anchor.
type Violation struct {
	Class        ViolationClass
	Presentation string
	Reason       string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Presentation, v.Reason)
}

// ── The mechanical diff ─────────────────────────────────────────────────────

// Check scans a synthetic egress picture and returns every wrong-destination
// violation, in a stable order (rule class, then presentation). An empty result
// means the picture conforms: every wrong-destination egress was blocked and
// every intended-destination egress passed, with both service ids named.
//
// Per-presentation verdict:
//
//   - issued or destination empty → UNDECIDABLE (c): no destination fence; a
//     breach, never a pass.
//   - destination != issued (WRONG) and NOT blocked → WrongDestinationEgressed
//     (a): the ISSUED{service_id} digest leaked to a destination it was not
//     issued to (doc 16 §5.5 keyed-issued-to-wrong-destination).
//   - destination == issued (INTENDED) and blocked → IntendedDestinationBlocked
//     (b): the injected credential was falsely blocked on its own service; it
//     must fire exactly once and pass (doc 16 §10).
//
// A wrong destination that WAS blocked, and an intended destination that was NOT
// blocked, are both conforming (no violation). The presentations are checked
// independently, so a picture with several failing attempts reports ALL of them —
// the diff never short-circuits after the first.
func Check(p Picture) []Violation {
	var vs []Violation
	for _, pr := range p.Presentations {
		if pr.IssuedServiceID == "" || pr.EgressDestination == "" {
			vs = append(vs, Violation{
				Class:        ViolationUndecidableDestination,
				Presentation: pr.label(),
				Reason: fmt.Sprintf("presentation %s names issued_service_id=%q egress_destination=%q — "+
					"a blank service id or destination provides no destination fence, so the "+
					"wrong-vs-intended verdict is undecidable; an undecidable destination is a breach, "+
					"never a silent pass (doc 16 §5.1/§6)", pr.label(), pr.IssuedServiceID, pr.EgressDestination),
			})
			continue
		}
		if pr.isWrongDestination() {
			if !pr.Blocked {
				vs = append(vs, Violation{
					Class:        ViolationWrongDestinationEgressed,
					Presentation: pr.label(),
					Reason: fmt.Sprintf("presentation %s carried an ISSUED{%s} digest out to destination %q "+
						"(NOT its issued service) without being blocked — an ISSUED{service_id} digest "+
						"presented to the wrong destination must be blocked on egress "+
						"(keyed-issued-to-wrong-destination, block+log; doc 16 §5.5/§6/§10; doc 06 §3c "+
						"inject-class twin)", pr.label(), pr.IssuedServiceID, pr.EgressDestination),
				})
			}
			continue
		}
		if pr.Blocked {
			vs = append(vs, Violation{
				Class:        ViolationIntendedDestinationBlocked,
				Presentation: pr.label(),
				Reason: fmt.Sprintf("presentation %s presented an ISSUED{%s} digest to its OWN intended "+
					"service %q but was blocked — on the intended egress the injected credential fires "+
					"exactly once and must NOT be flagged (the swap/scan filter-ordering interlock, "+
					"doc 16 §10/§5.5 step 7); a block here breaks the swap", pr.label(), pr.IssuedServiceID,
					pr.EgressDestination),
			})
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Presentation < vs[j].Presentation
	})
	return vs
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd — the same technique the
// sibling guardrail-conformance packages use.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate rejects a picture that cannot anchor a verdict: no presentations. A
// blank service id / destination is a legal INPUT — it is a Check-time
// UNDECIDABLE violation, never a load error, so the corpus can carry the breach
// fixture the coverage gate requires.
func (p Picture) validate() error {
	if len(p.Presentations) == 0 {
		return fmt.Errorf("picture %s declares no presentations — an ISSUED-digest egress picture must "+
			"cover at least one presentation", p.Name)
	}
	return nil
}

// Load reads a synthetic egress picture from a JSON file and labels it (and any
// unnamed presentation) with the file's base name for violation messages.
func Load(path string) (Picture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Picture{}, fmt.Errorf("reading injectdigest fixture %s: %w", path, err)
	}
	var p Picture
	if err := json.Unmarshal(data, &p); err != nil {
		return Picture{}, fmt.Errorf("parsing injectdigest fixture %s: %w", path, err)
	}
	p.Name = filepath.Base(path)
	for i := range p.Presentations {
		if p.Presentations[i].Name == "" {
			p.Presentations[i].Name = filepath.Base(path)
		}
	}
	if err := p.validate(); err != nil {
		return Picture{}, err
	}
	return p, nil
}
