// SPDX-License-Identifier: Apache-2.0

package e2e

// divergence_filer.go — the D34 nested-green / metal-red divergence auto-filer,
// promoted from prose (README.md "Where it runs: fidelity tags") to executable
// tooling.
//
// THE D34 CONTRACT (doc 06 OQ1, resolved 2026-06-11). Every (b) lifecycle
// assertion carries a fidelity tag: `nested-ok` (functional/logical assertions
// the nested KVM lane proves per-commit) or `metal-only` (timing, snapshot/CoW,
// storage semantics that only real hardware proves honestly, D31/D34). With D31
// (virtual metal) the two lanes run the SAME QEMU/libvirt stack, so the delta
// mostly closes itself — but any residual delta must surface, not hide. The rule:
// an assertion that is GREEN on the nested lane but RED on real metal is NOT a
// product regression, it is a **bug in the test environment** (the nested
// substrate diverged from metal) and it auto-files as such so the fidelity gap
// gets closed rather than papered over.
//
// This file is the pure, offline decision + record-builder half of that filer.
// Given the two lanes' assertion results it (1) finds every nested-green /
// metal-red pair and (2) turns each into a taskdb-file-able DivergenceRecord — a
// title/body/priority/dedup-key payload an operator step or a wired metal-nightly
// lane hands to `taskdb task add`. It DOES NOT dial taskdb, run a hypervisor, or
// carry any live/metal dependency: the actual metal results come from the
// separately-tracked, deferred metal-nightly lane (parent 01KV6VHSGH — the
// runner-provisioning + e2e.yml Lane-2 schedule flip stay operator/infra work,
// out of scope here). Keeping the filer pure lets the offline nested-ok lane test
// it exhaustively against synthetic fixtures, exactly as the wave rules require.

import (
	"fmt"
	"sort"
	"strings"
)

// Fidelity is the D34 fidelity tag an assertion carries: it decides which lane
// gates the assertion, and — for the auto-filer — which divergences are the
// load-bearing ones.
type Fidelity string

const (
	// FidelityNestedOK marks a functional/logical assertion the nested KVM lane
	// proves honestly and gates per-commit (README "Where it runs" table).
	FidelityNestedOK Fidelity = "nested-ok"
	// FidelityMetalOnly marks a timing / snapshot / CoW / storage assertion that
	// only real hardware proves honestly; it gates nightly/pre-release on metal.
	FidelityMetalOnly Fidelity = "metal-only"
)

// AssertionResult is one (b) lifecycle assertion as observed on ONE lane. The
// Name is the stable identity of the assertion across lanes (the join key
// between the nested and metal runs); Fidelity is its D34 tag; Passed is the
// lane's verdict; Detail is an optional human note carried into the filed record.
type AssertionResult struct {
	Name     string
	Fidelity Fidelity
	Passed   bool
	Detail   string
}

// LaneResults is one lane's set of assertion results, keyed by lane name for the
// record's provenance (e.g. "nested-ok" / "metal-nightly"). It is a thin wrapper
// so a caller can pass a whole lane run without threading a bare slice + label.
type LaneResults struct {
	// Lane is the lane's identity for provenance in the filed record (e.g.
	// "nested-ok" for the per-commit nested KVM lane, "metal-nightly" for the
	// virtual-metal lane).
	Lane string
	// Results is the lane's assertions. Duplicate Names within one lane are a
	// caller error surfaced by DetectDivergences.
	Results []AssertionResult
}

// DivergenceRecord is a single nested-green / metal-red divergence, shaped as a
// taskdb-file-able payload. It is deliberately the intersection of what
// `taskdb task add` accepts (a title, a body, a priority) plus a stable DedupKey
// so an operator step / wired lane can add-or-skip idempotently across nightly
// runs (the same fidelity gap filed once, not once per night).
type DivergenceRecord struct {
	// DedupKey is a stable, lane-pair-independent identity for this divergence
	// (derived from the assertion Name) so repeated nightly runs of the same
	// unclosed gap map to the SAME record — the caller keys its add-or-skip on
	// this, never on the ULID taskdb mints.
	DedupKey string
	// Title is the taskdb task title.
	Title string
	// Body is the taskdb task body: what diverged, on which lanes, and the D34
	// framing (this is a test-environment fidelity bug, not a product regression).
	Body string
	// Priority is the taskdb priority for the filed task. A fidelity gap that
	// gives per-commit CI false confidence is high-signal, so these file at p1
	// (matching taskdb's convention where lower is more urgent).
	Priority int
	// Assertion is the diverging assertion's name (carried through for callers
	// that group/report by assertion without re-parsing the title).
	Assertion string
	// NestedLane / MetalLane are the lane identities of the green/red sides, for
	// provenance in reporting.
	NestedLane string
	MetalLane  string
}

// divergencePriority is the taskdb priority a nested-green/metal-red divergence
// files at. A fidelity gap means the per-commit nested lane can give false
// confidence (doc 06 OQ1's motivating hazard), so it is high-signal but not a
// P0 outage — p1.
const divergencePriority = 1

// DetectDivergences is the D34 decision core: given a nested-lane run and a
// metal-lane run, it returns one DivergenceRecord for every assertion that
// PASSED nested but FAILED metal (a nested-green / metal-red divergence — the
// exact D34 auto-file trigger). The output is sorted by assertion Name for a
// deterministic, diffable record set.
//
// It reports an error (rather than silently mis-filing) when the results are
// internally inconsistent: a duplicate assertion Name within one lane makes the
// cross-lane join ambiguous, and a joined assertion whose D34 fidelity tag
// DIFFERS between the two lanes means the suite disagrees about what the
// assertion even is — carrying that silently would file (or suppress) a
// divergence under a mis-framed tag. Assertions present on only one lane are NOT
// a divergence (a metal-only assertion has no nested counterpart to be green,
// and vice-versa): the D34 trigger is specifically the SAME assertion
// disagreeing across lanes.
func DetectDivergences(nested, metal LaneResults) ([]DivergenceRecord, error) {
	nestedByName, err := indexByName(nested)
	if err != nil {
		return nil, fmt.Errorf("nested lane %q: %w", nested.Lane, err)
	}
	metalByName, err := indexByName(metal)
	if err != nil {
		return nil, fmt.Errorf("metal lane %q: %w", metal.Lane, err)
	}

	var records []DivergenceRecord
	for name, n := range nestedByName {
		m, ok := metalByName[name]
		if !ok {
			// No metal counterpart — cannot be a nested-green/metal-red pair.
			continue
		}
		// Cross-lane fidelity-tag consistency: the SAME assertion must carry the
		// SAME D34 fidelity tag on both lanes, or the join is joining two things the
		// suite disagrees about (one lane thinks it is nested-ok, the other
		// metal-only). Today that mismatch was carried silently; surface it as an
		// inconsistency — analogous to the duplicate-Name rejection above — so a
		// mis-tagged assertion is fixed, not absorbed into a mis-framed verdict.
		if n.Fidelity != m.Fidelity {
			return nil, fmt.Errorf("assertion %q carries inconsistent fidelity tags across lanes: %s on %q vs %s on %q "+
				"(the same assertion must be tagged identically on both lanes for a coherent cross-lane join)",
				name, tagOrUnknown(n.Fidelity), nested.Lane, tagOrUnknown(m.Fidelity), metal.Lane)
		}
		if n.Passed && !m.Passed {
			records = append(records, newDivergenceRecord(nested.Lane, metal.Lane, n, m))
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Assertion < records[j].Assertion })
	return records, nil
}

// indexByName builds a name→result map for one lane, rejecting duplicate names
// so the cross-lane join in DetectDivergences is unambiguous.
func indexByName(lane LaneResults) (map[string]AssertionResult, error) {
	out := make(map[string]AssertionResult, len(lane.Results))
	for _, r := range lane.Results {
		if r.Name == "" {
			return nil, fmt.Errorf("assertion with empty Name (an assertion must have a stable cross-lane identity)")
		}
		if _, dup := out[r.Name]; dup {
			return nil, fmt.Errorf("duplicate assertion Name %q in one lane (the cross-lane join needs a unique identity per assertion)", r.Name)
		}
		out[r.Name] = r
	}
	return out, nil
}

// newDivergenceRecord builds the taskdb-file-able record for one nested-green /
// metal-red divergence, with the D34 framing baked into the body.
func newDivergenceRecord(nestedLane, metalLane string, nested, metal AssertionResult) DivergenceRecord {
	title := fmt.Sprintf("[e2e-fidelity/D34] nested-green/metal-red divergence: %q", nested.Name)

	var body strings.Builder
	fmt.Fprintf(&body, "AUTO-FILED by the D34 divergence filer (assurance/e2e/divergence_filer.go).\n\n")
	fmt.Fprintf(&body, "The (b) lifecycle assertion %q PASSED on the nested lane %q but FAILED on the "+
		"metal lane %q. Per D34 (doc 06 OQ1) this is a bug in the TEST ENVIRONMENT — the nested "+
		"substrate has diverged from real metal on this assertion — NOT a product regression. Close "+
		"the fidelity gap (bring the nested lane's behavior back in line with metal, or re-tag the "+
		"assertion metal-only if it genuinely cannot be proven honestly nested).\n\n", nested.Name, nestedLane, metalLane)
	fmt.Fprintf(&body, "assertion:      %s\n", nested.Name)
	fmt.Fprintf(&body, "fidelity tag:   %s\n", tagOrUnknown(nested.Fidelity))
	fmt.Fprintf(&body, "nested (%s): PASS%s\n", nestedLane, detailSuffix(nested.Detail))
	fmt.Fprintf(&body, "metal  (%s): FAIL%s\n", metalLane, detailSuffix(metal.Detail))
	fmt.Fprintf(&body, "\nSource: D34 / D31 (doc 04 §6); doc 06 §3b + OQ1; assurance/e2e/README.md.")

	return DivergenceRecord{
		DedupKey:   dedupKey(nested.Name),
		Title:      title,
		Body:       body.String(),
		Priority:   divergencePriority,
		Assertion:  nested.Name,
		NestedLane: nestedLane,
		MetalLane:  metalLane,
	}
}

// dedupKey derives the stable add-or-skip identity for a divergence from the
// assertion Name, normalized so cosmetic variation (case, surrounding
// whitespace) does not spawn a duplicate record. It is intentionally lane-pair
// independent: the SAME unclosed gap seen across nightly runs must map to one key.
func dedupKey(assertion string) string {
	return "e2e-fidelity/d34/" + strings.ToLower(strings.TrimSpace(assertion))
}

// tagOrUnknown renders a fidelity tag, naming an unset tag explicitly rather than
// emitting an empty field in the filed body.
func tagOrUnknown(f Fidelity) string {
	if f == "" {
		return "(untagged)"
	}
	return string(f)
}

// detailSuffix appends an optional lane detail to a PASS/FAIL line without a
// dangling separator when the detail is empty.
func detailSuffix(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return " — " + strings.TrimSpace(detail)
}
