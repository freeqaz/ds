// SPDX-License-Identifier: Apache-2.0

package e2e

// lane_results_ingest.go — the OFFLINE ingest adapter that turns a real lane
// run's `go test -json` output into the LaneResults shape the D34 divergence
// filer (divergence_filer.go) consumes.
//
// divergence_filer.go landed the pure decision core (DetectDivergences over two
// LaneResults) but nothing fed it a REAL run — the fixtures were hand-authored.
// This adapter closes that gap on the offline half: given the line-delimited
// JSON `go test` emits (the `test2json` event stream, `go test -json`) it builds
// a LaneResults so a wired lane / operator step can hand the nested-lane and the
// deferred metal-nightly-lane outputs straight to DetectDivergences.
//
// SCOPE / what stays deferred. This is pure and offline: it parses a byte stream
// in memory, dials nothing, runs no hypervisor, and carries no live/metal
// dependency — exactly the discipline the rest of this tier uses (D50: synthetic
// wire shapes + fixtures, no live services in the wave). The DedupKey-keyed
// taskdb add-or-skip glue and the e2e.yml Lane-2 schedule flip stay the parent
// operator leg's job (task 01KV6VHSGH), out of scope here.
//
// FIDELITY TAGS. A test's D34 fidelity tag (nested-ok / metal-only) is metadata
// ABOUT the assertion, not something `go test -json` carries in its output, so
// the caller supplies a Name→Fidelity lookup (FidelityTags). An untagged test
// ingests with the zero Fidelity (""), which the filer renders "(untagged)" —
// the tag is never silently invented.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// testEvent is one line of the `go test -json` (test2json) event stream. Only
// the fields this adapter reads are decoded; unknown fields are ignored by
// encoding/json. A package-level event has an empty Test; a per-test event names
// the Test. The terminal Action for a test is one of "pass" / "fail" / "skip".
type testEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
	// ImportPath / FailedBuild mark a BUILD failure in the stream: a "build-fail"
	// event names the failed package in ImportPath, and the package-level "fail"
	// event that follows carries it in FailedBuild. Either one means the lane
	// produced no honest verdicts and must fail loud, not ingest as empty.
	ImportPath  string `json:"ImportPath"`
	FailedBuild string `json:"FailedBuild"`
}

// IngestOptions configures how a `go test -json` stream maps to LaneResults.
type IngestOptions struct {
	// Lane is the provenance identity stamped on the resulting LaneResults (e.g.
	// "nested-ok" for the per-commit nested KVM lane, "metal-nightly" for the
	// virtual-metal lane). Required — an empty Lane is a caller error.
	Lane string
	// FidelityTags maps a test Name to its D34 fidelity tag. A test not present
	// here ingests with the zero Fidelity (""), never a guessed tag. The map is
	// read-only to this adapter (never mutated).
	FidelityTags map[string]Fidelity
	// IncludeSubtests, when true, ingests subtests (names containing "/") as their
	// own assertions. By default subtests are folded away and only the top-level
	// test's verdict is ingested, because the top-level pass/fail already
	// aggregates its subtests and a subtest name is not a stable cross-lane
	// assertion identity.
	IncludeSubtests bool
}

// IngestGoTestJSON parses a `go test -json` event stream into a LaneResults the
// D34 filer (DetectDivergences) consumes. It is deterministic: the same byte
// stream always yields the same LaneResults, with Results sorted by assertion
// Name (no map-iteration nondeterminism leaks into the output).
//
// Verdict mapping, per test Name:
//   - a terminal "pass"  event → AssertionResult{Passed: true}
//   - a terminal "fail"  event → AssertionResult{Passed: false}
//   - a terminal "skip"  event → NOT ingested: a skipped test produced no
//     green/red verdict, so it has no place in the cross-lane join (a metal-only
//     assertion the nested lane skips must not read as nested-red).
//
// Package-level events (empty Test) carry no assertion identity and are ignored.
// A test's captured output (its "output" lines, trimmed and joined) rides the
// AssertionResult.Detail so the filed record can quote the real failure text.
//
// It reports an error on a malformed JSON line, an empty Lane, or a stream that
// records a BUILD failure ("build-fail" / a package-level fail with FailedBuild)
// — a lane run we cannot parse honestly, or that produced no honest verdicts,
// must fail loud, not ingest a partial/blank result.
func IngestGoTestJSON(r io.Reader, opts IngestOptions) (LaneResults, error) {
	if strings.TrimSpace(opts.Lane) == "" {
		return LaneResults{}, fmt.Errorf("ingest: Lane is required (the LaneResults needs a provenance identity)")
	}

	// Accumulate per-test verdict + output in first-seen order; sort at the end so
	// map iteration never leaks into the result.
	type acc struct {
		terminal string // "pass" / "fail" / "skip" / "" (not yet terminal)
		output   []string
	}
	byName := make(map[string]*acc)

	sc := bufio.NewScanner(r)
	// Test output lines can be long (panics, diffs); lift the default 64KiB cap.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue // tolerate blank lines between events
		}
		var ev testEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return LaneResults{}, fmt.Errorf("ingest: line %d: not a go test -json event: %w", line, err)
		}
		// A lane whose package failed to BUILD produced no honest verdicts at all —
		// ingesting the (empty) remainder would hand DetectDivergences a blank lane
		// that reads as "no divergences": exactly the false confidence D34 exists to
		// prevent. `go test -json` marks this two ways (both in the documented
		// shape): a "build-fail" event naming the package in ImportPath, and the
		// package-level "fail" event carrying FailedBuild. Fail loud on either.
		if ev.Action == "build-fail" || (ev.Test == "" && ev.FailedBuild != "") {
			return LaneResults{}, fmt.Errorf("ingest: line %d: lane build failed (package %s) — refusing to ingest a run that produced no honest verdicts",
				line, failedPackage(ev))
		}
		if ev.Test == "" {
			continue // package-level event: no assertion identity
		}
		if !opts.IncludeSubtests && strings.Contains(ev.Test, "/") {
			continue // subtest folded into its parent's verdict
		}
		a := byName[ev.Test]
		if a == nil {
			a = &acc{}
			byName[ev.Test] = a
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			a.terminal = ev.Action
		case "output":
			if out := strings.TrimRight(ev.Output, "\n"); strings.TrimSpace(out) != "" {
				a.output = append(a.output, strings.TrimSpace(out))
			}
		default:
			// "run", "pause", "cont", "start", "bench" carry no verdict — ignore.
		}
	}
	if err := sc.Err(); err != nil {
		return LaneResults{}, fmt.Errorf("ingest: reading stream: %w", err)
	}

	results := make([]AssertionResult, 0, len(byName))
	for name, a := range byName {
		switch a.terminal {
		case "pass", "fail":
			results = append(results, AssertionResult{
				Name:     name,
				Fidelity: opts.FidelityTags[name],
				Passed:   a.terminal == "pass",
				Detail:   detailFromOutput(a.output),
			})
		case "skip":
			// A skipped test produced no verdict — omit it from the cross-lane join.
		default:
			// No terminal event (truncated stream / test never finished) — omit it
			// rather than invent a verdict.
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	return LaneResults{Lane: opts.Lane, Results: results}, nil
}

// detailFromOutput distills a test's captured output lines into a compact,
// deterministic Detail for the filed record. It keeps the LAST non-empty,
// non-framing line (the failing assertion / final message is what an operator
// wants) so the Detail stays a one-liner rather than dragging the whole log
// into the task body. Framing lines ("=== RUN ...", "--- FAIL: ... (1.00s)")
// are skipped: on a real stream the "--- FAIL:" trailer is the LAST output line
// for a failing test, and quoting it would put the framing — not the failure
// text — into the filed record.
func detailFromOutput(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "=== ") || strings.HasPrefix(l, "--- ") {
			continue // go test framing, not the test's own message
		}
		return l
	}
	return ""
}

// failedPackage names the package a build failure was reported against, for the
// loud ingest error: a "build-fail" event carries ImportPath, the package-level
// "fail" event carries FailedBuild, and Package is the fallback.
func failedPackage(ev testEvent) string {
	for _, p := range []string{ev.ImportPath, ev.FailedBuild, ev.Package} {
		if p != "" {
			return p
		}
	}
	return "(unknown)"
}
