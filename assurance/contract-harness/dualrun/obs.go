// SPDX-License-Identifier: Apache-2.0

package dualrun

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the shared test-support home for parsing and comparing the
// canonical Observation form the streaming back-pressure seams assert against.
// The hypervisor (ExportDiskDelta) and orchestrator-session (WatchSession) seam
// _test.go files run the SAME slow-consumer drift matrix — short (dropping),
// permuted (reordering), and over (duplicating) — and each needs to crack a
// divergence's per-key observation values apart to prove which observation key
// bites in isolation. These helpers were byte-identical copies in both seam test
// files; promoting them here keeps the matrix assertions defined ONCE and lets a
// new streaming seam reuse them. They are purely additive test support — they do
// NOT touch the dualrun affordance's streaming/lifecycle behavior.
//
// The functions take *testing.T (or operate on the canonical form Observation.
// Canonical produces) so they live in a normal .go file consumable from the
// external *_test packages of any seam; they are not themselves a test.

// AtoiObs parses a numeric observation value (e.g. frames_total) as a base-10
// int, failing the test on a non-numeric value. The count observations the
// back-pressure matrix asserts on are always base-10 integers.
func AtoiObs(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("numeric observation %q is not an integer: %v", s, err)
	}
	return n
}

// ParseObs parses an Observation's canonical form — the sorted, newline-joined
// "key=value" lines Observation.Canonical produces — into a map for per-key
// comparison. Blank lines and lines without a '=' are skipped.
func ParseObs(canonical string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(canonical, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[k] = v
	}
	return m
}

// DifferingKeys returns, sorted, the observation keys whose values differ
// between two parsed Observations (treating a key present in one but not the
// other as differing). The back-pressure matrix uses it to prove a single drift
// trips a single observation key — e.g. a reorder must isolate drained_in_order.
func DifferingKeys(a, b map[string]string) []string {
	seen := map[string]bool{}
	var diff []string
	for k, av := range a {
		seen[k] = true
		if bv, ok := b[k]; !ok || bv != av {
			diff = append(diff, k)
		}
	}
	for k, bv := range b {
		if seen[k] {
			continue
		}
		if av, ok := a[k]; !ok || av != bv {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}
