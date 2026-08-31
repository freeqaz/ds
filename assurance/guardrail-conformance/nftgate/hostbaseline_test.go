// SPDX-License-Identifier: Apache-2.0

package nftgate

// Doc 06 §3c (c)-suite drift assertion for the versioned host-baseline artifact
// (doc 14 §11). "sysctl/kernel drift = failure, not log line": the shipped
// artifact is diffed against every §11 obligation and a violated obligation is
// RED. A synthetic violated-baseline fixture proves the red path is non-vacuous.

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestHostBaselineArtifactConforms is the drift assertion: the SHIPPED
// host-baseline v0 artifact must satisfy every doc 14 §11 obligation. A sysctl,
// kernel-floor, tap-posture, isolation, or mark-lint obligation that drifts out
// of the artifact fails this test — the doc 14 §11 "drift = suite failure" row.
func TestHostBaselineArtifactConforms(t *testing.T) {
	path := HostBaselineArtifactPath()
	b, err := LoadHostBaseline(path)
	if err != nil {
		t.Fatalf("loading shipped host-baseline artifact: %v", err)
	}
	if got := b.Check(); len(got) != 0 {
		for _, v := range got {
			t.Errorf("shipped host-baseline artifact violates §11 obligation: %s", v)
		}
		t.Fatalf("shipped host-baseline artifact has %d §11 drift(s) — see above", len(got))
	}
	if b.ArtifactVersion == nil || *b.ArtifactVersion != 0 {
		t.Errorf("shipped artifact must declare artifact_version 0 (host-baseline v0); got %v", b.ArtifactVersion)
	}
}

// TestHostBaselineDriftIsRed proves red-on-violation: feeding the synthetic
// violated-baseline fixture to Check reports EXACTLY the seeded obligation
// violations (six, spanning D68/D66/D75/D76). If Check silently passed a drifted
// baseline the drift assertion would be vacuous — this is the guard against that.
func TestHostBaselineDriftIsRed(t *testing.T) {
	path := filepath.Join(thisDir(), "fixtures", "hostbaseline", "violated-baseline.json")
	b, err := LoadHostBaseline(path)
	if err != nil {
		t.Fatalf("loading violated-baseline fixture: %v", err)
	}
	got := ViolationSlugs(b.Check())
	want := []string{
		OblBrNetfilter,
		OblConntrackLoose,
		OblKernelMin,
		OblMarkLintBits,
		OblTapDisableIPv6,
		OblTapFamilyInet,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("violated-baseline Check drift set mismatch\n got: %v\nwant: %v", got, want)
	}
	if len(got) == 0 {
		t.Fatalf("violated-baseline produced no violations — the drift assertion is vacuous")
	}
	// Every reported violation must carry a governing D-number.
	for _, v := range b.Check() {
		if v.Decision == "" {
			t.Errorf("violation %q carries no governing decision", v.Obligation)
		}
	}
}

// TestHostBaselineCheckIsFailClosed proves the fail-closed discipline: an EMPTY
// baseline (every obligation-bearing field omitted) must produce a violation for
// every obligation slug — a missing obligation is never a silent zero-value pass.
func TestHostBaselineCheckIsFailClosed(t *testing.T) {
	var empty HostBaseline
	got := ViolationSlugs(empty.Check())
	want := append([]string{}, AllBaselineObligations()...)
	// The libvirt-if-isolated-ports obligation only fires when isolated ports are
	// chosen; on an empty baseline isolated_ports is nil (not chosen), so that
	// slug is legitimately absent. Structural-L2 fires instead (neither structural
	// nor isolated-ports asserted).
	want = removeSlug(want, OblLibvirtIfIso)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("empty-baseline Check is not fail-closed\n got: %v\nwant: %v", got, want)
	}
}

// TestHostBaselineObligationVocabularyIsClosed pins that every slug Check can
// emit is declared in AllBaselineObligations (and vice versa) — a §11 row can
// never be silently added to or dropped from the model without updating the
// closed vocabulary. Mirrors the RowOwners()/fixture coverage precedent.
func TestHostBaselineObligationVocabularyIsClosed(t *testing.T) {
	declared := map[string]bool{}
	for _, s := range AllBaselineObligations() {
		if declared[s] {
			t.Errorf("duplicate obligation slug in AllBaselineObligations: %q", s)
		}
		declared[s] = true
	}
	// Drive every obligation to fire and confirm each emitted slug is declared.
	// OblStructuralL2 and OblLibvirtIfIso are mutually exclusive within one
	// baseline (structural-L2 fires only when isolated ports are NOT chosen;
	// libvirt-if-iso fires only when they ARE), so the coverage is the union of
	// two baselines: an empty one (fires all but libvirt-if-iso) and one that
	// chooses isolated ports with a sub-6.1.0 floor (fires libvirt-if-iso).
	seen := map[string]bool{}
	record := func(b HostBaseline) {
		for _, v := range b.Check() {
			if !declared[v.Obligation] {
				t.Errorf("Check emitted undeclared obligation slug %q", v.Obligation)
			}
			seen[v.Obligation] = true
		}
	}
	record(HostBaseline{})
	var isoBaseline HostBaseline
	iso := true
	isoBaseline.Libvirt.IsolatedPortsChosen = &iso
	isoBaseline.Libvirt.MinVersionIfIsolatedPorts = "5.0.0" // below 6.1.0 → fires OblLibvirtIfIso
	record(isoBaseline)
	for _, s := range AllBaselineObligations() {
		if !seen[s] {
			t.Errorf("declared obligation %q never fired — vocabulary has a dead slug", s)
		}
	}
}

// TestHostBaselineRulesetFamilyDrift is the artifact↔ruleset cross-check: the
// per-session-tap ruleset family the baseline declares (inet, D75) must match the
// family the NFT-1 bootstrap ruleset actually authors. A baseline that says inet
// while the ruleset drifts to `table ip` (or vice versa) is drift the (c) suite
// must catch — the two artifacts version together (doc 14 §11).
func TestHostBaselineRulesetFamilyDrift(t *testing.T) {
	b, err := LoadHostBaseline(HostBaselineArtifactPath())
	if err != nil {
		t.Fatalf("loading shipped host-baseline artifact: %v", err)
	}
	fam := strings.ToLower(strings.TrimSpace(b.PerSessionTap.RulesetFamily))
	data, err := os.ReadFile(NFT1BootstrapPath())
	if err != nil {
		t.Fatalf("reading NFT-1 bootstrap ruleset: %v", err)
	}
	ruleset := string(data)
	if !strings.Contains(ruleset, "table "+fam+" ds_boundary") {
		t.Errorf("baseline declares ruleset_family %q but NFT-1 bootstrap does not author `table %s ds_boundary` (artifact↔ruleset family drift)", fam, fam)
	}
	// br_netfilter is forbidden (D66): the ruleset must never author a bridge
	// table hooking br_netfilter frames.
	if strings.Contains(ruleset, "table bridge") {
		t.Errorf("NFT-1 bootstrap authors a `table bridge` — br_netfilter path is forbidden (D66)")
	}
}

func removeSlug(ss []string, drop string) []string {
	out := ss[:0:0]
	for _, s := range ss {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}
