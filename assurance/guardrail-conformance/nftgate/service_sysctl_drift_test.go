// SPDX-License-Identifier: Apache-2.0

package nftgate

// Doc 06 §3c (c)-suite drift assertion, extending the artifact<->ruleset drift
// test family in hostbaseline_test.go. The round-1 drift test
// (TestHostBaselineRulesetFamilyDrift) only cross-checks the inet
// per-session-tap ruleset family; ds-nft-bootstrap.service separately declares
// a conntrack-sysctls-before-rules PREREQUISITE — by prose only — via its
// After= ordering (ds-host-baseline.service systemd-sysctl.service
// network-pre.target) and a header comment listing the sysctl values it
// assumes are already in place (nf_conntrack_tcp_loose=0, nf_conntrack_acct=1,
// nf_conntrack_timestamp=1, br_netfilter forbidden, per-session-tap IPv6
// disabled). Nothing previously cross-checked that prose against the
// host-baseline artifact that actually owns those values (doc 14 §11,
// host-baseline.v0.json) — the two could drift silently, e.g. a host-baseline
// artifact_version bump that changes a sysctl value without anyone updating
// the service unit's comment, or vice versa.
//
// This file closes that gap: it parses the SHIPPED ds-nft-bootstrap.service
// unit file's declared prerequisite sysctl values and its After= unit list,
// loads the SHIPPED host-baseline.v0.json (via the same LoadHostBaseline /
// HostBaselineArtifactPath helpers hostbaseline_test.go uses), and asserts
// every declared prerequisite is present with the matching value in the
// baseline AND that the After= line names ds-host-baseline.service — the unit
// that owns those sysctls — so the "sysctls before ct-state rules" ordering
// invariant is structurally checked, not just prose.
//
// OFFLINE + SYNTHETIC (D50): reads two tracked repo files (the unit file and
// the JSON artifact), no live nft/netns/systemd. The negative arm
// (TestServiceSysctlDriftIsRed) proves the assertion is non-vacuous by running
// the SAME check function against mutated in-memory copies of the parsed
// inputs — never the shipped files on disk — confirming each mutation (a
// flipped sysctl value, a removed sysctl key, a dropped After= prerequisite)
// makes the check report a problem.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// NFTBootstrapServiceUnitPath returns the absolute path to the SHIPPED
// ds-nft-bootstrap.service unit file, anchored off this source file the same
// way HostBaselineArtifactPath / NFT1BootstrapPath are (thisDir() + repo
// root), so this test runs from any cwd.
func NFTBootstrapServiceUnitPath() string {
	repoRoot := filepath.Join(thisDir(), "..", "..", "..")
	return filepath.Join(repoRoot, "dataplane", "artifacts", "nft", "ds-nft-bootstrap.service")
}

// servicePrereqSysctl is one declared prerequisite the service unit's comment
// claims is already satisfied by the time it runs. For the three numeric
// net.netfilter.nf_conntrack_* sysctls, Name is the short sysctl name as the
// comment spells it (e.g. "nf_conntrack_tcp_loose") and it is checked against
// host-baseline.v0.json's sysctls map under the "net.netfilter." prefix. The
// two non-numeric prerequisites (br_netfilter forbidden, per-session-tap IPv6
// disabled) use the sentinel names below and are checked against their own
// HostBaseline fields instead of the Sysctls map.
type servicePrereqSysctl struct {
	Name string
	Want int
}

const (
	prereqBrNetfilterForbidden = "br_netfilter_forbidden"
	prereqTapDisableIPv6       = "per_session_tap_disable_ipv6"
)

// sysctlAssignRe matches a "name=value" conntrack-sysctl assignment as the
// service unit's header comment spells it, e.g. "nf_conntrack_tcp_loose=0".
var sysctlAssignRe = regexp.MustCompile(`\b(nf_conntrack_[a-z_]+)=(-?\d+)`)

// parseServicePrereqSysctls extracts the declared prerequisite sysctls from a
// ds-nft-bootstrap.service unit file's text: every "nf_conntrack_*=N"
// assignment in the comment, plus the two prose-only obligations if their
// exact phrasing is present. Returns an error if nothing is found at all — an
// empty prerequisite set means the parser or the artifact drifted, not a
// legitimate zero-obligation unit.
func parseServicePrereqSysctls(text string) ([]servicePrereqSysctl, error) {
	var out []servicePrereqSysctl
	seen := map[string]bool{}
	for _, m := range sysctlAssignRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		v, err := strconv.Atoi(m[2])
		if err != nil {
			return nil, fmt.Errorf("parsing sysctl assignment %q: %w", m[0], err)
		}
		out = append(out, servicePrereqSysctl{Name: name, Want: v})
	}
	if strings.Contains(text, "br_netfilter forbidden") {
		out = append(out, servicePrereqSysctl{Name: prereqBrNetfilterForbidden, Want: 1})
	}
	if strings.Contains(text, "per-session-tap IPv6 disabled") {
		out = append(out, servicePrereqSysctl{Name: prereqTapDisableIPv6, Want: 1})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no declared prerequisite sysctls found (parser or artifact drift)")
	}
	return out, nil
}

// afterUnitsRe matches a systemd unit file's After= directive line (the
// space-separated unit list on that line).
var afterUnitsRe = regexp.MustCompile(`(?m)^After=(.+)$`)

// parseAfterUnits extracts the space-separated unit list off the FIRST After=
// line in a unit file's text.
func parseAfterUnits(text string) ([]string, error) {
	m := afterUnitsRe.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("no After= directive found")
	}
	return strings.Fields(m[1]), nil
}

// checkServiceSysctlDrift is the drift assertion, factored out of the test
// function so the negative arm (TestServiceSysctlDriftIsRed) can call it
// directly against mutated in-memory copies of the parsed inputs rather than
// the shipped files. baselineUnit is the systemd unit that OWNS the
// host-baseline sysctls (ds-host-baseline.service) — it must appear in
// afterUnits for the ordering invariant to hold structurally. Returns one
// problem string per drifted prerequisite / missing ordering dependency; nil
// means no drift.
func checkServiceSysctlDrift(prereqs []servicePrereqSysctl, afterUnits []string, baselineUnit string, b HostBaseline) []string {
	var problems []string

	named := false
	for _, u := range afterUnits {
		if u == baselineUnit {
			named = true
			break
		}
	}
	if !named {
		problems = append(problems, fmt.Sprintf("After= does not name %q, the unit owning the declared prerequisite sysctls (ordering-declared-before-rules invariant violated)", baselineUnit))
	}

	for _, p := range prereqs {
		switch p.Name {
		case prereqBrNetfilterForbidden:
			got := b.L2Isolation.BrNetfilterForbidden
			if got == nil || !*got {
				problems = append(problems, fmt.Sprintf("service declares br_netfilter forbidden as a prerequisite but host-baseline l2_isolation.br_netfilter_forbidden is %s", boolPtrStr(got)))
			}
		case prereqTapDisableIPv6:
			got := b.PerSessionTap.DisableIPv6
			if got == nil || *got != 1 {
				problems = append(problems, fmt.Sprintf("service declares per-session-tap IPv6 disabled as a prerequisite but host-baseline per_session_tap.disable_ipv6 is %s (want 1)", intPtrStr(got)))
			}
		default:
			key := "net.netfilter." + p.Name
			got, present := b.Sysctls[key]
			switch {
			case !present || got == nil:
				problems = append(problems, fmt.Sprintf("service declares sysctls[%q]=%d as a prerequisite but host-baseline artifact has no such key", key, p.Want))
			case *got != p.Want:
				problems = append(problems, fmt.Sprintf("service declares sysctls[%q]=%d as a prerequisite but host-baseline artifact has %d", key, p.Want, *got))
			}
		}
	}
	return problems
}

func boolPtrStr(p *bool) string {
	if p == nil {
		return "<absent>"
	}
	return fmt.Sprintf("%v", *p)
}

func intPtrStr(p *int) string {
	if p == nil {
		return "<absent>"
	}
	return fmt.Sprintf("%d", *p)
}

// loadShippedServiceAndBaseline reads and parses the two SHIPPED tracked
// artifacts this test cross-checks: the ds-nft-bootstrap.service unit file
// and the host-baseline.v0.json artifact. Shared by both tests so the
// negative arm mutates copies derived from the same real inputs the green
// assertion checks.
func loadShippedServiceAndBaseline(t *testing.T) (prereqs []servicePrereqSysctl, afterUnits []string, b HostBaseline) {
	t.Helper()
	svcPath := NFTBootstrapServiceUnitPath()
	svcData, err := os.ReadFile(svcPath)
	if err != nil {
		t.Fatalf("reading shipped service unit %s: %v", svcPath, err)
	}
	svcText := string(svcData)

	prereqs, err = parseServicePrereqSysctls(svcText)
	if err != nil {
		t.Fatalf("parsing declared prerequisite sysctls from %s: %v", svcPath, err)
	}
	afterUnits, err = parseAfterUnits(svcText)
	if err != nil {
		t.Fatalf("parsing After= from %s: %v", svcPath, err)
	}

	b, err = LoadHostBaseline(HostBaselineArtifactPath())
	if err != nil {
		t.Fatalf("loading shipped host-baseline artifact: %v", err)
	}
	return prereqs, afterUnits, b
}

// TestServiceSysctlDriftAgainstShippedArtifacts is the drift assertion: every
// prerequisite conntrack/floor sysctl ds-nft-bootstrap.service's header
// comment declares must be present with the matching value in
// host-baseline.v0.json, and the unit's After= must name
// ds-host-baseline.service (the unit that owns those sysctls) so the
// "conntrack sysctls before ct-state rules" ordering invariant is more than
// prose.
func TestServiceSysctlDriftAgainstShippedArtifacts(t *testing.T) {
	prereqs, afterUnits, b := loadShippedServiceAndBaseline(t)

	// Sanity: the 5 obligations this test exists to close (3 numeric conntrack
	// sysctls + br_netfilter-forbidden + per-session-tap-ipv6-disabled) must all
	// have been found by the parser — fewer would make the assertion below
	// vacuous for whichever obligation silently dropped out of the parse.
	if len(prereqs) != 5 {
		t.Fatalf("expected 5 declared prerequisite sysctls in %s, parsed %d: %+v", NFTBootstrapServiceUnitPath(), len(prereqs), prereqs)
	}

	if got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", b); len(got) != 0 {
		for _, p := range got {
			t.Errorf("service<->host-baseline sysctl drift: %s", p)
		}
	}
}

// TestServiceSysctlDriftIsRed proves the drift assertion in
// TestServiceSysctlDriftAgainstShippedArtifacts is non-vacuous: each subtest
// takes the SAME real inputs parsed from the shipped files, mutates one
// in-memory copy (never the files on disk), and confirms
// checkServiceSysctlDrift reports a problem. A green control subtest first
// confirms the unmutated shipped pair is clean, so a later red result can only
// be attributed to the mutation.
func TestServiceSysctlDriftIsRed(t *testing.T) {
	prereqs, afterUnits, b := loadShippedServiceAndBaseline(t)

	t.Run("control: shipped pair is drift-free", func(t *testing.T) {
		if got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", b); len(got) != 0 {
			t.Fatalf("expected the shipped service/baseline pair to be drift-free as a control, got: %v", got)
		}
	})

	t.Run("flipped sysctl value is caught", func(t *testing.T) {
		mutated, err := LoadHostBaseline(HostBaselineArtifactPath()) // fresh parse: independent map, mutating it never leaks
		if err != nil {
			t.Fatalf("loading host-baseline artifact: %v", err)
		}
		flipped := *mutated.Sysctls["net.netfilter.nf_conntrack_tcp_loose"] + 1
		mutated.Sysctls["net.netfilter.nf_conntrack_tcp_loose"] = &flipped
		got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", mutated)
		if len(got) == 0 {
			t.Fatal("flipping sysctls[net.netfilter.nf_conntrack_tcp_loose]'s value did not trip the drift assertion")
		}
	})

	t.Run("removed declared prerequisite (sysctl key deleted from baseline) is caught", func(t *testing.T) {
		mutated, err := LoadHostBaseline(HostBaselineArtifactPath())
		if err != nil {
			t.Fatalf("loading host-baseline artifact: %v", err)
		}
		delete(mutated.Sysctls, "net.netfilter.nf_conntrack_acct")
		got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", mutated)
		if len(got) == 0 {
			t.Fatal("removing sysctls[net.netfilter.nf_conntrack_acct] from the baseline did not trip the drift assertion")
		}
	})

	t.Run("br_netfilter_forbidden flipped false is caught", func(t *testing.T) {
		mutated, err := LoadHostBaseline(HostBaselineArtifactPath())
		if err != nil {
			t.Fatalf("loading host-baseline artifact: %v", err)
		}
		f := false
		mutated.L2Isolation.BrNetfilterForbidden = &f
		got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", mutated)
		if len(got) == 0 {
			t.Fatal("flipping l2_isolation.br_netfilter_forbidden to false did not trip the drift assertion")
		}
	})

	t.Run("per_session_tap.disable_ipv6 flipped to 0 is caught", func(t *testing.T) {
		mutated, err := LoadHostBaseline(HostBaselineArtifactPath())
		if err != nil {
			t.Fatalf("loading host-baseline artifact: %v", err)
		}
		zero := 0
		mutated.PerSessionTap.DisableIPv6 = &zero
		got := checkServiceSysctlDrift(prereqs, afterUnits, "ds-host-baseline.service", mutated)
		if len(got) == 0 {
			t.Fatal("flipping per_session_tap.disable_ipv6 to 0 did not trip the drift assertion")
		}
	})

	t.Run("dropped After= prerequisite is caught", func(t *testing.T) {
		var reducedAfter []string
		for _, u := range afterUnits {
			if u != "ds-host-baseline.service" {
				reducedAfter = append(reducedAfter, u)
			}
		}
		if len(reducedAfter) != len(afterUnits)-1 {
			t.Fatalf("test setup: expected to drop exactly one After= unit, dropped %d of %d", len(afterUnits)-len(reducedAfter), len(afterUnits))
		}
		got := checkServiceSysctlDrift(prereqs, reducedAfter, "ds-host-baseline.service", b)
		if len(got) == 0 {
			t.Fatal("dropping ds-host-baseline.service from After= did not trip the ordering assertion")
		}
	})
}

// TestParseServicePrereqSysctlsRejectsEmptyInput guards the parser itself:
// text with no recognizable prerequisite (e.g. a service unit edited down to
// nothing declared) must error rather than silently returning zero
// obligations, which would make the count assertion in
// TestServiceSysctlDriftAgainstShippedArtifacts the only thing standing
// between an artifact edit and a vacuous drift check.
func TestParseServicePrereqSysctlsRejectsEmptyInput(t *testing.T) {
	if _, err := parseServicePrereqSysctls("# nothing declared here\n"); err == nil {
		t.Fatal("expected an error parsing text with no declared prerequisite sysctls, got nil")
	}
}

// TestParseAfterUnitsRejectsMissingDirective guards the After= parser: a unit
// file text with no After= line at all must error rather than silently
// returning an empty (and therefore vacuously-failing-for-the-wrong-reason)
// unit list.
func TestParseAfterUnitsRejectsMissingDirective(t *testing.T) {
	if _, err := parseAfterUnits("[Unit]\nDescription=x\n"); err == nil {
		t.Fatal("expected an error parsing text with no After= directive, got nil")
	}
}
