// SPDX-License-Identifier: Apache-2.0

package nftgate

// Host-baseline drift model (doc 14 §11 / doc 13 §4, D68/D66/D75/D76).
//
// The versioned host-baseline artifact (dataplane/artifacts/host-baseline/
// host-baseline.v0.json) consolidates every doc 14 §11 obligation the boundary
// stack imposes on the virtual-metal VM's host network namespace: the kernel
// floor, the conntrack sysctls, the per-session tap posture, the L2-isolation
// invariant, and the NFT-1 mark-discipline lint pointer. It is a BUILD ARTIFACT
// versioned with the NFT-1 ruleset and the host image — NOT live policy pushed
// over the D72 policy stream. Its lifecycle is "ships like code, asserted by
// CI and the (c) suite": a sysctl/kernel/tap obligation that drifts out of the
// shipped artifact is a suite FAILURE, not a log line (doc 14 §11 row).
//
// This file is the executable form of that obligation set. `HostBaseline` is
// the parsed artifact; `Check` returns one `BaselineViolation` per §11
// obligation the artifact fails to satisfy. The (c) suite (hostbaseline_test.go)
// loads the SHIPPED artifact and asserts `Check` is empty — so an edit that
// weakens any obligation goes RED — and loads a synthetic violated-baseline
// fixture and asserts `Check` reports exactly the seeded violations, proving the
// red path is non-vacuous.
//
// OFFLINE + SYNTHETIC (D50). Nothing here reads a live host: it diffs a parsed
// repo artifact against the frozen doc 14 §11 obligations. The live host apply
// (sysctl/tap enforcement on a real boundary netns) is the operator's job and is
// out of scope for this offline claims package (README.md).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// HostBaseline is the parsed host-baseline artifact. Field homes mirror
// host-baseline.v0.json (doc 13 §4 schema); the README pins the semantics. Every
// obligation-bearing scalar is a pointer so an OMITTED field is distinguishable
// from a present-but-zero one — a missing obligation is itself a violation, not a
// silent zero-value pass (fail-closed, D47 discipline).
type HostBaseline struct {
	ArtifactVersion *int   `json:"artifact_version"`
	License         string `json:"license"`

	Kernel struct {
		MinVersion    string `json:"min_version"`
		Fallback      string `json:"fallback"`
		BothPathsInCI *bool  `json:"both_paths_in_ci"`
	} `json:"kernel"`

	Libvirt struct {
		IsolatedPortsChosen       *bool  `json:"isolated_ports_chosen"`
		MinVersionIfIsolatedPorts string `json:"min_version_if_isolated_ports"`
	} `json:"libvirt"`

	L2Isolation struct {
		Structural           *bool `json:"structural"`
		BrNetfilterForbidden *bool `json:"br_netfilter_forbidden"`
	} `json:"l2_isolation"`

	// Sysctls is a raw map so a MISSING required key is a violation (fail-closed)
	// rather than defaulting to a conforming zero for tcp_loose.
	Sysctls map[string]*int `json:"sysctls"`

	PerSessionTap struct {
		DisableIPv6   *int   `json:"disable_ipv6"`
		AcceptRA      *int   `json:"accept_ra"`
		RADHCPv6OnSeg *bool  `json:"ra_dhcpv6_on_segment"`
		RulesetFamily string `json:"ruleset_family"`
	} `json:"per_session_tap"`

	NFTMarkLint struct {
		Ruleset             string `json:"ruleset"`
		ConstantsSource     string `json:"constants_source"`
		ForbidBits14To23    *bool  `json:"forbid_bits_14_23"`
		ForbidUnmaskedWrite *bool  `json:"forbid_unmasked_writes"`
	} `json:"nft_mark_lint"`
}

// BaselineViolation names one failed doc 14 §11 obligation: the obligation slug
// (stable, for coverage assertions), the D-number that ratifies it, and a
// human-readable detail. A non-empty Check result is a (c)-suite failure.
type BaselineViolation struct {
	Obligation string // stable slug, e.g. "kernel-min-6.12"
	Decision   string // governing D-number, e.g. "D68"
	Detail     string // what specifically drifted
}

func (v BaselineViolation) String() string {
	return fmt.Sprintf("%s (%s): %s", v.Obligation, v.Decision, v.Detail)
}

// Baseline obligation slugs — the stable identifiers the coverage assertions and
// the synthetic red-path fixture key on. Every §11 row maps to exactly one slug.
const (
	OblKernelMin        = "kernel-min-6.12"
	OblKernelFallback   = "kernel-delete-add-fallback"
	OblConntrackLoose   = "sysctl-nf_conntrack_tcp_loose-0"
	OblConntrackAcct    = "sysctl-nf_conntrack_acct-1"
	OblConntrackTstamp  = "sysctl-nf_conntrack_timestamp-1"
	OblLibvirtIfIso     = "libvirt-6.1.0-if-isolated-ports"
	OblStructuralL2     = "structural-l2-isolation"
	OblBrNetfilter      = "br_netfilter-forbidden"
	OblTapDisableIPv6   = "per-session-tap-disable_ipv6"
	OblTapAcceptRA      = "per-session-tap-accept_ra-0"
	OblTapNoRADHCPv6    = "per-session-tap-no-ra-dhcpv6"
	OblTapFamilyInet    = "per-session-tap-family-inet"
	OblMarkLintBits     = "nft-mark-lint-forbid-bits-14-23"
	OblMarkLintUnmasked = "nft-mark-lint-forbid-unmasked-writes"
	OblMarkLintSource   = "nft-mark-lint-source-ds-contracts"
)

// AllBaselineObligations is the full set of §11 obligation slugs Check can emit,
// in a stable order. The coverage assertion pins that Check's obligation
// vocabulary matches this set exactly, so a §11 row can never be silently
// dropped from the model (the RowOwners()/AllRowOwners() coverage precedent).
func AllBaselineObligations() []string {
	return []string{
		OblKernelMin,
		OblKernelFallback,
		OblConntrackLoose,
		OblConntrackAcct,
		OblConntrackTstamp,
		OblLibvirtIfIso,
		OblStructuralL2,
		OblBrNetfilter,
		OblTapDisableIPv6,
		OblTapAcceptRA,
		OblTapNoRADHCPv6,
		OblTapFamilyInet,
		OblMarkLintBits,
		OblMarkLintUnmasked,
		OblMarkLintSource,
	}
}

// Check evaluates every doc 14 §11 obligation against the parsed baseline and
// returns one BaselineViolation per failed obligation, in AllBaselineObligations
// order. An empty result means the artifact satisfies every §11 obligation.
//
// Fail-closed: a MISSING obligation-bearing field is a violation, never a
// zero-value pass — the pointer fields make "omitted" distinguishable from
// "present and conforming".
func (b HostBaseline) Check() []BaselineViolation {
	var vs []BaselineViolation
	add := func(slug, decision, detail string) {
		vs = append(vs, BaselineViolation{Obligation: slug, Decision: decision, Detail: detail})
	}

	// D68 — kernel floor. In-place nft element-timeout refresh needs ≥ 6.12.
	if cmp, ok := compareKernel(b.Kernel.MinVersion, "6.12"); !ok {
		add(OblKernelMin, "D68", fmt.Sprintf("kernel.min_version %q is absent or unparseable (floor is 6.12)", b.Kernel.MinVersion))
	} else if cmp < 0 {
		add(OblKernelMin, "D68", fmt.Sprintf("kernel.min_version %q is below the 6.12 floor", b.Kernel.MinVersion))
	}
	// D68 — the delete+add fallback ships behind the same nft-writer API and BOTH
	// paths run in CI (so a lower kernel degrades rather than breaks).
	if !strings.EqualFold(strings.TrimSpace(b.Kernel.Fallback), "delete+add") {
		add(OblKernelFallback, "D68", fmt.Sprintf("kernel.fallback %q is not the required delete+add path", b.Kernel.Fallback))
	} else if b.Kernel.BothPathsInCI == nil || !*b.Kernel.BothPathsInCI {
		add(OblKernelFallback, "D68", "kernel.both_paths_in_ci is not true (both refresh paths must run in CI)")
	}

	// D68 — conntrack sysctls. Without tcp_loose=0 the revocation flush_session
	// kill is a no-op (mid-stream packets re-picked-up as ESTABLISHED); acct=1 +
	// timestamp=1 back the D43/NFT-5 byte counters.
	checkSysctl := func(key string, want int, slug string) {
		got, present := b.Sysctls[key]
		switch {
		case !present || got == nil:
			add(slug, "D68", fmt.Sprintf("sysctls[%q] is absent (required = %d)", key, want))
		case *got != want:
			add(slug, "D68", fmt.Sprintf("sysctls[%q] = %d, required %d", key, *got, want))
		}
	}
	checkSysctl("net.netfilter.nf_conntrack_tcp_loose", 0, OblConntrackLoose)
	checkSysctl("net.netfilter.nf_conntrack_acct", 1, OblConntrackAcct)
	checkSysctl("net.netfilter.nf_conntrack_timestamp", 1, OblConntrackTstamp)

	// D66 — libvirt floor ONLY when the shared-bridge isolated-ports primitive is
	// chosen; the structural per-session bridge / routed tap is preferred and
	// needs no libvirt floor.
	if b.Libvirt.IsolatedPortsChosen != nil && *b.Libvirt.IsolatedPortsChosen {
		if cmp, ok := compareKernel(b.Libvirt.MinVersionIfIsolatedPorts, "6.1.0"); !ok || cmp < 0 {
			add(OblLibvirtIfIso, "D66", fmt.Sprintf("isolated-ports chosen but libvirt floor %q is absent or below 6.1.0", b.Libvirt.MinVersionIfIsolatedPorts))
		}
	}

	// D66 — structural L2 isolation invariant: no two agent-session devices ever
	// share an L2 segment. Either the structural primitive is used, or isolated
	// ports are chosen with the libvirt floor met (checked above).
	structural := b.L2Isolation.Structural != nil && *b.L2Isolation.Structural
	isolatedPorts := b.Libvirt.IsolatedPortsChosen != nil && *b.Libvirt.IsolatedPortsChosen
	if !structural && !isolatedPorts {
		add(OblStructuralL2, "D66", "neither structural L2 isolation nor the isolated-ports primitive is asserted (no two agent-session devices may share an L2 segment)")
	}

	// D66 — br_netfilter is FORBIDDEN, not merely unused (bridged frames bypassing
	// the inet chains is why isolation must be structural).
	if b.L2Isolation.BrNetfilterForbidden == nil || !*b.L2Isolation.BrNetfilterForbidden {
		add(OblBrNetfilter, "D66", "l2_isolation.br_netfilter_forbidden is not true (br_netfilter must be forbidden, not merely unused)")
	}

	// D75 — per-session taps: disable_ipv6=1, accept_ra=0, no RA/DHCPv6 on any
	// per-session segment, rulesets in the inet family so v6 drops by default.
	if b.PerSessionTap.DisableIPv6 == nil || *b.PerSessionTap.DisableIPv6 != 1 {
		add(OblTapDisableIPv6, "D75", "per_session_tap.disable_ipv6 is not 1")
	}
	if b.PerSessionTap.AcceptRA == nil || *b.PerSessionTap.AcceptRA != 0 {
		add(OblTapAcceptRA, "D75", "per_session_tap.accept_ra is not 0")
	}
	if b.PerSessionTap.RADHCPv6OnSeg == nil || *b.PerSessionTap.RADHCPv6OnSeg {
		add(OblTapNoRADHCPv6, "D75", "per_session_tap.ra_dhcpv6_on_segment is not false (no RA/DHCPv6 service on any per-session segment)")
	}
	if !strings.EqualFold(strings.TrimSpace(b.PerSessionTap.RulesetFamily), "inet") {
		add(OblTapFamilyInet, "D75", fmt.Sprintf("per_session_tap.ruleset_family %q is not inet (v6 must drop by default)", b.PerSessionTap.RulesetFamily))
	}

	// D76 — mark-constant CI lint of the NFT-1 ruleset: no bits 14–23, no unmasked
	// writes, constants sourced only from ds-contracts.
	if b.NFTMarkLint.ForbidBits14To23 == nil || !*b.NFTMarkLint.ForbidBits14To23 {
		add(OblMarkLintBits, "D76", "nft_mark_lint.forbid_bits_14_23 is not true")
	}
	if b.NFTMarkLint.ForbidUnmaskedWrite == nil || !*b.NFTMarkLint.ForbidUnmaskedWrite {
		add(OblMarkLintUnmasked, "D76", "nft_mark_lint.forbid_unmasked_writes is not true")
	}
	if !strings.EqualFold(strings.TrimSpace(b.NFTMarkLint.ConstantsSource), "ds-contracts") {
		add(OblMarkLintSource, "D76", fmt.Sprintf("nft_mark_lint.constants_source %q is not ds-contracts", b.NFTMarkLint.ConstantsSource))
	}

	return vs
}

// compareKernel compares two dotted numeric version strings (e.g. "6.12",
// "6.1.0"). It returns (sign, true) where sign is -1/0/+1 for a<b / a==b / a>b,
// or (0, false) if either string is empty or has a non-numeric component. Only
// the numeric dotted prefix is compared; missing trailing components read as 0
// ("6.12" == "6.12.0").
func compareKernel(a, b string) (int, bool) {
	pa, ok := parseVersion(a)
	if !ok {
		return 0, false
	}
	pb, ok := parseVersion(b)
	if !ok {
		return 0, false
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}

func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// HostBaselineArtifactPath returns the absolute path to the SHIPPED host-baseline
// v0 artifact, anchored off this source file (runtime.Caller via thisDir) so the
// (c) suite reaches the dataplane/ artifact from any cwd. This cross-tree FILE
// read — not a module import — is how the offline (c) suite asserts the shipped
// artifact and catches drift; it does not violate D80 (no identity/* import, no
// non-proto cross-tree Go import).
func HostBaselineArtifactPath() string {
	// thisDir() = assurance/guardrail-conformance/nftgate → repo root is three up.
	repoRoot := filepath.Join(thisDir(), "..", "..", "..")
	return filepath.Join(repoRoot, "dataplane", "artifacts", "host-baseline", "host-baseline.v0.json")
}

// NFT1BootstrapPath returns the absolute path to the NFT-1 bootstrap ruleset the
// host-baseline artifact governs, anchored the same way — for the artifact↔
// ruleset drift assertion (the baseline's declared inet family vs the ruleset's
// actual `table inet`).
func NFT1BootstrapPath() string {
	repoRoot := filepath.Join(thisDir(), "..", "..", "..")
	return filepath.Join(repoRoot, "dataplane", "artifacts", "nft", "nft-1-bootstrap.nft")
}

// LoadHostBaseline reads and parses a host-baseline artifact JSON file.
func LoadHostBaseline(path string) (HostBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return HostBaseline{}, fmt.Errorf("reading host-baseline artifact %s: %w", path, err)
	}
	var b HostBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return HostBaseline{}, fmt.Errorf("parsing host-baseline artifact %s: %w", path, err)
	}
	return b, nil
}

// ViolationSlugs returns the sorted obligation slugs of a violation slice — a
// stable projection for set-equality assertions in the red-path test.
func ViolationSlugs(vs []BaselineViolation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Obligation)
	}
	sort.Strings(out)
	return out
}
