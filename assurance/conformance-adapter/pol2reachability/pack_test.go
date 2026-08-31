// SPDX-License-Identifier: Apache-2.0

package pol2reachability

// pack_test.go — the OFFLINE half of the POL-2 done-when suite. These run
// today, with no network and no live services, against the frozen D74 pack
// fixture (ShippedPackV2). They assert the contract a fresh install must
// satisfy BEFORE any flow is made, and they drive the shared reachability
// matrix so the live half (live_test.go) reuses the identical cases.

import (
	"strings"
	"testing"
)

// capsTLS6Absent / capsTLS6Present model the host-capability set the matrix
// keys on. TLS-6 ⇒ the http-policy capability.
var (
	capsTLS6Absent  = map[Capability]bool{}
	capsTLS6Present = map[Capability]bool{CapHTTPPolicy: true}
)

// TestFrozenTierDefaults pins the D74 tier defaults: core/vcs/packages enabled;
// telemetry/binary-cdn/ghcr/lfs disabled-by-default (doc 13 §3 families block).
func TestFrozenTierDefaults(t *testing.T) {
	p := ParsePack()
	enabled := map[Family]bool{FamilyCore: true, FamilyVCS: true, FamilyPackages: true}
	disabled := map[Family]bool{FamilyTelemetry: true, FamilyBinaryCDN: true, FamilyGHCR: true, FamilyLFS: true}

	for f := range enabled {
		if got := p.TierOf(f); got != TierEnabled {
			t.Errorf("family %q: tier = %q, want %q (frozen enabled, D74)", f, got, TierEnabled)
		}
	}
	for f := range disabled {
		if got := p.TierOf(f); got != TierDisabled {
			t.Errorf("family %q: tier = %q, want %q (frozen disabled-by-default, D74)", f, got, TierDisabled)
		}
	}

	// EnabledFamilies must be exactly {core, vcs, packages}, in frozen order.
	want := []Family{FamilyCore, FamilyVCS, FamilyPackages}
	got := p.EnabledFamilies()
	if len(got) != len(want) {
		t.Fatalf("EnabledFamilies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("EnabledFamilies[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPassThroughEmpty pins the D17/D74 invariant: the pass-through list ships
// EMPTY and no baseline entry is a pass-through opaque tunnel.
func TestPassThroughEmpty(t *testing.T) {
	p := ParsePack()
	if len(p.Passthrough) != 0 {
		t.Errorf("pass-through list has %d entries, want 0 (D17/D74: ships empty)", len(p.Passthrough))
	}
	for _, e := range p.Entries {
		if e.Passthrough {
			t.Errorf("entry %q has passthrough=true; the baseline cert-pins nothing (D17/D74)", e.FQDN)
		}
	}
}

// TestMandatoryProvenance pins the §1.4/D74 invariant: every pack entry carries
// provenance_source_url; CI rejects an entry without one.
func TestMandatoryProvenance(t *testing.T) {
	p := ParsePack()
	if len(p.Entries) == 0 {
		t.Fatal("pack has no entries")
	}
	for _, e := range p.Entries {
		if strings.TrimSpace(e.ProvenanceSourceURL) == "" {
			t.Errorf("entry %q missing provenance_source_url (mandatory, §1.4/D74)", e.FQDN)
		}
		if len(e.Ports) == 0 {
			t.Errorf("entry %q has no ports; the baseline set is port 443", e.FQDN)
		}
	}
}

// TestDownloadsClaudeAIExcluded pins the coupled-invariant exclusion: the host
// is excluded from the SESSION pack (image-build-time allowlist instead, D74/D49)
// and never appears as a reachable entry.
func TestDownloadsClaudeAIExcluded(t *testing.T) {
	p := ParsePack()
	const host = "downloads.claude.ai"
	if _, ok := p.Lookup(host); ok {
		t.Errorf("%q is a pack entry; it must be excluded-because-pinned (D74/D49)", host)
	}
	found := false
	for _, h := range p.ExcludedPinned {
		if h == host {
			found = true
		}
	}
	if !found {
		t.Errorf("%q not recorded in ExcludedPinned; the excluded-because-pinned disposition must be explicit (D74)", host)
	}
}

// TestWildcardPolicy pins the frozen wildcard policy: exact FQDNs only in the
// ENABLED set; host-wide storage.googleapis.com is permanently rejected — the
// only such entry is path-scoped behind a capability gate, never host-wide.
func TestWildcardPolicy(t *testing.T) {
	p := ParsePack()
	for _, e := range p.Entries {
		if strings.HasPrefix(e.FQDN, "*.") && p.TierOf(e.Family) == TierEnabled {
			t.Errorf("enabled-tier entry %q is a wildcard; the enabled set is exact-FQDN-only (D74)", e.FQDN)
		}
	}
	gcs, ok := p.Lookup("storage.googleapis.com")
	if !ok {
		t.Fatal("storage.googleapis.com missing from the pack")
	}
	if !gcs.PathScoped() {
		t.Error("storage.googleapis.com is not path-scoped; host-wide is permanently rejected (D74)")
	}
	if gcs.Requires != CapHTTPPolicy {
		t.Errorf("storage.googleapis.com requires = %q, want %q (TLS-6 capability gate, D74)", gcs.Requires, CapHTTPPolicy)
	}
}

// TestCapabilityGateInertness pins doc 13 §1.7/§7: with TLS-6 absent the
// path-scoped storage.googleapis.com entry admits NOTHING at domain level
// (inert, never a host-wide allow, never a silent no-op); with TLS-6 present it
// activates.
func TestCapabilityGateInertness(t *testing.T) {
	p := ParsePack()
	gcs, ok := p.Lookup("storage.googleapis.com")
	if !ok {
		t.Fatal("storage.googleapis.com missing from the pack")
	}
	if !gcs.DomainInert(capsTLS6Absent) {
		t.Error("storage.googleapis.com is not domain-inert with TLS-6 absent; requires-gated entries must admit nothing pre-capability (§1.7/D74)")
	}
	if gcs.DomainInert(capsTLS6Present) {
		t.Error("storage.googleapis.com is still domain-inert with TLS-6 present; the same entry must activate when the capability lands (§1.7/D74)")
	}
	// Inert ⇒ Reachable false at domain level even though the family were
	// force-enabled. (binary-cdn is disabled by default; this isolates the gate
	// by checking the inertness path directly rather than via the tier.)
	if p.Reachable("storage.googleapis.com", capsTLS6Absent) {
		t.Error("storage.googleapis.com reachable with TLS-6 absent; must be inert (§1.7/D74)")
	}
}

// TestCanaryMatchesNothing pins "and can reach nothing else": the synthetic
// non-pack canary FQDN matches no pack entry and is unreachable.
func TestCanaryMatchesNothing(t *testing.T) {
	p := ParsePack()
	if _, ok := p.Lookup(CanaryDomain); ok {
		t.Errorf("canary %q matched a pack entry; it must match nothing (doc 09 §1)", CanaryDomain)
	}
	if p.Reachable(CanaryDomain, capsTLS6Present) {
		t.Errorf("canary %q is reachable; a non-pack domain must be unreachable (doc 09 §1)", CanaryDomain)
	}
	// Defend the labeled-fixture rule: the canary is an RFC-2606 reserved name.
	if !strings.HasSuffix(CanaryDomain, ".example") {
		t.Errorf("canary %q is not a reserved .example name; the canary must be synthetic, never a real host", CanaryDomain)
	}
}

// TestEnabledReachabilityZeroConfig pins the developer-value "must reach" set:
// on a fresh install (pack only) the Anthropic API, the GitHub clone/push set,
// and the npm/yarn/node registries are all reachable with zero config.
func TestEnabledReachabilityZeroConfig(t *testing.T) {
	p := ParsePack()
	mustReach := []string{
		"api.anthropic.com", "claude.ai", "platform.claude.com",
		"github.com", "api.github.com", "codeload.github.com",
		"raw.githubusercontent.com", "objects.githubusercontent.com",
		"registry.npmjs.org", "registry.yarnpkg.com", "nodejs.org",
	}
	for _, fqdn := range mustReach {
		if !p.Reachable(fqdn, capsTLS6Absent) {
			t.Errorf("%q not reachable on a fresh install; the zero-config developer-value set must be admitted (doc 09 §1)", fqdn)
		}
	}
}

// TestMatrixOffline drives every OFFLINE matrix row through EvalOffline against
// the frozen pack. This is the matrix-shared assertion the live half mirrors —
// the offline half proves the spec, the live half proves the wire matches it.
func TestMatrixOffline(t *testing.T) {
	p := ParsePack()
	for _, c := range OfflineCases() {
		t.Run(c.Name, func(t *testing.T) {
			present := capsTLS6Absent
			if c.RequiresTLS6 && c.Want == VerdictReachable {
				present = capsTLS6Present
			}
			if got := EvalOffline(p, c, present); got != c.Want {
				t.Errorf("case %q: verdict = %q, want %q\n  why: %s", c.Name, got, c.Want, c.Why)
			}
		})
	}
}

// TestCapabilityGateActiveWithFamilyFlip pins the capability-gate-ACTIVE
// semantics the live half cross-checks: the path-scoped storage.googleapis.com
// entry "activates path-scoped" (doc 13 §7) only when BOTH its disabled-by-
// default binary-cdn family is flipped on (ordinary org policy) AND TLS-6 is
// present. It also pins that WithFamilyEnabled never mutates the frozen fixture
// — the offline tier defaults must survive a tier flip on a copy.
func TestCapabilityGateActiveWithFamilyFlip(t *testing.T) {
	p := ParsePack()

	// Frozen pack, binary-cdn disabled: even with TLS-6 present the entry is not
	// fresh-reachable (the disabled tier is the residual gate).
	if got := EvalOffline(p, Case{FQDN: "storage.googleapis.com"}, capsTLS6Present); got != VerdictDisabledTier {
		t.Errorf("frozen pack + TLS-6: gcs verdict = %q, want %q (binary-cdn disabled-by-default)", got, VerdictDisabledTier)
	}

	// Operator flips binary-cdn on (the browser-install scenario) AND TLS-6
	// present: the entry activates path-scoped ⇒ reachable.
	flipped := p.WithFamilyEnabled(FamilyBinaryCDN)
	if got := EvalOffline(flipped, Case{FQDN: "storage.googleapis.com"}, capsTLS6Present); got != VerdictReachable {
		t.Errorf("binary-cdn flipped + TLS-6: gcs verdict = %q, want %q (entry activates path-scoped, doc 13 §7)", got, VerdictReachable)
	}

	// With the family flipped but TLS-6 ABSENT, the capability gate still holds:
	// inert, never a host-wide allow (the §1.7 invariant the inert case proves).
	if got := EvalOffline(flipped, Case{FQDN: "storage.googleapis.com"}, capsTLS6Absent); got != VerdictInertCapGate {
		t.Errorf("binary-cdn flipped + TLS-6 absent: gcs verdict = %q, want %q (capability gate holds even with family enabled, §1.7/D74)", got, VerdictInertCapGate)
	}

	// WithFamilyEnabled must not mutate the frozen fixture.
	if p.TierOf(FamilyBinaryCDN) != TierDisabled {
		t.Error("WithFamilyEnabled mutated the frozen pack; binary-cdn must stay disabled-by-default on the original")
	}
}

// TestMatrixCoverage guards against an empty or unbalanced matrix: every
// matrix row must carry a non-empty Want and Why, the offline subset must be
// non-empty (so CI actually asserts something), and the live subset must be
// non-empty (the deferred manual pass exists).
func TestMatrixCoverage(t *testing.T) {
	m := Matrix()
	if len(m) == 0 {
		t.Fatal("matrix is empty")
	}
	seen := map[string]bool{}
	for _, c := range m {
		if c.Name == "" || c.Want == "" || c.Why == "" {
			t.Errorf("matrix row %+v has an empty Name/Want/Why", c)
		}
		if seen[c.Name] {
			t.Errorf("duplicate matrix case name %q", c.Name)
		}
		seen[c.Name] = true
	}
	if len(OfflineCases()) == 0 {
		t.Error("no offline cases; CI would assert nothing")
	}
	if len(LiveCases()) == 0 {
		t.Error("no live cases; the deferred manual pass is missing")
	}
}
