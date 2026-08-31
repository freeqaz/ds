// SPDX-License-Identifier: Apache-2.0

package pol2reachability

// pack.go — a purpose-built reader over the FROZEN D74 baseline policy pack v2,
// plus a SYNTHETIC, clearly-labeled in-package fixture (shippedPackV2) that
// transcribes the pack contents enumerated in doc 13 §3 ("Baseline pack
// contents v2"), the doc 04 §6 D74 decision-log row, and sessions/round2/09
// ("The D64-v2 pack, in full").
//
// Why a fixture and not a file read: POL-1 v0 content is on the anti-scaffold
// list — the pack's schema home is dataplane/crates/ds-contracts and its
// contents land with POL-2 inside that crate (doc 13 §"Empty at skeleton time
// by design"; dataplane/artifacts/policy-packs/README.md). At this base there
// is no shipped pack YAML to read, and ds-contracts is frozen this wave. So the
// reachability matrix asserts against this executable transcription of the
// frozen spec — exactly the D26/D51 posture: the suite is the spec made
// runnable. When the real pack lands in ds-contracts, ParsePack can be pointed
// at it (the reader API below is data-source-agnostic) and these same
// assertions become a cross-check against the shipped bytes.
//
// Network vocabulary is egress-gateway / TLS-termination throughout; udp/443 is
// REJECTED, never silently dropped (D70), and is therefore not a reachability
// entry.

// Tier is an endpoint-family enablement state (doc 13 §3 families block, D74).
// "Flipping a tier is ordinary org policy"; the DEFAULTS here are frozen.
type Tier string

const (
	// TierEnabled families ship reachable on a fresh install (zero config).
	TierEnabled Tier = "enabled"
	// TierDisabled families ship NOT reachable on a fresh install; an operator
	// may flip them, which is ordinary org policy.
	TierDisabled Tier = "disabled"
)

// Family is a vendor-documented endpoint family (D74). The seven frozen family
// names are part of the snapshot contract so POL-3 provenance can cite
// "baseline-pack vN / family / entry" (doc 13 §2 baseline-pack row).
type Family string

const (
	FamilyCore      Family = "core"       // Anthropic API + auth — enabled
	FamilyVCS       Family = "vcs"        // GitHub clone/fetch/push set — enabled
	FamilyPackages  Family = "packages"   // npm/yarn/node registries — enabled
	FamilyTelemetry Family = "telemetry"  // sentry — disabled-by-default
	FamilyBinaryCDN Family = "binary-cdn" // Playwright/CfT/Cypress CDNs — disabled
	FamilyGHCR      Family = "ghcr"       // container registry — disabled
	FamilyLFS       Family = "lfs"        // Git LFS hosts — disabled
)

// Capability names a host capability an entry's enforcement requires before it
// may admit anything (doc 13 §1.7 capability gating, D74). An entry whose
// capability is absent is INERT with a logged warning — never a domain-level
// over-admit, never a silent no-op.
type Capability string

// CapHTTPPolicy is HTTP-level path-scoping, which exists only at TLS-6 (Stage
// 4). The path-scoped storage.googleapis.com entry carries requires:
// http-policy and stays domain-inert until TLS-6 lands.
const CapHTTPPolicy Capability = "http-policy"

// Entry is one baseline-pack endpoint (doc 13 §2 baseline-pack row schema). The
// reader only models the fields the reachability matrix needs; the full schema
// (machine_source, evidence detail, port lists beyond 443, ...) lives in
// ds-contracts. Every entry in a valid pack carries ProvenanceSourceURL (the
// D74/§1.4 mandatory-provenance invariant) — the offline suite asserts it.
type Entry struct {
	FQDN string // exact FQDN (wildcards only where vendor-published; none in the enabled set)
	// Family the entry belongs to; its tier (looked up via TierOf) decides
	// fresh-install reachability.
	Family Family
	Ports  []int // [443] for the whole baseline set
	// ProvenanceSourceURL is mandatory (D74/§1.4); a pack entry missing it
	// fails CI. Synthetic, clearly-labeled in this fixture.
	ProvenanceSourceURL string
	// Passthrough is the D17 pass-through (opaque-tunnel, no TLS-termination)
	// bit. FALSE for every baseline entry — the pass-through LIST ships empty.
	Passthrough bool
	// PathScope, when non-empty, scopes the entry to HTTP paths — enforceable
	// only at TLS-6 (Requires must then be set).
	PathScope []string
	// Requires names a capability gate; while absent the entry is domain-inert
	// with a logged warning (doc 13 §1.7). Empty means unconditionally active.
	Requires Capability
}

// PathScoped reports whether the entry is path-scoped (HTTP-level), which only
// the TLS-6 http-policy capability can enforce.
func (e Entry) PathScoped() bool { return len(e.PathScope) > 0 }

// DomainInert reports whether, given the set of capabilities currently present
// on the host, this entry admits NOTHING at domain level. A requires-gated
// entry whose capability is absent is inert (doc 13 §1.7, D74): it must not
// silently widen to a domain-level allow and must not silently no-op.
func (e Entry) DomainInert(present map[Capability]bool) bool {
	if e.Requires == "" {
		return false
	}
	return !present[e.Requires]
}

// Pack is the in-memory shape the reader produces from a pack source. The
// reachability matrix evaluates against this; it deliberately mirrors only the
// reachability-relevant projection of the doc 13 §3 document.
type Pack struct {
	PackVersion string // content identity cited in provenance — NOT a version namespace (doc 13 §1.3)
	Families    map[Family]Tier
	Entries     []Entry
	// Passthrough is the D17/D74 pass-through list. It ships EMPTY; an entry
	// requires attached reproduction evidence of a pinning failure under
	// TLS-termination inspection. The offline suite asserts len == 0.
	Passthrough []Entry
	// ExcludedPinned records hosts deliberately excluded from the SESSION pack
	// because the golden image pins them at build time (downloads.claude.ai —
	// the coupled-invariant exclusion, valid iff auto-update stays off, D74/D49).
	ExcludedPinned []string
}

// TierOf returns the tier of a family, defaulting to TierDisabled for an
// unknown family (fail-closed: an unrecognized family is never reachable).
func (p *Pack) TierOf(f Family) Tier {
	if t, ok := p.Families[f]; ok {
		return t
	}
	return TierDisabled
}

// WithFamilyEnabled returns a shallow copy of the pack with family f set to
// TierEnabled, modeling the ordinary org-policy tier flip ("flipping a tier is
// ordinary org policy", doc 13 §3) WITHOUT mutating the frozen fixture. The
// Entries/Passthrough slices are shared (read-only); only the Families map is
// copied, so the frozen defaults the offline half asserts stay intact. This is
// what the capability-gate-ACTIVE live case needs: a browser install through
// the path-scoped storage.googleapis.com entry presumes the operator both
// flipped its binary-cdn family on AND has TLS-6 present — the capability gate,
// not the disabled-by-default tier, is the residual admission control the case
// proves.
func (p *Pack) WithFamilyEnabled(f Family) *Pack {
	fams := make(map[Family]Tier, len(p.Families))
	for k, v := range p.Families {
		fams[k] = v
	}
	fams[f] = TierEnabled
	cp := *p
	cp.Families = fams
	return &cp
}

// Lookup returns the entry whose FQDN matches exactly, or false. The baseline
// enabled set is wildcard-free, so exact match is the whole story for it; the
// canary domain (a non-pack FQDN) is precisely the case this returns false for.
func (p *Pack) Lookup(fqdn string) (Entry, bool) {
	for _, e := range p.Entries {
		if e.FQDN == fqdn {
			return e, true
		}
	}
	return Entry{}, false
}

// Reachable reports whether a fresh-install host with the given present
// capabilities admits flows to fqdn under THIS pack, with no operator config.
// The rule: the FQDN must be a known pack entry, its family tier must be
// enabled, the entry must not be a pass-through opaque tunnel, and it must not
// be capability-gate inert. A non-pack (canary) domain, a disabled-tier entry,
// or a requires-gated entry without its capability all return false.
func (p *Pack) Reachable(fqdn string, present map[Capability]bool) bool {
	e, ok := p.Lookup(fqdn)
	if !ok {
		return false
	}
	if p.TierOf(e.Family) != TierEnabled {
		return false
	}
	if e.Passthrough {
		return false
	}
	if e.DomainInert(present) {
		return false
	}
	return true
}

// EnabledFamilies returns the frozen-enabled family set (core/vcs/packages).
func (p *Pack) EnabledFamilies() []Family {
	var out []Family
	for _, f := range []Family{FamilyCore, FamilyVCS, FamilyPackages, FamilyTelemetry, FamilyBinaryCDN, FamilyGHCR, FamilyLFS} {
		if p.TierOf(f) == TierEnabled {
			out = append(out, f)
		}
	}
	return out
}

// ParsePack is the reader entry point. The reader is data-source-agnostic by
// design: today the only source is the synthetic frozen fixture (ShippedPackV2),
// so ParsePack returns it. When the real pack lands in ds-contracts, a
// byte-level decoder slots in here without changing the matrix or the offline
// assertions (they consume the Pack value, not the source).
func ParsePack() *Pack { return ShippedPackV2() }

// ShippedPackV2 returns the SYNTHETIC, clearly-labeled fixture transcribing the
// FROZEN D74 baseline pack v2 (doc 13 §3, doc 04 §6 D74). Every field is the
// frozen spec value; provenance URLs are the vendor-doc sources named in the
// spec. This is the executable form of the spec, not a copy of a shipped
// artifact (none exists at this base — POL-1 v0 content is anti-scaffolded).
func ShippedPackV2() *Pack {
	const claudeNetCfg = "https://code.claude.com/docs/en/network-config"
	const ghMeta = "https://api.github.com/meta"
	const cfTChrome = "https://raw.githubusercontent.com/puppeteer/puppeteer/main/packages/browsers/src/browser-data/chrome.ts"

	p := &Pack{
		// Content identity cited in provenance — NOT a second version namespace
		// (doc 13 §1.3/§3). Value transcribed from the doc 13 §3 strawman.
		PackVersion: "2026.06.11-v2",
		Families: map[Family]Tier{
			// FROZEN tier defaults (doc 13 §3 families block, D74):
			FamilyCore:      TierEnabled,
			FamilyVCS:       TierEnabled,
			FamilyPackages:  TierEnabled,
			FamilyTelemetry: TierDisabled, // golden image sets CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
			FamilyBinaryCDN: TierDisabled, // golden image pre-bakes browsers + node headers
			FamilyGHCR:      TierDisabled, // community-sourced FQDNs; pending OQ9 empirical pass
			FamilyLFS:       TierDisabled, // GitHub publishes no LFS domain list
		},
		// The pass-through list ships EMPTY (D17/D74). An entry requires
		// attached reproduction evidence of a pinning failure under
		// TLS-termination inspection — no baseline client cert-pins.
		Passthrough: []Entry{},
		// Excluded-because-pinned: on the image-build-time allowlist, not the
		// session pack; the exclusion is valid iff auto-update stays off (D74/D49).
		ExcludedPinned: []string{"downloads.claude.ai"},
		Entries: []Entry{
			// ── core (enabled) — Anthropic API + auth. All three front one IP
			//    (160.79.104.10); SNI-keyed admission is load-bearing even here.
			{FQDN: "api.anthropic.com", Family: FamilyCore, Ports: []int{443}, ProvenanceSourceURL: claudeNetCfg},
			{FQDN: "claude.ai", Family: FamilyCore, Ports: []int{443}, ProvenanceSourceURL: claudeNetCfg},
			{FQDN: "platform.claude.com", Family: FamilyCore, Ports: []int{443}, ProvenanceSourceURL: claudeNetCfg},

			// ── vcs (enabled) — the clone/fetch/push + release-download set.
			//    machine_source: api.github.com/meta `domains` object.
			{FQDN: "github.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "api.github.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "codeload.github.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "raw.githubusercontent.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: claudeNetCfg},
			{FQDN: "objects.githubusercontent.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "release-assets.githubusercontent.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "github-releases.githubusercontent.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "github-registry-files.githubusercontent.com", Family: FamilyVCS, Ports: []int{443}, ProvenanceSourceURL: ghMeta},

			// ── packages (enabled) — npm/yarn/node registries.
			//    registry.npmjs.org is the canonical CNAME-chain/CDN-shared-IP case.
			{FQDN: "registry.npmjs.org", Family: FamilyPackages, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/nodejs/corepack#readme"},
			{FQDN: "registry.yarnpkg.com", Family: FamilyPackages, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/nodejs/corepack#readme"},
			{FQDN: "nodejs.org", Family: FamilyPackages, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/nodejs/node-gyp/blob/main/lib/process-release.js"},

			// ── telemetry (disabled) — CC error reporting. Only vendor-published-
			//    shaped wildcard in the pack. statsig.anthropic.com is NXDOMAIN
			//    (the staleness lesson) — successor TBD by the empirical pass.
			{FQDN: "sentry.io", Family: FamilyTelemetry, Ports: []int{443}, ProvenanceSourceURL: "https://code.claude.com/docs/en/data-usage"},
			{FQDN: "*.sentry.io", Family: FamilyTelemetry, Ports: []int{443}, ProvenanceSourceURL: "https://code.claude.com/docs/en/data-usage"},

			// ── binary-cdn (disabled) — browser/test CDNs.
			{FQDN: "cdn.playwright.dev", Family: FamilyBinaryCDN, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/registry/index.ts"},
			{FQDN: "playwright.download.prss.microsoft.com", Family: FamilyBinaryCDN, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/registry/index.ts"},
			{FQDN: "googlechromelabs.github.io", Family: FamilyBinaryCDN, Ports: []int{443}, ProvenanceSourceURL: cfTChrome},
			{FQDN: "download.cypress.io", Family: FamilyBinaryCDN, Ports: []int{443}, ProvenanceSourceURL: "https://docs.cypress.io/app/references/advanced-installation"},
			// storage.googleapis.com: PATH-SCOPED only, behind requires:
			// http-policy — DOMAIN-INERT until TLS-6 (doc 13 §1.7/§3, D74).
			// Host-wide storage.googleapis.com is PERMANENTLY rejected; this
			// entry is path-scoped, never a host-wide allow.
			{
				FQDN:                "storage.googleapis.com",
				Family:              FamilyBinaryCDN,
				Ports:               []int{443},
				PathScope:           []string{"/chrome-for-testing-public/*", "/chromium-browser-snapshots/*"},
				Requires:            CapHTTPPolicy,
				ProvenanceSourceURL: cfTChrome,
			},

			// ── ghcr (disabled) — container registry; blob host community-sourced.
			{FQDN: "ghcr.io", Family: FamilyGHCR, Ports: []int{443}, ProvenanceSourceURL: ghMeta},
			{FQDN: "pkg-containers.githubusercontent.com", Family: FamilyGHCR, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/orgs/community/discussions/118629"},

			// ── lfs (disabled) — community knowledge; /meta omits LFS.
			{FQDN: "github-cloud.githubusercontent.com", Family: FamilyLFS, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/orgs/community/discussions/" /* community-sourced, unverified */},
			{FQDN: "github-cloud.s3.amazonaws.com", Family: FamilyLFS, Ports: []int{443}, ProvenanceSourceURL: "https://github.com/orgs/community/discussions/" /* community-sourced, unverified */},
		},
	}
	return p
}
