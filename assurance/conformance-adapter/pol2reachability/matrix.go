// SPDX-License-Identifier: Apache-2.0

package pol2reachability

// matrix.go — the POL-2 done-when reachability matrix (doc 09 §1/§6, doc 13
// §7). One table of cases drives BOTH halves of the suite: the offline
// assertions (pack_test.go) evaluate each case against the frozen pack via the
// pack reader, and the env-gated live runners (live_test.go) replay the SAME
// cases against real client wire shapes. Keeping the matrix here — not inside a
// _test.go file — is what lets the live half reuse it verbatim.
//
// The developer-value test (doc 09 §1): "a fresh session can call the Anthropic
// API, clone/push GitHub, and install npm packages with zero configuration, and
// can reach NOTHING else." Each row below is one observable assertion of that
// claim; the Want field is the verdict a fresh-install host (pack only, no
// operator config) must produce.

// Verdict is a reachability outcome for one matrix case.
type Verdict string

const (
	// VerdictReachable: a fresh install admits the flow with zero config — the
	// developer-value endpoints (Anthropic API, GitHub, npm registries).
	VerdictReachable Verdict = "reachable"
	// VerdictRefusedDNS3TLS1: the canary/non-pack domain is refused at BOTH
	// DNS-3 (NXDOMAIN-class denial) AND the TLS-1 SNI check (doc 09 §7 (c)
	// suite). The two-layer refusal is the frozen contract — a refusal at only
	// one layer is a hole.
	VerdictRefusedDNS3TLS1 Verdict = "refused-dns3-and-tls1"
	// VerdictDisabledTier: the FQDN is a real pack entry but its family ships
	// disabled-by-default; a fresh install does NOT admit it (flipping the tier
	// is ordinary org policy, out of scope for the zero-config claim).
	VerdictDisabledTier Verdict = "disabled-tier-not-fresh-reachable"
	// VerdictInertCapGate: the path-scoped storage.googleapis.com entry behind
	// requires: http-policy admits NOTHING at domain level while TLS-6 is
	// absent, emitting the logged inert-entry warning (doc 13 §1.7, D74). With
	// TLS-6 present the same entry activates path-scoped.
	VerdictInertCapGate Verdict = "inert-until-tls6"
)

// Half labels which suite half a case primarily exercises. Offline cases assert
// the pack contract with no network; Live cases need real clients/services and
// run only under DS_POL2_LIVE=1.
type Half string

const (
	// HalfOffline: provable today against the frozen pack, no network.
	HalfOffline Half = "offline"
	// HalfLive: needs a real fresh install + live services; DEFERRED MANUAL,
	// env-gated behind DS_POL2_LIVE=1 (default skip).
	HalfLive Half = "live"
)

// Case is one row of the reachability matrix.
type Case struct {
	Name string // stable case name, used as the Go subtest name in both halves
	// FQDN under test. Empty FQDN means the case is not an FQDN-reachability
	// row but a structural invariant (e.g. zero-flows-outside-pack) the live
	// half asserts as an audit, not a single lookup.
	FQDN string
	Want Verdict
	Half Half
	// LiveRunner names the documented live workload the env-gated half drives
	// for this case (Anthropic stream, git clone/fetch/push, gh api, npm/yarn/
	// pnpm install, canary refusal, audit, TLS-6 paths). Informational — the
	// live half scaffolds each as a DEFERRED MANUAL step.
	LiveRunner string
	// RequiresTLS6 marks the capability-gate cases whose verdict flips when the
	// http-policy capability (TLS-6) is present.
	RequiresTLS6 bool
	// Why ties the row back to the spec for the reader of a failure.
	Why string
}

// CanaryDomain is the synthetic non-pack FQDN the suite probes to prove "and
// can reach nothing else". It is deliberately a clearly-labeled example domain
// (RFC 2606 reserved): it must match NO pack entry and must be refused at both
// DNS-3 and TLS-1. Never a real third-party host.
const CanaryDomain = "canary.not-in-pack.example"

// Matrix returns the full POL-2 done-when reachability matrix. The offline half
// asserts every HalfOffline row against the frozen pack; the live half drives
// every row (offline + live) against real wire shapes under DS_POL2_LIVE=1.
func Matrix() []Case {
	return []Case{
		// ── Developer-value reachability (the zero-config "must reach" set) ──
		{
			Name: "anthropic-api-reachable", FQDN: "api.anthropic.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "anthropic-streaming-call",
			Why: "doc 09 §1: a fresh session can call the Anthropic API with zero config (core/enabled)",
		},
		{
			Name: "github-web-reachable", FQDN: "github.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "git-clone-fetch-push",
			Why: "doc 09 §1: clone/push GitHub with zero config (vcs/enabled)",
		},
		{
			Name: "github-api-reachable", FQDN: "api.github.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "gh-api",
			Why: "doc 09 §7: gh api call succeeds on the fresh pack (vcs/enabled)",
		},
		{
			Name: "github-codeload-reachable", FQDN: "codeload.github.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "git-clone-fetch-push",
			Why: "tarball/zipball downloads on clone (vcs/enabled)",
		},
		{
			Name: "github-objects-reachable", FQDN: "objects.githubusercontent.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "git-clone-fetch-push",
			Why: "git objects + release assets on fetch (vcs/enabled)",
		},
		{
			Name: "npm-registry-reachable", FQDN: "registry.npmjs.org",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "npm-install-cname-chained",
			Why: "doc 09 §7: npm install of a CNAME-chained package succeeds (packages/enabled)",
		},
		{
			Name: "yarn-registry-reachable", FQDN: "registry.yarnpkg.com",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "yarn-classic-install",
			Why: "doc 09 §7: yarn-classic install succeeds (packages/enabled)",
		},
		{
			Name: "nodejs-headers-reachable", FQDN: "nodejs.org",
			Want: VerdictReachable, Half: HalfLive, LiveRunner: "pnpm-via-corepack-install",
			Why: "node-gyp headers / pnpm-via-corepack path (packages/enabled)",
		},

		// ── The canary: "and can reach nothing else" ──
		{
			Name: "canary-nonpack-refused", FQDN: CanaryDomain,
			Want: VerdictRefusedDNS3TLS1, Half: HalfLive, LiveRunner: "canary-refusal-dns3-and-tls1",
			Why: "doc 09 §1/§7: a non-pack domain is refused at BOTH DNS-3 and the TLS-1 SNI check",
		},

		// ── Disabled-by-default families: present in the pack, NOT fresh-reachable ──
		{
			Name: "telemetry-disabled-not-fresh-reachable", FQDN: "sentry.io",
			Want: VerdictDisabledTier, Half: HalfOffline,
			Why: "telemetry tier ships disabled-by-default (D74); fresh install does not admit it",
		},
		{
			Name: "ghcr-disabled-not-fresh-reachable", FQDN: "ghcr.io",
			Want: VerdictDisabledTier, Half: HalfOffline,
			Why: "ghcr tier ships disabled-by-default (D74)",
		},
		{
			Name: "lfs-disabled-not-fresh-reachable", FQDN: "github-cloud.s3.amazonaws.com",
			Want: VerdictDisabledTier, Half: HalfOffline,
			Why: "lfs tier ships disabled-by-default (D74)",
		},

		// ── Capability-gate inertness: path-scoped storage.googleapis.com ──
		{
			Name: "gcs-pathscoped-inert-without-tls6", FQDN: "storage.googleapis.com",
			Want: VerdictInertCapGate, Half: HalfOffline, RequiresTLS6: true,
			Why: "doc 13 §1.7/§7, D74: requires http-policy — DOMAIN-INERT with a logged warning until TLS-6; never a host-wide allow",
		},
		{
			Name: "gcs-pathscoped-active-with-tls6", FQDN: "storage.googleapis.com",
			Want: VerdictReachable, Half: HalfLive, RequiresTLS6: true, LiveRunner: "tls6-browser-install-pathscoped",
			Why: "doc 09 §7: with TLS-6 present the entry activates path-scoped; any other bucket path still refuses",
		},

		// ── Structural live audit (no single FQDN): zero flows outside the pack ──
		{
			Name: "zero-flows-outside-pack", FQDN: "",
			Want: VerdictRefusedDNS3TLS1, Half: HalfLive, LiveRunner: "zero-flows-outside-pack-audit",
			Why: "doc 09 §1/§7: during a full workload run, zero flows land outside pack entries (LOG-4 semantics)",
		},
	}
}

// OfflineCases returns the subset provable today against the frozen pack with
// no network — exactly the rows the offline half asserts.
func OfflineCases() []Case {
	var out []Case
	for _, c := range Matrix() {
		if c.Half == HalfOffline {
			out = append(out, c)
		}
	}
	return out
}

// LiveCases returns the env-gated (DEFERRED MANUAL) rows the DS_POL2_LIVE=1 half
// drives against real client wire shapes.
func LiveCases() []Case {
	var out []Case
	for _, c := range Matrix() {
		if c.Half == HalfLive {
			out = append(out, c)
		}
	}
	return out
}

// EvalOffline computes the verdict the FROZEN pack produces for a case, using
// only the pack reader — no network, no live services. present is the set of
// host capabilities (TLS-6 ⇒ CapHTTPPolicy). This is the single function the
// offline half asserts against and the live half cross-checks its real-world
// observation against, so both halves agree on the spec.
func EvalOffline(p *Pack, c Case, present map[Capability]bool) Verdict {
	// The structural audit row and the canary row are not single-entry
	// reachability lookups; the canary's frozen-pack expectation is simply
	// "matches nothing" (the live half proves the two-layer DNS-3/TLS-1
	// refusal). Treat an absent/non-pack FQDN as the refusal verdict.
	if c.FQDN == "" {
		return c.Want // structural audit — only the live half can observe it
	}
	e, ok := p.Lookup(c.FQDN)
	if !ok {
		// Non-pack (canary) domain: matches nothing ⇒ refused at both layers.
		return VerdictRefusedDNS3TLS1
	}
	if e.Passthrough {
		// Opaque pass-through tunnel — not part of the baseline (list is empty).
		return VerdictDisabledTier
	}
	if e.DomainInert(present) {
		return VerdictInertCapGate
	}
	if p.TierOf(e.Family) != TierEnabled {
		return VerdictDisabledTier
	}
	return VerdictReachable
}
