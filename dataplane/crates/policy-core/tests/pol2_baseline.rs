//! Integration test: the SHIPPED POL-2 system default baseline policy pack
//! (D64 / D74 v2) over the REAL `dataplane/artifacts/policy-packs/` directory
//! (doc 09 §6 POL-2, doc 13 §3).
//!
//! This is the reachability half of the doc 09 §1 developer-value test, proven
//! against the pack file the open data plane actually ships — loaded from the
//! CARGO_MANIFEST_DIR-relative artifacts path, parsed by the `ds-contracts`
//! stdlib reader with ZERO PolicyErrors, composed by `policy-core`, and queried
//! through the PUBLIC `policy-core` consumer surface
//! ([`policy_core::consumer::dns_admission_decision`], the ds-dnsgate embedding
//! path). No consumer reimplements a rule (POL-3): every admit/deny verdict here
//! comes out of the ONE shared evaluator the three boundary consumers embed.
//!
//! It proves the POL-2 done-when (doc 09 §6): "every endpoint the §1 test touches
//! is admitted by the shipped pack and nothing else is."
//!
//!   (a) every D74 enabled-family endpoint (core / vcs / packages) is admitted;
//!   (b) disabled-family endpoints (telemetry / binary-cdn / ghcr / lfs) and an
//!       arbitrary unlisted domain are NOT admitted;
//!   (c) the D17 pass-through list ships EMPTY;
//!   (d) the known public DoH/DoT resolver domains are DENIED via the blocklist
//!       (blocklists always win, deny-overrides);
//!   (e) negative test: a baseline-pack entry stripped of its mandatory
//!       provenance is REJECTED by the parse-time validators (D74, rule 4).

use ds_contracts::pol1::{parse_layer, PolicyErrorCode, PolicyLayer};
use policy_core::consumer::dns_admission_decision;
use policy_core::pol1_eval::{compose, ComposedPolicy};
use std::path::PathBuf;

/// The repo-relative path from this crate to the SHIPPED baseline pack file.
fn shipped_pack_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../dataplane/crates/policy-core
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // dataplane
    p.push("artifacts");
    p.push("policy-packs");
    p.push("pol2-system-baseline.pol1.yaml");
    p
}

/// Read + parse the shipped pack with ZERO PolicyErrors (the §6 "parses clean"
/// bar). A non-empty error bundle here fails CI exactly as a malformed pack must.
fn parse_shipped_pack() -> PolicyLayer {
    let path = shipped_pack_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading shipped pack {}: {e}", path.display()));
    parse_layer(&text).unwrap_or_else(|errs| {
        panic!("the SHIPPED POL-2 baseline pack must parse with zero PolicyErrors, got:\n{errs}")
    })
}

/// Compose the shipped baseline into the host's one composed document. No
/// capabilities are present (TLS-6 absent), so the `requires: http-policy`
/// entries (storage.googleapis.com) are INERT — exactly the fresh-install state
/// the reachability half of the §1 test runs in.
fn composed_fresh_install() -> ComposedPolicy {
    let baseline = parse_shipped_pack();
    compose(&[baseline], &[])
}

/// Admission through the PUBLIC consumer surface ds-dnsgate embeds (POL-3).
fn admits(policy: &ComposedPolicy, qname: &str) -> bool {
    dns_admission_decision(policy, qname).admits()
}

/// Whether the consumer surface DENIES the flow (a policy block — distinct from
/// the inert admit-nothing state of a capability-gated entry).
fn denies(policy: &ComposedPolicy, qname: &str) -> bool {
    dns_admission_decision(policy, qname).denies()
}

// ── (a) every D74 enabled-family endpoint is admitted ────────────────────────

#[test]
fn enabled_family_endpoints_are_admitted_on_a_fresh_install() {
    let policy = composed_fresh_install();

    // The doc 09 §1 developer-value reachability set, family by family (D74 v2).
    let core = ["api.anthropic.com", "claude.ai", "platform.claude.com"];
    let vcs = [
        "github.com",
        "api.github.com",
        "codeload.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
        "github-registry-files.githubusercontent.com",
    ];
    let packages = ["registry.npmjs.org", "registry.yarnpkg.com", "nodejs.org"];

    for fqdn in core.iter().chain(vcs.iter()).chain(packages.iter()) {
        let decision = dns_admission_decision(&policy, fqdn);
        assert!(
            decision.admits(),
            "enabled-family endpoint {fqdn:?} must be admitted on a fresh install, \
             got {decision:?}"
        );
        // POL-3: every decision carries provenance naming the matched entry.
        assert!(
            decision.provenance.rule_id.contains(fqdn),
            "admission provenance must name {fqdn:?}, got {:?}",
            decision.provenance
        );
    }
}

#[test]
fn downloads_claude_ai_is_excluded_from_the_session_pack() {
    // D74: downloads.claude.ai is EXCLUDED from the session pack (it joins the
    // image-build-time allowlist; the CC pin is the coupled invariant). On a
    // fresh install the session pack must NOT admit it.
    let policy = composed_fresh_install();
    assert!(
        !admits(&policy, "downloads.claude.ai"),
        "downloads.claude.ai is excluded from the session pack (D74) — must not admit"
    );
}

// ── (b) disabled families + an unlisted domain are NOT admitted ──────────────

#[test]
fn disabled_family_endpoints_and_unlisted_domains_are_not_admitted() {
    let policy = composed_fresh_install();

    // Disabled-by-default families: the tier is off, so the entry denies.
    let disabled = [
        "sentry.io",          // telemetry
        "cdn.playwright.dev", // binary-cdn
        "playwright.download.prss.microsoft.com",
        "googlechromelabs.github.io",
        "download.cypress.io",
        "ghcr.io", // ghcr
        "pkg-containers.githubusercontent.com",
        "github-cloud.githubusercontent.com", // lfs
        "github-cloud.s3.amazonaws.com",
    ];
    for fqdn in disabled {
        assert!(
            !admits(&policy, fqdn),
            "disabled-family endpoint {fqdn:?} must NOT be admitted on a fresh install"
        );
        assert!(
            denies(&policy, fqdn),
            "disabled-family endpoint {fqdn:?} denies (the tier is off), got {:?}",
            dns_admission_decision(&policy, fqdn)
        );
    }

    // The path-scoped storage.googleapis.com entry is `requires: http-policy`:
    // INERT until TLS-6 (admits NOTHING, NOT a deny). It must not admit, and the
    // composition must have warned about the inert gate (§1.7 / D74).
    assert!(
        !admits(&policy, "storage.googleapis.com"),
        "the capability-gated storage.googleapis.com entry admits NOTHING pre-TLS-6"
    );
    assert!(
        policy.warnings.iter().any(|w| {
            w.code == "capability-gate-inert" && w.subject == "storage.googleapis.com"
        }),
        "composition must warn on the inert capability-gated entry, got {:?}",
        policy.warnings
    );

    // An arbitrary unlisted domain reaches nothing (the "and nothing else"
    // half of the §1 test): not admitted.
    for fqdn in [
        "evil.example.com",
        "totally-unlisted.invalid",
        "pypi.org", // a real registry NOT in the v0 packages family
    ] {
        assert!(
            !admits(&policy, fqdn),
            "an unlisted domain {fqdn:?} must reach nothing on a fresh install"
        );
    }
}

// ── (c) the D17 pass-through list ships EMPTY ────────────────────────────────

#[test]
fn passthrough_list_ships_empty() {
    let baseline = parse_shipped_pack();
    assert!(
        baseline.passthrough.is_empty(),
        "the D17/D74 pass-through list must ship EMPTY (an entry requires reproduced \
         pinning-failure evidence), got {:?}",
        baseline.passthrough
    );
}

// ── (d) the known public DoH/DoT resolver domains are DENIED ─────────────────

#[test]
fn known_public_doh_resolvers_are_blocklisted_and_denied() {
    let policy = composed_fresh_install();

    // The resolver-lock: a VM must not resolve names out of band. Blocklists
    // always win (deny-overrides), so these deny through the consumer surface
    // even though they are not pack entries.
    let resolvers = [
        "dns.google",
        "cloudflare-dns.com",
        "dns.quad9.net",
        "one.one.one.one",
        "dns.nextdns.io",
    ];
    // The acceptance bar is "at least 3"; assert all the named ones to be safe.
    assert!(resolvers.len() >= 3);
    for fqdn in resolvers {
        let decision = dns_admission_decision(&policy, fqdn);
        assert!(
            decision.denies(),
            "known public DoH/DoT resolver {fqdn:?} must be DENIED via the blocklist, \
             got {decision:?}"
        );
        assert!(
            !decision.admits(),
            "DoH/DoT resolver {fqdn:?} must never admit"
        );
        // A block+log rung is block-or-higher → severs established flows on
        // revocation (§5): the fleet DoH block has teeth.
        assert!(
            decision.severs_established_flows(),
            "the DoH/DoT block must sever established flows on revocation (§5), got {decision:?}"
        );
        assert!(decision.provenance.rule_id.contains(fqdn));
    }
}

// ── (e) negative: a provenance-stripped entry is REJECTED by the validators ──

#[test]
fn entry_missing_provenance_is_rejected_by_the_validators() {
    // A baseline-pack entry without `provenance_source_url` + `evidence` must be
    // rejected at parse time (D74, rule 4: CI rejects entries without provenance).
    // This is the negative twin of the shipped pack parsing clean — it proves the
    // mandatory-provenance gate has teeth, against an in-test fixture.
    let stripped = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
baseline_pack:
  pack_version: "test-missing-provenance"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: api.anthropic.com
      family: core
      ports: [443]
"#;
    let errs = parse_layer(stripped)
        .expect_err("a baseline-pack entry missing provenance must be REJECTED (D74)");
    assert!(
        errs.has(PolicyErrorCode::MissingProvenance),
        "the rejection must be a MissingProvenance error, got:\n{errs}"
    );

    // Control: the SAME entry WITH provenance + evidence parses clean — so the
    // rejection above is the provenance gate firing, not an unrelated shape error.
    let with_provenance = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
baseline_pack:
  pack_version: "test-with-provenance"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: api.anthropic.com
      family: core
      ports: [443]
      provenance_source_url: https://code.claude.com/docs/en/network-config
      evidence: vendor-doc
"#;
    parse_layer(with_provenance)
        .expect("the same entry WITH provenance + evidence must parse clean");
}
