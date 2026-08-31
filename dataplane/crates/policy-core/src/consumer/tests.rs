//! Consumer-surface tests (doc 13 §7 first row, extended to the full consumer
//! API): a sample policy per posture plus a layered system→org→session
//! composition round-trips parse→evaluate through ALL THREE consumer query
//! surfaces (DNS admission, TLS/egress connect, NFT ruleset inputs), with
//! deny-overrides covered and POL-3 provenance asserted on every decision.
//!
//! These BUILD ON the [`crate::pol1_eval`] engine — they re-use its `compose`
//! and `evaluate_domain`; they never re-derive composition. The engine's own
//! tests (deny-overrides, capability-gate inertness, posture round-trips) stay
//! the source of truth for the engine; these assert the consumer skin agrees
//! with it on all three surfaces.

use super::*;
use crate::pol1_eval::compose;
use ds_contracts::pol1::{parse_layer, PolicyLayer, Posture};

// ── Layer documents (a layered system→org→session composition) ────────────────

fn system_baseline() -> &'static str {
    r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 30
  ttl_ceil: 600
  grace: 45
  max_ips_per_domain: 256
dns:
  negative_ttl: 7
allowlist:
  - domain: api.anthropic.com
blocklist:
  - domain: dns.google
    reason: doh-resolver
    rung: block+log
baseline_pack:
  pack_version: "2026.06.11-v2"
  families:
    core: { tier: enabled }
    binary-cdn: { tier: disabled }
  entries:
    - fqdn: github.com
      family: core
      ports: [443]
      provenance_source_url: https://api.github.com/meta
      evidence: vendor-doc
    - fqdn: cdn.disabled.example
      family: binary-cdn
      ports: [443]
      provenance_source_url: https://example.invalid/x
      evidence: vendor-doc
    - fqdn: storage.googleapis.com
      family: binary-cdn
      ports: [443]
      path_scope: ["/chrome-for-testing-public/*"]
      requires: http-policy
      provenance_source_url: https://example.invalid/chrome.ts
      evidence: vendor-doc
"#
}

fn org_layer() -> &'static str {
    r#"
schema_version: pol1/v0
layer: org
posture: standard
allowlist:
  - domain: registry.npmjs.org
blocklist:
  - domain: tracker.example
    reason: org-block
    rung: block+log
"#
}

fn session_layer_denies_anthropic() -> &'static str {
    // Session BLOCKS a domain the baseline ALLOWED, at a severing rung.
    r#"
schema_version: pol1/v0
layer: session
posture: locked
blocklist:
  - domain: api.anthropic.com
    reason: session-quarantine
    rung: kill+snapshot
"#
}

fn parse(text: &str) -> PolicyLayer {
    parse_layer(text).expect("layer parses clean")
}

fn full_stack() -> ComposedPolicy {
    let layers = [
        parse(system_baseline()),
        parse(org_layer()),
        parse(session_layer_denies_anthropic()),
    ];
    // No capabilities present (TLS-6 absent) → http-policy gate inert.
    compose(&layers, &[])
}

// ── Every decision carries POL-3 provenance (rule 4), on every surface ────────

fn assert_provenance(d: &Decision, ctx: &str) {
    assert!(
        !d.provenance.rule_id.is_empty(),
        "rule_id present ({ctx}): {d:?}"
    );
    assert!(
        !d.provenance.policy_layer.is_empty(),
        "policy_layer present ({ctx}): {d:?}"
    );
    assert!(
        !d.provenance.policy_version.is_empty(),
        "policy_version present ({ctx}): {d:?}"
    );
}

#[test]
fn dns_admission_surface_round_trips_with_provenance() {
    let composed = full_stack();

    // A baseline allow (github via the enabled core family) is admitted.
    let gh = dns_admission_decision(&composed, "github.com");
    assert!(gh.admits(), "github admits: {gh:?}");
    assert_provenance(&gh, "github");
    assert!(gh.provenance.rule_id.contains("github.com"));

    // The org allowlist entry is admitted, provenance layer = org.
    let npm = dns_admission_decision(&composed, "registry.npmjs.org");
    assert!(npm.admits(), "npmjs admits: {npm:?}");
    assert_eq!(npm.provenance.policy_layer, "org");
    assert_provenance(&npm, "npmjs");

    // A disabled-tier entry denies.
    let cdn = dns_admission_decision(&composed, "cdn.disabled.example");
    assert!(cdn.denies(), "disabled-tier denies: {cdn:?}");
    assert_provenance(&cdn, "cdn");

    // Unknown domain → ask.
    let unknown = dns_admission_decision(&composed, "random.unknown.example");
    assert!(matches!(unknown.kind, DecisionKind::Ask), "{unknown:?}");
    assert_provenance(&unknown, "unknown");
}

#[test]
fn tls_connect_surface_round_trips_with_provenance() {
    let composed = full_stack();

    let gh = tls_connect_decision(&composed, "github.com");
    assert!(gh.admits(), "github connect admits: {gh:?}");
    assert_provenance(&gh, "tls github");

    let unknown = tls_connect_decision(&composed, "random.unknown.example");
    assert!(matches!(unknown.kind, DecisionKind::Ask), "{unknown:?}");
    assert_provenance(&unknown, "tls unknown");
}

#[test]
fn dns_and_tls_surfaces_agree_no_consumer_reimplements_a_rule() {
    // POL-3: the two surfaces are the SAME engine verdict. For every probe the
    // DNS admission and the TLS connect decision must be byte-identical.
    let composed = full_stack();
    for domain in [
        "github.com",
        "registry.npmjs.org",
        "api.anthropic.com",
        "cdn.disabled.example",
        "storage.googleapis.com",
        "random.unknown.example",
    ] {
        let dns = dns_admission_decision(&composed, domain);
        let tls = tls_connect_decision(&composed, domain);
        assert_eq!(dns, tls, "DNS and TLS surfaces must agree for {domain}");
    }
}

// ── Deny-overrides covered through the consumer surface (rule 2 / §1.2) ───────

#[test]
fn deny_overrides_session_block_beats_baseline_allow_via_consumer_api() {
    let composed = full_stack();

    // api.anthropic.com is allowlisted at baseline, blocked at session — the
    // block must win, on the consumer surface, carrying the session rung.
    let dns = dns_admission_decision(&composed, "api.anthropic.com");
    assert!(dns.denies(), "deny-overrides via consumer API: {dns:?}");
    assert_eq!(dns.rung, Some(Rung::KillSnapshot));
    assert!(dns.provenance.rule_id.contains("api.anthropic.com"));
    assert_provenance(&dns, "deny-overrides");

    // The TLS surface reaches the same deny (no reimplemented rule).
    let tls = tls_connect_decision(&composed, "api.anthropic.com");
    assert_eq!(dns, tls);
}

// ── D53 rung + severing predicate (rule 6) ────────────────────────────────────

#[test]
fn severing_predicate_keeps_is_block_or_higher_name_stable() {
    let composed = full_stack();

    // kill+snapshot is block-or-higher → severs established flows (§5).
    let kill = dns_admission_decision(&composed, "api.anthropic.com");
    assert!(
        kill.severs_established_flows(),
        "kill+snapshot severs: {kill:?}"
    );
    assert!(kill.is_revocation_severing());

    // block+log is the first severing rung.
    let blk = dns_admission_decision(&composed, "dns.google");
    assert!(blk.denies());
    assert!(blk.severs_established_flows(), "block+log severs: {blk:?}");
    assert!(blk.is_revocation_severing());

    // A disabled-tier deny has no explicit rung → it gates new flows only,
    // it does NOT sever an established flow.
    let cdn = dns_admission_decision(&composed, "cdn.disabled.example");
    assert!(cdn.denies());
    assert!(
        !cdn.severs_established_flows(),
        "a rung-less tier deny does not sever: {cdn:?}"
    );
    assert!(!cdn.is_revocation_severing());
}

// ── Expiry is not revocation (rule 8) ─────────────────────────────────────────

#[test]
fn expiry_severs_nothing() {
    // Rule 8 / D68: only an explicit block-or-higher deny severs. An ADMIT
    // decision (a live admission that would lapse on its TTL) is not a severing
    // revocation — `is_revocation_severing` is false for it. Expiry re-admits
    // through full DNS-2 admission; it never produces a severing decision.
    let composed = full_stack();
    let admit = dns_admission_decision(&composed, "github.com");
    assert!(admit.admits());
    assert!(
        !admit.is_revocation_severing(),
        "an admitted (TTL-lapsing) flow is not a severing revocation: {admit:?}"
    );
    // Even an Ask is not a severing revocation.
    let ask = dns_admission_decision(&composed, "random.unknown.example");
    assert!(!ask.is_revocation_severing());
}

// ── Capability gating stays inert+warn through the consumer surface (rule 7) ──

#[test]
fn inert_capability_gated_admits_nothing_and_is_distinct_from_deny() {
    let composed = full_stack(); // http-policy absent → storage entry inert.

    let v = dns_admission_decision(&composed, "storage.googleapis.com");
    assert!(!v.admits(), "inert entry admits nothing (§1.7): {v:?}");
    assert!(
        !v.denies(),
        "inert is DISTINCT from a policy deny (§1.7): {v:?}"
    );
    match &v.kind {
        DecisionKind::InertCapabilityGated { requires } => {
            assert_eq!(requires, "http-policy");
        }
        other => panic!("expected InertCapabilityGated, got {other:?}"),
    }
    assert_provenance(&v, "inert");
    // It is not a severing revocation (no rung, not a deny).
    assert!(!v.is_revocation_severing());

    // The composition warned on it (rule 7 logged warning) — engine-owned, but
    // observable here too.
    assert!(composed
        .warnings
        .iter()
        .any(|w| w.subject == "storage.googleapis.com"));
}

// ── Surface 3: NFT ruleset-derivation inputs ──────────────────────────────────

#[test]
fn nft_ruleset_inputs_derive_allow_and_deny_sets_off_composed_doc() {
    let composed = full_stack();
    let inputs = nft_ruleset_inputs(&composed);

    // Allow set: the admitted domains — github (enabled core) and the two
    // allowlist entries (npmjs from org). api.anthropic.com is allowlisted at
    // baseline but session-blocked, so it must NOT appear in the allow set.
    assert!(inputs.allow_domains.contains(&"github.com".to_string()));
    assert!(inputs
        .allow_domains
        .contains(&"registry.npmjs.org".to_string()));
    assert!(
        !inputs
            .allow_domains
            .contains(&"api.anthropic.com".to_string()),
        "deny-overrides: a session-blocked domain is not in the NFT allow set"
    );
    // The disabled-tier and inert entries are excluded from the allow set.
    assert!(!inputs
        .allow_domains
        .contains(&"cdn.disabled.example".to_string()));
    assert!(
        !inputs
            .allow_domains
            .contains(&"storage.googleapis.com".to_string()),
        "an inert capability-gated entry is not in the NFT allow set (rule 7)"
    );

    // Allow set is sorted + deduped (deterministic derivation).
    let mut sorted = inputs.allow_domains.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(inputs.allow_domains, sorted);

    // Deny set: every layer's block is present (deny is monotone, §8.2), each
    // with its severing flag.
    let deny_domains: Vec<&str> = inputs
        .deny_inputs
        .iter()
        .map(|d| d.domain.as_str())
        .collect();
    assert!(deny_domains.contains(&"dns.google")); // baseline
    assert!(deny_domains.contains(&"tracker.example")); // org
    assert!(deny_domains.contains(&"api.anthropic.com")); // session

    // The kill+snapshot session block severs; a block+log block severs.
    let anthropic = inputs
        .deny_inputs
        .iter()
        .find(|d| d.domain == "api.anthropic.com")
        .unwrap();
    assert_eq!(anthropic.rung, Some(Rung::KillSnapshot));
    assert!(anthropic.severs);

    // Deny inputs sorted by domain (deterministic derivation).
    let mut sorted_deny = inputs.deny_inputs.clone();
    sorted_deny.sort_by(|a, b| a.domain.cmp(&b.domain));
    assert_eq!(inputs.deny_inputs, sorted_deny);

    // The single policy version is stamped (rule 3).
    assert_eq!(inputs.policy_version.as_str(), "pol1/v0");
}

#[test]
fn nft_allow_set_agrees_with_dns_admission_by_construction() {
    // POL-3: a domain is in the NFT allow set IFF the DNS admission surface
    // admits it. This is the no-skew property — the NFT path never admits what
    // DNS would refuse.
    let composed = full_stack();
    let inputs = nft_ruleset_inputs(&composed);
    for domain in [
        "github.com",
        "registry.npmjs.org",
        "api.anthropic.com",
        "cdn.disabled.example",
        "storage.googleapis.com",
    ] {
        let in_allow = inputs.allow_domains.iter().any(|d| d == domain);
        let admits = dns_admission_decision(&composed, domain).admits();
        assert_eq!(
            in_allow, admits,
            "NFT allow-set membership must equal DNS admission for {domain}"
        );
    }
}

// ── Single version namespace (rule 3) ─────────────────────────────────────────

#[test]
fn host_snapshot_carries_one_policy_version_pack_is_content_id_only() {
    let composed = full_stack();

    // The host snapshot carries ONE version off the composed document (rule 2/3).
    let ver = host_snapshot_policy_version(&composed);
    assert_eq!(ver.as_str(), "pol1/v0");

    // The pack content id is a CONTENT identifier, never compared as a version.
    // It is a distinct type (ContentId vs PolicyVersion) so the two cannot be
    // confused at a call site — this is a compile-time guarantee; here we just
    // confirm it is produced and carries the content string.
    let cid = baseline_pack_content_id(&composed);
    assert!(cid.is_some(), "a pack with entries surfaces a content id");
    assert_eq!(cid.unwrap().as_str(), "pol1/v0");
}

// ── Tunables are policy values, not code constants (rule 5) ───────────────────

#[test]
fn tunables_are_read_from_the_policy_document() {
    // The baseline layer sets non-default tunables; they must come through as
    // POLICY VALUES (rule 5), not the §3 code-constant defaults.
    let layer = parse(system_baseline());
    let t = tunables(&layer);
    assert_eq!(t.ttl_floor, 30);
    assert_eq!(t.ttl_ceil, 600);
    assert_eq!(t.grace, 45);
    assert_eq!(t.negative_ttl, 7);
    assert_eq!(t.max_ips_per_domain, 256);
}

#[test]
fn tunables_default_when_the_document_omits_them() {
    // A layer that omits admission/dns falls back to the §3 schema defaults —
    // tests pin them (rule 5: "tests pin the defaults").
    let layer = parse(org_layer()); // org_layer omits admission/dns
    let t = tunables(&layer);
    assert_eq!(t.ttl_floor, ds_contracts::pol1::DEFAULT_TTL_FLOOR_SECS);
    assert_eq!(t.ttl_ceil, ds_contracts::pol1::DEFAULT_TTL_CEIL_SECS);
    assert_eq!(t.grace, ds_contracts::pol1::DEFAULT_GRACE_SECS);
    assert_eq!(
        t.negative_ttl,
        ds_contracts::pol1::DEFAULT_NEGATIVE_TTL_SECS
    );
    assert_eq!(
        t.max_ips_per_domain,
        ds_contracts::pol1::DEFAULT_MAX_IPS_PER_DOMAIN
    );
}

// ── §7 first row, extended: a sample policy PER POSTURE round-trips through the
//    full consumer API surface (not just the engine) ───────────────────────────

#[test]
fn sample_per_posture_round_trips_through_all_consumer_surfaces() {
    for posture_tok in ["locked", "standard", "open"] {
        let text = format!(
            r#"
schema_version: pol1/v0
layer: system-baseline
posture: {posture_tok}
allowlist:
  - domain: example.allowed
blocklist:
  - domain: example.blocked
    rung: block+log
"#
        );
        let layer = parse(&text);
        let composed = compose(std::slice::from_ref(&layer), &[]);

        let expected = match posture_tok {
            "locked" => Posture::Locked,
            "standard" => Posture::Standard,
            _ => Posture::Open,
        };
        assert_eq!(composed.posture, expected);

        // DNS admission surface: allow admits, block denies + severs (block+log).
        let allow = dns_admission_decision(&composed, "example.allowed");
        assert!(allow.admits());
        assert_provenance(&allow, "posture allow");
        let block = dns_admission_decision(&composed, "example.blocked");
        assert!(block.denies());
        assert!(block.severs_established_flows());
        assert_provenance(&block, "posture block");

        // TLS surface agrees.
        assert_eq!(allow, tls_connect_decision(&composed, "example.allowed"));
        assert_eq!(block, tls_connect_decision(&composed, "example.blocked"));

        // NFT inputs: allow set has the allowed domain, deny set has the blocked.
        let inputs = nft_ruleset_inputs(&composed);
        assert!(inputs
            .allow_domains
            .contains(&"example.allowed".to_string()));
        let denied = inputs
            .deny_inputs
            .iter()
            .find(|d| d.domain == "example.blocked")
            .expect("blocked domain in deny inputs");
        assert!(denied.severs);
    }
}
