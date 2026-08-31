//! POL-1 evaluator tests — the §7 done-when's compose→evaluate half (doc 13 §7):
//! a layered system→org→session composition round-trips parse→evaluate; deny-
//! overrides covered; capability-gate inertness admits nothing (§7 inertness
//! done-when). The parse-time rejections (rung-cap, fail-open, bare-CIDR,
//! provenance) live in `ds-contracts::pol1`'s tests (the schema side).

use super::*;
use ds_contracts::pol1::parse_layer;

// ── Layer documents for the system→org→session composition round-trip ─────────

fn system_baseline() -> &'static str {
    r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
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
    // Org adds an allowlist entry and a blocklist entry (org tightening).
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
    // Session layer BLOCKS a domain the baseline ALLOWED — deny-overrides: the
    // session block must win even though the baseline allowlisted it.
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

// ── §7: sample policy round-trips parse→evaluate; deny-overrides covered ──────

#[test]
fn layered_composition_round_trips_parse_then_evaluate() {
    // Parse three layers, compose system→org→session, evaluate domains.
    let layers = [
        parse(system_baseline()),
        parse(org_layer()),
        parse(session_layer_denies_anthropic()),
    ];
    // No capabilities present yet (TLS-6 absent), so the http-policy gate is inert.
    let composed = compose(&layers, &[]);

    // Most-specific layer's posture wins (session = locked).
    assert_eq!(composed.posture, Posture::Locked);

    // A baseline allow (github via the enabled `core` family) is admitted.
    let gh = evaluate_domain(&composed, "github.com");
    assert!(gh.admits(), "github (core/enabled) admits, got {gh:?}");
    assert!(gh.provenance().rule_id.contains("github.com"));

    // The npmjs.org allowlist entry (org layer) is admitted, provenance = org.
    let npm = evaluate_domain(&composed, "registry.npmjs.org");
    assert!(npm.admits(), "npmjs allowlisted at org, got {npm:?}");
    assert_eq!(npm.provenance().policy_layer, "org");

    // A domain in a DISABLED tier denies.
    let cdn = evaluate_domain(&composed, "cdn.disabled.example");
    assert!(!cdn.admits(), "disabled-tier entry denies, got {cdn:?}");
    assert!(matches!(cdn, Eval::Deny { .. }));

    // Unknown domain → ask.
    let unknown = evaluate_domain(&composed, "random.unknown.example");
    assert!(matches!(unknown, Eval::Ask(_)), "got {unknown:?}");
}

#[test]
fn deny_overrides_session_block_beats_baseline_allow() {
    // The crux of §1.2 deny-overrides: api.anthropic.com is ALLOWLISTED at the
    // system baseline but BLOCKED at the session layer — the block must win.
    let layers = [
        parse(system_baseline()),
        parse(org_layer()),
        parse(session_layer_denies_anthropic()),
    ];
    let composed = compose(&layers, &[]);

    let v = evaluate_domain(&composed, "api.anthropic.com");
    assert!(
        !v.admits(),
        "deny-overrides: a later-layer block must beat a baseline allow, got {v:?}"
    );
    match v {
        Eval::Deny { rung, provenance } => {
            // The session block pins kill+snapshot, and it is block-or-higher
            // (severs established flows on revocation, §5).
            assert_eq!(rung, Some(Rung::KillSnapshot));
            assert!(rung.unwrap().is_block_or_higher());
            assert!(provenance.rule_id.contains("api.anthropic.com"));
        }
        other => panic!("expected Deny from the session block, got {other:?}"),
    }
}

#[test]
fn blocklists_are_unioned_across_layers_deny_is_monotone() {
    // Every layer's deny is present in the composed document (§8.2: deny is
    // monotone — no layer removes a block).
    let layers = [parse(system_baseline()), parse(org_layer())];
    let composed = compose(&layers, &[]);

    // baseline block.
    assert!(matches!(
        evaluate_domain(&composed, "dns.google"),
        Eval::Deny { .. }
    ));
    // org block.
    assert!(matches!(
        evaluate_domain(&composed, "tracker.example"),
        Eval::Deny { .. }
    ));
    // both present in the composed blocklist map.
    assert!(composed.blocklist.contains_key("dns.google"));
    assert!(composed.blocklist.contains_key("tracker.example"));
}

// ── §7 capability-gate inertness: admits nothing + logged warning (§1.7/D74) ──

#[test]
fn capability_gate_inert_admits_nothing_and_warns_when_capability_absent() {
    let layers = [parse(system_baseline())];
    // http-policy NOT present → the storage.googleapis.com entry is inert.
    let composed = compose(&layers, &[]);

    // The composition emitted a logged warning naming the gated entry (§1.7).
    assert!(
        composed
            .warnings
            .iter()
            .any(|w| w.code == "capability-gate-inert" && w.subject == "storage.googleapis.com"),
        "composition must warn on the inert entry: {:?}",
        composed.warnings
    );

    // Evaluation admits NOTHING for the gated entry — not a deny, not a silent
    // skip, but the observable INERT state (§7 capability-gate done-when).
    let v = evaluate_domain(&composed, "storage.googleapis.com");
    assert!(
        !v.admits(),
        "an inert capability-gated entry admits nothing"
    );
    match v {
        Eval::InertCapabilityGated { requires, .. } => {
            assert_eq!(requires, "http-policy");
        }
        other => panic!("expected InertCapabilityGated, got {other:?}"),
    }
}

#[test]
fn capability_gate_activates_when_capability_present_no_schema_change() {
    // When the capability lands the SAME entry activates with no schema change
    // (§2 D74 row: parse now, enforce at capability). With http-policy present
    // and its family enabled, the entry would admit — here binary-cdn is
    // disabled, so it denies (a tier deny), but crucially it is NO LONGER inert.
    let layers = [parse(system_baseline())];
    let composed = compose(&layers, &["http-policy"]);

    // No inertness warning this time.
    assert!(
        !composed
            .warnings
            .iter()
            .any(|w| w.subject == "storage.googleapis.com"),
        "capability present → no inertness warning: {:?}",
        composed.warnings
    );

    let v = evaluate_domain(&composed, "storage.googleapis.com");
    // It is no longer InertCapabilityGated — the gate is satisfied. (Family is
    // disabled, so the verdict is a tier Deny, not an inert admit-nothing.)
    assert!(
        !matches!(v, Eval::InertCapabilityGated { .. }),
        "capability present → entry is not inert, got {v:?}"
    );
}

// ── Provenance is carried on every verdict (POL-3) ────────────────────────────

#[test]
fn every_verdict_carries_pol3_provenance() {
    let layers = [
        parse(system_baseline()),
        parse(session_layer_denies_anthropic()),
    ];
    let composed = compose(&layers, &[]);

    for domain in [
        "github.com",
        "api.anthropic.com",
        "unknown.example",
        "storage.googleapis.com",
    ] {
        let v = evaluate_domain(&composed, domain);
        let p = v.provenance();
        assert!(!p.rule_id.is_empty(), "rule_id present for {domain}: {v:?}");
        assert!(
            !p.policy_version.is_empty(),
            "policy_version present for {domain}: {v:?}"
        );
    }
}

// ── A full §3-shaped sample per posture round-trips (parse→compose→evaluate) ──

#[test]
fn sample_per_posture_round_trips() {
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
        // Posture survives the round-trip.
        let expected = match posture_tok {
            "locked" => Posture::Locked,
            "standard" => Posture::Standard,
            _ => Posture::Open,
        };
        assert_eq!(composed.posture, expected);
        // Allow and deny both evaluate correctly.
        assert!(evaluate_domain(&composed, "example.allowed").admits());
        assert!(!evaluate_domain(&composed, "example.blocked").admits());
    }
}

// ── §3 services[]: the credential-swap registry folds into the composed document ──
// `compose` folds every layer's `services[]` (doc 13 §3) into `ComposedPolicy.services`,
// most-specific-layer-wins per `service` id, in deterministic id-sorted order — the
// live registry the ds-tlsproxy TLS-5 SwapRegistry is built off (D8/D83, doc 12 §13.3).

fn baseline_with_services() -> &'static str {
    r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
services:
  - service: github
    hosts: [github.com, api.github.com]
    credential: { location: header, name: Authorization }
  - service: anthropic
    hosts: [api.anthropic.com]
    credential: { location: header, name: Authorization }
"#
}

fn session_overrides_github_service() -> &'static str {
    // The session layer supplies a NARROWER github row (a single host) for the SAME
    // `service` id — most-specific-layer-wins must replace the baseline github row.
    r#"
schema_version: pol1/v0
layer: session
posture: standard
services:
  - service: github
    hosts: [github.com]
    credential: { location: header, name: Authorization }
"#
}

#[test]
fn compose_folds_services_into_the_composed_document_sorted_by_id() {
    let layers = [parse(baseline_with_services())];
    let composed = compose(&layers, &[]);

    // Both service rows are present, in deterministic `service`-id-sorted order
    // (anthropic < github).
    let ids: Vec<&str> = composed
        .services
        .iter()
        .map(|s| s.service.as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["anthropic", "github"],
        "services fold into the composed document id-sorted, got {ids:?}"
    );

    let gh = composed
        .services
        .iter()
        .find(|s| s.service == "github")
        .expect("github service composed");
    assert_eq!(gh.hosts, vec!["github.com", "api.github.com"]);
    assert_eq!(gh.credential_location, "header");
    assert_eq!(gh.credential_name, "Authorization");
}

#[test]
fn compose_services_most_specific_layer_wins_per_service_id() {
    // The session layer's narrower github row replaces the baseline's for the same id;
    // the baseline-only anthropic row survives.
    let layers = [
        parse(baseline_with_services()),
        parse(session_overrides_github_service()),
    ];
    let composed = compose(&layers, &[]);

    assert_eq!(
        composed.services.len(),
        2,
        "one row per service id (github deduped), got {:?}",
        composed.services
    );
    let gh = composed
        .services
        .iter()
        .find(|s| s.service == "github")
        .expect("github service composed");
    assert_eq!(
        gh.hosts,
        vec!["github.com"],
        "the session (most-specific) github row wins over the baseline"
    );
    assert!(
        composed.services.iter().any(|s| s.service == "anthropic"),
        "the baseline-only anthropic service survives composition"
    );
}

#[test]
fn compose_no_services_yields_empty_registry() {
    // A layer stack that carries no `services[]` composes to an empty registry — the
    // default-deny-of-swap posture the proxy then falls back to its operator pack for.
    let layers = [parse(system_baseline())];
    let composed = compose(&layers, &[]);
    assert!(
        composed.services.is_empty(),
        "no services[] in the stack → empty composed registry, got {:?}",
        composed.services
    );
}
