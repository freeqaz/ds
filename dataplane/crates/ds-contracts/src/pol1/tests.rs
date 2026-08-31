//! POL-1 v0 schema tests — one named failing-input rejection test per §7 rule
//! plus posture round-trip parsing (doc 13 §7 schema-validation suite).
//!
//! The §7 suite (verbatim): a sample policy per posture round-trips parse; the
//! rung-cap, fail-open, bare-CIDR, and provenance rejections each fire on a named
//! failing input. The layered compose→evaluate round-trip and deny-overrides live
//! on the `policy-core` evaluator side (the consumer of these types).

use super::*;

// ── A clean, full-coverage sample document (the §3 strawman, trimmed) ─────────
//
// Exercises the full §2 field inventory the reader must accept: posture, timers
// incl. per_domain_overrides, dns, quic, baseline_pack (families+entries with
// provenance), blocklist with severing rungs, empty passthrough, escape_hatches,
// services, typed guardrails (incl. the gh-cred-swap-rate + vm-llm-token-quota
// §3 instances), two-plane content, ask defaults incl. attendedness, ipv6.

fn sample_standard() -> &'static str {
    r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard

admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
  per_domain_overrides:
    - domain: api.anthropic.com
      ttl_ceil: 3600

dns:
  negative_ttl: 5
  upstream_resolvers:
    - 1.1.1.1
    - 8.8.8.8

quic:
  reject_counter: true
  canary_latency_budget_ms: 250
  trigger_eval: weekly

baseline_pack:
  pack_version: "2026.06.11-v2"
  families:
    core: { tier: enabled }
    vcs: { tier: enabled }
    telemetry: { tier: disabled }
  entries:
    - fqdn: api.anthropic.com
      family: core
      ports: [443]
      provenance_source_url: https://code.claude.com/docs/en/network-config
      machine_source: null
      passthrough: false
      evidence: vendor-doc
    - fqdn: storage.googleapis.com
      family: binary-cdn
      ports: [443]
      path_scope: ["/chrome-for-testing-public/*"]
      requires: http-policy
      provenance_source_url: https://example.invalid/chrome.ts
      passthrough: false
      evidence: vendor-doc

blocklist:
  - domain: dns.google
    reason: doh-resolver
    rung: block+log
  - domain: cloudflare-dns.com
    reason: doh-resolver
    rung: block+log

passthrough: []

escape_hatches:
  catalog:
    - id: pg-staging
      protocol: postgres
      host: db.staging.example.internal
      port: 5432
      scope: org
      approval: allow-always

services:
  - service: github
    hosts: [github.com, api.github.com]
    credential: { location: header, name: Authorization }

guardrails:
  - id: gh-push-rate
    class: rate
    match: { service: github, method: POST }
    limit: { count: 30, per: 3600 }
    rung: suspend+ask
    ttl: null
  - id: gh-cred-swap-rate
    class: credential
    match: { service: github }
    limit: { count: 60, per: 3600 }
    rung: block+log
    ttl: null
  - id: vm-llm-token-quota
    class: quota
    match: { scope: vm }
    limit: { tokens: 1000000, window: session }
    rung: block+log
    ttl: null

content:
  generic:
    fail_open: false
    ruleset_version: "gitleaks-compat-2026.06"
    rules:
      - id: github-pat
        regex: "ghp_[0-9A-Za-z]{36}"
        keywords: [ghp_]
        secret_group: 0
        entropy: null
        rung: block+log
  keyed:
    forbidden_default_rung: suspend+ask
    issued_wrong_destination_rung: block+log

ask:
  unknown_domain: ask
  unattended_downgrade: block
  attendedness:
    activity_window_minutes: 10

ipv6:
  phase: b
  synthetic_a_pool: 198.18.0.0/15
"#
}

// ── Posture round-trip: a sample policy per posture parses (§7) ───────────────

fn minimal(posture: &str) -> String {
    format!(
        r#"
schema_version: pol1/v0
layer: system-baseline
posture: {posture}
"#
    )
}

#[test]
fn posture_round_trip_locked_standard_open() {
    let locked = parse_layer(&minimal("locked")).expect("locked parses");
    assert_eq!(locked.posture, Posture::Locked);
    let standard = parse_layer(&minimal("standard")).expect("standard parses");
    assert_eq!(standard.posture, Posture::Standard);
    let open = parse_layer(&minimal("open")).expect("open parses");
    assert_eq!(open.posture, Posture::Open);
}

#[test]
fn unknown_posture_is_rejected() {
    let errs = parse_layer(&minimal("paranoid")).expect_err("bad posture rejected");
    assert!(errs.has(PolicyErrorCode::BadPosture), "got {errs}");
}

#[test]
fn full_sample_parses_and_covers_the_field_inventory() {
    let layer = parse_layer(sample_standard()).expect("full sample parses clean");

    // Posture / layer / schema_version.
    assert_eq!(layer.schema_version, "pol1/v0");
    assert_eq!(layer.layer, Layer::SystemBaseline);
    assert_eq!(layer.posture, Posture::Standard);

    // Admission timers + per-domain override.
    assert_eq!(layer.admission.ttl_floor, 60);
    assert_eq!(layer.admission.ttl_ceil, 900);
    assert_eq!(layer.admission.grace, 60);
    assert_eq!(layer.admission.max_ips_per_domain, 1000);
    assert_eq!(layer.admission.per_domain_overrides.len(), 1);
    assert_eq!(
        layer.admission.per_domain_overrides[0].domain,
        "api.anthropic.com"
    );
    assert_eq!(layer.admission.per_domain_overrides[0].ttl_ceil, 3600);

    // DNS — negative_ttl + upstream resolvers parsed as addresses.
    assert_eq!(layer.dns.negative_ttl, 5);
    assert_eq!(layer.dns.upstream_resolvers.len(), 2);
    assert_eq!(layer.dns.upstream_resolvers[0].family, AddressFamily::V4);
    assert_eq!(layer.dns.upstream_resolvers[0].octets, vec![1, 1, 1, 1]);

    // QUIC counters.
    assert!(layer.quic.reject_counter);
    assert_eq!(layer.quic.canary_latency_budget_ms, 250);
    assert_eq!(layer.quic.trigger_eval, "weekly");

    // Baseline pack: families + entries with provenance; requires gate captured.
    assert_eq!(layer.baseline_pack.pack_version, "2026.06.11-v2");
    assert_eq!(
        layer.baseline_pack.families.get("core"),
        Some(&Tier::Enabled)
    );
    assert_eq!(
        layer.baseline_pack.families.get("telemetry"),
        Some(&Tier::Disabled)
    );
    assert_eq!(layer.baseline_pack.entries.len(), 2);
    let gated = layer
        .baseline_pack
        .entries
        .iter()
        .find(|e| e.fqdn == "storage.googleapis.com")
        .unwrap();
    assert_eq!(gated.requires.as_deref(), Some("http-policy"));
    assert_eq!(
        gated.path_scope,
        vec!["/chrome-for-testing-public/*".to_string()]
    );
    let anthropic = layer
        .baseline_pack
        .entries
        .iter()
        .find(|e| e.fqdn == "api.anthropic.com")
        .unwrap();
    assert_eq!(anthropic.machine_source, None); // null → None
    assert_eq!(anthropic.ports, vec![443]);

    // Blocklist with severing rungs.
    assert_eq!(layer.blocklist.len(), 2);
    assert_eq!(layer.blocklist[0].domain, "dns.google");
    assert_eq!(layer.blocklist[0].rung, Some(Rung::BlockLog));
    assert!(layer.blocklist[0].rung.unwrap().is_block_or_higher());

    // Empty passthrough.
    assert!(layer.passthrough.is_empty());

    // Escape hatch.
    assert_eq!(layer.escape_hatches.len(), 1);
    assert_eq!(layer.escape_hatches[0].id, "pg-staging");
    assert_eq!(layer.escape_hatches[0].protocol, "postgres");
    assert_eq!(layer.escape_hatches[0].host, "db.staging.example.internal");
    assert_eq!(layer.escape_hatches[0].port, 5432);

    // Services registry.
    assert_eq!(layer.services.len(), 1);
    assert_eq!(layer.services[0].service, "github");
    assert_eq!(
        layer.services[0].hosts,
        vec!["github.com", "api.github.com"]
    );
    assert_eq!(layer.services[0].credential_location, "header");
    assert_eq!(layer.services[0].credential_name, "Authorization");

    // Guardrails — incl. the §3 instances gh-cred-swap-rate and vm-llm-token-quota.
    assert_eq!(layer.guardrails.len(), 3);
    let cred = layer
        .guardrails
        .iter()
        .find(|g| g.id == "gh-cred-swap-rate")
        .unwrap();
    assert_eq!(cred.class, GuardrailClass::Credential);
    assert_eq!(cred.rung, Rung::BlockLog);
    assert_eq!(
        cred.match_.get("service").map(String::as_str),
        Some("github")
    );
    let quota = layer
        .guardrails
        .iter()
        .find(|g| g.id == "vm-llm-token-quota")
        .unwrap();
    assert_eq!(quota.class, GuardrailClass::Quota);
    assert_eq!(quota.rung, Rung::BlockLog);
    assert_eq!(
        quota.limit.get("tokens").map(String::as_str),
        Some("1000000")
    );
    assert_eq!(
        quota.limit.get("window").map(String::as_str),
        Some("session")
    );

    // Two-plane content: generic capped, keyed loaded.
    assert!(!layer.content.fail_open);
    assert_eq!(layer.content.generic_rules.len(), 1);
    assert_eq!(layer.content.generic_rules[0].id, "github-pat");
    assert_eq!(layer.content.generic_rules[0].rung, Rung::BlockLog);
    assert!(layer.content.keyed.is_some());
    assert_eq!(
        layer.content.keyed.as_ref().unwrap().forbidden_default_rung,
        Rung::SuspendAsk
    );

    // Ask defaults incl. attendedness window.
    assert_eq!(layer.ask.unknown_domain, "ask");
    assert_eq!(layer.ask.unattended_downgrade, "block");
    assert_eq!(layer.ask.attendedness.activity_window_minutes, 10);

    // IPv6 phasing.
    assert_eq!(layer.ipv6.phase, Ipv6Phase::B);
    assert_eq!(
        layer.ipv6.synthetic_a_pool.as_deref(),
        Some("198.18.0.0/15")
    );
}

// ── (a) Missing rung on a guardrail rule is rejected at parse (§7 (a), D53) ────

#[test]
fn rejection_missing_guardrail_rung() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
guardrails:
  - id: no-rung-rule
    class: rate
    match: { service: github }
    limit: { count: 30, per: 3600 }
    ttl: null
"#;
    let errs = parse_layer(text).expect_err("missing rung must reject");
    assert!(errs.has(PolicyErrorCode::MissingRung), "got {errs}");
    // The offending rule_id is named in the detail (§7 (a)).
    assert!(
        errs.0.iter().any(|e| e.detail.contains("no-rung-rule")),
        "rejection must name the offending rule_id: {errs}"
    );
}

// ── (b) Generic content rung cap — suspend+ask / kill+snapshot rejected ───────

#[test]
fn rejection_generic_rung_cap_suspend_ask() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
content:
  generic:
    fail_open: false
    rules:
      - id: over-rung-rule
        regex: "x"
        secret_group: 0
        rung: suspend+ask
"#;
    let errs = parse_layer(text).expect_err("generic suspend+ask must reject");
    assert!(errs.has(PolicyErrorCode::GenericRungCap), "got {errs}");
    // Names the offending (rule_id, declared_rung) (§8.1 rung-cap rejection).
    assert!(
        errs.0
            .iter()
            .any(|e| e.detail.contains("over-rung-rule") && e.detail.contains("suspend+ask")),
        "rung-cap rejection must name (rule_id, declared_rung): {errs}"
    );
}

#[test]
fn rejection_generic_rung_cap_kill_snapshot() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
content:
  generic:
    rules:
      - id: kill-rule
        regex: "x"
        secret_group: 0
        rung: kill+snapshot
"#;
    let errs = parse_layer(text).expect_err("generic kill+snapshot must reject");
    assert!(errs.has(PolicyErrorCode::GenericRungCap), "got {errs}");
    assert!(
        errs.0
            .iter()
            .any(|e| e.detail.contains("kill-rule") && e.detail.contains("kill+snapshot")),
        "got {errs}"
    );
}

// ── (c) fail_open legality (§7 (c), D73) ──────────────────────────────────────

#[test]
fn rejection_fail_open_with_non_allow_log_generic() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
content:
  generic:
    fail_open: true
    rules:
      - id: blocking-rule
        regex: "x"
        secret_group: 0
        rung: block+log
"#;
    let errs = parse_layer(text).expect_err("fail_open with a block+log generic rule must reject");
    assert!(errs.has(PolicyErrorCode::FailOpenIllegal), "got {errs}");
}

#[test]
fn rejection_fail_open_with_keyed_plane_loaded() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
content:
  generic:
    fail_open: true
    rules:
      - id: allow-only-rule
        regex: "x"
        secret_group: 0
        rung: allow+log
  keyed:
    forbidden_default_rung: suspend+ask
    issued_wrong_destination_rung: block+log
"#;
    let errs = parse_layer(text).expect_err("fail_open with keyed plane loaded must reject");
    assert!(errs.has(PolicyErrorCode::FailOpenIllegal), "got {errs}");
}

#[test]
fn fail_open_legal_only_for_allow_log_generic_no_keyed() {
    // The one legal fail_open shape: every generic rule allow+log AND no keyed.
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
content:
  generic:
    fail_open: true
    rules:
      - id: observe-only
        regex: "x"
        secret_group: 0
        rung: allow+log
"#;
    let layer = parse_layer(text).expect("legal fail_open shape parses");
    assert!(layer.content.fail_open);
}

// ── (d) Bare-CIDR / address-literal escape-hatch host rejected (§7 (d), D45) ──

#[test]
fn rejection_escape_hatch_bare_cidr() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
escape_hatches:
  catalog:
    - id: bad-cidr
      protocol: postgres
      host: 10.0.0.0/8
      port: 5432
      scope: org
      approval: allow-always
"#;
    let errs = parse_layer(text).expect_err("bare-CIDR escape-hatch host must reject");
    assert!(
        errs.has(PolicyErrorCode::EscapeHatchBareAddress),
        "got {errs}"
    );
}

#[test]
fn rejection_escape_hatch_bare_v4_literal() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
escape_hatches:
  catalog:
    - id: bad-literal
      protocol: postgres
      host: 203.0.113.10
      port: 5432
      scope: org
      approval: allow-always
"#;
    let errs = parse_layer(text).expect_err("bare v4 literal escape-hatch host must reject");
    assert!(
        errs.has(PolicyErrorCode::EscapeHatchBareAddress),
        "got {errs}"
    );
}

#[test]
fn rejection_escape_hatch_bare_v6_literal() {
    // v6-literal acceptance elsewhere (D75) does NOT loosen the escape-hatch host
    // rule (§8.1): a bare v6 literal host is still rejected.
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
escape_hatches:
  catalog:
    - id: bad-v6
      protocol: postgres
      host: "2001:db8::1"
      port: 5432
      scope: org
      approval: allow-always
"#;
    let errs = parse_layer(text).expect_err("bare v6 literal escape-hatch host must reject");
    assert!(
        errs.has(PolicyErrorCode::EscapeHatchBareAddress),
        "got {errs}"
    );
}

#[test]
fn escape_hatch_hostname_accepted() {
    // A dotted hostname (not an address) is fine.
    let layer = parse_layer(sample_standard()).expect("hostname host parses");
    assert_eq!(layer.escape_hatches[0].host, "db.staging.example.internal");
}

// ── (e) Mandatory baseline-pack provenance (§7 (e), D74) ──────────────────────

#[test]
fn rejection_pack_entry_missing_provenance_source_url() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
baseline_pack:
  pack_version: "v1"
  entries:
    - fqdn: missing-url.example
      family: core
      ports: [443]
      evidence: vendor-doc
"#;
    let errs = parse_layer(text).expect_err("missing provenance_source_url must reject");
    assert!(errs.has(PolicyErrorCode::MissingProvenance), "got {errs}");
    assert!(
        errs.0
            .iter()
            .any(|e| e.detail.contains("missing-url.example")
                && e.detail.contains("provenance_source_url")),
        "got {errs}"
    );
}

#[test]
fn rejection_pack_entry_missing_evidence() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
baseline_pack:
  pack_version: "v1"
  entries:
    - fqdn: missing-evidence.example
      family: core
      ports: [443]
      provenance_source_url: https://example.invalid/x
"#;
    let errs = parse_layer(text).expect_err("missing evidence must reject");
    assert!(errs.has(PolicyErrorCode::MissingProvenance), "got {errs}");
    assert!(
        errs.0.iter().any(|e| e.detail.contains("missing-evidence.example") && e.detail.contains("evidence")),
        "got {errs}"
    );
}

// ── (g) v6 literals accepted in address-shaped fields (§2 IPv6 row, D75) ──────

#[test]
fn v6_literal_accepted_in_upstream_resolvers() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
dns:
  negative_ttl: 0
  upstream_resolvers:
    - "2001:4860:4860::8888"
    - 1.1.1.1
"#;
    let layer = parse_layer(text).expect("v6 + v4 resolvers parse");
    assert_eq!(layer.dns.negative_ttl, 0); // meaningful zero accepted
    assert_eq!(layer.dns.upstream_resolvers.len(), 2);
    assert_eq!(layer.dns.upstream_resolvers[0].family, AddressFamily::V6);
    assert_eq!(layer.dns.upstream_resolvers[0].octets.len(), 16);
    assert_eq!(layer.dns.upstream_resolvers[1].family, AddressFamily::V4);
}

#[test]
fn address_parser_round_trips_v4_and_v6() {
    // Reuse of AdmittedAddr/AddressFamily (dns_admission.rs) — no parallel type.
    let v4 = parse_ip_literal("203.0.113.5").unwrap();
    assert_eq!(v4.family, AddressFamily::V4);
    assert_eq!(v4.octets, vec![203, 0, 113, 5]);
    // The DstKey canonical encoding (dns_admission.rs) works on the parsed addr.
    assert_eq!(v4.to_dst_key().0, "v4:cb007105");

    let v6 = parse_ip_literal("2001:db8::1").unwrap();
    assert_eq!(v6.family, AddressFamily::V6);
    assert_eq!(v6.octets[0], 0x20);
    assert_eq!(v6.octets[1], 0x01);
    assert_eq!(*v6.octets.last().unwrap(), 1);

    // Embedded-v4 v6 form.
    let mapped = parse_ip_literal("::ffff:192.0.2.1").unwrap();
    assert_eq!(mapped.family, AddressFamily::V6);
    assert_eq!(&mapped.octets[12..], &[192, 0, 2, 1]);

    // A hostname is not an address literal.
    assert!(parse_ip_literal("db.staging.example.internal").is_none());
    // A CIDR is recognised by is_cidr (used by the escape-hatch validator).
    assert!(is_cidr("10.0.0.0/8"));
    assert!(is_cidr("2001:db8::/32"));
    assert!(!is_cidr("db.staging.example.internal"));
}

// ── Collect-all: multiple violations surface in one pass (§8.1) ───────────────

#[test]
fn collect_all_surfaces_every_violation_in_one_pass() {
    let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
escape_hatches:
  catalog:
    - id: bad-cidr
      protocol: postgres
      host: 10.0.0.0/8
      port: 5432
      scope: org
      approval: allow-always
baseline_pack:
  pack_version: "v1"
  entries:
    - fqdn: missing-prov.example
      family: core
      ports: [443]
content:
  generic:
    fail_open: false
    rules:
      - id: over-rung
        regex: "x"
        secret_group: 0
        rung: kill+snapshot
"#;
    let errs = parse_layer(text).expect_err("multiple violations reject");
    // All three independent §7 rejections present in one bundle.
    assert!(
        errs.has(PolicyErrorCode::EscapeHatchBareAddress),
        "got {errs}"
    );
    assert!(errs.has(PolicyErrorCode::MissingProvenance), "got {errs}");
    assert!(errs.has(PolicyErrorCode::GenericRungCap), "got {errs}");
    assert!(
        errs.0.len() >= 3,
        "collect-all should surface >=3, got {}",
        errs.0.len()
    );
}

// ── Reader robustness: tabs rejected, comments stripped ───────────────────────

#[test]
fn tabs_in_indentation_are_rejected() {
    let text = "schema_version: pol1/v0\nlayer: system-baseline\nposture: standard\nadmission:\n\tttl_floor: 60\n";
    let errs = parse_layer(text).expect_err("tab indentation rejected");
    assert!(errs.has(PolicyErrorCode::Syntax), "got {errs}");
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let text = r#"
# a leading comment
schema_version: pol1/v0   # inline comment
layer: system-baseline

posture: open  # another
"#;
    let layer = parse_layer(text).expect("comments stripped, parses");
    assert_eq!(layer.posture, Posture::Open);
    assert_eq!(layer.schema_version, "pol1/v0");
}
