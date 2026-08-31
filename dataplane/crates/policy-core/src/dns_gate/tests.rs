//! Tests for the frozen ds-dnsgate verdict API (doc 11 §4 / policy-core README).
//!
//! These assert the [`evaluate`] projection is a LOSSLESS routing of the shared
//! engine verdict into the gate-facing [`DnsVerdict`] family — every arm of the
//! frozen `{Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}` shape is
//! reachable, carries POL-3 provenance (doc 11 §6.7), and agrees with the
//! [`crate::consumer::dns_admission_decision`] surface it projects (POL-3: no
//! consumer reimplements a rule).

use super::*;
use crate::consumer::dns_admission_decision;
use crate::pol1_eval::compose;
use ds_contracts::pol1::{parse_layer, PolicyLayer};

// A baseline that allows github (enabled core family), denies a DoH resolver at a
// severing rung, and capability-gates a chrome CDN (http-policy absent → inert).
fn system_baseline() -> &'static str {
    r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: api.anthropic.com
blocklist:
  - domain: dns.google
    reason: doh-resolver
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: github.com
      family: core
      ports: [443]
      provenance_source_url: https://api.github.com/meta
      evidence: vendor-doc
    - fqdn: storage.googleapis.com
      family: core
      ports: [443]
      requires: http-policy
      provenance_source_url: https://example.invalid/chrome.ts
      evidence: vendor-doc
"#
}

fn parse(text: &str) -> PolicyLayer {
    parse_layer(text).expect("layer parses clean")
}

fn baseline_composed() -> ComposedPolicy {
    // No capabilities present (TLS-6 absent) → the http-policy gate is inert.
    compose(&[parse(system_baseline())], &[])
}

fn ctx(qname: &str, qtype: u16) -> DnsQueryCtx {
    DnsQueryCtx {
        session: "dstap-7".to_string(),
        qname: qname.to_string(),
        qtype,
        source: "dstap-7/local".to_string(),
    }
}

// The W2 admit window the gate threads off the POL-1 tunables (FLOOR/CEIL).
fn admit_window() -> Admit {
    Admit {
        ttl_floor: 60,
        ttl_ceil: 900,
    }
}

fn assert_provenance(v: &DnsVerdict) {
    let p = v.provenance();
    assert!(!p.rule_id.is_empty(), "rule_id present: {v:?}");
    assert!(!p.policy_layer.is_empty(), "policy_layer present: {v:?}");
    assert!(
        !p.policy_version.is_empty(),
        "policy_version present: {v:?}"
    );
}

#[test]
fn allow_arm_carries_admit_window_and_provenance() {
    let policy = baseline_composed();
    let v = evaluate(&policy, &ctx("github.com.", 1), admit_window());
    match &v {
        DnsVerdict::Allow { admit, provenance } => {
            assert_eq!(admit.ttl_floor, 60);
            assert_eq!(admit.ttl_ceil, 900);
            assert!(provenance.rule_id.contains("github.com"));
        }
        other => panic!("expected Allow, got {other:?}"),
    }
    assert!(v.admits());
    assert!(!v.severs_established_flows(), "an allow severs nothing");
    assert_provenance(&v);
}

#[test]
fn deny_arm_is_nxdomain_and_carries_the_severing_rung() {
    let policy = baseline_composed();
    // dns.google is blocked at kill+snapshot (a severing rung).
    let v = evaluate(&policy, &ctx("dns.google.", 1), admit_window());
    match &v {
        DnsVerdict::Deny {
            rcode_policy,
            rung,
            provenance,
        } => {
            assert_eq!(*rcode_policy, RcodePolicy::NxDomain);
            assert!(rung.is_some(), "an explicit blocklist rung is carried");
            assert!(provenance.rule_id.contains("dns.google"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
    assert!(!v.admits());
    // kill+snapshot is block-or-higher → revoking it severs established flows (§5.4).
    assert!(v.severs_established_flows());
    assert_provenance(&v);
}

#[test]
fn ask_arm_carries_prompt_ref_scoped_to_session_and_qname() {
    let policy = baseline_composed();
    // An unknown domain → Ask (the §3.2 REFUSED path / D18 prompt seam).
    let v = evaluate(&policy, &ctx("unknown.example.", 1), admit_window());
    match &v {
        DnsVerdict::Ask {
            prompt_ref,
            provenance,
        } => {
            assert_eq!(prompt_ref.session, "dstap-7");
            assert_eq!(prompt_ref.qname, "unknown.example.");
            assert!(!provenance.rule_id.is_empty());
        }
        other => panic!("expected Ask, got {other:?}"),
    }
    assert!(!v.admits());
    assert!(!v.severs_established_flows(), "an ask severs nothing");
    assert_provenance(&v);
}

#[test]
fn inert_capability_gated_folds_to_nxdomain_deny_that_severs_nothing() {
    let policy = baseline_composed();
    // storage.googleapis.com requires http-policy (absent) → inert: admits nothing.
    // On the DNS wire that is the §3.2 NXDOMAIN hard-deny; the provenance keeps the
    // inert rule id so a LOG-1 join still sees it was an inert gate, not a block.
    let v = evaluate(&policy, &ctx("storage.googleapis.com.", 1), admit_window());
    match &v {
        DnsVerdict::Deny {
            rcode_policy,
            rung,
            provenance,
        } => {
            assert_eq!(*rcode_policy, RcodePolicy::NxDomain);
            assert!(rung.is_none(), "an inert gate carries no severing rung");
            assert!(provenance.rule_id.contains("storage.googleapis.com"));
        }
        other => panic!("expected Deny (inert folds to NXDOMAIN), got {other:?}"),
    }
    assert!(!v.admits(), "an inert entry admits NOTHING (§1.7)");
    // An inert gate is not a policy block — it severs nothing.
    assert!(!v.severs_established_flows());
}

#[test]
fn projection_agrees_with_the_consumer_dns_surface_no_reimplemented_rule() {
    // POL-3: the gate verdict must agree with the consumer DNS admission surface —
    // both route the ONE engine verdict. We assert admits() parity across a
    // representative domain set.
    let policy = baseline_composed();
    for qname in [
        "github.com.",
        "dns.google.",
        "unknown.example.",
        "storage.googleapis.com.",
        "api.anthropic.com.",
    ] {
        let gate = evaluate(&policy, &ctx(qname, 1), admit_window());
        // The gate normalizes the trailing root dot before the engine; the consumer
        // surface takes the hostname-form key, so compare against the same form.
        let consumer = dns_admission_decision(&policy, qname.strip_suffix('.').unwrap_or(qname));
        assert_eq!(
            gate.admits(),
            consumer.admits(),
            "admits() parity for {qname}: gate={gate:?} consumer={consumer:?}"
        );
        // The provenance rule id is the SAME engine rule id (no reimplemented rule).
        assert_eq!(
            gate.provenance().rule_id,
            consumer.provenance.rule_id,
            "same rule id for {qname}"
        );
    }
}

#[test]
fn admit_clamps_chain_min_ttl_into_the_w2_window() {
    // W2: the answered TTL is clamp(chain_min_ttl, FLOOR, CEIL), no grace on the wire.
    let admit = Admit {
        ttl_floor: 60,
        ttl_ceil: 900,
    };
    assert_eq!(admit.clamp_ttl(10), 60, "below floor clamps up to FLOOR");
    assert_eq!(admit.clamp_ttl(300), 300, "in-window passes through");
    assert_eq!(admit.clamp_ttl(5000), 900, "above ceil clamps down to CEIL");
}

#[test]
fn qtype_does_not_change_the_policy_verdict_in_v0() {
    // Admission is keyed on the NAME (W3), not the record type — the AAAA/HTTPS scrub
    // is a record-type behavior in the gate's scrub/, not a policy verdict. So an A
    // and an AAAA query for the same allowed name get the same policy verdict.
    let policy = baseline_composed();
    let a = evaluate(&policy, &ctx("github.com.", 1), admit_window());
    let aaaa = evaluate(&policy, &ctx("github.com.", 28), admit_window());
    assert_eq!(a.admits(), aaaa.admits());
    assert_eq!(a.provenance().rule_id, aaaa.provenance().rule_id);
}
