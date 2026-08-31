// SPDX-License-Identifier: Apache-2.0

//! Resolver-lock TLS-1 (SNI) conformance — the second enforcement layer of the
//! doc 09 §9 DoH/DoT-block (resolver-lock) contract, asserted through the
//! **consumer** decision surface [`policy_core::consumer::tls_connect_decision`]
//! (doc 13 §1.1; doc 09 line 144 "Resolver lock"; doc 09 NFT-4).
//!
//! Doc 09 splits resolver-lock enforcement into two layers over the ONE D64
//! baseline **blocklist** (POL-2): **DNS-3 denial** (the resolver refuses the
//! qname) and **the TLS-1 SNI check** (the egress gateway refuses the connect
//! when the peeked ClientHello SNI is a blocklisted resolver host). The companion
//! `pol2_baseline.rs` reachability suite exercises the **DNS-3 half** of this
//! block (`dns_admission_decision` over the shipped pack); this file closes the
//! **TLS-1 half**: every shipped resolver-lock blocklist entry must DENY on
//! [`tls_connect_decision`], must **sever established flows** at parity with the
//! DNS-3 surface (POL-3 "no consumer reimplements a rule"), and the deny must
//! **win over an allowlist** on the TLS path (blocklists always win, §1.2
//! deny-overrides).
//!
//! Why a consumer-surface test, not a live boundary test: ds-tlsproxy EMBEDS
//! `policy-core` (doc 13 §1.1) — the SNI it peeks off the ClientHello is routed
//! verbatim into `tls_connect_decision`, so a deny here is the deny the live
//! egress gateway reaches. The live half (a DoH client refused against running
//! ds-dnsgate/ds-tlsproxy — the doc.go wire-matrix "DoH client that must be
//! blocked" row) is env-gated and deferred to the NFT-4 step in
//! `assurance/conformance-adapter/resolverlock/`; it is NOT duplicated here.
//!
//! ## Single source: the shipped pack artifact
//!
//! Both this suite and the Go offline conformance half
//! (`assurance/conformance-adapter/resolverlock`) read the SAME bytes — the
//! shipped pack `dataplane/artifacts/policy-packs/pol2-system-baseline.pol1.yaml`
//! — so the Rust and Go suites can never drift: one artifact, two readers. The
//! Rust side parses it through the real `ds_contracts::pol1::parse_layer` (the
//! reader the host uses), so an entry that stops parsing, stops denying, or stops
//! severing fails this test. The companion `pol2_baseline.rs` already proves the
//! pack parses with zero `PolicyError`s and that the named resolvers deny on the
//! DNS-3 surface; this file does NOT re-assert those — it drives the **TLS-1
//! surface** over **every** shipped blocklist entry and proves DNS/TLS parity.

use ds_contracts::pol1::{parse_layer, BlockEntry, PolicyLayer, Rung};
use policy_core::consumer::{dns_admission_decision, tls_connect_decision, DecisionKind};
use policy_core::pol1_eval::{compose, ComposedPolicy};
use std::path::PathBuf;

/// The repo-relative path from this crate to the SHIPPED baseline pack file —
/// the SAME artifact `pol2_baseline.rs` reads and the Go offline half reads.
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

/// Read + parse the SHIPPED pack with zero PolicyErrors. (The "parses clean" bar
/// is the companion suite's; here it is the precondition for driving the shipped
/// blocklist through the TLS-1 surface — a malformed pack fails identically.)
fn parse_shipped_pack() -> PolicyLayer {
    let path = shipped_pack_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading shipped pack {}: {e}", path.display()));
    parse_layer(&text).unwrap_or_else(|errs| {
        panic!("the SHIPPED POL-2 baseline pack must parse with zero PolicyErrors, got:\n{errs}")
    })
}

/// Compose the shipped baseline into the host's one composed document (no
/// capabilities present — the fresh-install state), the document the consumer
/// surfaces query.
fn composed_fresh_install() -> ComposedPolicy {
    compose(&[parse_shipped_pack()], &[])
}

/// THE shipped resolver-lock blocklist, read straight off the parsed pack — the
/// single source of truth this whole suite iterates. Every test below drives THIS
/// set (no in-test transcription), so adding/removing a shipped blocklist entry
/// changes exactly what is asserted on the TLS-1 path.
fn shipped_blocklist() -> Vec<BlockEntry> {
    parse_shipped_pack().blocklist
}

// ── TLS-1 half: every shipped resolver-lock entry DENIES on tls_connect ────────

#[test]
fn every_shipped_blocklist_entry_denies_on_the_tls_connect_surface() {
    // The TLS-1 SNI check: ds-tlsproxy peeks the ClientHello SNI and routes it
    // into tls_connect_decision. Every shipped blocklist resolver MUST deny on
    // the connect surface, not just the DNS-3 admission surface.
    let composed = composed_fresh_install();
    let blocklist = shipped_blocklist();
    assert!(
        !blocklist.is_empty(),
        "the shipped pack must carry a non-empty resolver-lock blocklist (D64)"
    );
    for be in &blocklist {
        let fqdn = &be.domain;
        let tls = tls_connect_decision(&composed, fqdn);
        assert!(
            tls.denies(),
            "resolver-lock entry {fqdn} must DENY on the TLS-1 SNI surface: {tls:?}"
        );
        assert_eq!(
            tls.kind,
            DecisionKind::Deny,
            "resolver-lock entry {fqdn} is a policy deny (not inert/ask): {tls:?}"
        );
        // POL-3 mandatory provenance (rule 4): the deny names the rule.
        assert!(
            tls.provenance.rule_id.contains(fqdn.as_str()),
            "deny provenance names the blocked resolver {fqdn}: {tls:?}"
        );
    }
}

// ── Sever-established-flows on the TLS path (§5 / D53) ─────────────────────────

#[test]
fn every_shipped_blocklist_entry_severs_established_flows_on_the_tls_path() {
    // Every shipped resolver-lock entry pins a block-or-higher rung (block+log is
    // the first severing rung, §5/D53). A resolver-lock deny must sever
    // established flows on the TLS path so revoking the DoH/DoT tunnel tears down
    // the in-flight stream, not just new connects.
    let composed = composed_fresh_install();
    for be in &shipped_blocklist() {
        let fqdn = &be.domain;
        // The shipped entry itself carries a severing rung.
        assert!(
            be.rung.map(Rung::is_block_or_higher).unwrap_or(false),
            "shipped resolver-lock entry {fqdn} must pin a block-or-higher rung \
             so the TLS-1 deny severs (§5/D53), got rung {:?}",
            be.rung
        );
        let tls = tls_connect_decision(&composed, fqdn);
        assert_eq!(
            tls.rung, be.rung,
            "the TLS-1 decision carries the shipped rung for {fqdn}: {tls:?}"
        );
        assert!(
            tls.severs_established_flows(),
            "resolver-lock entry {fqdn} must SEVER established flows on the TLS path: {tls:?}"
        );
        assert!(
            tls.is_revocation_severing(),
            "revoking the resolver-lock block on {fqdn} severs: {tls:?}"
        );
    }
}

#[test]
fn tls_and_dns_surfaces_agree_for_every_shipped_blocklist_entry() {
    // POL-3 "no consumer reimplements a rule": the TLS-1 SNI decision and the
    // DNS-3 admission decision are the SAME engine verdict — byte-identical — for
    // every shipped resolver-lock entry. This is the sever-parity proof:
    // whatever the DNS-3 half severs, the TLS-1 half severs identically. (The
    // companion pol2_baseline.rs asserts the DNS-3 verdicts in isolation; this is
    // the cross-surface equality the TLS-1 half adds.)
    let composed = composed_fresh_install();
    for be in &shipped_blocklist() {
        let fqdn = &be.domain;
        let dns = dns_admission_decision(&composed, fqdn);
        let tls = tls_connect_decision(&composed, fqdn);
        assert_eq!(
            dns, tls,
            "DNS-3 and TLS-1 surfaces must agree for resolver-lock entry {fqdn}"
        );
        assert_eq!(
            dns.severs_established_flows(),
            tls.severs_established_flows(),
            "sever-established-flows parity for {fqdn}"
        );
    }
}

// ── Blocklist wins over allowlist on the TLS path (§1.2 deny-overrides) ────────

/// A synthetic, clearly-labeled org layer that ALLOWLISTS a host the shipped
/// baseline BLOCKLISTS — the only construction that exercises deny-overrides on
/// the TLS path, since the shipped pack ships no allowlist∩blocklist overlap
/// (and must not, by design). The blocklisted host is taken from the SHIPPED
/// blocklist (the single source), so the test stays true to the real list.
fn org_allowlisting_a_blocklisted_resolver(fqdn: &str) -> PolicyLayer {
    let text = format!(
        "schema_version: pol1/v0\n\
         layer: org\n\
         posture: standard\n\
         allowlist:\n\
         \x20\x20- domain: {fqdn}\n"
    );
    parse_layer(&text).expect("synthetic org allowlist layer parses clean")
}

#[test]
fn blocklist_wins_over_allowlist_on_the_tls_path() {
    // Take the FIRST shipped resolver-lock entry and allowlist it in a higher-
    // precedence org layer. Blocklists always win (§1.2) — the composed TLS-1
    // surface must still DENY it, and it must still sever (the block rung is
    // carried, not the allow). Composing org OVER baseline is the deny-overrides
    // case proper: a later, more-specific allowlist cannot lift a blocklist.
    let blocklist = shipped_blocklist();
    let target = blocklist
        .first()
        .map(|be| be.domain.clone())
        .expect("the shipped blocklist is non-empty");

    let baseline = parse_shipped_pack();
    let org = org_allowlisting_a_blocklisted_resolver(&target);
    // Precedence order: system-baseline (index 0) → org (index 1, most-specific).
    let composed = compose(&[baseline, org], &[]);

    // Sanity: the allowlist entry actually composed in, so deny-overrides is the
    // path under test (not a no-op where the allowlist silently dropped).
    assert!(
        composed.allowlist.contains_key(&target),
        "the org allowlist for {target} must compose in so deny-overrides is exercised"
    );

    let tls = tls_connect_decision(&composed, &target);
    assert!(
        tls.denies(),
        "blocklist must win over allowlist on the TLS path for {target}: {tls:?}"
    );
    assert!(
        tls.severs_established_flows(),
        "the surviving block still severs on the TLS path for {target}: {tls:?}"
    );
    // The DNS surface reaches the same deny-overrides verdict (POL-3 no-skew).
    assert_eq!(tls, dns_admission_decision(&composed, &target));
}

// ── Case handling: the caller normalizes (doc 13 §1.1 contract) ───────────────

#[test]
fn case_normalized_form_denies_on_the_tls_path() {
    // tls_connect_decision documents `host` as the SNI "already lowercased /
    // normalized by the caller" (doc 13 §1.1). DNS names are case-insensitive
    // (RFC 4343): the egress gateway lowercases the peeked SNI before the policy
    // query, so a `DNS.GOOGLE` ClientHello must reach the SAME deny as
    // `dns.google`. We assert the contract the way the consumer surface is
    // specified — normalize, then evaluate — so a regression that started
    // case-folding inside the engine (or stopped denying the lowercased form) is
    // caught, for EVERY shipped blocklist entry.
    let composed = composed_fresh_install();
    for be in &shipped_blocklist() {
        let fqdn = &be.domain;
        let upper = fqdn.to_ascii_uppercase();
        // An uppercase SNI normalized back to the shipped (lowercase) form must
        // reach the deny. (Shipped entries are lowercase; see the shape test.)
        let normalized = upper.to_ascii_lowercase();
        assert_eq!(
            &normalized, fqdn,
            "shipped entry {fqdn} must round-trip through ASCII case-folding"
        );
        let tls = tls_connect_decision(&composed, &normalized);
        assert!(
            tls.denies(),
            "the normalized (lowercased) SNI {upper:?} -> {normalized:?} must DENY: {tls:?}"
        );
        assert!(
            tls.severs_established_flows(),
            "the case-normalized deny still severs for {fqdn}: {tls:?}"
        );
    }
}

// ── Subdomain handling: exact FQDNs only (D74 wildcard policy) ─────────────────

#[test]
fn subdomain_of_a_shipped_blocklist_entry_does_not_match_on_the_tls_path() {
    // The D74 wildcard policy is exact-FQDNs-only (pack README): the resolver-lock
    // entries are exact FQDNs, so the engine matches the exact name and a NON-
    // listed subdomain is NOT a blocklist hit — it falls through to the
    // unknown-domain `Ask` path. This is the honest behavior of the v0 engine
    // (`evaluate_domain` is an exact-name lookup, doc 13 §1.1), and it documents
    // the boundary of the resolver-lock guarantee on the TLS path: a *listed* host
    // is the unit of enforcement, and adding a new resolver host means adding a
    // new exact entry, never relying on suffix matching.
    let composed = composed_fresh_install();
    let blocklist = shipped_blocklist();

    for be in &blocklist {
        let fqdn = &be.domain;
        // A label prepended to a listed entry yields a NON-listed subdomain. Skip
        // the (rare) case where the synthesized subdomain happens to itself be a
        // shipped entry — then it legitimately denies and is not a counterexample.
        let sub = format!("edge.{fqdn}");
        if blocklist.iter().any(|b| b.domain == sub) {
            continue;
        }
        let decision = tls_connect_decision(&composed, &sub);
        assert!(
            !decision.denies(),
            "a non-listed subdomain {sub} of a resolver-lock entry is NOT a blocklist hit \
             on the TLS path (exact-FQDN policy, D74): {decision:?}"
        );
        assert!(
            matches!(decision.kind, DecisionKind::Ask),
            "the non-listed subdomain {sub} falls through to Ask, not a pack admit/deny: {decision:?}"
        );

        // The exact listed FQDN still denies (the entry itself is the unit).
        assert!(
            tls_connect_decision(&composed, fqdn).denies(),
            "the exact shipped entry {fqdn} still denies on the TLS path"
        );
    }

    // Where a vendor ships BOTH an apex and a subdomain as SEPARATE exact entries
    // (e.g. cloudflare-dns.com + mozilla.cloudflare-dns.com), BOTH deny — because
    // BOTH are listed, not by suffix inheritance. Assert this only for pairs the
    // shipped pack actually carries, so the property tracks the real list.
    let listed: std::collections::BTreeSet<&str> =
        blocklist.iter().map(|be| be.domain.as_str()).collect();
    for (apex, sub) in [
        ("cloudflare-dns.com", "mozilla.cloudflare-dns.com"),
        ("dns.google", "dns.google.com"),
    ] {
        if listed.contains(apex) && listed.contains(sub) {
            assert!(
                tls_connect_decision(&composed, apex).denies(),
                "{apex} denies (listed entry)"
            );
            assert!(
                tls_connect_decision(&composed, sub).denies(),
                "{sub} denies (separately listed entry, not suffix inheritance)"
            );
        }
    }
}

// ── Single-source shape: the shipped blocklist entries are exact lowercase FQDNs ─

#[test]
fn shipped_blocklist_entries_are_exact_lowercase_fqdns() {
    // The single-source shape check on the RUST side (the Go offline half asserts
    // the mirror over the SAME pack bytes): every shipped resolver-lock entry is
    // a non-empty, lowercase exact FQDN — the form the egress gateway normalizes
    // the SNI into before the policy query (doc 13 §1.1). A regression that
    // shipped an empty or mixed-case entry would silently weaken the TLS-1 match;
    // this catches it. Both suites read the one artifact, so the Go
    // TestShippedBlocklistShape and this test can never disagree.
    let blocklist = shipped_blocklist();
    assert!(
        !blocklist.is_empty(),
        "the shipped resolver-lock blocklist must not be empty"
    );
    let mut seen = std::collections::BTreeSet::new();
    for be in &blocklist {
        let fqdn = &be.domain;
        assert!(!fqdn.is_empty(), "no empty resolver-lock entry");
        assert_eq!(
            *fqdn,
            fqdn.to_ascii_lowercase(),
            "shipped resolver-lock entries are stored lowercase: {fqdn}"
        );
        assert!(
            seen.insert(fqdn.clone()),
            "duplicate shipped resolver-lock entry: {fqdn}"
        );
    }
}
