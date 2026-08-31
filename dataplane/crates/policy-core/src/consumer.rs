//! POL-1 consumer-facing decision API — the single shared evaluator's three
//! consumer query surfaces (doc 13 §1 rule 1, D63/POL-3).
//!
//! `policy-core` is THE one evaluator (doc 13 §1.1): ds-dnsgate, ds-tlsproxy, and
//! the NFTables programmer EMBED it — no consumer reimplements a rule. The
//! [`crate::pol1_eval`] module already lands the engine: [`compose`] folds a layer
//! stack into one deny-wins [`ComposedPolicy`] (§1.2), and [`evaluate_domain`]
//! resolves a single domain query to an [`Eval`] verdict carrying POL-3
//! provenance with capability-gate inertness (§1.7). This module is the
//! consumer-facing skin on top of that engine: it does not re-derive composition,
//! deny-overrides, or the capability gate — it routes the ONE [`evaluate_domain`]
//! verdict into the shape each of the three consumers needs, so all three reach
//! identical decisions (POL-3 "no consumer reimplements a rule").
//!
//! The three surfaces (doc 13 §1.1, §5):
//!
//! - **DNS admission query** for ds-dnsgate ([`dns_admission_decision`]): does a
//!   resolved qname get admitted, denied, or asked? Carries the §5 severing
//!   predicate so the revocation sweep knows whether a block-or-higher rung
//!   severs established flows.
//! - **TLS / egress-gateway connect decision** for ds-tlsproxy
//!   ([`tls_connect_decision`]): may the egress gateway open an upstream
//!   connection to this host? Same engine verdict, the connect-shaped projection.
//! - **NFT ruleset-derivation inputs** for the NFTables programmer
//!   ([`nft_ruleset_inputs`]): the composed allow-set domains, the composed
//!   blocklist with per-entry severing flags, and the policy version — the
//!   derived state the programmer turns into allow-set / deny ruleset elements.
//!
//! Cross-cutting rules this module makes observable on every decision:
//!
//! - **The composed document is what the host carries (rule 2).** Every surface
//!   here takes a [`ComposedPolicy`] — the deny-wins composed output, never raw
//!   layers. [`host_snapshot_policy_version`] is the one version the host snapshot
//!   stamps.
//! - **Single version namespace (rule 3).** [`PolicyVersion`] wraps the one policy
//!   version (the D36 `policy_log` seq end to end); pack/digest version strings are
//!   content identifiers cited in provenance only, surfaced as [`ContentId`]s, never
//!   a second version namespace.
//! - **Mandatory provenance (rule 4).** Every decision this module returns carries
//!   a POL-3 [`Provenance`] (matched rule id + layer + policy version) — there is
//!   no decision constructor here that omits it.
//! - **Tunables are policy values (rule 5).** [`tunables`] surfaces the TTL
//!   floor/ceil/grace, negative-TTL, and per-domain caps off the composed document
//!   as policy values, not code constants.
//! - **D53 rung + severing predicate (rule 6).** Every decision exposes
//!   [`Decision::severs_established_flows`], which delegates to
//!   [`Verdict::is_block_or_higher`] — the stable name ds-tlsproxy comments already
//!   reference (`policy-core`'s `Verdict::is_block_or_higher`). Extended additively.
//! - **Capability gating stays inert+warn (rule 7).** An inert verdict surfaces as
//!   [`DecisionKind::InertCapabilityGated`] — it admits NOTHING and is distinct
//!   from a policy deny (the [`crate::pol1_eval`] engine owns the gate).
//! - **Expiry is not revocation (rule 8).** [`Decision::is_revocation_severing`]
//!   encodes that only an explicit block-or-higher policy decision severs; a TTL
//!   lapse is re-admission, never a sever (see [`expiry_severs_nothing`]).
//!
//! No hickory or pingora types cross this module (D67/D40): it consumes only the
//! family-agnostic ds-contracts shapes and the [`crate::pol1_eval`] verdict types.

use crate::pol1_eval::{evaluate_domain, ComposedPolicy, Eval, Provenance};
use ds_contracts::pol1::Rung;
use ds_contracts::scopes::{token_has_scope, SCOPE_NETWORK_EGRESS};

/// The decision verdict family (doc 11 §4 frozen verdict family, narrowed to what
/// the three POL-1 consumers need). This is the consumer projection of the engine
/// [`Eval`]; it never re-decides anything — [`Decision::from_eval`] is a total,
/// lossless mapping of an engine verdict into a consumer-facing kind plus the
/// carried rung.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionKind {
    /// Admit the flow (DNS admission / TLS connect / NFT allow-set entry).
    Admit,
    /// Deny the flow. A `block-or-higher` rung severs established flows on
    /// revocation (§5); a `None`/`allow+log` rung denies new flows only.
    Deny,
    /// Ask the user (unknown-domain posture path; the attendedness downgrade to
    /// block is the orchestrator-signal layer, not this pure evaluation).
    Ask,
    /// The domain matched ONLY a capability-gated (inert) entry: admit NOTHING
    /// (§1.7) — distinct from a policy deny. The unmet capability is named.
    InertCapabilityGated {
        /// The capability the gated entry needs (e.g. "http-policy").
        requires: String,
    },
}

/// The single shared verdict every consumer surface returns (doc 13 §1.1). It
/// carries the consumer-facing kind, the D53 rung the decision was reached at
/// (rule 6), and the mandatory POL-3 provenance (rule 4). The three consumer
/// entry points all funnel the ONE engine verdict through this type, so a DNS
/// admission, a TLS connect, and an NFT ruleset entry can never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The consumer-facing verdict kind.
    pub kind: DecisionKind,
    /// The D53 rung the decision carries (rule 6). `Some` for an explicit
    /// blocklist rung; `None` for a default/posture decision with no explicit
    /// rule rung. The rung drives the §5 revocation severing predicate.
    pub rung: Option<Rung>,
    /// POL-3 provenance: matched rule id + composing layer + policy version
    /// (rule 4). MANDATORY — there is no `Decision` without it.
    pub provenance: Provenance,
}

impl Decision {
    /// Project the ONE engine verdict ([`Eval`]) into a consumer [`Decision`]
    /// (doc 13 §1.1: no consumer reimplements a rule — every surface routes the
    /// same engine output). Total and lossless: the engine's rung is carried
    /// through, the inert-capability state stays distinct from a deny.
    pub fn from_eval(eval: &Eval) -> Decision {
        let provenance = eval.provenance().clone();
        match eval {
            Eval::Allow(_) => Decision {
                kind: DecisionKind::Admit,
                rung: None,
                provenance,
            },
            Eval::Deny { rung, .. } => Decision {
                kind: DecisionKind::Deny,
                rung: *rung,
                provenance,
            },
            Eval::Ask(_) => Decision {
                kind: DecisionKind::Ask,
                rung: None,
                provenance,
            },
            Eval::InertCapabilityGated { requires, .. } => Decision {
                kind: DecisionKind::InertCapabilityGated {
                    requires: requires.clone(),
                },
                rung: None,
                provenance,
            },
        }
    }

    /// Whether this decision ADMITS the flow. An inert capability-gated entry does
    /// NOT admit (§1.7) — that is the whole point of the inertness contract.
    pub fn admits(&self) -> bool {
        matches!(self.kind, DecisionKind::Admit)
    }

    /// Whether this decision DENIES the flow (a policy block — distinct from the
    /// inert admit-nothing state, which is `DecisionKind::InertCapabilityGated`).
    pub fn denies(&self) -> bool {
        matches!(self.kind, DecisionKind::Deny)
    }

    /// Whether this decision's rung is "block-or-higher" — the §5 D53 severing
    /// threshold (rule 6). Delegates to [`Rung::is_block_or_higher`], the stable
    /// predicate ds-tlsproxy comments reference as `policy-core`'s
    /// `Verdict::is_block_or_higher`. A decision with no explicit rung (`None`)
    /// does NOT sever — a default/posture deny gates new flows only.
    pub fn severs_established_flows(&self) -> bool {
        self.rung.map(Rung::is_block_or_higher).unwrap_or(false)
    }

    /// Whether THIS decision, applied as a revocation, severs established flows
    /// per §5 / rule 8. A revocation severs iff it is a policy DENY at a
    /// block-or-higher rung. Expiry is NOT revocation (rule 8, D68): a TTL lapse
    /// re-admits through full DNS-2 admission and severs nothing — it never
    /// produces a severing decision here, because expiry is not a policy verdict
    /// at all. Only an explicit block-or-higher deny returns `true`.
    pub fn is_revocation_severing(&self) -> bool {
        self.denies() && self.severs_established_flows()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version & content-id plumbing (rule 3: single version namespace).
// ─────────────────────────────────────────────────────────────────────────────

/// THE policy version (doc 13 §1 rule 3 / §5, D72): the D36 `policy_log` bigserial
/// seq is the single monotonic version end to end. In POL-1 v0 (no `policy_log`
/// seq wired yet) this carries the composed layer's `schema_version` string; the
/// type is the seam so consumers plumb ONE version, never per-service namespaces.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub String);

impl PolicyVersion {
    /// The version string, for provenance stamping / heartbeat `applied_seq`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A CONTENT identifier (rule 3): a pack version (D74) or digest-set version
/// (D73). It is cited in provenance to identify content, but is NEVER a second
/// version namespace — it must not be compared against a [`PolicyVersion`] and
/// LOG-4's version-chain assertion never treats it as policy skew (§5
/// digest-feed classification). Kept a distinct type so the two cannot be
/// confused at a call site.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub String);

impl ContentId {
    /// The content-identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The ONE policy version the host snapshot carries (doc 13 §1 rule 2 / §5): the
/// composed document — not any single layer — is what the host snapshot stamps,
/// and it stamps exactly one version (rule 3). This reads it off the composed
/// document so consumers never reach back to a raw layer for it.
pub fn host_snapshot_policy_version(policy: &ComposedPolicy) -> PolicyVersion {
    PolicyVersion(policy.policy_version.clone())
}

/// The baseline-pack content id cited in provenance (rule 3, D74): the
/// `pack_version` is a CONTENT identifier, not a version namespace. Returns
/// `None` when the composed document carries no pack version string.
pub fn baseline_pack_content_id(policy: &ComposedPolicy) -> Option<ContentId> {
    // The composed pack_version lives on the per-entry pack entries; in v0 the
    // composed document keeps the most-specific layer's entries, each of which
    // references its family. The pack_version itself is a per-pack content id we
    // surface only when an entry is present (an empty pack has no content id).
    policy
        .pack_entries
        .values()
        .map(|ce| ce.entry.family.clone())
        .next()
        .map(|_| ContentId(policy.policy_version.clone()))
        .filter(|c| !c.0.is_empty())
}

// ─────────────────────────────────────────────────────────────────────────────
// Surface 1 — DNS admission query (ds-dnsgate).
// ─────────────────────────────────────────────────────────────────────────────

/// The DNS admission decision ds-dnsgate needs for a resolved qname (doc 13 §1.1,
/// §5; the ds-dnsgate "embedding policy-core" path). It is the consumer skin on
/// the ONE [`evaluate_domain`] verdict — ds-dnsgate does not re-decide; it asks
/// here and admits / refuses / asks accordingly.
///
/// `qname` is the resolved query name (already lowercased / normalized by the
/// caller). The returned [`Decision`] carries POL-3 provenance (rule 4) and the
/// §5 severing predicate (rule 6).
pub fn dns_admission_decision(policy: &ComposedPolicy, qname: &str) -> Decision {
    Decision::from_eval(&evaluate_domain(policy, qname))
}

// ─────────────────────────────────────────────────────────────────────────────
// Surface 2 — TLS / egress-gateway connect decision (ds-tlsproxy).
// ─────────────────────────────────────────────────────────────────────────────

/// The egress-gateway connect decision ds-tlsproxy needs before opening an
/// upstream connection (doc 13 §1.1; doc 12). Same ONE engine verdict, projected
/// to a connect-shaped decision: ds-tlsproxy admits the connect iff
/// [`Decision::admits`], refuses otherwise, and consults
/// [`Decision::severs_established_flows`] on a revocation to decide whether to
/// tear down its live tunnels and pooled upstream sockets (the proxy-side residual
/// of the §5 sweep). No reimplemented rule — the same provenance and rung the DNS
/// admission used.
///
/// `host` is the SNI / upstream host the proxy is about to connect to.
pub fn tls_connect_decision(policy: &ComposedPolicy, host: &str) -> Decision {
    Decision::from_eval(&evaluate_domain(policy, host))
}

/// The D127-scope-gated egress-gateway connect decision (doc 23 §6, the
/// policy-core enforcement point): the SAME connect decision as
/// [`tls_connect_decision`], with the `v1:network:egress` scope asserted as an
/// ADDITIONAL predicate BEFORE the admission-map (domain) lookup — the fast-path
/// deny (doc 23 §6: "`tls_connect_decision` checks `v1:network:egress` before any
/// upstream connect; scope is an additional predicate, not a replacement").
///
/// `token_scopes` is the presenting sub-token's `ds_scopes` claim (the scope set
/// surfaced to the proxy from the D22 Validate seam). When it does NOT carry
/// [`SCOPE_NETWORK_EGRESS`], this returns a `Deny` at [`SCOPE_INSUFFICIENT_RULE`]
/// WITHOUT evaluating the domain — a session lacking egress authority never
/// reaches the allow/deny/ask domain engine at all (the fast path). When the
/// scope IS present, it delegates verbatim to [`tls_connect_decision`], so the
/// domain verdict, rung, and provenance are byte-identical to the unscoped
/// surface (no rule is re-decided — POL-3).
///
/// A scope deny carries `rung: None` (a posture/credential deny, not a blocklist
/// rung), so it gates NEW connects only and never severs established flows via
/// [`Decision::severs_established_flows`] — scope insufficiency is an admission
/// refusal, not a §5 revocation event.
pub fn tls_connect_decision_scoped(
    policy: &ComposedPolicy,
    host: &str,
    token_scopes: &[String],
) -> Decision {
    if !token_has_scope(token_scopes, SCOPE_NETWORK_EGRESS) {
        return Decision {
            kind: DecisionKind::Deny,
            rung: None,
            provenance: Provenance {
                rule_id: SCOPE_INSUFFICIENT_RULE.to_string(),
                policy_layer: SCOPE_GATE_LAYER.to_string(),
                policy_version: policy.policy_version.clone(),
            },
        };
    }
    tls_connect_decision(policy, host)
}

/// The provenance `rule_id` a scope-insufficient egress deny carries (doc 23 §6):
/// the machine-readable marker that the deny came from the `v1:network:egress`
/// scope gate, not from a domain blocklist rule — so a consumer/audit can tell a
/// credential-scope refusal apart from a policy block.
pub const SCOPE_INSUFFICIENT_RULE: &str = "scope_insufficient";

/// The provenance `policy_layer` a scope-insufficient egress deny carries: the
/// scope predicate is a credential gate layered ahead of the composed document,
/// not any single composing policy layer.
pub const SCOPE_GATE_LAYER: &str = "scope-gate";

/// Whether a presented sub-token's `ds_scopes` claim authorizes network egress —
/// the EXACT fast-path predicate [`tls_connect_decision_scoped`] applies BEFORE the
/// admission-map (domain) lookup (doc 23 §6: "`tls_connect_decision` checks
/// `v1:network:egress` before any upstream connect"). A thin, named wrapper over
/// [`ds_contracts::scopes::token_has_scope`] for [`SCOPE_NETWORK_EGRESS`] — it
/// re-decides NOTHING (POL-3), it only names the credential predicate so the
/// ds-tlsproxy connect adapter can assert the egress gate (e.g. to skip a
/// capability diagnostic on a scope-refused connect) WITHOUT re-deriving the scope
/// string or re-implementing the check. Fail-closed: a token that does not carry
/// the scope returns `false`, and an empty scope set holds nothing.
pub fn egress_scope_satisfied(token_scopes: &[String]) -> bool {
    token_has_scope(token_scopes, SCOPE_NETWORK_EGRESS)
}

// ─────────────────────────────────────────────────────────────────────────────
// Surface 3 — NFT ruleset-derivation inputs (the NFTables programmer).
// ─────────────────────────────────────────────────────────────────────────────

/// One blocklisted domain the NFT programmer derives a deny element from, with the
/// §5 severing flag the revocation sweep keys off (rule 6). The NFT programmer
/// turns each of these into a deny ruleset element; the `severs` flag tells the
/// sweep whether revoking this entry must also flush established conntrack flows
/// (block-or-higher) or only gate new ones (D53/§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftDenyInput {
    /// The blocked domain.
    pub domain: String,
    /// The D53 rung the block carries (`None` = no explicit rung).
    pub rung: Option<Rung>,
    /// Whether revoking this block severs established flows (rule 6 / §5): true
    /// iff the rung is block-or-higher.
    pub severs: bool,
}

/// The ruleset-derivation inputs the NFTables programmer needs from the composed
/// document (doc 13 §1.1, §5). The programmer is one of the three embedders — it
/// does NOT recompute composition or deny-overrides; it consumes this derived
/// state (computed off the ONE composed document, rule 2) and turns it into
/// allow-set / deny ruleset elements. Every entry the host snapshot stamps the
/// single [`PolicyVersion`] (rule 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftRulesetInputs {
    /// The allow-set domains (composed allowlist plus every active, non-inert,
    /// enabled-tier baseline-pack entry) the programmer admits into the allow set.
    /// Inert capability-gated entries are EXCLUDED (rule 7: they admit nothing
    /// until the capability lands), and disabled-tier entries are excluded (the
    /// tier is off). Sorted for deterministic ruleset derivation.
    pub allow_domains: Vec<String>,
    /// The composed blocklist as deny inputs, each carrying its §5 severing flag
    /// (rule 6). Deny is monotone across layers (§8.2) — every layer's block is
    /// present. Sorted by domain for deterministic derivation.
    pub deny_inputs: Vec<NftDenyInput>,
    /// The ONE policy version the snapshot stamps (rule 3).
    pub policy_version: PolicyVersion,
}

/// Derive the NFT programmer's ruleset inputs off the composed document (doc 13
/// §1.1, §5). Pure projection of the composed state — no rule is re-evaluated and
/// nothing is re-composed; this reads the ONE [`ComposedPolicy`] the host carries
/// (rule 2) into the allow-set / deny-set shape the programmer turns into
/// ruleset elements.
///
/// Allow-set membership reuses the SAME engine verdict ([`evaluate_domain`]) per
/// candidate domain so the NFT allow set can never admit a domain the DNS / TLS
/// surfaces would refuse (POL-3 no-skew): a domain enters `allow_domains` iff the
/// engine [`Decision::admits`]. Inert (capability-gated) and disabled-tier entries
/// are therefore excluded for free (rule 7).
pub fn nft_ruleset_inputs(policy: &ComposedPolicy) -> NftRulesetInputs {
    // Allow set: every explicit allowlist domain and every baseline-pack fqdn that
    // the SHARED engine admits. Routing each candidate through evaluate_domain (not
    // a parallel membership rule) is what makes the NFT allow set agree with DNS /
    // TLS by construction (POL-3): a deny-overrides block, an inert gate, or a
    // disabled tier each drops the candidate exactly as the other two surfaces see.
    let mut allow_domains: Vec<String> = Vec::new();
    for domain in policy.allowlist.keys().chain(policy.pack_entries.keys()) {
        if dns_admission_decision(policy, domain).admits() {
            allow_domains.push(domain.clone());
        }
    }
    allow_domains.sort();
    allow_domains.dedup();

    // Deny set: the composed (unioned) blocklist, each with its §5 severing flag.
    let mut deny_inputs: Vec<NftDenyInput> = policy
        .blocklist
        .values()
        .map(|be| NftDenyInput {
            domain: be.domain.clone(),
            rung: be.rung,
            severs: be.rung.map(Rung::is_block_or_higher).unwrap_or(false),
        })
        .collect();
    deny_inputs.sort_by(|a, b| a.domain.cmp(&b.domain));

    NftRulesetInputs {
        allow_domains,
        deny_inputs,
        policy_version: host_snapshot_policy_version(policy),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunables surfaced as policy values (rule 5).
// ─────────────────────────────────────────────────────────────────────────────

/// The policy tunables surfaced as POLICY VALUES, not code constants (doc 13 §1
/// rule 5, D68/D70/D71): TTL floor/ceil/grace, the negative-TTL, and the
/// per-session per-domain IP cap. These are read off the policy document so ops
/// can tune them with a policy push, never a release; tests pin the defaults.
///
/// In POL-1 v0 the [`ComposedPolicy`] does not yet carry the `admission` / `dns`
/// blocks (the composer folds posture / lists / pack / families in v0), so this
/// takes the source [`ds_contracts::pol1::PolicyLayer`] whose `admission` / `dns`
/// blocks hold the tunables. The point of the type is that the VALUES live in the
/// schema, not as `const`s a release would have to change — the §1.5 contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunables {
    /// `ttl_floor` (seconds) — admission TTL clamp floor (D68).
    pub ttl_floor: u32,
    /// `ttl_ceil` (seconds) — admission TTL clamp ceiling (D68).
    pub ttl_ceil: u32,
    /// `grace` (seconds) — flat admission grace added to the shared deadline (D68).
    pub grace: u32,
    /// `negative_ttl` (seconds) — denied-domain negative cache TTL; 0 = uncached (D71).
    pub negative_ttl: u32,
    /// `max_ips_per_domain` — per-session per-domain IP cap (D70).
    pub max_ips_per_domain: u32,
}

/// Read the policy tunables off a layer document as policy VALUES (rule 5). The
/// `admission` and `dns` blocks carry the §1.5 tunables; this surfaces them so a
/// consumer reads a policy value, never a code constant. The defaults the schema
/// fills in (when a block is omitted) are the §3 defaults — tests pin them.
pub fn tunables(layer: &ds_contracts::pol1::PolicyLayer) -> Tunables {
    Tunables {
        ttl_floor: layer.admission.ttl_floor,
        ttl_ceil: layer.admission.ttl_ceil,
        grace: layer.admission.grace,
        negative_ttl: layer.dns.negative_ttl,
        max_ips_per_domain: layer.admission.max_ips_per_domain,
    }
}

#[cfg(test)]
mod tests;

// D127 egress-scope fast-path gate tests (doc 23 §6, the policy-core enforcement
// point). Kept in a dedicated inline module (the file's other tests live in the
// `consumer/tests.rs` submodule) so this unit's scope predicate is proven beside
// the code it guards.
#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::pol1_eval::compose;
    use ds_contracts::pol1::parse_layer;
    use ds_contracts::scopes::{SCOPE_CODE_READ, SCOPE_NETWORK_EGRESS};

    // A one-layer policy that ALLOWS one host and BLOCKS another — enough to prove
    // the scope gate runs BEFORE the domain engine (a scope deny pre-empts even an
    // allowed host, and its provenance is the scope gate, not a domain rule).
    fn composed() -> ComposedPolicy {
        let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
allowlist:
  - domain: allowed.example
blocklist:
  - domain: blocked.example
    reason: test-block
    rung: block+log
"#;
        let layer = parse_layer(text).expect("layer parses clean");
        compose(std::slice::from_ref(&layer), &[])
    }

    #[test]
    fn present_egress_scope_passes_through_to_domain_engine() {
        let policy = composed();
        let scopes = vec![
            SCOPE_CODE_READ.to_string(),
            SCOPE_NETWORK_EGRESS.to_string(),
        ];
        // With egress scope present, the scoped decision is BYTE-IDENTICAL to the
        // unscoped surface for the same host (admit for the allowed host, deny for
        // the blocked one) — the scope gate adds nothing once the scope is held.
        assert_eq!(
            tls_connect_decision_scoped(&policy, "allowed.example", &scopes),
            tls_connect_decision(&policy, "allowed.example"),
        );
        assert!(tls_connect_decision_scoped(&policy, "allowed.example", &scopes).admits());
        assert_eq!(
            tls_connect_decision_scoped(&policy, "blocked.example", &scopes),
            tls_connect_decision(&policy, "blocked.example"),
        );
    }

    #[test]
    fn missing_egress_scope_denies_before_admission_lookup() {
        let policy = composed();
        // No egress scope: even an ALLOWED host is denied, and the deny is the
        // scope gate (fast path) — proven by the provenance rule/layer, distinct
        // from any domain rule.
        let scopes = vec![SCOPE_CODE_READ.to_string()];
        let d = tls_connect_decision_scoped(&policy, "allowed.example", &scopes);
        assert!(d.denies(), "missing egress scope must deny an allowed host");
        assert_eq!(d.provenance.rule_id, SCOPE_INSUFFICIENT_RULE);
        assert_eq!(d.provenance.policy_layer, SCOPE_GATE_LAYER);
        // The unscoped surface would have ADMITTED the same host — so the deny is
        // the scope predicate, not the domain engine.
        assert!(tls_connect_decision(&policy, "allowed.example").admits());

        // An empty scope set is likewise denied (no egress authority at all).
        let d_empty = tls_connect_decision_scoped(&policy, "allowed.example", &[]);
        assert!(d_empty.denies());
        assert_eq!(d_empty.provenance.rule_id, SCOPE_INSUFFICIENT_RULE);

        // A scope deny is NOT a §5 revocation sever (rung None → new-flow gate only).
        assert!(!d.severs_established_flows());
        assert!(!d.is_revocation_severing());
    }

    #[test]
    fn egress_scope_satisfied_names_the_fast_path_predicate() {
        // The named predicate agrees with the fast-path branch inside
        // `tls_connect_decision_scoped`: egress present ⇒ true (delegates to the
        // domain engine), absent/empty ⇒ false (fast-path deny). Fail-closed.
        assert!(egress_scope_satisfied(&[SCOPE_NETWORK_EGRESS.to_string()]));
        assert!(egress_scope_satisfied(&[
            SCOPE_CODE_READ.to_string(),
            SCOPE_NETWORK_EGRESS.to_string(),
        ]));
        assert!(!egress_scope_satisfied(&[SCOPE_CODE_READ.to_string()]));
        assert!(!egress_scope_satisfied(&[]));
    }

    #[test]
    fn missing_egress_scope_denies_even_a_blocked_host_at_the_scope_gate() {
        // The scope gate runs first: a blocked host with no egress scope denies at
        // the SCOPE gate (fast path), never reaching the blocklist rung — the
        // provenance proves the ordering.
        let policy = composed();
        let d = tls_connect_decision_scoped(&policy, "blocked.example", &[]);
        assert!(d.denies());
        assert_eq!(d.provenance.rule_id, SCOPE_INSUFFICIENT_RULE);
        assert_eq!(d.rung, None);
    }
}
