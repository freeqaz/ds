//! POL-1 v0 evaluator — the consumer side of the §7 parse→evaluate round-trip
//! (doc 13 §1.1/§1.2, §7, §8.2).
//!
//! `policy-core` is THE one evaluator (doc 13 §1 rule 1). The *schema types*,
//! the *document reader*, and the *parse-time validators* live in `ds-contracts`
//! ([`ds_contracts::pol1`]); this module is the brain that consumes a composed
//! document and produces verdicts. The split is the doc 14 §6 home discipline:
//! ds-contracts defines shapes and validates them at parse; policy-core decides.
//!
//! What this module adds on top of the parsed [`PolicyLayer`]s:
//!
//! - **Layered composition with deny-overrides (§1.2, §8.2).** [`compose`] folds
//!   `system-baseline → org → repo/session` into one [`ComposedPolicy`]: blocklists
//!   are unioned (deny is monotone — a later layer tightens, never loosens), and
//!   allowlists/posture/timers take the most-specific layer's value EXCEPT where a
//!   block at ANY layer vetoes. The host receives only the composed output, never
//!   raw layers (§1.2).
//! - **Capability-gate inertness (§1.7, §8.2, D74).** A baseline-pack entry whose
//!   `requires:` capability is absent is tagged INERT in the composed document and
//!   [`evaluate_domain`] admits NOTHING for it (not a domain-level fallback, not a
//!   silent skip) while emitting the logged warning — observably inert until the
//!   capability lands (the §7 capability-gate inertness done-when).
//! - **Domain evaluation.** [`evaluate_domain`] resolves a single domain query to
//!   an [`Eval`] verdict carrying POL-3 provenance (rule id, policy layer, policy
//!   version) — deny-overrides applied, capability-gated entries inert.
//!
//! No hickory or pingora types cross this module (D67/D40); it consumes only the
//! family-agnostic ds-contracts contract shapes.

use ds_contracts::pol1::{BlockEntry, PackEntry, PolicyLayer, Posture, Rung, ServiceEntry, Tier};
use std::collections::BTreeMap;

/// A warning emitted during composition / evaluation (the §1.7 "logged warning"
/// for a capability-gated entry). The caller (the boundary host agent) routes
/// these to LOG-1; this type just carries the structured payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyWarning {
    /// A short machine code (e.g. "capability-gate-inert").
    pub code: String,
    /// The subject (e.g. the gated FQDN).
    pub subject: String,
    /// Human-readable detail.
    pub detail: String,
}

/// POL-3 provenance on a verdict (doc 13 §1.4 / POL-3): matched rule id, the
/// composing layer, and the policy version. Mirrors the shape
/// [`ds_contracts::dns_admission::Provenance`] stamps onto admissions — kept local
/// here so the evaluator's verdict type owns its own provenance rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The matched rule id (e.g. a blocklist domain, a pack family, an allow rule).
    pub rule_id: String,
    /// The composing policy layer the matched rule came from.
    pub policy_layer: String,
    /// The policy version (the layer's `schema_version` / pack version in v0).
    pub policy_version: String,
}

/// The verdict the evaluator returns for a domain query (doc 13 §1.1; the doc 11
/// §4 frozen verdict family, narrowed to what POL-1 domain evaluation needs in
/// v0). Every non-trivial verdict carries POL-3 [`Provenance`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Eval {
    /// Admit the flow. Carries the matched rule's provenance.
    Allow(Provenance),
    /// Deny the flow at the given D53 rung. A `block-or-higher` rung severs
    /// established flows on revocation (§5). Carries provenance.
    Deny {
        /// The deny rung (D53). `None` for a posture/default deny with no explicit
        /// rule rung; an explicit blocklist rung is carried when present.
        rung: Option<Rung>,
        /// POL-3 provenance.
        provenance: Provenance,
    },
    /// Ask the user (unknown-domain posture path). Carries provenance.
    Ask(Provenance),
    /// The domain matched ONLY a capability-gated (inert) entry: admit NOTHING
    /// (§1.7). This is distinct from `Deny` — it is the observable "inert" state
    /// the §7 capability-gate test asserts (admits nothing, emits a warning), not
    /// a policy block. Carries provenance and the unmet capability name.
    InertCapabilityGated {
        /// The capability the gated entry needs (e.g. "http-policy").
        requires: String,
        /// POL-3 provenance.
        provenance: Provenance,
    },
}

impl Eval {
    /// The provenance every verdict carries.
    pub fn provenance(&self) -> &Provenance {
        match self {
            Eval::Allow(p)
            | Eval::Ask(p)
            | Eval::Deny { provenance: p, .. }
            | Eval::InertCapabilityGated { provenance: p, .. } => p,
        }
    }

    /// Whether this verdict admits the flow. An inert capability-gated entry does
    /// NOT admit (§1.7) — that is the whole point of the inertness contract.
    pub fn admits(&self) -> bool {
        matches!(self, Eval::Allow(_))
    }
}

/// One composed pack entry, carrying the inert tag composition computes (§8.2):
/// an entry whose `requires:` capability is absent is kept in the composed
/// document tagged inert, not dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedPackEntry {
    /// The underlying parsed pack entry.
    pub entry: PackEntry,
    /// The composing layer this entry came from.
    pub source_layer: String,
    /// Whether this entry is INERT (its `requires:` capability is not present).
    /// An inert entry admits NOTHING (§1.7); composition keeps it tagged rather
    /// than dropping it so the inertness is observable, not a silent skip.
    pub inert: bool,
}

/// The composed policy document — the deny-wins composition of the layer stack
/// (§1.2). The host snapshot carries THIS, never raw layers (§1.2/§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedPolicy {
    /// The most-specific layer's posture (repo/session over org over baseline).
    pub posture: Posture,
    /// The unioned blocklist — every layer's deny is present (deny is monotone).
    /// Keyed by domain so a later-layer rung tightening on the same domain wins.
    pub blocklist: BTreeMap<String, BlockEntry>,
    /// The unioned allowlist (domain → source layer for provenance).
    pub allowlist: BTreeMap<String, String>,
    /// The composed baseline-pack entries (keyed by fqdn), inert-tagged.
    pub pack_entries: BTreeMap<String, ComposedPackEntry>,
    /// The composed family → tier map (most-specific layer wins per family).
    pub families: BTreeMap<String, Tier>,
    /// The composed credential-swap service registry (doc 13 §3 `services[]`) — the
    /// SAME snapshot the TLS-1 SNI gate consults, folded here so the ds-tlsproxy TLS-5
    /// [`SwapRegistry`](../../services/ds-tlsproxy/src/swap.rs) is built off the LIVE
    /// composed policy rather than a host-local env pack (D8/D83, doc 12 §13.3).
    ///
    /// Composition follows the same most-specific-layer-wins discipline as the pack
    /// entries/families/allowlist: services are keyed by their `service` id during the
    /// fold (a later, more-specific layer supplies the row for that id) and then
    /// materialized in deterministic (`service`-id-sorted) order. Empty when no layer
    /// carries a `services[]` row — the default-deny-of-swap posture the proxy then
    /// falls back to its operator pack (or the empty registry) for.
    pub services: Vec<ServiceEntry>,
    /// The composed policy version string (the most-specific layer's
    /// `schema_version`; v0 has no `policy_log` seq yet).
    pub policy_version: String,
    /// Warnings raised during composition (the §1.7 capability-gate warnings).
    pub warnings: Vec<PolicyWarning>,
}

/// Compose a layer stack into one deny-wins composed document (§1.2, §8.2).
///
/// `layers` is the stack in precedence order `system-baseline → org →
/// repo/session` (index 0 lowest precedence). `available_capabilities` is the set
/// of capabilities that currently exist (e.g. `{"http-policy"}` once TLS-6 lands);
/// a pack entry whose `requires:` is NOT in this set is tagged inert with a logged
/// warning (§1.7) — it never silently over-admits and never silently no-ops.
///
/// Frozen properties (§1.2, §8.2):
/// - **blocklists always win**: every layer's blocklist entry is present in the
///   composed output (deny is monotone — no layer removes a block); a later layer
///   may tighten the rung on the same domain.
/// - allowlists / posture / families take the most-specific layer's value;
/// - the composed output is deny-complete and is what the host applies — callers
///   evaluate against this, never re-running the merge.
pub fn compose(layers: &[PolicyLayer], available_capabilities: &[&str]) -> ComposedPolicy {
    // Default posture if the stack is empty (never expected — there is always a
    // system-baseline) is `standard`; otherwise the most-specific layer wins.
    let mut posture = Posture::Standard;
    let mut blocklist: BTreeMap<String, BlockEntry> = BTreeMap::new();
    let mut allowlist: BTreeMap<String, String> = BTreeMap::new();
    let mut pack_entries: BTreeMap<String, ComposedPackEntry> = BTreeMap::new();
    let mut families: BTreeMap<String, Tier> = BTreeMap::new();
    // Services keyed by `service` id during the fold so a later, more-specific layer
    // supplies the row for that id (most-specific-layer-wins, like pack entries /
    // families). Materialized into a Vec in deterministic id-sorted order below.
    let mut services: BTreeMap<String, ServiceEntry> = BTreeMap::new();
    let mut warnings: Vec<PolicyWarning> = Vec::new();
    let mut policy_version = String::new();

    for layer in layers {
        let layer_name = layer_token(layer);
        // Posture / families / pack entries: most-specific layer wins (layers
        // are iterated in precedence order, so a later write overwrites).
        posture = layer.posture;
        policy_version = layer.schema_version.clone();
        for (fam, tier) in &layer.baseline_pack.families {
            families.insert(fam.clone(), *tier);
        }

        // Blocklist: union — deny is monotone. A later layer tightening the rung
        // on the same domain wins (most-specific layer's rung).
        for be in &layer.blocklist {
            blocklist.insert(be.domain.clone(), be.clone());
        }

        // Allowlist: union; provenance is the most-specific layer that allowed it.
        for ae in &layer.allowlist {
            allowlist.insert(ae.domain.clone(), layer_name.clone());
        }

        // Services (credential-swap registry): most-specific layer wins per service
        // id (later layers overwrite an earlier row for the same `service`). Deny is
        // not relevant here — a service row ARMS a swap; the blocklist above still
        // vetoes any host the swap would reach.
        for se in &layer.services {
            services.insert(se.service.clone(), se.clone());
        }

        // Pack entries: most-specific layer wins per fqdn; tag inert if the
        // entry's required capability is absent (§1.7, §8.2).
        for entry in &layer.baseline_pack.entries {
            let inert = match &entry.requires {
                Some(cap) if !available_capabilities.contains(&cap.as_str()) => {
                    warnings.push(PolicyWarning {
                        code: "capability-gate-inert".to_string(),
                        subject: entry.fqdn.clone(),
                        detail: format!(
                            "baseline-pack entry {:?} requires capability {:?} which is not \
                             present; entry is INERT and admits nothing until it lands (§1.7/D74)",
                            entry.fqdn, cap
                        ),
                    });
                    true
                }
                _ => false,
            };
            pack_entries.insert(
                entry.fqdn.clone(),
                ComposedPackEntry {
                    entry: entry.clone(),
                    source_layer: layer_name.clone(),
                    inert,
                },
            );
        }
    }

    ComposedPolicy {
        posture,
        blocklist,
        allowlist,
        pack_entries,
        families,
        // Deterministic id-sorted order (BTreeMap value iteration) so a given layer
        // stack always composes to the same registry vector.
        services: services.into_values().collect(),
        policy_version,
        warnings,
    }
}

/// Evaluate a single domain query against a composed document (the §7
/// parse→evaluate round-trip endpoint). Deny-overrides applied; capability-gated
/// pack entries are inert (admit nothing, §1.7).
///
/// Resolution order (deny-overrides: blocklist always wins):
/// 1. A blocklist match at any layer → `Deny` (carries the rule's rung; a
///    block-or-higher rung severs established flows on revocation, §5).
/// 2. An explicit allowlist match → `Allow`.
/// 3. A baseline-pack entry match:
///    - inert (capability-gated, requires absent) → `InertCapabilityGated`
///      (admits NOTHING — §1.7);
///    - in an ENABLED family → `Allow`;
///    - in a DISABLED family → `Deny` (the tier is off).
/// 4. No match → `Ask` (unknown-domain posture path; the attendedness downgrade
///    to block is the orchestrator-signal layer, not modelled in this pure fn).
pub fn evaluate_domain(policy: &ComposedPolicy, domain: &str) -> Eval {
    // 1. Deny-overrides: a blocklist match wins over everything (§1.2).
    if let Some(be) = policy.blocklist.get(domain) {
        return Eval::Deny {
            rung: be.rung,
            provenance: Provenance {
                rule_id: format!("blocklist:{}", be.domain),
                policy_layer: "composed".to_string(),
                policy_version: policy.policy_version.clone(),
            },
        };
    }

    // 2. Explicit allowlist.
    if let Some(layer) = policy.allowlist.get(domain) {
        return Eval::Allow(Provenance {
            rule_id: format!("allowlist:{domain}"),
            policy_layer: layer.clone(),
            policy_version: policy.policy_version.clone(),
        });
    }

    // 3. Baseline-pack entry.
    if let Some(ce) = policy.pack_entries.get(domain) {
        let provenance = Provenance {
            rule_id: format!("baseline-pack:{}/{}", ce.entry.family, ce.entry.fqdn),
            policy_layer: ce.source_layer.clone(),
            policy_version: policy.policy_version.clone(),
        };
        // Inert (capability-gated): admit NOTHING (§1.7). Distinct from a deny.
        if ce.inert {
            let requires = ce.entry.requires.clone().unwrap_or_default();
            return Eval::InertCapabilityGated {
                requires,
                provenance,
            };
        }
        // Tier gate: enabled family admits, disabled family denies.
        match policy.families.get(&ce.entry.family) {
            Some(Tier::Enabled) => return Eval::Allow(provenance),
            // disabled (or unknown family) → the tier is off.
            _ => {
                return Eval::Deny {
                    rung: None,
                    provenance,
                }
            }
        }
    }

    // 4. Unknown domain → ask (posture-dependent; the unattended downgrade to
    // block is the orchestrator-signal layer, not this pure evaluation).
    Eval::Ask(Provenance {
        rule_id: "ask:unknown_domain".to_string(),
        policy_layer: "composed".to_string(),
        policy_version: policy.policy_version.clone(),
    })
}

fn layer_token(layer: &PolicyLayer) -> String {
    use ds_contracts::pol1::Layer::*;
    match layer.layer {
        SystemBaseline => "system-baseline",
        Org => "org",
        Repo => "repo",
        Session => "session",
    }
    .to_string()
}

#[cfg(test)]
mod tests;
