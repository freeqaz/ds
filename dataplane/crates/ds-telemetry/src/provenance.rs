//! POL-3 provenance — the mandatory `{rule_id, policy_layer, policy_version}`
//! triple every event-construction entry point requires (doc 14 §2 `DnsEvent`
//! POL-3 row, doc 11 §5.5; D67/POL-3).
//!
//! # Why this lives here, and why it is mandatory *by construction*
//!
//! Doc 14 §2 freezes "POL-3 provenance: rule id, policy layer, policy version —
//! mandatory; missing provenance fails CI" and notes it is "the same provenance
//! struct as `PolicyDecision`". The ds-telemetry crate owns CONVENTIONS, not the
//! frozen LOG-1 schema (that lands in `ds-contracts` from the Stage-0 proto
//! freeze), so this is the convention-layer mirror of that field shape — the
//! same `{rule_id, policy_layer, policy_version}` triple the `ds-dnsgate`
//! `event.rs` `EventProvenance` mirror carries (doc 11 §5.5). When the frozen
//! `ds-contracts::Provenance` lands, the migration replaces this type, never the
//! emission sites (see [`crate::event`]).
//!
//! The doc says "missing provenance fails CI." We make it *structurally
//! impossible to construct an event without provenance* rather than asserting it
//! after the fact: the event-construction entry points ([`crate::event`]) take a
//! [`Provenance`] by value, and the only constructor that builds one validates it
//! is non-empty. A construction without provenance is therefore a compile-time
//! failure (the field is non-optional and has no `Default`); a construction with
//! *empty* provenance is a test-time failure ([`Provenance::new`] returns
//! `Err`). It is never a silent pass.

/// The POL-3 provenance triple, mandatory on every constructed event.
///
/// Plain owned `String`s only — never a framework type, never a `ds-contracts`
/// type (the LOG-1 freeze is the separate seam; this is the conventions mirror,
/// like `ds-dnsgate`'s `EventProvenance`). No `Default`: an event has no
/// well-defined "zero" provenance, so there is no way to materialize a blank
/// triple by accident.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Provenance {
    rule_id: String,
    policy_layer: String,
    policy_version: String,
}

/// The error a [`Provenance::new`] returns when a field is missing — the
/// test-time face of "missing provenance fails CI" (doc 14 §2). A construction
/// path that ignores this `Result` cannot silently emit a blank-provenance event:
/// the only way to obtain a [`Provenance`] is through a checked constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// `rule_id` was empty — no matched rule was recorded (POL-3 violation).
    MissingRuleId,
    /// `policy_layer` was empty — no composing layer was recorded (POL-3 violation).
    MissingPolicyLayer,
    /// `policy_version` was empty — no policy version was stamped (POL-3 violation).
    MissingPolicyVersion,
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let which = match self {
            ProvenanceError::MissingRuleId => "rule_id",
            ProvenanceError::MissingPolicyLayer => "policy_layer",
            ProvenanceError::MissingPolicyVersion => "policy_version",
        };
        write!(f, "POL-3 provenance is missing its {which}")
    }
}

impl std::error::Error for ProvenanceError {}

impl Provenance {
    /// Build a checked POL-3 triple. Every field must be non-empty — an empty
    /// field is the convention-layer face of "missing provenance fails CI"
    /// (doc 14 §2): it returns `Err`, never an event with blank provenance.
    pub fn new(
        rule_id: impl Into<String>,
        policy_layer: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let rule_id = rule_id.into();
        let policy_layer = policy_layer.into();
        let policy_version = policy_version.into();
        if rule_id.is_empty() {
            return Err(ProvenanceError::MissingRuleId);
        }
        if policy_layer.is_empty() {
            return Err(ProvenanceError::MissingPolicyLayer);
        }
        if policy_version.is_empty() {
            return Err(ProvenanceError::MissingPolicyVersion);
        }
        Ok(Self {
            rule_id,
            policy_layer,
            policy_version,
        })
    }

    /// The matched rule id that produced the verdict (POL-3).
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// The composing policy layer the rule came from (POL-3).
    pub fn policy_layer(&self) -> &str {
        &self.policy_layer
    }

    /// The policy version under which the verdict was minted (POL-3).
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_triple_is_accepted() {
        let p = Provenance::new(
            "core/api.anthropic.com",
            "pol2-system-baseline",
            "2026-06-01",
        )
        .expect("a full triple is valid");
        assert_eq!(p.rule_id(), "core/api.anthropic.com");
        assert_eq!(p.policy_layer(), "pol2-system-baseline");
        assert_eq!(p.policy_version(), "2026-06-01");
    }

    #[test]
    fn each_empty_field_is_a_construction_time_failure() {
        // "missing provenance fails CI" (doc 14 §2): every empty field is a hard
        // Err, never a silent blank-provenance pass.
        assert_eq!(
            Provenance::new("", "layer", "v"),
            Err(ProvenanceError::MissingRuleId)
        );
        assert_eq!(
            Provenance::new("rule", "", "v"),
            Err(ProvenanceError::MissingPolicyLayer)
        );
        assert_eq!(
            Provenance::new("rule", "layer", ""),
            Err(ProvenanceError::MissingPolicyVersion)
        );
    }
}
