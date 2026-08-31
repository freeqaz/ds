// SPDX-License-Identifier: Apache-2.0

//! D127 token scope taxonomy — the `v1:` prefix is the taxonomy version.
//!
//! These constants are the authoritative source for scope strings used in
//! `dreamserpent.auth.v1` sub-token derivation (doc 23 §6; D126/D127).
//! They are consumed by the TLS proxy admission gate (`v1:network:egress`
//! gating on `tls_connect_decision` — the `TODO(seam:admission)` stub in
//! `ds-tlsproxy/src/main.rs`).
//!
//! The Go mirror lives at `identity/auth-sdk/token/config.go`. Both sets of
//! constants MUST agree exactly — a divergence is a cross-language contract bug.

/// Grants read access to the session's code workspace.
pub const SCOPE_CODE_READ: &str = "v1:code:read";
/// Grants write access to the session's code workspace.
pub const SCOPE_CODE_WRITE: &str = "v1:code:write";
/// Grants read access to session-scoped secrets.
pub const SCOPE_SECRETS_READ: &str = "v1:secrets:read";
/// Grants outbound network egress for the session (gating `tls_connect_decision`).
pub const SCOPE_NETWORK_EGRESS: &str = "v1:network:egress";
/// Grants the right to call `TokenAttenuationService.DeriveAgentToken` (orchestrator fan-out only).
pub const SCOPE_IDENT_MINT: &str = "v1:identity:mint";
/// Grants reception of agent lifecycle notifications.
pub const SCOPE_NOTIFY_RECV: &str = "v1:notify:receive";
/// Grants read access to the session's active policy snapshot.
pub const SCOPE_POLICY_READ: &str = "v1:policy:read";
/// Grants write access to the session audit log.
pub const SCOPE_AUDIT_WRITE: &str = "v1:audit:write";

/// All D127 scopes in canonical order.
pub const ALL_SCOPES: &[&str] = &[
    SCOPE_CODE_READ,
    SCOPE_CODE_WRITE,
    SCOPE_SECRETS_READ,
    SCOPE_NETWORK_EGRESS,
    SCOPE_IDENT_MINT,
    SCOPE_NOTIFY_RECV,
    SCOPE_POLICY_READ,
    SCOPE_AUDIT_WRITE,
];

/// Extract the RECOGNIZED D127 scopes carried on a sub-token's raw `ds_scopes`
/// claim (doc 23 §6). The `presented_credential` scope claim is a set of opaque
/// strings; this filters it to the canonical taxonomy ([`ALL_SCOPES`]), dropping
/// anything unrecognized, so a consumer gates on known scopes only and an unknown
/// string can never satisfy a scope predicate (fail-closed). Borrows from the
/// input — no allocation of the strings themselves.
///
/// This is the Rust half of the two-language enforcement: the Go D22 Validate
/// seam asserts `desired_scopes ⊆ ds_scopes` on the same taxonomy, and the scope
/// STRINGS are pinned byte-identical to the Go constants
/// (`identity/auth-sdk/token/config.go`) by `scripts/check-corpus-suffix.sh`.
pub fn scope_from_token(token_scopes: &[String]) -> Vec<&str> {
    token_scopes
        .iter()
        .map(String::as_str)
        .filter(|s| ALL_SCOPES.contains(s))
        .collect()
}

/// Report whether a sub-token's `ds_scopes` claim carries `required` — an exact
/// match against a D127 scope string (doc 23 §6). The fail-closed direction: a
/// token that does not carry the scope returns `false`, and an unrecognized
/// `required` string (not in the taxonomy) is treated as an unmet requirement, so
/// a garbled demand never passes. This is the predicate the policy-core egress
/// gate applies for [`SCOPE_NETWORK_EGRESS`] before the admission-map lookup.
pub fn token_has_scope(token_scopes: &[String], required: &str) -> bool {
    if !ALL_SCOPES.contains(&required) {
        return false;
    }
    token_scopes.iter().any(|s| s == required)
}

/// The presenting sub-token's `ds_scopes` claim as it travels into the connect
/// context (doc 23 §6) — the additive credential-scope surface the D22 Validate
/// seam surfaces to the FORWARD egress gate in `ds-tlsproxy`.
///
/// This grows the *credential* surface additively; it does NOT touch the FROZEN
/// [`crate::session::SessionRef`] address arithmetic. The scope set is always the
/// recognized D127 taxonomy ([`ALL_SCOPES`]) — construction filters through
/// [`scope_from_token`], so an unknown string can never enter the claim and thus
/// can never satisfy a scope predicate (fail-closed).
///
/// An EMPTY claim carries no authority: it satisfies no [`token_has_scope`]
/// predicate, so an armed egress gate denies fast on it (the fail-closed default
/// when the presenting credential carries no scopes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectScopeClaim {
    scopes: Vec<String>,
}

impl ConnectScopeClaim {
    /// The empty claim — no scopes presented (satisfies no predicate; fail-closed).
    pub fn empty() -> Self {
        Self { scopes: Vec::new() }
    }

    /// Build from a raw `ds_scopes` claim, filtering to the recognized D127
    /// taxonomy ([`scope_from_token`]): unknown strings are dropped so the claim
    /// only ever carries canonical scopes. The raw claim's recognized order is
    /// preserved (no dedup).
    pub fn from_raw(raw: &[String]) -> Self {
        Self {
            scopes: scope_from_token(raw)
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    /// Build from the OPTIONAL raw `ds_scopes` claim carried on the connect context —
    /// the validated sub-token's scopes (doc 23 §6). `Some(raw)` filters through
    /// [`from_raw`] (taxonomy-filtered, fail-closed on unknowns); `None` — no
    /// sub-token was surfaced on the connect (the deferred-manual / no-credential
    /// case) — is the [`empty`](Self::empty) claim, which satisfies no predicate so an
    /// armed egress gate denies fast (the fail-closed default). This is the
    /// constructor the ds-tlsproxy LIVE connect-scope source turns a carried
    /// sub-token into the FORWARD scope claim with.
    pub fn from_presented(raw: Option<&[String]>) -> Self {
        match raw {
            Some(scopes) => Self::from_raw(scopes),
            None => Self::empty(),
        }
    }

    /// The standing single-scope grant carrying only [`SCOPE_NETWORK_EGRESS`] — the
    /// disarmed-default claim presented when live scope enforcement is OFF, so the
    /// scope-gated FORWARD decision delegates verbatim to the unscoped engine
    /// verdict (byte-identical to the pre-scope surface).
    pub fn network_egress_grant() -> Self {
        Self {
            scopes: vec![SCOPE_NETWORK_EGRESS.to_string()],
        }
    }

    /// The recognized scope set (already taxonomy-filtered).
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Consume into the owned scope vector (the shape the policy-core oracle wants).
    pub fn into_scopes(self) -> Vec<String> {
        self.scopes
    }

    /// Whether the claim carries no recognized scope (the fast-deny signal).
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Whether the claim carries `required` (a D127 scope string) — the fail-closed
    /// predicate ([`token_has_scope`]): an unrecognized `required` is never held.
    pub fn has_scope(&self, required: &str) -> bool {
        token_has_scope(&self.scopes, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_scopes_have_v1_prefix() {
        for s in ALL_SCOPES {
            assert!(s.starts_with("v1:"), "scope {s:?} missing v1: prefix");
        }
    }

    #[test]
    fn all_scopes_count() {
        assert_eq!(ALL_SCOPES.len(), 8, "D127 defines exactly 8 scopes");
    }

    #[test]
    fn network_egress_scope_matches_go() {
        // Go: token.ScopeNetEgress = "v1:network:egress"
        assert_eq!(SCOPE_NETWORK_EGRESS, "v1:network:egress");
    }

    #[test]
    fn token_has_scope_exact_match() {
        let held = vec![
            SCOPE_CODE_READ.to_string(),
            SCOPE_NETWORK_EGRESS.to_string(),
        ];
        assert!(token_has_scope(&held, SCOPE_NETWORK_EGRESS));
        assert!(token_has_scope(&held, SCOPE_CODE_READ));
        // A scope the token does not carry is not held (fail-closed).
        assert!(!token_has_scope(&held, SCOPE_CODE_WRITE));
        // An empty token holds nothing.
        assert!(!token_has_scope(&[], SCOPE_NETWORK_EGRESS));
    }

    #[test]
    fn token_has_scope_rejects_unknown_required() {
        // An unrecognized required string is never satisfiable, even if the token
        // literally carries that exact string — the demand must be a taxonomy scope.
        let held = vec!["v9:made:up".to_string()];
        assert!(!token_has_scope(&held, "v9:made:up"));
    }

    #[test]
    fn scope_from_token_filters_to_taxonomy() {
        let raw = vec![
            SCOPE_CODE_READ.to_string(),
            "v9:unknown:scope".to_string(),
            SCOPE_NETWORK_EGRESS.to_string(),
        ];
        let got = scope_from_token(&raw);
        assert_eq!(got, vec![SCOPE_CODE_READ, SCOPE_NETWORK_EGRESS]);
    }

    #[test]
    fn connect_scope_claim_empty_carries_no_authority() {
        let claim = ConnectScopeClaim::empty();
        assert!(claim.is_empty());
        assert!(claim.scopes().is_empty());
        // An empty claim satisfies no predicate (fail-closed egress deny).
        assert!(!claim.has_scope(SCOPE_NETWORK_EGRESS));
        assert!(claim.into_scopes().is_empty());
    }

    #[test]
    fn connect_scope_claim_default_is_empty() {
        // Derive(Default) must agree with the explicit empty constructor.
        assert_eq!(ConnectScopeClaim::default(), ConnectScopeClaim::empty());
    }

    #[test]
    fn connect_scope_claim_network_egress_grant() {
        let claim = ConnectScopeClaim::network_egress_grant();
        assert!(!claim.is_empty());
        assert!(claim.has_scope(SCOPE_NETWORK_EGRESS));
        // The standing grant carries ONLY egress — nothing else.
        assert!(!claim.has_scope(SCOPE_CODE_READ));
        assert_eq!(claim.scopes(), &[SCOPE_NETWORK_EGRESS.to_string()]);
    }

    #[test]
    fn connect_scope_claim_from_raw_filters_to_taxonomy() {
        let raw = vec![
            SCOPE_NETWORK_EGRESS.to_string(),
            SCOPE_CODE_READ.to_string(),
            "v9:made:up".to_string(),
        ];
        let claim = ConnectScopeClaim::from_raw(&raw);
        // Recognized scopes retained in order; the unknown string is dropped.
        assert_eq!(
            claim.scopes(),
            &[
                SCOPE_NETWORK_EGRESS.to_string(),
                SCOPE_CODE_READ.to_string()
            ]
        );
        assert!(claim.has_scope(SCOPE_NETWORK_EGRESS));
        // An unknown string can never enter the claim, so it never satisfies a
        // predicate even when literally presented (fail-closed).
        assert!(!claim.has_scope("v9:made:up"));
    }

    #[test]
    fn connect_scope_claim_from_raw_without_egress_denies_fast() {
        // A presented set lacking egress carries no egress authority.
        let claim = ConnectScopeClaim::from_raw(&[SCOPE_CODE_READ.to_string()]);
        assert!(!claim.is_empty());
        assert!(!claim.has_scope(SCOPE_NETWORK_EGRESS));
    }

    #[test]
    fn connect_scope_claim_from_presented_maps_absent_and_present() {
        // No sub-token surfaced on the connect (`None`) → the EMPTY claim (fail-closed
        // egress deny) — byte-identical to the explicit empty constructor.
        assert_eq!(
            ConnectScopeClaim::from_presented(None),
            ConnectScopeClaim::empty()
        );
        assert!(!ConnectScopeClaim::from_presented(None).has_scope(SCOPE_NETWORK_EGRESS));

        // A surfaced sub-token (`Some`) is taxonomy-filtered exactly like `from_raw`:
        // recognized scopes retained in order, unknown strings dropped (fail-closed).
        let raw = vec![
            SCOPE_NETWORK_EGRESS.to_string(),
            "v9:made:up".to_string(),
            SCOPE_CODE_READ.to_string(),
        ];
        let claim = ConnectScopeClaim::from_presented(Some(&raw));
        assert_eq!(claim, ConnectScopeClaim::from_raw(&raw));
        assert!(claim.has_scope(SCOPE_NETWORK_EGRESS));
        assert!(!claim.has_scope("v9:made:up"));
    }
}
