//! `RejectReason` — the reject/drop reason code carried on FlowRecord and drop
//! events (doc 14 §2, D70).
//!
//! D70's frozen distinction: the udp/443 reject is **rejected (icmp
//! port-unreachable) + counted per session — never silently dropped**. The
//! reason code is what makes the D70 flip-to-inspect trigger queryable off-box.
//! `QuicBlocked` is therefore a *distinct* reason from generic default-deny so a
//! standing query can count QUIC-reject volume per session without conflating it
//! with everything else the default-deny posture drops.

/// Why a flow or packet was rejected or dropped (doc 14 §2/§5, D70).
///
/// The discriminant set is a frozen contract: `QuicBlocked` must stay distinct
/// from `DefaultDeny`. New variants are additive only (a removal/renumber would
/// be a v2 event, mirrored on the LOG-1 proto side per doc 14 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// udp/443 (QUIC) rejected with icmp port-unreachable and counted per
    /// session (D70). Distinct from [`RejectReason::DefaultDeny`] so the
    /// flip-to-inspect trigger is queryable off-box. DNS-4 rule 4 steers
    /// cooperative clients; this NFT-4 reject is the sole control for
    /// non-cooperative clients (doc 14 §10).
    QuicBlocked,
    /// The generic default-deny verdict: traffic with no admitting rule
    /// (D3/D4). The catch-all reason that is *not* the QUIC carveout.
    DefaultDeny,
    /// A NFT-2 three-keys-agree drop: iif / assigned guest IP / ct mark
    /// disagreement = kernel drop (doc 14 §2/§4). Surfaced as a reason so the
    /// disagreement is observable, not silent.
    KeysDisagree,
    /// Recovery-failure refusal: original-destination recovery failed →
    /// connection refused, attributed to the session (D69, doc 14 §2 event
    /// class). Keeps the mechanism-agnostic recovery interface observable.
    RecoveryFailed,
    /// An admission expired before this NEW flow (D68): expiry gates new flows
    /// only and is not revocation. Distinct so expired-admission refusals are
    /// queryable for the TLS-1 expired-admission path.
    AdmissionExpired,
    /// An explicit policy revocation severed the flow (D68/D72 revocation +
    /// `flush_session`). Distinct from passive expiry.
    Revoked,
}

impl RejectReason {
    /// Whether this reason is the D70 QUIC carveout — the one a flip-to-inspect
    /// trigger counts. True only for [`RejectReason::QuicBlocked`].
    pub const fn is_quic_carveout(self) -> bool {
        matches!(self, RejectReason::QuicBlocked)
    }

    /// A stable lowercase token for logs/metrics labels. Additive-only,
    /// mirrored on the LOG-1 proto enum names (doc 14 §2).
    pub const fn as_str(self) -> &'static str {
        match self {
            RejectReason::QuicBlocked => "quic_blocked",
            RejectReason::DefaultDeny => "default_deny",
            RejectReason::KeysDisagree => "keys_disagree",
            RejectReason::RecoveryFailed => "recovery_failed",
            RejectReason::AdmissionExpired => "admission_expired",
            RejectReason::Revoked => "revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_is_distinct_from_default_deny() {
        assert_ne!(RejectReason::QuicBlocked, RejectReason::DefaultDeny);
        assert!(RejectReason::QuicBlocked.is_quic_carveout());
        assert!(!RejectReason::DefaultDeny.is_quic_carveout());
    }

    #[test]
    fn no_other_reason_is_the_quic_carveout() {
        for r in [
            RejectReason::DefaultDeny,
            RejectReason::KeysDisagree,
            RejectReason::RecoveryFailed,
            RejectReason::AdmissionExpired,
            RejectReason::Revoked,
        ] {
            assert!(!r.is_quic_carveout(), "{r:?} must not be the carveout");
        }
    }

    #[test]
    fn tokens_are_distinct_and_stable() {
        let all = [
            RejectReason::QuicBlocked,
            RejectReason::DefaultDeny,
            RejectReason::KeysDisagree,
            RejectReason::RecoveryFailed,
            RejectReason::AdmissionExpired,
            RejectReason::Revoked,
        ];
        let mut seen = std::collections::HashSet::new();
        for r in all {
            assert!(seen.insert(r.as_str()), "duplicate token for {r:?}");
        }
        assert_eq!(RejectReason::QuicBlocked.as_str(), "quic_blocked");
    }
}
