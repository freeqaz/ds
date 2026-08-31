//! `flush_session` — the one revocation/teardown conntrack-flush primitive,
//! defined once and cited by all three callers (doc 14 §5, D76).
//!
//! The SIGNATURE lives here; the IMPLEMENTATION lives in `ds-nft` (the single
//! nft/netlink writer). Callers:
//!
//! - **D68 revocation** — rung-conditional per D53: flush when the revoking
//!   rule's rung is block-or-higher.
//! - **D72 revocation sweep** — same rung rule; the (d)-rig push-to-enforced
//!   clock stops at sweep-plus-flush completion.
//! - **NFT-6 teardown** — unconditional, `legs = all`, emits final destroy
//!   events with byte counts into ds-flowlog.
//!
//! The primitive is DS_MARK_MASK-aware (a bare-index match never fires against
//! the composite layout) and spans both leg nibbles (`0x1` and `0x2`) when the
//! rung severs. Effectiveness requires `nf_conntrack_tcp_loose=0` (doc 14 §11).
//!
//! This module declares the contract shape only — no `nft`/netlink types, no
//! framework types (doc 14 §6). The implementor in `ds-nft` provides the
//! [`FlushSession`] body.

use crate::mark::Leg;
use crate::session::SessionRef;

/// Which destinations a flush targets (doc 14 §5). The revocation path narrows
/// the flush to the IPs being revoked (refcount-zero set elements, per the §3
/// reverse index); teardown flushes everything for the session.
///
/// This is a contract shape, not an address type — it deliberately avoids any
/// concrete IP/CIDR representation so neither hickory nor pingora address types
/// can leak across the crate (D67/D40). The `ds-nft` implementor binds it to
/// its own address model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DstFilter {
    /// Flush every destination for the session (teardown / NFT-6).
    All,
    /// Flush only the listed destinations (revocation): opaque destination
    /// keys whose concrete type the `ds-nft` implementor owns. Each entry is
    /// the same key shape the §3 admission map's reverse index counts.
    Only(Vec<DstKey>),
}

/// An opaque destination key. The shape is a contract placeholder: the concrete
/// address representation is owned by `ds-nft` / the §3 admission map and is
/// deliberately NOT an address framework type here (D67/D40).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DstKey(pub String);

impl DstKey {
    /// Render the destination as a literal an `nft` set element / `conntrack
    /// --dst` accepts (dotted-quad for v4, RFC 5952 for v6).
    ///
    /// [`crate::dns_admission::AdmittedAddr::to_dst_key`] freezes this key's
    /// textual form as `"<family>:<lower-hex-octets>"` — the right shape for the
    /// §3 refcount reverse index (the bytes ARE the identity), but NOT a string
    /// any CLI accepts. The two `ds-nft` consumers that render a key into a
    /// command — the `nft add/delete element` allow-set ops (admission/refresh)
    /// and the `conntrack -D --dst` revocation narrowing — MUST go through this,
    /// or nft rejects `v4:a04f680a` outright (`syntax error`) and admission /
    /// revocation fail closed with no kernel effect.
    ///
    /// A key that is already a bare address literal (a hand-written fixture, or a
    /// future producer that stores literals) passes through unchanged, so this is
    /// a safe idempotent normaliser, not a second encoding to keep in sync.
    pub fn address_literal(&self) -> String {
        if let Some(hex) = self.0.strip_prefix("v4:") {
            if hex.len() == 8 {
                if let Ok(bits) = u32::from_str_radix(hex, 16) {
                    return std::net::Ipv4Addr::from(bits).to_string();
                }
            }
        } else if let Some(hex) = self.0.strip_prefix("v6:") {
            if hex.len() == 32 {
                if let Ok(bits) = u128::from_str_radix(hex, 16) {
                    return std::net::Ipv6Addr::from(bits).to_string();
                }
            }
        }
        self.0.clone()
    }
}

/// Which boundary legs a flush spans (doc 14 §5).
///
/// Revocation severs the agent-VM leg (`0x1`) and the ds-tlsproxy upstream leg
/// (`0x2`) together; teardown spans all legs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegSelector {
    /// Every leg nibble (NFT-6 teardown: `legs = all`).
    All,
    /// A specific set of legs (revocation: typically `{AgentVm, TlsproxyUpstream}`).
    Some(Vec<Leg>),
}

impl LegSelector {
    /// The pair severed on a block-or-higher revocation rung (doc 14 §5): the
    /// agent-VM leg and the ds-tlsproxy upstream leg.
    pub fn sever_pair() -> LegSelector {
        LegSelector::Some(vec![Leg::AgentVm, Leg::TlsproxyUpstream])
    }
}

/// Outcome of a flush: how many conntrack entries were destroyed, for the
/// per-session destroy-event accounting NFT-6 emits into ds-flowlog
/// (doc 14 §5). A contract shape — the implementor fills it in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushOutcome {
    /// Number of conntrack entries destroyed by this flush.
    pub entries_flushed: u64,
}

/// The error surface of a flush is implementor-defined (netlink/nft errors live
/// in `ds-nft`). The contract fixes only that it is an opaque, `Sized` error
/// type so callers can propagate it.
pub trait FlushError: core::fmt::Debug {}

/// The `flush_session` primitive (doc 14 §5). Defined once here; implemented in
/// `ds-nft`. All three callers (D68 revocation, D72 sweep, NFT-6 teardown)
/// invoke this one signature.
///
/// Contract obligations the implementor must honour (doc 14 §5):
/// - the conntrack match is DS_MARK_MASK-aware — a bare-index match must never
///   fire against the composite layout;
/// - `legs` selects which leg nibbles are severed; `LegSelector::sever_pair()`
///   is the block-rung default;
/// - `dst_filter` narrows the destinations (revocation) or is `All` (teardown);
/// - effectiveness requires `nf_conntrack_tcp_loose=0` (doc 14 §11).
pub trait FlushSession {
    /// The implementor's error type (netlink/nft failures), opaque to callers.
    type Error: FlushError;

    /// Flush conntrack entries for `session` matching `dst_filter` on `legs`.
    fn flush_session(
        &self,
        session: &SessionRef,
        dst_filter: &DstFilter,
        legs: &LegSelector,
    ) -> Result<FlushOutcome, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionRef;

    #[test]
    fn sever_pair_is_agent_and_tlsproxy() {
        assert_eq!(
            LegSelector::sever_pair(),
            LegSelector::Some(vec![Leg::AgentVm, Leg::TlsproxyUpstream])
        );
    }

    #[test]
    fn dst_key_address_literal_renders_cli_forms() {
        use crate::dns_admission::{AddressFamily, AdmittedAddr};
        // The frozen hex identity (a04f680a == 160.79.104.10) renders to the
        // dotted-quad form an nft set element / `conntrack --dst` accepts.
        let v4 = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![160, 79, 104, 10],
        };
        assert_eq!(v4.to_dst_key().0, "v4:a04f680a");
        assert_eq!(v4.to_dst_key().address_literal(), "160.79.104.10");
        // v6 hex identity renders to RFC 5952.
        let mut octets = vec![0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[2] = 0x0d;
        octets[3] = 0xb8;
        octets[15] = 0x01;
        let v6 = AdmittedAddr {
            family: AddressFamily::V6,
            octets,
        };
        assert_eq!(v6.to_dst_key().address_literal(), "2001:db8::1");
        // Already-literal keys (fixtures / a future literal producer) pass through.
        assert_eq!(
            DstKey("203.0.113.10".into()).address_literal(),
            "203.0.113.10"
        );
        // A malformed prefixed key is left as-is — it fails closed downstream
        // (invalid nft batch) rather than being silently mis-parsed.
        assert_eq!(DstKey("v4:zz".into()).address_literal(), "v4:zz");
    }

    // A trivial in-memory implementor proves the signature is object-safe-ish
    // for ordinary static dispatch and that callers can be written against it
    // without any nft/netlink types — the whole point of the contract split.
    #[derive(Debug)]
    struct NotPlumbed;
    impl FlushError for NotPlumbed {}

    struct StubWriter;
    impl FlushSession for StubWriter {
        type Error = NotPlumbed;
        fn flush_session(
            &self,
            _session: &SessionRef,
            dst_filter: &DstFilter,
            legs: &LegSelector,
        ) -> Result<FlushOutcome, Self::Error> {
            // teardown shape: all legs, all destinations.
            if matches!(dst_filter, DstFilter::All) && matches!(legs, LegSelector::All) {
                Ok(FlushOutcome { entries_flushed: 0 })
            } else {
                Ok(FlushOutcome::default())
            }
        }
    }

    #[test]
    fn a_caller_can_link_the_signature_with_no_framework_types() {
        let writer = StubWriter;
        let session = SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            7,
            "dstap-7".into(),
        );
        let out = writer
            .flush_session(&session, &DstFilter::All, &LegSelector::All)
            .expect("stub flush");
        assert_eq!(out, FlushOutcome { entries_flushed: 0 });
    }
}
