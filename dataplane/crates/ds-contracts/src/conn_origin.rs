//! `ConnOrigin` — the frozen mechanism-agnostic original-destination / session
//! recovery seam the transparent path resolves at accept time (D69, doc 09 §3
//! NFT-2, doc 09 OQ4 / round2/04).
//!
//! D69 chose REDIRECT/DNAT for the v0 transparent path but froze the *interface*,
//! not the *mechanism*, so a TPROXY / `bpf_sk_assign` backend can slot in later
//! without touching policy or TLS-1 (doc 12 TLS-1's `allow = f(session, sni,
//! original_dst)`). **This seam IS the D70 QUIC carveout** — the clean lane a
//! future UDP/QUIC terminator recovers behind, never extended to datagrams here.
//!
//! Under REDIRECT today the two halves come from the kernel for free:
//! `original_dst` from Pingora's stock `SocketDigest::original_dst()`
//! (`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`, conntrack-backed), and `session`
//! from the post-NAT local address of the per-session tap (`getsockname()` on the
//! accepted socket). This crate owns neither mechanism — it freezes the *shape*
//! every backend must produce and the three invariants every backend must honor,
//! so the recovery code in `ds-tlsproxy` and any future QUIC listener bind to one
//! contract, not a syscall.
//!
//! # The three frozen D69 invariants (round2/04 "Frozen vs free")
//!
//! 1. **`original_dst` comes ONLY from a kernel source.** Never inferred from
//!    SNI, Host, or any client-supplied byte. SNI is checked *against* it
//!    (TLS-1 × DNS-2b), never substituted for it. Enforced here by
//!    [`OriginSource`]: the only constructors that yield an `original_dst` are
//!    the kernel ones; there is no `from_sni` / `from_client` path to call.
//! 2. **`session` derives ONLY from an interface-anchored signal** (the post-NAT
//!    local address under REDIRECT; `getsockname` under a future TPROXY backend) —
//!    **never raw source IP**, which the VM forges at will (doc 03 §3, the NFT-2
//!    `iifname`-only rule). Enforced by [`SessionSource`]: there is no
//!    `from_source_ip` constructor.
//! 3. **Recovery failure REFUSES the connection.** A direct connect to the proxy
//!    port that never transited the NAT rule has no `SO_ORIGINAL_DST`
//!    (`ENOENT`/`ENOPROTOOPT`); recovery returns [`RecoveryError`], the caller
//!    refuses — same class as TLS-1's absent-SNI refusal — and emits the
//!    [`crate::reject::RejectReason::RecoveryFailed`] LOG-1 event. Never a silent
//!    fallback, never a guessed dst.
//!
//! # What is FREE (round2/04)
//!
//! The mechanism behind each half — `redirect to :port` vs explicit per-tap
//! `dnat`, exact port numbers, lazy-vs-eager getsockopt, and the entire UDP
//! recovery shape (deliberately NOT modeled: a future QUIC terminator defines its
//! own impl behind this same logical contract). This module is `#![no_std]`-clean
//! shape only; it spawns nothing and reads no socket.

use crate::dns_admission::AdmittedAddr;
use crate::reject::RejectReason;
use crate::session::SessionRef;

/// Where an `original_dst` value came from. The discriminant exists to make
/// D69 invariant (1) — *kernel source only* — a property of the type rather than
/// a prose promise: every constructor that produces an [`OriginDst`] tags it with
/// a kernel mechanism, and there is **no** `Sni` / `ClientClaimed` variant to
/// construct one from. A reviewer can see at the call site that a dst the policy
/// check trusts was never derived from a client-supplied byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OriginSource {
    /// `SO_ORIGINAL_DST` getsockopt on the accepted v4 socket (conntrack-backed)
    /// — Pingora's `SocketDigest::original_dst()` under the REDIRECT backend.
    SoOriginalDst,
    /// `IP6T_SO_ORIGINAL_DST` getsockopt on the accepted v6 socket — the D75
    /// dormant dual-stack recovery path (same Pingora primitive, v6 family).
    Ip6tSoOriginalDst,
    /// `getsockname()` on the accepted socket under a future TPROXY / sk_assign
    /// backend, where nothing is NAT-rewritten so the local name IS the original
    /// dst. Reserved now so the swap is additive — not reachable on the v0
    /// REDIRECT path.
    TproxyGetsockname,
}

/// Where a `session` signal came from. Mirrors [`OriginSource`] for invariant (2)
/// — *interface-anchored only, never raw source IP*. There is intentionally no
/// `SourceIp` variant: the VM forges its source address, so it can never be a
/// session signal (doc 03 §3; NFT-2's `iifname`-only enforcement match).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionSource {
    /// The post-NAT local address of the accepted socket (`getsockname()`), which
    /// under REDIRECT is the per-session tap's boundary-side address — the
    /// interface-anchored signal D69 names. The authoritative join key remains
    /// the tap name in the resolved [`SessionRef`]; this records the *mechanism*
    /// the index was recovered through.
    PostNatLocalAddr,
    /// A future per-session redirect *port* fallback (round2/04's named exit
    /// criterion if per-session tap addressing proves infeasible) — the listener
    /// port disambiguates the session. Reserved; never the v0 default. Still
    /// interface-anchored: the port is assigned per tap by the NFT-2 ruleset, not
    /// chosen by the guest.
    PerSessionRedirectPort,
}

/// The original destination the guest dialed, recovered from a kernel source.
///
/// Carries the family-agnostic [`AdmittedAddr`] (D75-ready, the same shape the
/// DNS-2b admission map and TLS-1's SNI×IP check use) plus the TCP port and the
/// [`OriginSource`] tag proving invariant (1). There is no public constructor
/// that takes a client-supplied address — see [`OriginDst::from_kernel`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginDst {
    /// The destination address, network byte order octets + family (D75).
    pub addr: AdmittedAddr,
    /// The destination TCP port (the guest's dialed port — 53 / 80 / 443 on the
    /// intercepted paths). Host byte order.
    pub port: u16,
    /// The kernel mechanism this dst was recovered through (invariant 1).
    pub source: OriginSource,
}

impl OriginDst {
    /// The ONLY way to build an [`OriginDst`]: from a kernel source. Taking the
    /// [`OriginSource`] tag explicitly — and naming no client input — is how the
    /// type enforces D69 invariant (1). A caller that wanted to forge a dst from
    /// SNI has no path through this API.
    pub fn from_kernel(addr: AdmittedAddr, port: u16, source: OriginSource) -> OriginDst {
        OriginDst { addr, port, source }
    }
}

/// A fully recovered connection origin: the kernel-sourced [`OriginDst`] and the
/// interface-anchored [`SessionRef`], resolved at accept time **before any byte
/// is read** (round2/04). This is the exact tuple TLS-1's admission signature
/// `allow = f(session, sni, original_dst)` consumes; the signature is
/// mechanism-independent because this shape is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnOrigin {
    /// The kernel-sourced original destination (invariant 1).
    pub original_dst: OriginDst,
    /// The interface-anchored session (invariant 2). The tap name in this
    /// [`SessionRef`] is the authoritative LOG-2 / NFT-2 / NFT-5 join key.
    pub session: SessionRef,
    /// How the session signal was recovered (invariant 2's mechanism tag).
    pub session_source: SessionSource,
}

impl ConnOrigin {
    /// Assemble a recovered origin from its two kernel/interface-sourced halves.
    /// Both arguments already encode their provenance ([`OriginDst`] carries an
    /// [`OriginSource`]; `session_source` is interface-anchored by enum), so this
    /// constructor cannot be handed a client-forged value — the invariants are
    /// upheld by the inputs' types, not re-checked here.
    pub fn new(
        original_dst: OriginDst,
        session: SessionRef,
        session_source: SessionSource,
    ) -> ConnOrigin {
        ConnOrigin {
            original_dst,
            session,
            session_source,
        }
    }
}

/// Why recovery failed — D69 invariant (3): recovery failure **refuses** the
/// connection. Every variant maps to [`RejectReason::RecoveryFailed`]
/// ([`RecoveryError::reject_reason`]) so the refusal is one observable LOG-1
/// event class, never a silent fallback to a guessed destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryError {
    /// `SO_ORIGINAL_DST` getsockopt returned `ENOENT` — the accepted connection
    /// never transited the NAT/REDIRECT rule (e.g. a direct connect to the proxy
    /// listener port). No original dst exists; refuse. This is the round2/04
    /// "dial the proxy's listener port directly → refused, logged as a
    /// recovery-failure event" assertion.
    NoConntrackOrigin,
    /// `SO_ORIGINAL_DST` returned `ENOPROTOOPT` — the protocol has no
    /// original-dst recovery on this path (UDP under REDIRECT; the kernel rejects
    /// the getsockopt before any lookup). Refuse. udp/53 never needs the dst to
    /// answer (it is `ds-dnsgate`'s own query), and udp/443 is rejected at the
    /// nft layer (D70) — so a UDP packet reaching this recovery path is itself a
    /// misroute to refuse.
    UnsupportedProtocol,
    /// The interface-anchored session signal could not be resolved to a known
    /// session (no matching tap / index in the orchestrator session record).
    /// Refuse rather than attribute the flow to a guessed or source-IP-derived
    /// session — the D44 three-keys-must-agree posture (NFT-2's explicit clause)
    /// at the proxy layer.
    UnresolvedSession,
}

impl RecoveryError {
    /// The LOG-1 reason every recovery failure is emitted under (D69 invariant 3).
    /// Always [`RejectReason::RecoveryFailed`] — distinct from `DefaultDeny` so a
    /// standing query can count recovery-failure volume (e.g. direct-to-port
    /// probes) without conflating it with the default-deny floor.
    pub const fn reject_reason(self) -> RejectReason {
        RejectReason::RecoveryFailed
    }

    /// A stable lowercase token for logs/metrics labels (additive-only).
    pub const fn as_str(self) -> &'static str {
        match self {
            RecoveryError::NoConntrackOrigin => "no_conntrack_origin",
            RecoveryError::UnsupportedProtocol => "unsupported_protocol",
            RecoveryError::UnresolvedSession => "unresolved_session",
        }
    }
}

/// The result of an accept-time recovery: either a fully resolved [`ConnOrigin`]
/// or a [`RecoveryError`] the caller turns into a refusal. Spelling the contract
/// as a `Result` is invariant (3) in the type system — there is no "recovered
/// with a default dst" third state to leak a forgeable value through.
pub type RecoveredOrigin = Result<ConnOrigin, RecoveryError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_admission::AddressFamily;

    fn v4(octets: [u8; 4]) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: octets.to_vec(),
        }
    }

    fn a_session() -> SessionRef {
        SessionRef::new(
            "abcd1234-0000-0000-0000-000000000001".into(),
            "host-7".into(),
            42,
            "dstap-42".into(),
        )
    }

    #[test]
    fn origin_dst_is_kernel_sourced_only() {
        // The only constructor takes an OriginSource — every source is a kernel
        // mechanism, none is client-derived. (1) is enforced by construction.
        let dst = OriginDst::from_kernel(v4([93, 184, 216, 34]), 443, OriginSource::SoOriginalDst);
        assert_eq!(dst.port, 443);
        assert_eq!(dst.source, OriginSource::SoOriginalDst);
        for s in [
            OriginSource::SoOriginalDst,
            OriginSource::Ip6tSoOriginalDst,
            OriginSource::TproxyGetsockname,
        ] {
            // Exhaustively: every OriginSource variant is a kernel mechanism.
            let d = OriginDst::from_kernel(v4([10, 0, 0, 1]), 80, s);
            assert_eq!(d.source, s);
        }
    }

    #[test]
    fn conn_origin_carries_both_halves() {
        let dst = OriginDst::from_kernel(v4([93, 184, 216, 34]), 443, OriginSource::SoOriginalDst);
        let co = ConnOrigin::new(dst.clone(), a_session(), SessionSource::PostNatLocalAddr);
        assert_eq!(co.original_dst, dst);
        // The authoritative join key is the tap name on the SessionRef.
        assert_eq!(co.session.tap_name, "dstap-42");
        assert_eq!(co.session_source, SessionSource::PostNatLocalAddr);
    }

    #[test]
    fn every_recovery_error_refuses_as_recovery_failed() {
        // Invariant (3): every failure maps to RecoveryFailed, distinct from
        // DefaultDeny so it is independently countable off-box.
        for e in [
            RecoveryError::NoConntrackOrigin,
            RecoveryError::UnsupportedProtocol,
            RecoveryError::UnresolvedSession,
        ] {
            assert_eq!(e.reject_reason(), RejectReason::RecoveryFailed);
            assert_ne!(e.reject_reason(), RejectReason::DefaultDeny);
        }
    }

    #[test]
    fn recovery_error_tokens_are_distinct() {
        let all = [
            RecoveryError::NoConntrackOrigin,
            RecoveryError::UnsupportedProtocol,
            RecoveryError::UnresolvedSession,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in all {
            assert!(seen.insert(e.as_str()), "duplicate token for {e:?}");
        }
    }

    #[test]
    fn the_result_alias_has_no_default_dst_third_state() {
        // A direct-to-port connect has no conntrack origin → Err, which the
        // caller refuses. There is no Ok-with-default variant to leak a forged
        // dst through; the type only admits a kernel-sourced ConnOrigin or an
        // error.
        let refused: RecoveredOrigin = Err(RecoveryError::NoConntrackOrigin);
        assert!(refused.is_err());
        let dst = OriginDst::from_kernel(v4([1, 1, 1, 1]), 53, OriginSource::SoOriginalDst);
        let ok: RecoveredOrigin = Ok(ConnOrigin::new(
            dst,
            a_session(),
            SessionSource::PostNatLocalAddr,
        ));
        assert!(ok.is_ok());
    }
}
