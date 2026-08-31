//! NFT-2 transparent path — the `accept/` redirect listener and the frozen
//! `ConnOrigin` recovery seam (doc 03 §3; doc 09 NFT-2; doc 12 §2/§2.1/§13.1;
//! D2/D40/D69).
//!
//! # What this is
//!
//! The transparent path is the half of `ds-tlsproxy` that catches traffic which
//! ignores the `HTTP_PROXY`/`HTTPS_PROXY` variables (the explicit path,
//! [`crate::explicit`], catches the well-behaved clients). An `iifname`-matched
//! nftables REDIRECT (doc 03 §3, doc 09 NFT-2 — match on the *interface the VM is
//! attached to*, NEVER on source IP) rewrites the agent VM's outbound `tcp 80`/
//! `tcp 443` to the proxy's loopback listener ports `:18080`/`:18443`. The VM
//! still believes it is talking to the real upstream; the kernel has silently
//! pointed the socket at us.
//!
//! Because the destination IP/port were rewritten by the kernel, the *real*
//! upstream the VM intended is no longer in the accepted socket's peer/local
//! address — it lives in conntrack, recovered through the `SO_ORIGINAL_DST`
//! (v4) / `IP6T_SO_ORIGINAL_DST` (v6) getsockopt. This module is the
//! framework-agnostic core of doc 12 §13.1's `accept/` layer:
//!
//! - [`recover_conn_origin`] — resolve [`ConnOrigin`] `{ original_dst, session }`
//!   at accept time, before any byte is read (D69 invariant 3 wants to refuse
//!   *before* reading a single client byte), over an [`OriginalDst`] recovery
//!   provider. Recovery FAILURE refuses (invariant 3, frozen).
//! - [`Socket2OriginalDst`] — the production recovery provider: the
//!   `SO_ORIGINAL_DST`/`IP6T_SO_ORIGINAL_DST` getsockopt via `socket2`. This is
//!   the EXACT kernel mechanism Pingora's stock `SocketDigest::original_dst()`
//!   performs (doc 12 §2); the pingora type is named only at the real listener
//!   seam, everything inward — including this module — speaks [`OriginalDst`].
//! - [`forward`] — the bidirectional splice that carries bytes between the
//!   accepted downstream socket and the upstream connection once recovery + (in
//!   the real path) the TLS-1 admission check succeed.
//!
//! # The frozen recovery seam (doc 12 §2.1, D69 — invariants 1–4)
//!
//! At accept time the listener resolves a [`ConnOrigin`]. The four frozen
//! invariants this module enforces:
//!
//! 1. `original_dst` comes **only from a kernel source** — never inferred from
//!    SNI/Host/any client byte. The recovery provider is the kernel getsockopt;
//!    SNI is checked *against* this value (TLS-1), never substituted for it. This
//!    module never reads a client byte to derive the destination.
//! 2. `session` comes **only from an interface-anchored signal** (the post-NAT
//!    local address / the per-session tap), never raw source IP (D44's
//!    three-keys-must-agree drop precedes it; doc 12 §2.2). This module derives
//!    `session` from the resolved [`SessionRef`] the listener attaches per tap,
//!    never from the connection's peer address.
//! 3. Recovery **failure refuses** the connection ([`RecoveryError`]), the same
//!    class as TLS-1's absent-SNI refusal, surfaced as the §10 recovery-failure
//!    event ([`RecoveryFailure`]). A flow that did not transit the redirect (a
//!    direct dial of the listener port, `ENOENT`/`ENOPROTOOPT`) has no
//!    trustworthy origin and is dropped.
//! 4. The downstream admission signature `allow = f(session, sni, original_dst)`
//!    is **mechanism-independent** — it consumes only [`ConnOrigin`] fields, so a
//!    TPROXY/`bpf_sk_assign` backend (or the §7 QUIC terminator's datagram impl)
//!    slots in behind this same interface without touching policy or TLS-1.
//!
//! # The pingora wiring seam (doc 12 §13.1)
//!
//! What lands here: the recovery interface ([`OriginalDst`]), the production
//! getsockopt provider ([`Socket2OriginalDst`]) over an `AsFd` (so it works on a
//! `std::net::TcpStream`, a `socket2::Socket`, or — in production — the fd
//! Pingora hands the `accept/` callback), the refuse-on-failure resolution, and
//! the byte-forwarding splice. What does NOT land here, and is M0-host
//! integration work (the Pingora dependency stays inside the listener layer):
//!
//! - the real `pingora-core` `ServerApp`/`SocketDigest` listener that binds
//!   `:18080`/`:18443`, attaches the per-tap [`SessionRef`], and calls the
//!   accept callback — this module's [`recover_conn_origin`] is what that
//!   callback runs, with `SocketDigest::original_dst()` swapped in for
//!   [`Socket2OriginalDst`] (same getsockopt, doc 12 §2);
//! - the TLS-1 SNI peek + DNS-2b admission check ([`crate::explicit`] holds the
//!   shared policy verdict the SNI path also reaches; the transparent path's SNI
//!   peek is a sibling unit) — this module produces the [`ConnOrigin`] that
//!   check consumes;
//! - the `0x2` upstream-leg `SO_MARK` before connect (§4.2) — the connect layer
//!   applies it; [`crate::explicit::UpstreamConnect`] is the descriptor.
//!
//! # Frozen non-edge (doc 12 §4.2, D76)
//!
//! Like the rest of this service, the transparent path NEVER depends on `ds-nft`
//! and issues no conntrack/netlink syscall. The `SO_ORIGINAL_DST` getsockopt is a
//! *read* of conntrack-derived NAT state on the proxy's OWN accepted socket
//! (`CAP_NET_RAW` is not even required for it) — it never writes the ruleset that
//! contains the proxy. The interface-matched REDIRECT ruleset that drives this
//! path is authored as golden text in `SPIKE-NOTES.md` and programmed by
//! `ds-dnsgate`/the host agent (D76), never by this service.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;

use socket2::SockRef;

use ds_contracts::session::SessionRef;

use crate::scan::{ScanCtx, ScanGate, SecretMatcher, Verdict};

/// The frozen mechanism-agnostic recovery result (doc 12 §2.1, D69). Resolved at
/// accept time before any client byte is read; this — not the kernel mechanism —
/// is what TLS-1 and every downstream consumer sees, so the REDIRECT backend can
/// be swapped for TPROXY/`bpf_sk_assign` without touching policy (invariant 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnOrigin {
    /// The real upstream the VM intended, recovered from a KERNEL source only
    /// (SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST) — never inferred from SNI, Host,
    /// or any client byte (invariant 1, frozen). SNI is checked *against* this,
    /// never substituted for it.
    pub original_dst: SocketAddr,
    /// The session, derived ONLY from an interface-anchored signal — the
    /// per-session tap the listener is bound to / the post-NAT local address —
    /// never the raw source IP (invariant 2, frozen; doc 12 §2.2, D44).
    pub session: SessionRef,
}

/// The validated sub-token's `ds_scopes` claim carried ONTO the connect context
/// (the D22 Validate seam / session-record join; doc 23 §6). This is the ADDITIVE
/// credential-scope surface that rides ALONGSIDE the FROZEN [`ConnOrigin`] recovery
/// seam — it never modifies `ConnOrigin` (invariants 1–4 untouched) and carries no
/// address arithmetic; it is purely the presenting credential's scope set the
/// FORWARD egress gate consumes ([`ds_contracts::scopes::ConnectScopeClaim`]).
///
/// # Absent vs present (fail-closed)
///
/// [`absent`](ConnectSubToken::absent) is the DEFAULT: no sub-token was validated /
/// surfaced on this connect (the production posture until the live D22 Validate
/// wiring lands, and every path that never presents a credential). An absent
/// sub-token yields the EMPTY [`ds_contracts::scopes::ConnectScopeClaim`] downstream
/// (via [`ds_contracts::scopes::ConnectScopeClaim::from_presented`]), which satisfies
/// no predicate — so an armed egress gate denies fast (the fail-closed default).
/// [`from_ds_scopes`](ConnectSubToken::from_ds_scopes) carries the raw `ds_scopes`
/// the Validate seam attached; the downstream claim constructor filters it to the
/// recognized D127 taxonomy, so an unknown string can never enter the claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectSubToken {
    /// The raw `ds_scopes` claim validated by the D22 Validate seam, or `None` when
    /// no sub-token was presented / surfaced on this connect (the fail-closed
    /// default). Held raw (unfiltered) so this carrier stays a faithful record of
    /// what the credential presented; the D127 taxonomy filter is applied where the
    /// downstream [`ds_contracts::scopes::ConnectScopeClaim`] is built.
    ds_scopes: Option<Vec<String>>,
}

impl ConnectSubToken {
    /// No sub-token surfaced on this connect (the default) — yields the EMPTY scope
    /// claim downstream (fail-closed egress deny).
    pub fn absent() -> ConnectSubToken {
        ConnectSubToken { ds_scopes: None }
    }

    /// Carry the validated sub-token's raw `ds_scopes` claim (doc 23 §6) onto the
    /// connect context. The strings are the credential's presented scopes as the D22
    /// Validate seam surfaced them; taxonomy filtering happens where the downstream
    /// [`ds_contracts::scopes::ConnectScopeClaim`] is built.
    pub fn from_ds_scopes(ds_scopes: Vec<String>) -> ConnectSubToken {
        ConnectSubToken {
            ds_scopes: Some(ds_scopes),
        }
    }

    /// The presented raw `ds_scopes`, or `None` when no sub-token was surfaced
    /// ([`absent`](ConnectSubToken::absent)). This is the exact shape
    /// [`ds_contracts::scopes::ConnectScopeClaim::from_presented`] consumes.
    pub fn presented(&self) -> Option<&[String]> {
        self.ds_scopes.as_deref()
    }

    /// Whether a validated sub-token was surfaced on this connect (a present — even if
    /// empty — `ds_scopes` claim). An absent sub-token is the fail-closed default.
    pub fn is_present(&self) -> bool {
        self.ds_scopes.is_some()
    }
}

/// Why `ConnOrigin` recovery failed — D69 invariant 3: recovery failure REFUSES
/// the connection (same class as TLS-1's absent-SNI refusal). Carried into the
/// §10 [`RecoveryFailure`] event; the listener closes the connection without
/// reading a byte or opening any upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The accepted socket carries no original destination — it did not transit
    /// the NAT/REDIRECT rule (a direct dial of the proxy listener port). Two
    /// kernel shapes both land here, because both mean "no DNAT happened":
    ///
    /// - the getsockopt errored `ENOENT` (no conntrack entry) / `ENOPROTOOPT`
    ///   (the option is unsupported on this socket/family); OR
    /// - the getsockopt SUCCEEDED but returned the listener's **own local
    ///   address** — the kernel falls back to `getsockname()` when there is no
    ///   conntrack DNAT entry, so a recovered dst equal to where we are bound is
    ///   exactly the "never redirected" signal (a genuine REDIRECT recovers the
    ///   *pre-DNAT* upstream, which is never the proxy's own bind address).
    ///
    /// A flow with no real kernel original_dst has no trustworthy origin —
    /// REFUSE (invariant 3).
    NoOriginalDst,
    /// The original-destination address family did not match the socket's family
    /// (a v4 socket whose recovery returned a non-v4 storage, or vice-versa) —
    /// treated as an unrecoverable origin and refused, never guessed.
    AddressFamilyMismatch,
    /// The recovered storage could not be decoded into a `SocketAddr` (a
    /// zero/garbage address from a non-redirected socket). Refuse — never admit a
    /// flow whose origin we cannot name.
    Undecodable,
}

impl RecoveryError {
    /// A stable, secret-free reason code for the §10 recovery-failure LOG-1 event
    /// (LOG-1 never logs client bytes; the failure class is the whole payload).
    pub fn reason_code(&self) -> &'static str {
        match self {
            RecoveryError::NoOriginalDst => "no-original-dst",
            RecoveryError::AddressFamilyMismatch => "original-dst-family-mismatch",
            RecoveryError::Undecodable => "original-dst-undecodable",
        }
    }
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnOrigin recovery failed: {}", self.reason_code())
    }
}

impl std::error::Error for RecoveryError {}

/// The §10 recovery-failure event (doc 12 §10, §2.1 invariant 3). Emitted when
/// the transparent listener refuses a connection because its origin could not be
/// recovered — the same event class as TLS-1's absent-SNI refusal. Carries the
/// session attribution and the failure reason ONLY; never a client byte (no
/// original_dst was trustworthy, so none is logged).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryFailure {
    /// The never-recycled tap name (LOG-2 attribution key) the listener was bound
    /// to — known even on refusal, because `session` is interface-anchored
    /// (invariant 2), not derived from the recovered (absent) destination.
    pub tap_name: String,
    /// The stable, secret-free failure reason code.
    pub reason: &'static str,
}

/// The mechanism-agnostic recovery provider (doc 12 §2.1, §13.1 — the seam). The
/// production impl is [`Socket2OriginalDst`] (the SO_ORIGINAL_DST getsockopt, the
/// same mechanism as Pingora's stock `SocketDigest::original_dst()`); tests
/// implement it over a fake so the refuse-on-failure path is exercised without a
/// live REDIRECT (which this host's kernel cannot program — reboot-pending; see
/// `SPIKE-NOTES.md`). Swapping this trait for a TPROXY `getsockname` backend is
/// the D70 QUIC carveout — no policy/TLS-1 code changes (invariant 4).
pub trait OriginalDst {
    /// Recover the kernel-held original destination of an accepted socket, or a
    /// [`RecoveryError`] when the socket carries none (it did not transit the
    /// redirect). MUST consult only a kernel source (invariant 1) — never a
    /// client byte.
    fn original_dst(&self) -> Result<SocketAddr, RecoveryError>;
}

/// The production recovery provider: `SO_ORIGINAL_DST` (v4) / `IP6T_SO_ORIGINAL_DST`
/// (v6) on the accepted socket, via `socket2`'s safe getters — the EXACT kernel
/// mechanism Pingora's stock `SocketDigest::original_dst()` performs (doc 12 §2),
/// so the production `accept/` callback swaps `SocketDigest` in for this with no
/// change to [`recover_conn_origin`] or anything downstream.
///
/// Generic over any `AsFd` (a `std::net::TcpStream`, a `socket2::Socket`, or the
/// raw fd Pingora hands the accept callback). Holds a borrowed fd, so it is
/// zero-copy and never owns/closes the socket.
pub struct Socket2OriginalDst<'a, F: AsFd> {
    socket: SockRef<'a>,
    /// The listener's own local address (where the proxy is bound — `:18080`/
    /// `:18443`). On a socket that never transited a DNAT, the kernel's
    /// `SO_ORIGINAL_DST` falls back to `getsockname()` and returns THIS address;
    /// a recovered dst equal to it is the "never redirected" signal → refuse
    /// (invariant 3). A genuine REDIRECT recovers the pre-DNAT upstream, which is
    /// never the proxy's own bind address.
    listener_local: SocketAddr,
    /// Whether the accepted socket is v6 — picks `original_dst_v6` vs
    /// `original_dst_v4`. The listener knows this from its own bind family; the
    /// recovered family must agree (else [`RecoveryError::AddressFamilyMismatch`]).
    is_ipv6: bool,
    _fd: std::marker::PhantomData<&'a F>,
}

impl<'a, F: AsFd> Socket2OriginalDst<'a, F> {
    /// Wrap an accepted socket's fd for IPv4 original-dst recovery
    /// (`SO_ORIGINAL_DST`). `listener_local` is the proxy's own bind address (the
    /// REDIRECT target, e.g. `:18443`) — used to reject the kernel's
    /// `getsockname()` fallback on a never-redirected socket (invariant 3).
    pub fn v4(socket: &'a F, listener_local: SocketAddr) -> Socket2OriginalDst<'a, F> {
        Socket2OriginalDst {
            socket: SockRef::from(socket),
            listener_local,
            is_ipv6: false,
            _fd: std::marker::PhantomData,
        }
    }

    /// Wrap an accepted socket's fd for IPv6 original-dst recovery
    /// (`IP6T_SO_ORIGINAL_DST`). Written now, dormant until D75 enables v6 (doc 12
    /// §2 "IPv6 dormant test"); the getsockopt and decode are identical in shape.
    pub fn v6(socket: &'a F, listener_local: SocketAddr) -> Socket2OriginalDst<'a, F> {
        Socket2OriginalDst {
            socket: SockRef::from(socket),
            listener_local,
            is_ipv6: true,
            _fd: std::marker::PhantomData,
        }
    }
}

impl<F: AsFd> OriginalDst for Socket2OriginalDst<'_, F> {
    fn original_dst(&self) -> Result<SocketAddr, RecoveryError> {
        // The SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST getsockopt — the exact kernel
        // read SocketDigest::original_dst() performs. socket2 owns the unsafe
        // getsockopt internally, so this module stays #![forbid(unsafe_code)].
        let raw = if self.is_ipv6 {
            self.socket.original_dst_v6()
        } else {
            self.socket.original_dst_v4()
        };
        let sockaddr = raw.map_err(classify_getsockopt_err)?;
        let recovered = sockaddr.as_socket().ok_or(RecoveryError::Undecodable)?;
        // Family agreement (invariant: a v4 listener must recover a v4 dst). A
        // mismatch means the option returned a foreign-family storage — refuse,
        // never reinterpret the bytes.
        if recovered.is_ipv6() != self.is_ipv6 {
            return Err(RecoveryError::AddressFamilyMismatch);
        }
        // The getsockname() fallback: a recovered dst equal to the listener's own
        // bind address means no DNAT happened (the socket never transited the
        // REDIRECT). Refuse — exactly invariant 3's "direct connect to the proxy
        // port that never transited the NAT rule". The comparison matches on
        // BOTH ip and port so the proxy's own ip:port is the only rejected value;
        // a genuine upstream coincidentally on the proxy's host but a different
        // port still recovers (it is a real pre-DNAT destination).
        if recovered == self.listener_local {
            return Err(RecoveryError::NoOriginalDst);
        }
        Ok(recovered)
    }
}

/// Map a getsockopt `io::Error` to a [`RecoveryError`]. Every errno is a
/// refusal — we never admit a flow whose origin we could not read (D69 invariant
/// 3). The two doc 12 §2.1 named cases collapse here along with any other kernel
/// error:
///
/// - `ENOENT` (2): no conntrack entry — the connection never transited the NAT
///   rule.
/// - `ENOPROTOOPT` (92): the getsockopt option is unsupported on this
///   socket/family (e.g. an IPv6 socket queried for `SO_ORIGINAL_DST`).
/// - any other errno: still "no trustworthy origin" and still refused.
///
/// All three cases produce `RecoveryError::NoOriginalDst` — the distinction
/// between them does not change admission behavior, so one honest fail-closed arm
/// is clearer than decorative errno discrimination that changes nothing.
fn classify_getsockopt_err(_err: io::Error) -> RecoveryError {
    RecoveryError::NoOriginalDst
}

/// Resolve [`ConnOrigin`] at accept time (doc 12 §2.1, D69). Pairs the
/// interface-anchored `session` (invariant 2 — known to the listener from the tap
/// it is bound to, NEVER the peer/source IP) with the kernel-recovered
/// `original_dst` (invariant 1). Recovery failure REFUSES (invariant 3): returns
/// `Err`, and the caller closes the connection and emits the §10 recovery-failure
/// event — no byte is read, no upstream opened.
///
/// `session` is supplied by the listener (it is the per-tap attachment); this
/// function never derives it from the connection, which is exactly what keeps the
/// source IP out of attribution (invariant 2). `recovery` is the mechanism seam
/// ([`Socket2OriginalDst`] in production, the same getsockopt as
/// `SocketDigest::original_dst()`).
pub fn recover_conn_origin<R: OriginalDst>(
    session: &SessionRef,
    recovery: &R,
) -> Result<ConnOrigin, RecoveryError> {
    let original_dst = recovery.original_dst()?;
    Ok(ConnOrigin {
        original_dst,
        session: session.clone(),
    })
}

/// Build the §10 recovery-failure event for a refused connection (D69 invariant
/// 3). The session attribution survives the refusal because it is
/// interface-anchored, not derived from the (absent) destination.
pub fn recovery_failure_event(session: &SessionRef, err: &RecoveryError) -> RecoveryFailure {
    RecoveryFailure {
        tap_name: session.tap_name.clone(),
        reason: err.reason_code(),
    }
}

/// The original destination as a `(ip, port)` policy key — the admission
/// signature's `original_dst` component (invariant 4, `allow = f(session, sni,
/// original_dst)`). Lowercased-IP string + port, the same shape the DNS-2b map is
/// keyed on. Mechanism-independent: derives only from [`ConnOrigin`] fields.
pub fn admission_dst_key(origin: &ConnOrigin) -> (IpAddr, u16) {
    (origin.original_dst.ip(), origin.original_dst.port())
}

/// The first two octets of the per-session /31 host-side address space
/// (`10.77.<host_session_index>.0/31`, RFC 3021) — the OQ1/D66 spike's per-session
/// addressing plan (doc 12 §2.2 / §13.1). The `host_session_index` rides in the
/// **third** octet; the derivation below is one subtraction of this base prefix
/// from the post-NAT local address (the base's third octet is `0`, so the index is
/// exactly the third octet — a single arithmetic step, NO cross-stream registry).
const SESSION_NET_OCTET_0: u8 = 10;
const SESSION_NET_OCTET_1: u8 = 77;

/// Derive the per-tap [`SessionRef`] from the **post-NAT local address** of an
/// accepted transparent-path socket — the OQ1/D66 attribution key (doc 12 §2.1
/// invariant 2, §2.2 three-keys-agree, §13.1, settled PROPOSED 2026-06-13).
///
/// The OQ1/D66 spike confirmed each per-session tap gets its **own /31**
/// (`10.77.<host_session_index>.0/31`, RFC 3021 — host-side gateway `.0`, guest
/// `.1`, distinct per session and interface-anchored). Under the single-redirect-
/// port REDIRECT shape, the kernel's `getsockname()` on the accepted socket returns
/// that per-session host-side gateway as the socket's LOCAL address, so the local
/// address *encodes* the session — exactly the "post-NAT local address as the
/// `ConnOrigin.session` key" recommendation (§13.1).
///
/// The derivation is **pure address ARITHMETIC** (§13.1 "one subtraction"), NOT a
/// call into the orchestrator tap-registry (that is a different cross-stream seam):
///
/// 1. `host_session_index` = the **third octet** of the local IPv4 address (one
///    subtraction of the `10.77.0.0` base prefix, whose third octet is `0`).
/// 2. the never-recycled **`dstap-<idx>` tap name** is the authoritative
///    [`SessionRef`] join key (doc 14 §4; the local address is the recovery
///    *signal*, the tap name the *join key* — exactly §2.2's three-keys-agree
///    clause).
///
/// Returns `None` for an address that does NOT fit the per-session `10.77.x.y`
/// shape (an unexpected/malformed local address — e.g. a loopback test bind, an
/// IPv6 local, or an address outside the session net): the caller then DEGRADES to
/// the prior unmarked best-effort connect (the D76 mark only ADDS; it never gates —
/// the fail-closed boundary is unchanged). `session_uuid`/`host_id` are not carried
/// in the post-NAT address; the orchestrator session record is their authority
/// (doc 14 §4), so the locally-derivable identity is the `(host_session_index,
/// tap_name)` pair the mark + LOG-2 attribution need — `session_uuid`/`host_id` are
/// left empty here and joined from the session record at the M0-host seam.
/// The operator-supplied single-session UUID (`DS_SESSION_UUID`), read from the
/// environment exactly ONCE and cached. This is the READ-side half of the testbed
/// cross-process key agreement (doc 11 §5.1 / D131-rollout): a co-host ds-dnsgate
/// (its `SessionSource::FixedUuid`) writes the DNS-2b `AdmissionKey` under
/// `{DS_SESSION_UUID, fqdn}`, so the transparent path must stamp the SAME string as
/// the per-connection [`SessionRef::session_uuid`] for the FORWARD lookup
/// (`tls1_admission::decide` / `origin_is_admitted`) to HIT rather than miss on the
/// empty `""` it would otherwise carry (the post-NAT local address does not encode
/// the orchestrator UUID; doc 14 §4).
///
/// UNSET (or set to the empty string) → `None`, and [`session_from_local_addr`]
/// keeps the prior empty `session_uuid` — byte-identical to pre-agreement behavior.
/// Read once via a [`OnceLock`] so the per-connection derivation is a cached clone,
/// not an `getenv` per accept.
fn fixed_session_uuid() -> Option<&'static str> {
    static FIXED_SESSION_UUID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    FIXED_SESSION_UUID
        .get_or_init(|| match std::env::var("DS_SESSION_UUID") {
            Ok(v) if !v.is_empty() => Some(v),
            _ => None,
        })
        .as_deref()
}

pub fn session_from_local_addr(listener_local: SocketAddr) -> Option<SessionRef> {
    session_from_local_addr_with_uuid(listener_local, fixed_session_uuid())
}

/// The pure address-arithmetic core of [`session_from_local_addr`], with the
/// cross-process `session_uuid` injected explicitly (the production caller passes the
/// env-cached [`fixed_session_uuid`]). Splitting the env read out keeps the derivation
/// PURE and unit-testable for both the unset (`None` → `""`) and set (the agreed uuid)
/// paths without the `OnceLock` global caching the env read carries.
fn session_from_local_addr_with_uuid(
    listener_local: SocketAddr,
    fixed_uuid: Option<&str>,
) -> Option<SessionRef> {
    // The per-session host-side address is an IPv4 /31 gateway; an IPv6 (or any
    // non-v4) local address is not the OQ1 shape → degrade to unmarked.
    let octets = match listener_local.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => return None,
    };
    // One subtraction of the 10.77.0.0 base prefix: require the address to live in
    // the per-session net, then read host_session_index out of the third octet.
    // (The base's third octet is 0, so `octets[2] - 0` is the index — the single
    // arithmetic step §13.1 specifies.)
    if octets[0] != SESSION_NET_OCTET_0 || octets[1] != SESSION_NET_OCTET_1 {
        return None;
    }
    let host_session_index = u32::from(octets[2]);
    let tap_name = format!("dstap-{host_session_index}");
    // The authoritative join key is the tap name; host_id is joined from the
    // orchestrator session record (doc 14 §4) at the M0-host seam, not recoverable
    // from the address alone. `session_uuid` is likewise not in the address, BUT the
    // testbed cross-process key agreement (doc 11 §5.1 / D131-rollout) supplies it
    // out-of-band via `DS_SESSION_UUID`: when that env is set, stamp it here at the
    // SINGLE derivation point so ALL consumers (TLS-1 `decide`, TLS-3
    // `origin_is_admitted`, the upstream-mark path) read the SAME `session_uuid` the
    // co-host ds-dnsgate wrote the `AdmissionKey` under, and the FORWARD lookup HITS.
    // Unset/empty → `""`, byte-identical to pre-agreement behavior.
    let session_uuid = fixed_uuid.unwrap_or_default().to_string();
    Some(SessionRef::new(
        session_uuid,
        String::new(),
        host_session_index,
        tap_name,
    ))
}

// ===========================================================================
// M0-host session-identity JOIN seam + fail-loud UUID guard (doc 14 §4; doc 12
// §2.1 invariant 2; D66/D44) — the address-derived vs orchestrator-joined split.
// ===========================================================================
//
// `session_from_local_addr` is PURE address arithmetic: it can derive only the
// interface-anchored `(host_session_index, tap_name)` pair (invariant 2 — never
// the source IP), because `session_uuid`/`host_id` are NOT carried in the
// post-NAT /31 address. Their authority is the ORCHESTRATOR SESSION RECORD
// (doc 14 §4), joined at the M0-host integration seam. An address-derived
// `SessionRef` therefore carries an EMPTY `session_uuid`/`host_id` (or, on the
// testbed, the best-effort `DS_SESSION_UUID`) — and any UUID-needing downstream
// (the FORWARD admission lookup, the DNS-2 re-resolve, the per-session CA ingest
// key, the §10 telemetry join) that reads it off an un-joined ref silently gets
// `""` and MIS-ATTRIBUTES the flow with no error.
//
// This seam makes that failure LOUD and the join EXPLICIT, WITHOUT modifying the
// FROZEN `ds_contracts::session::SessionRef` (it wraps `SessionRef`, consuming
// `SessionRef::new` as-is):
//
//   - [`SessionProvenance`] tags whether the global identity is `AddressDerived`
//     (only the address pair is authoritative) or `Joined` (the orchestrator
//     record supplied `session_uuid`/`host_id`);
//   - [`AttributedSession`] wraps a `SessionRef` + its provenance and offers a
//     [`AttributedSession::checked_session_uuid`] guard that REFUSES an empty
//     `session_uuid` (a UUID consumer must [`AttributedSession::join`] first or
//     explicitly opt into the address-only identity via
//     [`AttributedSession::session_ref`]);
//   - [`SessionRecordSource`] is the documented M0-host JOIN HOOK the orchestrator
//     session record implements; the LIVE integration (dialing/reading the record)
//     is DEFERRED-MANUAL — this module consumes the hook against a synthetic record
//     so the join + guard are exercised without a live orchestrator call.
//
// MARK-ONLY-ADDS is preserved (doc 12 §4.2): the guard gates UUID CONSUMERS only.
// An un-joined (empty-UUID) `AttributedSession` still marks + connects best-effort
// because the mark uses `host_session_index` (always authoritative — see
// [`AttributedSession::host_session_index`]), never the UUID. The guard NEVER
// touches the fail-closed egress boundary (the `SO_ORIGINAL_DST` refusal).

/// The provenance of a [`SessionRef`]'s GLOBAL-identity fields
/// (`session_uuid`/`host_id`) — doc 14 §4. The interface-anchored fields
/// (`host_session_index`/`tap_name`) are authoritative on BOTH arms; only the
/// global identity's trustworthiness differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionProvenance {
    /// Derived purely from the post-NAT local address
    /// ([`session_from_local_addr`]): only `host_session_index` + `tap_name` are
    /// authoritative. `session_uuid`/`host_id` were NOT joined from the
    /// orchestrator session record — they are either empty (the default) or the
    /// best-effort `DS_SESSION_UUID` testbed value, and a UUID CONSUMER must not
    /// read them without joining first (or explicitly opting into address-only
    /// identity).
    AddressDerived,
    /// `session_uuid`/`host_id` were supplied by the ORCHESTRATOR SESSION RECORD
    /// (doc 14 §4) at the M0-host join seam — the global identity is authoritative
    /// and safe for a UUID-needing downstream to consume.
    Joined,
}

/// The guard error: a UUID-needing downstream tried to consume `session_uuid` off
/// a [`SessionRef`] whose global identity was NEVER joined from the orchestrator
/// session record (doc 14 §4), so the field is the empty string — consuming it
/// would silently mis-attribute the flow to `""`. Fail LOUD (this error), never
/// silently. Carries the interface-anchored `tap_name` (always known — invariant
/// 2) so the caller can still name the flow when it reports/degrades.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UuidNotJoined {
    /// The never-recycled tap name (LOG-2 attribution key) — authoritative even on
    /// an un-joined ref, because it is interface-anchored (invariant 2), not part
    /// of the (absent) orchestrator identity.
    pub tap_name: String,
}

impl std::fmt::Display for UuidNotJoined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session_uuid consumed on an un-joined (address-derived) SessionRef for {} — \
             join from the orchestrator session record first (doc 14 §4)",
            self.tap_name
        )
    }
}

impl std::error::Error for UuidNotJoined {}

/// The GUARDED `session_uuid` read for a consumer that holds a RAW [`SessionRef`]
/// whose provenance was dropped at the M0-host join seam boundary
/// (`join_session_at_m0_host_seam` hands the existing accept-path consumers a bare
/// `SessionRef` via [`AttributedSession::into_session_ref`]). The two such live
/// consumers are the per-session-CA ingest key and the FORWARD / §10-telemetry
/// [`ds_contracts::dns_admission::AdmissionKey`] builder.
///
/// This is the SINGLE emptiness invariant [`AttributedSession::checked_session_uuid`]
/// also delegates to, so a raw-ref consumer that threads through it is guarded
/// BYTE-IDENTICALLY to the `AttributedSession` accessor: a NON-EMPTY uuid (a joined
/// ref, or an address-derived ref carrying the best-effort `DS_SESSION_UUID` testbed
/// value) is returned; an EMPTY (un-joined) uuid is REJECTED ([`UuidNotJoined`]) so
/// the consumer degrades to its sentinel / best-effort key rather than minting an
/// empty-string key (doc 12 §2.1 invariant 2 — attribution keys are interface-anchored,
/// never mis-keyed on an unresolved session). The guard NEVER refuses the flow: it
/// only names the degrade (mark-only-adds, doc 12 §4.2).
pub fn checked_session_uuid_of(session: &SessionRef) -> Result<&str, UuidNotJoined> {
    if session.session_uuid.is_empty() {
        return Err(UuidNotJoined {
            tap_name: session.tap_name.clone(),
        });
    }
    Ok(&session.session_uuid)
}

/// The orchestrator-supplied GLOBAL identity for a session (doc 14 §4) — the two
/// fields the post-NAT address cannot carry, resolved from the session record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    /// The orchestrator session UUID — the global identity.
    pub session_uuid: String,
    /// The host the session runs on.
    pub host_id: String,
}

/// The M0-host JOIN HOOK (doc 14 §4): the orchestrator session record, looked up
/// by the interface-anchored `(host_session_index, tap_name)` key — NEVER the
/// source IP (invariant 2) — that supplies the authoritative
/// `(session_uuid, host_id)` an address-derived [`SessionRef`] lacks.
///
/// The LIVE implementation dials/reads the orchestrator session record and is
/// DEFERRED-MANUAL (gate the live call behind an env flag in `main.rs`, the same
/// posture as the other `DS_*_LIVE` seams); this trait is consumed here against a
/// synthetic in-process record so the join + guard are exercised WITHOUT a live
/// orchestrator call (loopback/synthetic only, D50).
pub trait SessionRecordSource {
    /// Look the orchestrator identity up for an address-derived session, keyed on
    /// the interface-anchored `(host_session_index, tap_name)`. Returns `None` when
    /// the record has no entry — the join then does NOT fire and the ref stays
    /// [`SessionProvenance::AddressDerived`] (mark-only-adds: a session the record
    /// cannot name still marks + connects best-effort).
    fn identity_for(&self, host_session_index: u32, tap_name: &str) -> Option<SessionIdentity>;
}

/// A [`SessionRef`] tagged with the PROVENANCE of its global-identity fields, with
/// a fail-loud guard on `session_uuid` consumption. Wraps the FROZEN
/// `ds_contracts::session::SessionRef` (never modifies it) — the address-arithmetic
/// pair (`host_session_index`/`tap_name`) is always authoritative; the global
/// identity is trustworthy only after a [`join`](AttributedSession::join).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributedSession {
    session: SessionRef,
    provenance: SessionProvenance,
}

impl AttributedSession {
    /// Tag an address-derived [`SessionRef`] (from [`session_from_local_addr`]): the
    /// `(host_session_index, tap_name)` pair is authoritative, the global identity
    /// is NOT (empty, or the best-effort `DS_SESSION_UUID` testbed value).
    pub fn address_derived(session: SessionRef) -> AttributedSession {
        AttributedSession {
            session,
            provenance: SessionProvenance::AddressDerived,
        }
    }

    /// The M0-host JOIN (doc 14 §4): stamp the orchestrator session record's
    /// `session_uuid`/`host_id` onto the ref, producing a [`SessionProvenance::Joined`]
    /// ref whose global identity is authoritative. The interface-anchored
    /// `(host_session_index, tap_name)` arithmetic is PRESERVED byte-for-byte — the
    /// join supplies the global identity, it NEVER re-derives the address pair.
    ///
    /// Fails LOUD ([`UuidNotJoined`]) if the record supplies an EMPTY `session_uuid`:
    /// a record that cannot name the session is not a valid join, so we never mint a
    /// `Joined` ref that is still empty (that would defeat the guard).
    pub fn join(
        mut self,
        session_uuid: String,
        host_id: String,
    ) -> Result<AttributedSession, UuidNotJoined> {
        if session_uuid.is_empty() {
            return Err(UuidNotJoined {
                tap_name: self.session.tap_name.clone(),
            });
        }
        // Consume SessionRef::new as-is (FROZEN contract): reuse the authoritative
        // address pair, substitute the joined global identity.
        self.session = SessionRef::new(
            session_uuid,
            host_id,
            self.session.host_session_index,
            self.session.tap_name,
        );
        self.provenance = SessionProvenance::Joined;
        Ok(self)
    }

    /// Join via a [`SessionRecordSource`] hook: look the orchestrator identity up by
    /// the interface-anchored key and stamp it. A source MISS leaves the ref
    /// [`SessionProvenance::AddressDerived`] (mark-only-adds — a session the record
    /// cannot name still marks + connects best-effort, never refuses); a source HIT
    /// with an empty UUID fails LOUD via [`join`](AttributedSession::join) (never a
    /// `Joined`-but-empty ref). This is the deferred-manual live wire-up's shape.
    pub fn join_from<S: SessionRecordSource>(
        self,
        source: &S,
    ) -> Result<AttributedSession, UuidNotJoined> {
        match source.identity_for(self.session.host_session_index, &self.session.tap_name) {
            Some(id) => self.join(id.session_uuid, id.host_id),
            // Record has no entry → stay AddressDerived (best-effort), never refuse.
            None => Ok(self),
        }
    }

    /// The provenance of the global-identity fields.
    pub fn provenance(&self) -> SessionProvenance {
        self.provenance
    }

    /// Whether the global identity was joined from the orchestrator session record.
    pub fn is_joined(&self) -> bool {
        self.provenance == SessionProvenance::Joined
    }

    /// The always-authoritative host-local session index (address-derived; the mark
    /// key). Safe on BOTH provenances — the D76 mark never needs the UUID
    /// (mark-only-adds, doc 12 §4.2).
    pub fn host_session_index(&self) -> u32 {
        self.session.host_session_index
    }

    /// The always-authoritative never-recycled tap name (the LOG-2 attribution /
    /// NFT join key). Safe on BOTH provenances (interface-anchored, invariant 2).
    pub fn tap_name(&self) -> &str {
        &self.session.tap_name
    }

    /// The GUARDED `session_uuid` accessor for a UUID-needing downstream (the FORWARD
    /// admission lookup, the DNS-2 re-resolve, the per-session CA ingest key, the §10
    /// telemetry join). Returns the UUID only when it is NON-EMPTY (a joined ref, or
    /// an address-derived ref carrying the best-effort `DS_SESSION_UUID` testbed
    /// value); an un-joined EMPTY UUID is REJECTED ([`UuidNotJoined`]) so the flow is
    /// never silently mis-attributed to `""`.
    pub fn checked_session_uuid(&self) -> Result<&str, UuidNotJoined> {
        // Delegate to the shared emptiness invariant so a raw-ref consumer that
        // threads through [`checked_session_uuid_of`] is guarded byte-identically.
        checked_session_uuid_of(&self.session)
    }

    /// Borrow the underlying [`SessionRef`] for the address-anchored best-effort
    /// mark-and-connect path — the EXPLICIT address-only opt-in. Always safe
    /// regardless of join provenance because that path consumes only
    /// `host_session_index` (doc 12 §4.2 mark-only-adds), never `session_uuid`. This
    /// is how an un-joined session still marks and connects best-effort without
    /// tripping the UUID guard.
    pub fn session_ref(&self) -> &SessionRef {
        &self.session
    }

    /// Consume into the underlying [`SessionRef`] (for the existing accept-path
    /// consumers that take `SessionRef` directly). On the default un-joined path this
    /// is byte-identical to the ref [`session_from_local_addr`] produced.
    pub fn into_session_ref(self) -> SessionRef {
        self.session
    }
}

/// Bidirectionally splice an accepted downstream socket and an upstream
/// connection until both directions reach EOF, returning `(downstream→upstream,
/// upstream→downstream)` byte counts. This is the opaque-tunnel forward of the
/// transparent path (TLS-1 tunnels opaquely after the SNI/admission check; the
/// inspected TLS-3 path re-originates instead, a separate unit). It is the
/// framework-agnostic splice the real `accept/`/`connect/` layer drives over the
/// pingora-managed sockets; here it runs over any `Read + Write` pair so the
/// loopback e2e (and tests) can exercise an end-to-end transparent forward
/// without a live REDIRECT.
///
/// Half-close aware: each direction is copied on its own thread and shuts down
/// the write half of its sink at EOF, so a client that finishes sending (e.g. an
/// HTTP request) but waits for the response does not deadlock.
pub fn forward<D, U>(downstream: D, upstream: U) -> io::Result<(u64, u64)>
where
    D: io::Read + io::Write + TryCloneShutdown + Send + 'static,
    U: io::Read + io::Write + TryCloneShutdown + Send + 'static,
{
    let down_read = downstream;
    let up_read = upstream;
    // Clone the write halves so each pump thread owns one read end + one write end.
    let mut down_to_up_src = down_read.try_clone_io()?;
    let mut up_to_down_dst = down_read; // downstream write side
    let mut up_to_down_src = up_read.try_clone_io()?;
    let mut down_to_up_dst = up_read; // upstream write side

    // downstream → upstream
    let h1 = std::thread::spawn(move || -> io::Result<u64> {
        let n = io::copy(&mut down_to_up_src, &mut down_to_up_dst)?;
        // signal EOF upstream so the upstream peer can finish responding
        let _ = down_to_up_dst.shutdown_write();
        Ok(n)
    });
    // upstream → downstream
    let n_up_to_down = io::copy(&mut up_to_down_src, &mut up_to_down_dst)?;
    let _ = up_to_down_dst.shutdown_write();

    let n_down_to_up = h1
        .join()
        .map_err(|_| io::Error::other("downstream→upstream pump panicked"))??;
    Ok((n_down_to_up, n_up_to_down))
}

/// A socket that can be split into independent read/write handles and have its
/// write half shut down — the minimal surface [`forward`]'s half-close-aware
/// splice needs. Implemented for `std::net::TcpStream` (the loopback e2e and the
/// real downstream/upstream sockets); the production `accept/` layer implements
/// the equivalent over pingora's managed stream.
pub trait TryCloneShutdown: Sized {
    /// A second handle to the same underlying socket (the dual read/write end).
    fn try_clone_io(&self) -> io::Result<Self>;
    /// Shut down the write half (send EOF) without closing the read half.
    fn shutdown_write(&self) -> io::Result<()>;
}

impl TryCloneShutdown for std::net::TcpStream {
    fn try_clone_io(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

// ===========================================================================
// TLS-7 body-filter integration seam (doc 09 §5 TLS-7; doc 12 §5.1/§5.2/§13.5;
// D17/D73/D74/D40) — the DOCUMENTED, pingora-free entry point.
// ===========================================================================
//
// The opaque-tunnel [`forward`] splice above carries the TLS-1 default + TLS-4
// pass-through paths byte-for-byte (no inspection). The TLS-3-INSPECTED path is
// different: once the per-session CA ([`crate::ca`]) terminates the VM's TLS, the
// body-filter reads CLEARTEXT chunks and must scan each for secret egress (D73 the
// TLS-7 two-plane scan). The detection CORE — the [`crate::scan::SecretMatcher`]
// trait, the [`Verdict`] enum, the proxy-owned [`crate::scan::HoldBackBuffer`] /
// [`ScanGate`], and the [`crate::scan::DigestSetMatcher`] two-plane consumer — is
// already the pingora-free `crate::scan` module. THIS is the documented INTEGRATION
// SEAM that joins that core to the body-filter call shape: one cleartext chunk in,
// `(Verdict, released_bytes_count)` out.
//
// What is wired here (this unit): the chunk → gate → verdict → release-count
// translation, with the three frozen contracts honored by construction (they live
// in the gate, which this seam only drives):
//
//   - HOLD-BACK INVARIANT: no byte is released until the matcher says so. The gate's
//     [`crate::scan::HoldBackBuffer`] retains up to `max_secret_len - 1` trailing
//     bytes, so a secret straddling a chunk / TLS-record boundary is held until its
//     whole span is seen — never released after only its prefix. This seam returns
//     the COUNT the verdict released (0 for `Hold`/`Block`), never more.
//   - FAIL-CLOSED-WHEN-KEYED: a matcher error while the keyed plane is loaded
//     collapses to [`Verdict::Hold`] inside [`ScanGate::scan_chunk`] (doc 12 §13.5);
//     the present-but-UNSEALED keyed plane (mint-before-attach, D109) is exactly that
//     case — the [`crate::scan::DigestSetMatcher`] errors until `seal_keyed`, so this
//     seam returns `(Hold, 0)` and releases nothing.
//   - DIRECTION-SYMMETRIC, EGRESS-ONLY v0: the [`ScanCtx`] is request-direction
//     (`egress`); the response leg is policy, not a verdict-shape change (D73).
//
// What is DEFERRED (the real wiring, a later unit): the live pingora `TlsAccept`
// resolver integration and the body-filter HOOK INSTALLATION that pulls each
// cleartext chunk off the terminated stream and feeds it here. That hook lives in
// `src/main.rs` behind `DS_TLS3_LIVE` exactly as the TLS-3 inspected path is gated;
// the TLS-4 pass-through arm (D17/D74) NEVER reaches it. This unit is the documented
// seam + a no-op test harness proving the call signature — it is NOT live-wired, so
// the default (`DS_TLS3_LIVE` unset) path stays byte-identical and this symbol does
// not appear in any boundary test name.
//
// NEVER-LOG-THE-SECRET (D73 §5.1): the seam returns only the [`Verdict`] (which
// carries the fingerprint-free [`crate::scan::ScanProvenance`] on a non-`Pass` arm —
// rule id + ruleset version + policy layer + plane, NEVER a matched byte) and a
// release COUNT. No cleartext byte and no matched fingerprint crosses this boundary
// into any event the caller builds.

/// The pingora-free TLS-7 body-filter integration seam (doc 12 §5.1/§13.5; D73).
///
/// Drive ONE cleartext `chunk` of the inspected (TLS-3-terminated) request body
/// through the proxy-owned [`ScanGate`] and report what the matcher decided:
///
/// - the [`Verdict`] the body-filter hook acts on (`Pass{release_n}` → forward that
///   many cleared bytes; `Hold` → forward nothing, await more; `Block`/`Flag`/
///   `Redact` → the non-`Pass` arms carry the fingerprint-free provenance), and
/// - the COUNT of leading hold-back bytes the matcher CLEARED for egress this call
///   (`release_n` on `Pass`, the releasable-floor span on `Flag`, and `0` on
///   `Hold`/`Block`/`Redact` — no byte released).
///
/// The returned count is the contract the caller's forwarding loop obeys: it may
/// forward exactly that many bytes from the front of the gate's hold-back buffer (via
/// [`ScanGate::take_released`]), never more. The hold-back invariant is the gate's:
/// this seam never asks for more than the verdict cleared, so a boundary-spanning
/// secret stays buffered until its whole span is scanned.
///
/// `end_of_stream` is set on the final chunk so a tail candidate is resolved (the
/// matcher's `Pass` then clears the remainder). `ctx` names the scan direction
/// ([`ScanCtx::egress`] for the v0 request direction).
///
/// Fail-closed posture is the GATE's (doc 12 §13.5): with the keyed plane loaded any
/// matcher error — including the present-but-unsealed mint-before-attach case (D109)
/// — collapses to `(Verdict::Hold, 0)` inside [`ScanGate::scan_chunk`], so this seam
/// releases NO byte against a half-attached digest set. With NO plane loaded the gate
/// `Pass`es its hold-back floor: a clean stream forwards intact (the byte-identical
/// inspected default), and a `zero-length` hold-back window is a no-op release.
///
/// This is the documented seam ONLY — not the live body-filter wiring (the pingora
/// `TlsAccept` resolver + the hook install are a deferred `main.rs` unit behind
/// `DS_TLS3_LIVE`). Never-log-the-secret: the return carries only the `Verdict`
/// (fingerprint-free provenance) + a count — no cleartext byte, no matched
/// fingerprint (D73 §5.1).
pub fn request_body_scan<M: SecretMatcher>(
    gate: &mut ScanGate<M>,
    chunk: &[u8],
    end_of_stream: bool,
    ctx: &ScanCtx,
) -> (Verdict, usize) {
    let verdict = gate.scan_chunk(chunk, end_of_stream, ctx);
    let released = match &verdict {
        // The matcher cleared `release_n` leading bytes for egress.
        Verdict::Pass { release_n } => *release_n,
        // Alert mode: the bytes pass (the generic-plane block+log alert rung is a
        // Block; Flag is pass+log). Release up to the hold-back floor so the stream
        // keeps moving — never the trailing window (a candidate may still be forming).
        Verdict::Flag(_) => gate.buffer().releasable_floor(),
        // No byte released: Hold awaits more input, Block drops the whole buffer
        // (matched bytes never egress), Redact is reserved (release nothing so an
        // unredacted byte never leaks while the slot is unimplemented).
        Verdict::Hold | Verdict::Block(_) | Verdict::Redact(_) => 0,
    };
    (verdict, released)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    /// A fake recovery provider so the refuse-on-failure path (D69 invariant 3)
    /// is unit-tested WITHOUT a live REDIRECT — this host's kernel cannot program
    /// the nft redirect/nat modules (reboot-pending; see SPIKE-NOTES.md), so the
    /// getsockopt against a real redirected socket is the deferred live demo. The
    /// `Socket2OriginalDst` getsockopt path itself is exercised against a real
    /// loopback socket in `socket2_recovery_refuses_a_non_redirected_socket`.
    struct FakeRecovery {
        result: Result<SocketAddr, RecoveryError>,
        calls: Arc<AtomicUsize>,
    }

    impl FakeRecovery {
        fn ok(addr: SocketAddr) -> FakeRecovery {
            FakeRecovery {
                result: Ok(addr),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn fail(err: RecoveryError) -> FakeRecovery {
            FakeRecovery {
                result: Err(err),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl OriginalDst for FakeRecovery {
        fn original_dst(&self) -> Result<SocketAddr, RecoveryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    // ── invariant 1 + 2: ConnOrigin pairs kernel dst with interface session ──

    #[test]
    fn recovery_pairs_kernel_dst_with_interface_anchored_session() {
        // The recovered original_dst is the unforgeable kernel fact (invariant 1);
        // the session is the listener's per-tap attachment, NEVER the peer/source
        // IP (invariant 2). Here the recovery provider stands in for the kernel.
        let s = session(7);
        let dst: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let origin = recover_conn_origin(&s, &FakeRecovery::ok(dst)).expect("recovers");
        assert_eq!(origin.original_dst, dst);
        // session came from the SessionRef the listener supplied (the tap), not
        // from any connection peer address.
        assert_eq!(origin.session.tap_name, "dstap-7");
        assert_eq!(origin.session, s);
    }

    #[test]
    fn admission_signature_consumes_only_conn_origin_fields() {
        // invariant 4: allow = f(session, sni, original_dst) is mechanism-
        // independent — the dst component derives ONLY from ConnOrigin, so a
        // TPROXY backend that produced the same ConnOrigin yields the same key.
        let s = session(3);
        let dst: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let origin = recover_conn_origin(&s, &FakeRecovery::ok(dst)).unwrap();
        let (ip, port) = admission_dst_key(&origin);
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    // ── invariant 3: recovery failure REFUSES (the graded core) ──────────────

    #[test]
    fn recovery_failure_refuses_the_connection() {
        // D69 invariant 3 (frozen): a flow with no kernel original_dst — it never
        // transited the redirect — has no trustworthy origin and is REFUSED. The
        // resolver returns Err; the listener closes without reading a byte.
        let s = session(5);
        let err = recover_conn_origin(&s, &FakeRecovery::fail(RecoveryError::NoOriginalDst))
            .expect_err("must refuse");
        assert_eq!(err, RecoveryError::NoOriginalDst);
    }

    #[test]
    fn every_recovery_error_class_refuses() {
        let s = session(2);
        for err in [
            RecoveryError::NoOriginalDst,
            RecoveryError::AddressFamilyMismatch,
            RecoveryError::Undecodable,
        ] {
            let got = recover_conn_origin(&s, &FakeRecovery::fail(err.clone()))
                .expect_err("every class refuses");
            assert_eq!(got, err);
        }
    }

    #[test]
    fn recovery_failure_event_carries_session_attribution_and_no_client_bytes() {
        // The §10 event keeps the LOG-2 attribution (the tap name, which survives
        // because session is interface-anchored, invariant 2) and a stable
        // reason code — never a client byte (no trustworthy dst was recovered).
        let s = session(9);
        let err = RecoveryError::NoOriginalDst;
        let ev = recovery_failure_event(&s, &err);
        assert_eq!(ev.tap_name, "dstap-9");
        assert_eq!(ev.reason, "no-original-dst");
        // reason codes are stable + secret-free for every class.
        assert_eq!(
            recovery_failure_event(&s, &RecoveryError::AddressFamilyMismatch).reason,
            "original-dst-family-mismatch"
        );
        assert_eq!(
            recovery_failure_event(&s, &RecoveryError::Undecodable).reason,
            "original-dst-undecodable"
        );
    }

    #[test]
    fn recovery_reads_the_kernel_source_exactly_once_before_any_byte() {
        // invariant 1 + the eager-getsockopt recommendation (doc 12 §2 free cell):
        // recover before reading a client byte; exactly one kernel read.
        let s = session(1);
        let dst: SocketAddr = "203.0.113.1:80".parse().unwrap();
        let fake = FakeRecovery::ok(dst);
        let calls = fake.calls.clone();
        let _ = recover_conn_origin(&s, &fake).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ── the production getsockopt path against a REAL socket ──────────────────

    #[test]
    fn socket2_recovery_refuses_a_non_redirected_socket() {
        // The production Socket2OriginalDst provider (the SO_ORIGINAL_DST
        // getsockopt — the same mechanism as SocketDigest::original_dst()) run
        // against a REAL loopback socket that never transited a REDIRECT rule.
        // The kernel has no conntrack original-dst for it, so the getsockopt
        // fails (ENOENT/ENOPROTOOPT) and we REFUSE (invariant 3). This exercises
        // the actual syscall path on this host; the live REDIRECT demo (where the
        // SAME call SUCCEEDS) is reboot-pending — see SPIKE-NOTES.md.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, _peer) = listener.accept().unwrap();
        // the listener's own bind address — the REDIRECT target stand-in. On a
        // never-redirected socket the kernel's SO_ORIGINAL_DST falls back to this.
        let listener_local = accepted.local_addr().unwrap();

        let s = session(4);
        let recovery = Socket2OriginalDst::v4(&accepted, listener_local);
        let result = recover_conn_origin(&s, &recovery);
        // A direct loopback connect never transited the NAT rule → refuse.
        assert!(
            matches!(result, Err(RecoveryError::NoOriginalDst)),
            "non-redirected socket must refuse, got {result:?}"
        );

        // and the §10 event is well-formed off that refusal.
        let err = result.unwrap_err();
        let ev = recovery_failure_event(&s, &err);
        assert_eq!(ev.tap_name, "dstap-4");
        drop(client);
    }

    #[test]
    fn socket2_recovery_succeeds_and_decodes_a_real_getsockopt_value() {
        // The SUCCESS half of the production getsockopt path against a REAL
        // socket: the SO_ORIGINAL_DST decode yields a concrete v4 SocketAddr (the
        // kernel's getsockname fallback returns the loopback local address here).
        // By telling the provider a DIFFERENT listener_local than the real bind
        // address, the recovered value is treated as a genuine pre-DNAT dst and
        // decodes into a ConnOrigin — proving the getsockopt → SockAddr →
        // SocketAddr decode (the exact bytes SocketDigest::original_dst() returns)
        // works end to end on this host. The live REDIRECT, where the kernel
        // returns the REAL upstream instead of the getsockname fallback, is
        // reboot-pending (SPIKE-NOTES.md) — but the decode path is identical.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, _peer) = listener.accept().unwrap();

        // a sentinel listener_local the recovered value will NOT equal, so the
        // getsockname-fallback guard does not trip and we see the decode succeed.
        let sentinel: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 255, 255, 254), 1));
        let s = session(8);
        let recovery = Socket2OriginalDst::v4(&accepted, sentinel);
        let origin =
            recover_conn_origin(&s, &recovery).expect("decodes a real v4 getsockopt value");
        // the recovered dst is a real, decoded v4 SocketAddr (the loopback local
        // address the kernel returned), paired with the interface-anchored session.
        assert!(origin.original_dst.is_ipv4());
        assert_eq!(origin.original_dst.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(origin.session.tap_name, "dstap-8");
        drop(client);
    }

    #[test]
    fn family_mismatch_is_refused_never_reinterpreted() {
        // A v6 expectation against a v4-recovering loopback socket: the recovered
        // SockAddr is v4 but is_ipv6 is true, so the family guard refuses rather
        // than reinterpreting the bytes (invariant: never guess the family).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, _peer) = listener.accept().unwrap();

        let sentinel: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0));
        let s = session(2);
        // v6 provider over a v4 socket → original_dst_v6 either errors (→ refuse)
        // or returns a v4-shaped storage the family guard rejects. Either way:
        // REFUSE, never a reinterpreted address.
        let recovery = Socket2OriginalDst::v6(&accepted, sentinel);
        let result = recover_conn_origin(&s, &recovery);
        assert!(
            result.is_err(),
            "a v6 recovery over a v4 socket must refuse, got {result:?}"
        );
        drop(client);
    }

    // ── OQ1/D66: session derivation from the post-NAT local address ───────────

    #[test]
    fn session_from_local_addr_derives_index_and_tap_by_one_subtraction() {
        // The post-NAT local address is the per-session /31 host-side gateway
        // 10.77.<idx>.0 (OQ1/D66). host_session_index is the third octet (one
        // subtraction of the 10.77.0.0 base, whose third octet is 0); the tap name
        // is the never-recycled dstap-<idx> join key (doc 12 §2.1 invariant 2,
        // §13.1).
        for idx in [0u8, 1, 7, 42, 200, 255] {
            let local: SocketAddr =
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, idx, 0), 18443));
            let s = session_from_local_addr(local).expect("derives a session");
            assert_eq!(
                s.host_session_index,
                u32::from(idx),
                "host_session_index is the third octet (idx={idx})"
            );
            assert_eq!(
                s.tap_name,
                format!("dstap-{idx}"),
                "tap name is the authoritative dstap-<idx> join key (idx={idx})"
            );
        }
    }

    #[test]
    fn session_from_local_addr_ignores_the_port_and_the_guest_half_of_the_31() {
        // Only the third octet matters: the listener port and the /31 host part
        // (the .0 gateway vs the .1 guest) do not change the derived index — the
        // recovery signal is the per-session network, encoded in the third octet.
        let gw: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 9, 0), 18080));
        let other_port: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 9, 0), 18443));
        assert_eq!(
            session_from_local_addr(gw).unwrap().host_session_index,
            session_from_local_addr(other_port)
                .unwrap()
                .host_session_index,
            "the listener port does not change attribution"
        );
        assert_eq!(session_from_local_addr(gw).unwrap().tap_name, "dstap-9");
    }

    #[test]
    fn session_from_local_addr_degrades_on_a_malformed_address() {
        // A local address that is NOT the per-session 10.77.x.y shape (an
        // unexpected/malformed post-NAT local: a loopback test bind, a foreign
        // prefix, or a v6 local) yields None → the caller degrades to the prior
        // UNMARKED best-effort connect. The D76 mark only ADDS; a derivation that
        // cannot resolve a session NEVER refuses the connect (fail-closed boundary
        // unchanged).
        let cases: [SocketAddr; 4] = [
            // loopback (a direct test/connect bind, not a per-session gateway)
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443)),
            // right first octet, wrong second → outside the session net
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 99, 7, 0), 18443)),
            // a wholly foreign prefix
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 443)),
            // an IPv6 local address (not the OQ1 v4 /31 shape)
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 18443, 0, 0)),
        ];
        for local in cases {
            assert!(
                session_from_local_addr(local).is_none(),
                "a non-per-session local address must degrade to None (no session), got Some for {local}"
            );
        }
    }

    #[test]
    fn unset_session_uuid_stamps_empty_byte_identical_to_pre_agreement() {
        // DEFAULT (DS_SESSION_UUID unset / `None`): the derived SessionRef carries the
        // EMPTY session_uuid — byte-identical to pre-agreement behavior. host_id stays
        // empty; the address-arithmetic (index/tap) is unchanged.
        let local: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 7, 0), 18443));
        let s = session_from_local_addr_with_uuid(local, None).expect("derives a session");
        assert_eq!(
            s.session_uuid, "",
            "unset env → empty session_uuid (unchanged)"
        );
        assert_eq!(
            s.host_id, "",
            "host_id stays empty (joined at the M0-host seam)"
        );
        assert_eq!(s.host_session_index, 7);
        assert_eq!(s.tap_name, "dstap-7");
    }

    #[test]
    fn set_session_uuid_is_stamped_at_the_single_derivation_point() {
        // With DS_SESSION_UUID set, the agreed uuid is stamped as the SessionRef
        // session_uuid (the single derivation point ALL consumers read). The
        // address-arithmetic (index/tap) is untouched.
        let uuid = "sess-2026-nested-testbed-0001";
        let local: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 7, 0), 18443));
        let s = session_from_local_addr_with_uuid(local, Some(uuid)).expect("derives a session");
        assert_eq!(
            s.session_uuid, uuid,
            "the agreed uuid is stamped on the SessionRef"
        );
        assert_eq!(s.host_session_index, 7, "the index arithmetic is unchanged");
        assert_eq!(s.tap_name, "dstap-7", "the tap join key is unchanged");
    }

    // ── M0-host join seam + fail-loud UUID guard (doc 14 §4) ──────────────────

    /// A synthetic orchestrator session record (the M0-host join hook) keyed on the
    /// interface-anchored `(host_session_index, tap_name)` — stands in for the live
    /// record read (deferred-manual) so the join + guard run without an orchestrator.
    struct FakeSessionRecord {
        entries: std::collections::HashMap<(u32, String), SessionIdentity>,
    }

    impl FakeSessionRecord {
        fn with(idx: u32, tap: &str, uuid: &str, host: &str) -> FakeSessionRecord {
            let mut entries = std::collections::HashMap::new();
            entries.insert(
                (idx, tap.to_string()),
                SessionIdentity {
                    session_uuid: uuid.to_string(),
                    host_id: host.to_string(),
                },
            );
            FakeSessionRecord { entries }
        }
        fn empty() -> FakeSessionRecord {
            FakeSessionRecord {
                entries: std::collections::HashMap::new(),
            }
        }
    }

    impl SessionRecordSource for FakeSessionRecord {
        fn identity_for(&self, idx: u32, tap: &str) -> Option<SessionIdentity> {
            self.entries.get(&(idx, tap.to_string())).cloned()
        }
    }

    /// The address-derived SessionRef the accept path builds when DS_SESSION_UUID is
    /// unset: empty global identity, authoritative address pair.
    fn address_derived_session(idx: u32) -> AttributedSession {
        let local: SocketAddr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 77, u8::try_from(idx).unwrap(), 0),
            18443,
        ));
        let s = session_from_local_addr_with_uuid(local, None).expect("derives a session");
        AttributedSession::address_derived(s)
    }

    #[test]
    fn address_derived_ref_marks_and_connects_unchanged() {
        // MARK-ONLY-ADDS: an un-joined (empty-UUID) ref still exposes the
        // authoritative address pair the mark + connect path consume — byte-identical
        // to the raw SessionRef `session_from_local_addr` produced. The guard gates
        // UUID consumers ONLY, never the address-anchored mark/connect.
        let attr = address_derived_session(7);
        assert_eq!(attr.provenance(), SessionProvenance::AddressDerived);
        assert!(!attr.is_joined());
        // the address pair the D76 mark uses is present + correct on the un-joined ref
        assert_eq!(attr.host_session_index(), 7);
        assert_eq!(attr.tap_name(), "dstap-7");
        // and the underlying SessionRef the connect path takes is byte-identical to
        // the pure address-derivation (empty global identity, same index/tap).
        let local: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 7, 0), 18443));
        let raw = session_from_local_addr_with_uuid(local, None).unwrap();
        assert_eq!(attr.session_ref(), &raw);
        assert_eq!(attr.clone().into_session_ref(), raw);
        // the mark index (host_session_index residue) is derivable with NO join.
        assert_eq!(attr.session_ref().host_session_index, 7);
    }

    #[test]
    fn uuid_consumption_of_an_unjoined_ref_is_rejected() {
        // The fail-loud guard: a UUID-needing downstream that reads session_uuid off
        // an un-joined (empty) ref is REJECTED rather than silently handed `""` (which
        // would mis-attribute the flow). The error carries the interface-anchored tap
        // name so the caller can still name the flow.
        let attr = address_derived_session(9);
        let err = attr
            .checked_session_uuid()
            .expect_err("empty session_uuid must be rejected");
        assert_eq!(err.tap_name, "dstap-9");
        // the Display is secret-free + names the tap (LOG-2 attribution survives).
        assert!(err.to_string().contains("dstap-9"));
        assert!(err.to_string().contains("un-joined"));
    }

    #[test]
    fn checked_session_uuid_of_guards_a_raw_ref_identically_to_the_method() {
        // The raw-ref free-function guard (threaded by the per-session-CA + FORWARD
        // AdmissionKey consumers whose provenance is dropped at the M0-host seam) is
        // the SINGLE emptiness invariant the AttributedSession accessor delegates to,
        // so a raw `SessionRef` is guarded BYTE-IDENTICALLY.
        //
        // Un-joined (empty UUID) ⇒ rejected, never handed `""`; the error carries the
        // interface-anchored tap so the consumer can still name the degrade.
        let unjoined = SessionRef::new(String::new(), String::new(), 9, "dstap-9".into());
        let err = checked_session_uuid_of(&unjoined)
            .expect_err("an empty session_uuid must be rejected, never keyed on \"\"");
        assert_eq!(err.tap_name, "dstap-9");
        // The method delegates to the free fn ⇒ same verdict for the same ref.
        assert!(AttributedSession::address_derived(unjoined)
            .checked_session_uuid()
            .is_err());

        // A NON-EMPTY uuid (a joined ref, or the best-effort DS_SESSION_UUID testbed
        // value on an address-derived ref) PASSES and returns the authoritative id.
        let joined = SessionRef::new(
            "sess-orch-0042".into(),
            "host-a".into(),
            7,
            "dstap-7".into(),
        );
        assert_eq!(
            checked_session_uuid_of(&joined).expect("a non-empty uuid passes"),
            "sess-orch-0042"
        );
    }

    #[test]
    fn a_joined_ref_passes_through_with_both_fields_populated() {
        // The join stamps the orchestrator identity; the guard then PASSES, returning
        // the authoritative UUID. The address pair is preserved byte-for-byte.
        let joined = address_derived_session(7)
            .join(
                "11111111-2222-3333-4444-555555555555".into(),
                "host-a".into(),
            )
            .expect("a non-empty UUID joins");
        assert_eq!(joined.provenance(), SessionProvenance::Joined);
        assert!(joined.is_joined());
        assert_eq!(
            joined.checked_session_uuid().expect("joined UUID passes"),
            "11111111-2222-3333-4444-555555555555"
        );
        // both global fields are populated, and the address pair is UNCHANGED.
        assert_eq!(
            joined.session_ref().host_id,
            "host-a",
            "host_id joined from the record"
        );
        assert_eq!(joined.host_session_index(), 7, "the index is preserved");
        assert_eq!(
            joined.tap_name(),
            "dstap-7",
            "the tap join key is preserved"
        );
    }

    #[test]
    fn join_with_an_empty_uuid_fails_loud_never_a_joined_but_empty_ref() {
        // A record that supplies an EMPTY session_uuid is NOT a valid join: joining
        // must never mint a `Joined` ref that is still empty (that would defeat the
        // guard downstream). Fail loud instead.
        let err = address_derived_session(3)
            .join(String::new(), "host-a".into())
            .expect_err("an empty UUID must not produce a Joined ref");
        assert_eq!(err.tap_name, "dstap-3");
    }

    #[test]
    fn join_from_a_record_hit_stamps_identity_and_passes_the_guard() {
        // The M0-host hook: a record HIT keyed on (host_session_index, tap_name)
        // stamps both fields → Joined → the guard passes.
        let record = FakeSessionRecord::with(7, "dstap-7", "sess-orch-0007", "host-bare-metal-a");
        let joined = address_derived_session(7)
            .join_from(&record)
            .expect("a record hit joins");
        assert!(joined.is_joined());
        assert_eq!(joined.checked_session_uuid().unwrap(), "sess-orch-0007");
        assert_eq!(joined.session_ref().host_id, "host-bare-metal-a");
    }

    #[test]
    fn join_from_a_record_miss_stays_address_derived_best_effort() {
        // A record MISS (the orchestrator record has no entry for this key) leaves the
        // ref AddressDerived — mark-only-adds: it still marks + connects best-effort,
        // and the UUID guard still fires for any UUID consumer (never silently `""`).
        let record = FakeSessionRecord::empty();
        let attr = address_derived_session(7)
            .join_from(&record)
            .expect("a miss does not refuse");
        assert_eq!(attr.provenance(), SessionProvenance::AddressDerived);
        assert!(
            attr.checked_session_uuid().is_err(),
            "the guard still fires"
        );
        // the address pair is intact for the best-effort mark.
        assert_eq!(attr.host_session_index(), 7);
        assert_eq!(attr.tap_name(), "dstap-7");
    }

    #[test]
    fn best_effort_testbed_uuid_passes_the_guard_without_a_join() {
        // The DS_SESSION_UUID testbed path stamps a NON-EMPTY session_uuid onto an
        // address-derived ref (cross-process key agreement, doc 11 §5.1). The guard is
        // emptiness-based, so that best-effort UUID is a legitimate opt-in that PASSES
        // — while the field stays provenance-tagged AddressDerived (not orch-joined).
        let local: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 7, 0), 18443));
        let s = session_from_local_addr_with_uuid(local, Some("sess-testbed-0001"))
            .expect("derives a session");
        let attr = AttributedSession::address_derived(s);
        assert_eq!(attr.provenance(), SessionProvenance::AddressDerived);
        assert_eq!(
            attr.checked_session_uuid()
                .expect("a non-empty testbed UUID passes"),
            "sess-testbed-0001"
        );
    }

    #[test]
    fn forward_read_key_equals_the_dnsgate_written_key_so_the_lookup_hits() {
        // The cross-process FORWARD-lookup agreement (doc 11 §5.1 / D131-rollout): with the
        // SAME DS_SESSION_UUID on both sides AND the dot-less canonical fqdn, the
        // AdmissionKey ds-tlsproxy BUILDS for a redirected conn EQUALS the AdmissionKey
        // ds-dnsgate WRITES for the same (uuid, host) — so the FORWARD lookup HITS instead of
        // missing on the empty `""` / dotted-fqdn divergence the fix closes.
        let uuid = "sess-2026-nested-testbed-0001";
        // ds-tlsproxy READ side: derive the redirected-conn SessionRef (uuid stamped from the
        // agreed env), then build the FORWARD key exactly as `decide`/`origin_is_admitted`
        // do — `session_uuid` from the conn origin + the SNI host (dot-less, as
        // `classify_host` yields).
        let local: SocketAddr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 77, 7, 0), 18443));
        let session =
            session_from_local_addr_with_uuid(local, Some(uuid)).expect("derives a session");
        let sni_dot_less = "api.anthropic.com"; // the classify_host output (trailing dot stripped)
        let read_key = ds_contracts::dns_admission::AdmissionKey {
            session_uuid: session.session_uuid.clone(),
            original_query_fqdn: sni_dot_less.to_string(),
        };

        // ds-dnsgate WRITE side: the handler composes its AdmissionKey from the FixedUuid
        // session token + the DOT-LESS canonical fqdn (`admission_key_fqdn` strips the
        // trailing dot of the `api.anthropic.com.` query name). Model that written key here.
        let written_key = ds_contracts::dns_admission::AdmissionKey {
            session_uuid: uuid.to_string(),
            original_query_fqdn: "api.anthropic.com".to_string(),
        };

        assert_eq!(
            read_key, written_key,
            "the tlsproxy read key equals the dnsgate write key — the cross-process FORWARD lookup HITS"
        );
        // And the divergent pre-fix halves (empty uuid OR dotted fqdn) would NOT have matched.
        assert_ne!(
            read_key,
            ds_contracts::dns_admission::AdmissionKey {
                session_uuid: String::new(),
                original_query_fqdn: "api.anthropic.com".to_string(),
            },
            "the empty-uuid read key (pre-fix) would have missed"
        );
        assert_ne!(
            written_key,
            ds_contracts::dns_admission::AdmissionKey {
                session_uuid: uuid.to_string(),
                original_query_fqdn: "api.anthropic.com.".to_string(),
            },
            "the dotted-fqdn write key (pre-fix) would have missed"
        );
    }

    // ── the forward splice: end-to-end transparent forward over loopback ──────

    #[test]
    fn forward_splices_bytes_bidirectionally_to_eof() {
        // The opaque-tunnel forward: once recovery (+ in production, admission)
        // succeed, bytes flow both ways between the accepted downstream socket and
        // the upstream. Stand up a real loopback upstream echo-with-banner and
        // splice a downstream pair through forward(), proving an end-to-end
        // transparent forward without a live REDIRECT.
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_addr = upstream.local_addr().unwrap();

        // upstream: read the request, reply with a banner + echo.
        let up_handle = std::thread::spawn(move || {
            let (mut conn, _) = upstream.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            conn.write_all(b"UPSTREAM-OK:").unwrap();
            conn.write_all(&buf[..n]).unwrap();
            conn.shutdown(std::net::Shutdown::Write).unwrap();
        });

        // downstream: a socketpair-like loopback the "client" writes to.
        let down_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let down_addr = down_listener.local_addr().unwrap();
        let client_handle = std::thread::spawn(move || {
            let mut client = TcpStream::connect(down_addr).unwrap();
            client.write_all(b"hello-upstream").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).unwrap();
            resp
        });
        let (downstream, _) = down_listener.accept().unwrap();
        let up_conn = TcpStream::connect(up_addr).unwrap();

        let (n_down_up, n_up_down) = forward(downstream, up_conn).unwrap();

        let resp = client_handle.join().unwrap();
        up_handle.join().unwrap();
        assert_eq!(&resp, b"UPSTREAM-OK:hello-upstream");
        assert_eq!(n_down_up, b"hello-upstream".len() as u64);
        assert_eq!(n_up_down, b"UPSTREAM-OK:hello-upstream".len() as u64);
    }

    // =======================================================================
    // TLS-7 body-filter integration seam — `request_body_scan` (doc 12 §5.1 /
    // §13.5; D73). A no-op harness PROVING the call signature `(ScanGate<
    // DigestSetMatcher>, cleartext_chunk, end_of_stream) -> (Verdict,
    // released_bytes_count)` over a pre-loaded matcher + gate, and that no
    // plaintext / matched byte leaks into the returned Verdict (the only thing
    // the caller would build an event from). This is the documented seam, NOT
    // the live body-filter wiring (the pingora hook is a deferred `main.rs`
    // unit) — so `request_body_scan` appears in no boundary test name.
    // =======================================================================

    use crate::scan::{
        CredClass, DigestAlgo, DigestFamily, DigestHasher, DigestScope, DigestSetMatcher, FailMode,
        KeyedDigest, KeyedPublish, Plane, VariantTag,
    };

    const SEAM_KEY_ID: &str = "seam-key-u3";

    /// A self-contained fake keyed-hash for the seam harness (independent of the
    /// `scan` module's test hasher): identity-over-the-window for the one known
    /// key. The stored digest is therefore the encoded secret bytes themselves, so
    /// a wire window equal to the secret matches — enough to PROVE the seam's
    /// release/hold translation without re-implementing HMAC (the live `ring::hmac`
    /// is Identity/Boundary, §9-Free). Never holds a key; never logs a byte.
    struct SeamHasher;

    impl DigestHasher for SeamHasher {
        fn hash(
            &self,
            key_id: &str,
            candidate: &[u8],
            _truncation_len_bytes: usize,
        ) -> Option<Vec<u8>> {
            if key_id == SEAM_KEY_ID {
                Some(candidate.to_vec())
            } else {
                None
            }
        }
    }

    /// Publish a single Forbidden-class keyed digest over `secret` (raw variant)
    /// the way [`SeamHasher`] hashes it (identity), so the matcher blocks an exact
    /// `secret` window. Produces ONLY the digest, never the plaintext field
    /// (plaintext-never-crosses-the-seam, doc 14 §7).
    fn seam_digest(secret: &[u8], rule_id: &str) -> KeyedDigest {
        KeyedDigest {
            key_id: SEAM_KEY_ID.to_string(),
            algo: DigestAlgo {
                family: DigestFamily::HmacSha256,
                truncation_len_bytes: secret.len(),
            },
            digest: secret.to_vec(),
            cred_class: CredClass::Forbidden,
            scope: DigestScope::Session,
            expiry_unix_secs: Some(1_900_000_000),
            variant_tag: VariantTag::Raw,
            rule_id: rule_id.to_string(),
        }
    }

    /// Build a SEALED keyed gate over a single canary (mint-before-attach
    /// satisfied → keyed matching live), sized so the canary fits the hold-back
    /// window. The exact shape the deferred body-filter hook hands the seam.
    fn sealed_gate(secret: &[u8], rule_id: &str) -> ScanGate<DigestSetMatcher<SeamHasher>> {
        let max_len = secret.len();
        let mut matcher = DigestSetMatcher::new(SeamHasher, max_len);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "sess-u3".into(),
            entries: vec![seam_digest(secret, rule_id)],
            batch_id: "batch-u3".into(),
            digest_set_version: "ds-u3".into(),
        });
        matcher.seal_keyed();
        let keyed_loaded = matcher.keyed_loaded();
        ScanGate::new(matcher, max_len, keyed_loaded, FailMode::Closed)
            .expect("fail-closed gate is always constructible")
    }

    /// Stringify a `(Verdict, usize)` seam return and assert the secret's bytes
    /// appear NOWHERE in it — the never-log-the-secret type property the caller
    /// relies on when it builds an event off the returned Verdict (D73 §5.1).
    fn assert_no_secret_in_return(ret: &(Verdict, usize), secret: &[u8]) {
        let dbg = format!("{ret:?}");
        assert!(
            !dbg.as_bytes().windows(secret.len()).any(|w| w == secret),
            "secret bytes leaked into the seam return: {dbg}"
        );
    }

    #[test]
    fn request_body_scan_seam_blocks_a_single_chunk_canary_releasing_zero_bytes() {
        // The documented call signature: (ScanGate<DigestSetMatcher>, chunk,
        // end_of_stream) -> (Verdict, released_n). A planted canary blocks; the
        // seam reports Block + ZERO released bytes (matched bytes never egress).
        let secret = b"ghp_seamCANARY0001xx";
        let mut gate = sealed_gate(secret, "canary-seam");
        let ctx = ScanCtx::egress();

        let body = b"clean-lead ghp_seamCANARY0001xx".as_slice();
        let ret = request_body_scan(&mut gate, body, true, &ctx);

        match &ret.0 {
            Verdict::Block(p) => {
                assert_eq!(p.plane, Plane::Keyed, "the keyed canary blocks");
                assert_eq!(p.rule_id, "canary-seam");
            }
            other => panic!("the canary must Block; got {other:?}"),
        }
        assert_eq!(
            ret.1, 0,
            "Block releases ZERO bytes (matched bytes never egress)"
        );
        // Never-log-the-secret: no matched byte rides the returned Verdict.
        assert_no_secret_in_return(&ret, secret);
    }

    #[test]
    fn request_body_scan_seam_holds_a_canary_split_across_two_chunks() {
        // Hold-back invariant: a canary split across two chunks is HELD — chunk 1
        // releases only the clean lead (never the buffered candidate prefix), and
        // chunk 2 completes the canary → Block, still releasing zero bytes.
        let secret = b"SEAMSPLIT0123456789";
        let mut gate = sealed_gate(secret, "canary-split");
        let ctx = ScanCtx::egress();

        // Chunk 1 ends mid-canary: the hold-back window retains the prefix, so the
        // released count covers ONLY the clean lead before the window.
        let (v1, released1) = request_body_scan(&mut gate, b"lead-clean SEAMSPLIT012", false, &ctx);
        assert!(
            !matches!(v1, Verdict::Block(_)),
            "chunk 1 alone does not complete the canary"
        );
        // The released count never reaches into the held candidate tail: it is
        // bounded by the buffered span minus the hold-back window (the matcher
        // cleared at most the prefix outside the trailing window).
        assert!(
            released1 <= gate.buffer().len(),
            "released count never exceeds the buffered span (hold-back invariant)"
        );
        // Drain exactly the released bytes (what the caller forwards upstream).
        let forwarded1 = gate.take_released(released1);
        assert!(
            !forwarded1
                .windows(b"SEAMSPLIT".len())
                .any(|w| w == b"SEAMSPLIT"),
            "the split canary's chunk-1 prefix must stay buffered, not forwarded"
        );

        // Chunk 2 completes the canary across the boundary → Block, zero released.
        let (v2, released2) = request_body_scan(&mut gate, b"3456789 trailing", true, &ctx);
        assert!(
            matches!(v2, Verdict::Block(_)),
            "the boundary-spanning canary blocks once joined"
        );
        assert_eq!(released2, 0, "Block releases nothing");
    }

    #[test]
    fn request_body_scan_seam_passes_a_clean_stream_through() {
        // A clean stream (no canary) PASSES: the seam returns Pass and a release
        // count, and at end_of_stream the whole body is releasable. No Hold/Block.
        let secret = b"NEVER_PRESENT_SEAM00";
        let mut gate = sealed_gate(secret, "canary-clean");
        let ctx = ScanCtx::egress();

        let body = b"a perfectly clean request body with no secret".as_slice();
        let (verdict, released) = request_body_scan(&mut gate, body, true, &ctx);
        assert!(
            matches!(verdict, Verdict::Pass { .. }),
            "a clean end_of_stream chunk Passes; got {verdict:?}"
        );
        assert_eq!(
            released,
            body.len(),
            "end_of_stream releases the whole clean body"
        );
        let forwarded = gate.take_released(released);
        assert_eq!(forwarded, body, "the clean body egresses byte-for-byte");
    }

    #[test]
    fn request_body_scan_seam_fails_closed_on_present_but_unsealed_keyed_plane() {
        // Mint-before-attach (D109): a keyed plane PRESENT but NOT sealed makes the
        // matcher error; fail-closed-when-keyed collapses that to Hold inside the
        // gate, so the seam returns (Hold, 0) — no byte released against a
        // half-attached digest set.
        let secret = b"ghp_unsealedSEAM0001";
        let max_len = secret.len();
        let mut matcher = DigestSetMatcher::new(SeamHasher, max_len);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![seam_digest(secret, "canary-unsealed")],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        // NOT sealed (mint-before-attach unsatisfied).
        let keyed_loaded = matcher.keyed_loaded();
        let mut gate = ScanGate::new(matcher, max_len, keyed_loaded, FailMode::Closed).unwrap();
        let ctx = ScanCtx::egress();

        let (verdict, released) =
            request_body_scan(&mut gate, b"clean lead bytes here too", true, &ctx);
        assert_eq!(
            verdict,
            Verdict::Hold,
            "an unsealed keyed plane fails closed (Hold)"
        );
        assert_eq!(released, 0, "fail-closed releases NO byte");
    }

    #[test]
    fn request_body_scan_seam_is_noop_passthrough_when_no_plane_is_loaded() {
        // ZERO-LENGTH-HOLD → NO-OP RELEASE: with NO keyed plane loaded (the
        // inspected default before any digest-feed lands) the matcher never
        // matches, the gate Passes its hold-back floor, and the seam releases the
        // body — the byte-identical inspected default (nothing synthetically held
        // or blocked).
        let matcher = DigestSetMatcher::new(SeamHasher, 64);
        assert!(!matcher.keyed_loaded(), "no plane loaded");
        // No keyed plane → keyed_loaded() is false → fail-open is permitted, but we
        // keep the mandatory Closed posture (matches the live acquisition seam).
        let keyed_loaded = matcher.keyed_loaded();
        let mut gate = ScanGate::new(matcher, 64, keyed_loaded, FailMode::Closed).unwrap();
        let ctx = ScanCtx::egress();

        let body = b"GET / HTTP/1.1\r\n\r\n".as_slice();
        let (verdict, released) = request_body_scan(&mut gate, body, true, &ctx);
        assert!(
            matches!(verdict, Verdict::Pass { .. }),
            "no plane loaded → Pass (byte-identical default); got {verdict:?}"
        );
        assert_eq!(released, body.len(), "the whole body releases (no-op scan)");
    }

    // ── ConnectSubToken: the additive credential-scope carrier (doc 23 §6) ──────

    #[test]
    fn connect_sub_token_absent_surfaces_nothing() {
        // The fail-closed default: no sub-token surfaced on the connect. `presented()`
        // is `None`, which the downstream claim maps to the EMPTY claim (egress deny).
        let absent = ConnectSubToken::absent();
        assert!(!absent.is_present());
        assert_eq!(absent.presented(), None);
        // `Default` agrees with the explicit `absent` constructor.
        assert_eq!(ConnectSubToken::default(), absent);
    }

    #[test]
    fn connect_sub_token_carries_raw_ds_scopes_verbatim() {
        // A validated sub-token carries its raw `ds_scopes` verbatim (unfiltered — the
        // D127 taxonomy filter is a downstream concern); `presented()` hands them out
        // for `ConnectScopeClaim::from_presented` to consume.
        let raw = vec!["v1:network:egress".to_string(), "v9:made:up".to_string()];
        let tok = ConnectSubToken::from_ds_scopes(raw.clone());
        assert!(tok.is_present());
        assert_eq!(tok.presented(), Some(raw.as_slice()));
        // An empty-but-present claim is distinct from absent (a credential that
        // presented no scopes vs no credential at all) — both fail-closed downstream.
        let empty_present = ConnectSubToken::from_ds_scopes(vec![]);
        assert!(empty_present.is_present());
        assert_eq!(empty_present.presented(), Some(&[][..]));
        assert_ne!(empty_present, ConnectSubToken::absent());
    }
}
