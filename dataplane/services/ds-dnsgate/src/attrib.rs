//! Session attribution — interface-anchored, never raw source IP (doc 11 §5.1, D44).
//!
//! Doc 11 §5.1 / W6 freeze: a query's session identity derives **only from
//! interface-anchored signals** — the per-session tap a query arrived on — never
//! from raw source IP alone. This module is the pure attribution step the handler
//! runs before the policy verdict: it maps the interface-anchored signal the
//! listener observed (the local address the NFT-2 redirect landed on, or the per-tap
//! bind, §8.2) to a never-recycled session id.
//!
//! # The frozen rule this enforces (doc 11 §5.1, D44/D66)
//!
//!  * The **per-session tap name** is the authoritative, never-recycled join key.
//!    A session is its tap, and a destroyed session's tap name is never reused
//!    (the orchestrator session record owns that guarantee, consumed here).
//!  * The **14-bit D76 mark index** carries `index mod 2^14` as a **disambiguator
//!    only** — never the primary key — with a **monitored wrap alarm**: when the
//!    14-bit space wraps, two live sessions could collide on the same index, so a
//!    wrap is an alarm, not a silent reuse. [`MarkIndex::wrapped`] is the alarm
//!    predicate the handler / telemetry raises on.
//!  * The **src-IP single-listener shortcut** is acceptable ONLY if NFT-2's
//!    three-keys-must-agree drop (iif / assigned guest IP / ct mark disagreement =
//!    kernel drop, D44) precedes the gate as a frozen NFT-2 clause; otherwise the
//!    gate must use per-session local-address attribution. This module models BOTH
//!    shapes ([`AttributionMode`]) and records WHICH one resolved the session, so a
//!    deployment that has not frozen the three-keys clause cannot silently fall back
//!    to bare src-IP keying — the mode is explicit, not implicit.
//!
//! No hickory type appears here (D67): attribution consumes plain `SocketAddr` /
//! `&str` interface signals and produces a plain `String` session id. The handler
//! bridges the hickory `Request`'s `src` into these plain signals at the listen
//! boundary; `attrib/` itself is engine-agnostic and pure given the NFT-2 contract.

use std::collections::BTreeMap;
use std::net::IpAddr;

/// The 14-bit D76 composite-mark index, carried as a session **disambiguator only**
/// (doc 11 §5.1). The full D76 mark layout is owned by `ds-nft` / the shared layout
/// package; this is the gate's read-only view of the 14-bit index field with the
/// wrap alarm the §5.1 contract requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MarkIndex(u16);

impl MarkIndex {
    /// The width of the D76 mark-index field (14 bits, doc 11 §5.1 / D76).
    pub const BITS: u32 = 14;
    /// The number of distinct indices before the field wraps (`2^14`).
    pub const SPACE: u32 = 1 << Self::BITS;

    /// Construct a mark index from a raw session counter, taking `counter mod 2^14`
    /// (doc 11 §5.1: "index mod 2^14"). The high bits beyond 14 are the wrap, which
    /// [`MarkIndex::wrapped`] flags.
    pub fn from_counter(counter: u32) -> Self {
        MarkIndex((counter % Self::SPACE) as u16)
    }

    /// Whether a session counter has WRAPPED the 14-bit index space — the monitored
    /// **wrap alarm** (doc 11 §5.1). At/above `2^14` two live sessions can collide on
    /// the same index, so the disambiguator alone is no longer unique and the tap
    /// name (never-recycled) MUST be the join key. The caller raises the alarm; this
    /// is the predicate. NOT a silent reuse — a wrapped index is an operational
    /// signal, the §5.1 "monitored wrap alarm".
    pub fn wrapped(counter: u32) -> bool {
        counter >= Self::SPACE
    }

    /// The raw 14-bit index value (`0..2^14`).
    pub fn value(self) -> u16 {
        self.0
    }
}

/// Which attribution shape resolved the session (doc 11 §5.1 / §8.2). Recorded on
/// every resolution so a deployment can never silently key on bare src-IP without
/// the three-keys precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionMode {
    /// **Per-tap bind** (§8.2): one listener per `dstap-<idx>`; attribution is the
    /// bind itself — structural, no src-IP read at all. The strongest shape.
    PerTapBind,
    /// **Single listener + post-NAT local-address attribution** (§8.2): the session
    /// is derived from the interface-anchored LOCAL address the NFT-2 redirect landed
    /// on (never raw source IP). Acceptable because the local address is
    /// interface-anchored, not the guest's chosen source.
    LocalAddress,
    /// **Single listener + src-IP shortcut** (§5.1): acceptable ONLY when NFT-2's
    /// three-keys-must-agree drop (D44) precedes the gate as a frozen clause. The
    /// resolver REFUSES this mode unless the precondition is asserted present, so a
    /// deployment cannot fall into bare src-IP keying by accident.
    SrcIpWithThreeKeysDrop,
}

/// A resolved session attribution (doc 11 §5.1). Carries the never-recycled tap-name
/// join key (the authoritative identity), the 14-bit disambiguator, and WHICH mode
/// resolved it. The handler turns `session` into the [`crate::policy::DnsQueryCtx`]
/// `session` field and `source` descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttribution {
    /// The per-session **tap name** — the authoritative, never-recycled join key
    /// (doc 11 §5.1). This is the policy/LOG-1 session identity, not the index.
    pub tap_name: String,
    /// The 14-bit D76 mark index — a **disambiguator only** (doc 11 §5.1), present so
    /// a LOG-1 join can cross-reference the kernel mark, never as the primary key.
    pub mark_index: MarkIndex,
    /// Which attribution shape resolved this session (§5.1 / §8.2).
    pub mode: AttributionMode,
}

impl SessionAttribution {
    /// The source descriptor the handler threads into [`crate::policy::DnsQueryCtx`]'s
    /// `source` field for §5.1 three-keys disambiguation + LOG-1 attribution — the
    /// tap name plus the mode, NEVER a bare source IP standing alone as the key.
    pub fn source_descriptor(&self) -> String {
        format!("{}/{:?}", self.tap_name, self.mode)
    }
}

/// Why an attribution failed — a query the gate cannot session-attribute is a
/// fail-closed condition (doc 11 §5.1 / W6: attribution is interface-anchored; an
/// un-attributable query is never silently keyed on bare src-IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionError {
    /// No per-session tap is registered for the interface-anchored signal the query
    /// arrived on (the local address / tap index). Fail closed: the handler answers a
    /// genuine failure (SERVFAIL), never an unattributed admission.
    UnknownInterface(String),
    /// The deployment asked for the src-IP shortcut but has NOT asserted NFT-2's
    /// three-keys-must-agree drop precedes the gate (doc 11 §5.1). REFUSED — the
    /// shortcut is illegal without the precondition; use [`AttributionMode::LocalAddress`]
    /// or [`AttributionMode::PerTapBind`].
    SrcIpShortcutWithoutThreeKeysDrop,
}

/// The interface-anchored attribution table (doc 11 §5.1, D44). Maps the
/// interface-anchored signal the listener observed — the post-NAT LOCAL address the
/// NFT-2 redirect landed on, or the per-tap bind index — to the never-recycled
/// per-session tap. It NEVER maps a raw source IP to a session: the only IP it keys
/// on is the gate's own local address (interface-anchored), which the guest cannot
/// spoof, and the src-IP shortcut is gated behind the three-keys precondition flag.
///
/// The table is populated by the orchestrator session record / NFT-2 programming
/// (the never-recycled tap registry); this is the gate's read view of it. Pure given
/// that registry — no I/O, no hickory type.
#[derive(Debug, Clone, Default)]
pub struct AttributionTable {
    /// Interface-anchored local address → (tap name, mark index). The KEY is the
    /// gate's own local listen address per session (the NFT-2 redirect target),
    /// never the guest source IP.
    by_local_addr: BTreeMap<IpAddr, (String, MarkIndex)>,
    /// Whether NFT-2's three-keys-must-agree drop (D44) is asserted to precede the
    /// gate as a frozen clause — the precondition that makes the src-IP shortcut
    /// legal (§5.1). When `false`, [`AttributionTable::attribute_src_ip`] REFUSES.
    three_keys_drop_present: bool,
}

impl AttributionTable {
    /// A fresh table with the src-IP shortcut DISABLED (the safe default: until a
    /// deployment asserts the three-keys drop, only local-address / per-tap
    /// attribution is legal, §5.1).
    pub fn new() -> Self {
        Self::default()
    }

    /// Assert that NFT-2's three-keys-must-agree drop precedes the gate (doc 11 §5.1
    /// / D44) — the precondition that legalizes the src-IP shortcut. A deployment
    /// sets this only when the drop is a frozen NFT-2 clause; until then the shortcut
    /// is refused.
    pub fn with_three_keys_drop(mut self) -> Self {
        self.three_keys_drop_present = true;
        self
    }

    /// Register a per-session tap against its interface-anchored local address (the
    /// NFT-2 redirect target for that session). `mark_index` is built with the wrap
    /// alarm via [`MarkIndex::from_counter`]; the tap name is the never-recycled key.
    pub fn register(
        &mut self,
        local_addr: IpAddr,
        tap_name: impl Into<String>,
        mark_index: MarkIndex,
    ) {
        self.by_local_addr
            .insert(local_addr, (tap_name.into(), mark_index));
    }

    /// Attribute a query to a session by its interface-anchored LOCAL address (the
    /// post-NAT address the NFT-2 redirect landed on, §5.1 / §8.2 single-listener
    /// shape). This is the safe path: the local address is the gate's own, not the
    /// guest's spoofable source. Returns [`AttributionMode::LocalAddress`].
    pub fn attribute_local(
        &self,
        local_addr: IpAddr,
    ) -> Result<SessionAttribution, AttributionError> {
        match self.by_local_addr.get(&local_addr) {
            Some((tap_name, mark_index)) => Ok(SessionAttribution {
                tap_name: tap_name.clone(),
                mark_index: *mark_index,
                mode: AttributionMode::LocalAddress,
            }),
            None => Err(AttributionError::UnknownInterface(local_addr.to_string())),
        }
    }

    /// Attribute a query by its per-tap bind (the §8.2 per-tap-binds shape):
    /// attribution is the bind itself, so the caller passes the tap the listener was
    /// bound for directly. Always [`AttributionMode::PerTapBind`] — the structural,
    /// strongest shape (no address lookup at all).
    pub fn attribute_per_tap(
        tap_name: impl Into<String>,
        mark_index: MarkIndex,
    ) -> SessionAttribution {
        SessionAttribution {
            tap_name: tap_name.into(),
            mark_index,
            mode: AttributionMode::PerTapBind,
        }
    }

    /// Attribute a query by its raw SOURCE IP — the §5.1 single-listener shortcut.
    /// REFUSED ([`AttributionError::SrcIpShortcutWithoutThreeKeysDrop`]) unless the
    /// three-keys drop precondition is asserted present ([`with_three_keys_drop`]).
    /// Even then it resolves through the SAME never-recycled tap registry (keyed on
    /// the local-address map), so it never becomes bare src-IP keying — the source IP
    /// is a redundant cross-check the three-keys drop already enforced, not the join
    /// key. The mode is recorded as [`AttributionMode::SrcIpWithThreeKeysDrop`] so the
    /// shortcut is always observable, never silent.
    ///
    /// [`with_three_keys_drop`]: AttributionTable::with_three_keys_drop
    pub fn attribute_src_ip(
        &self,
        local_addr: IpAddr,
        _src_ip: IpAddr,
    ) -> Result<SessionAttribution, AttributionError> {
        if !self.three_keys_drop_present {
            return Err(AttributionError::SrcIpShortcutWithoutThreeKeysDrop);
        }
        // The shortcut still resolves through the interface-anchored registry (the
        // three-keys drop guarantees iif/guest-IP/ct-mark already agreed before us),
        // so we look up the local address and only TAG the mode as the shortcut.
        let mut attribution = self.attribute_local(local_addr)?;
        attribution.mode = AttributionMode::SrcIpWithThreeKeysDrop;
        Ok(attribution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn local(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn mark_index_is_14_bit_and_wraps_with_an_alarm() {
        assert_eq!(MarkIndex::SPACE, 16_384);
        // Below the space: no wrap, index is the counter.
        assert!(!MarkIndex::wrapped(5));
        assert_eq!(MarkIndex::from_counter(5).value(), 5);
        // At/above 2^14: the wrap alarm fires, the index folds mod 2^14.
        assert!(MarkIndex::wrapped(MarkIndex::SPACE));
        assert!(MarkIndex::wrapped(MarkIndex::SPACE + 3));
        assert_eq!(MarkIndex::from_counter(MarkIndex::SPACE + 3).value(), 3);
    }

    #[test]
    fn local_address_attribution_returns_the_never_recycled_tap_name() {
        let mut table = AttributionTable::new();
        table.register(local(2), "dstap-42", MarkIndex::from_counter(42));
        let attr = table.attribute_local(local(2)).expect("registered");
        assert_eq!(attr.tap_name, "dstap-42");
        assert_eq!(attr.mode, AttributionMode::LocalAddress);
        // The tap name (never the index) is the join key surfaced as the source.
        assert!(attr.source_descriptor().starts_with("dstap-42/"));
    }

    #[test]
    fn unknown_interface_is_fail_closed_not_a_default_session() {
        let table = AttributionTable::new();
        let err = table.attribute_local(local(9)).unwrap_err();
        assert!(matches!(err, AttributionError::UnknownInterface(_)));
    }

    #[test]
    fn src_ip_shortcut_is_refused_without_the_three_keys_drop() {
        let mut table = AttributionTable::new();
        table.register(local(2), "dstap-1", MarkIndex::from_counter(1));
        // No three-keys drop asserted → the shortcut is illegal.
        let err = table.attribute_src_ip(local(2), local(200)).unwrap_err();
        assert_eq!(err, AttributionError::SrcIpShortcutWithoutThreeKeysDrop);
    }

    #[test]
    fn src_ip_shortcut_is_allowed_only_with_the_three_keys_drop_and_is_tagged() {
        let mut table = AttributionTable::new().with_three_keys_drop();
        table.register(local(2), "dstap-1", MarkIndex::from_counter(1));
        let attr = table
            .attribute_src_ip(local(2), local(200))
            .expect("legal now");
        // It still resolves through the never-recycled tap registry — the source IP
        // is a redundant cross-check, not the join key — and the mode is tagged.
        assert_eq!(attr.tap_name, "dstap-1");
        assert_eq!(attr.mode, AttributionMode::SrcIpWithThreeKeysDrop);
    }

    #[test]
    fn per_tap_bind_attribution_is_structural() {
        let attr = AttributionTable::attribute_per_tap("dstap-7", MarkIndex::from_counter(7));
        assert_eq!(attr.tap_name, "dstap-7");
        assert_eq!(attr.mode, AttributionMode::PerTapBind);
    }
}
