// SPDX-License-Identifier: Apache-2.0

//! LOG-1 `FlowRecord` — the FROZEN NFT-5 kernel-flow record SHAPE (doc 09 §3
//! NFT-5; doc 14 §2/§5, D43/D76).
//!
//! # What this module is
//!
//! This is the single frozen *shape* of a LOG-1 flow record: the field set an
//! NFT-5 conntrack/nflog event maps onto and the emitter renders into the
//! Stage-1 local event log. Per the crate charter it defines a SHAPE and decides
//! nothing — the `ds-telemetry` conventions layer owns the text→record mapping
//! (`conntrack -E`/`nflog` parsing) and the `EventEnvelope` emission, while THIS
//! crate owns only the record's fields and the two total, deterministic
//! renderings both sides must agree on byte-for-byte:
//!
//!   * the composed `value/mask` `ct mark` token ([`FlowRecord::ct_mark_token`]),
//!     sourced ONLY from [`crate::mark`] constants — never a typed-in literal, so
//!     a flow record's mark token agrees with the `ds-nft` stamping rule; and
//!   * the on-disk payload body ([`FlowRecord::payload`]), the scrubbed
//!     deterministic rendering the spool flushes (no secret can appear — a flow
//!     record references no credential, D73).
//!
//! # Field-type contracts
//!
//! Addresses are the family-agnostic [`crate::dns_admission::AdmittedAddr`] (D75,
//! `bytes + family`, NEVER a `u32`/`fixed32` — a v6 address would force a breaking
//! v2 the moment IPv6 telemetry is real); the decoded session is the frozen
//! [`crate::mark::MarkParts`] (leg + 14-bit index). No framework address type
//! crosses this crate (D67/D40); `[dependencies]` stays empty.
//!
//! A reject/drop reason, where a consumer records one, is the frozen
//! [`crate::reject::RejectReason`] — that path is unchanged by this shape (a
//! `FlowRecord` carries the 5-tuple + accounting; the reason code is the sibling
//! contract in [`crate::reject`], not re-declared here).
//!
//! # Mark-only-adds: an unresolvable session degrades, never refuses (doc 14 §5)
//!
//! [`FlowRecord::session`] is `None` for an unmarked best-effort flow (a
//! host-origin or pre-stamp packet, a foreign fwmark); the record is still a valid
//! shape — the contract never forces a session. The authoritative join key stays
//! the never-recycled tap name in `ds-flowlog`; the 14-bit index disambiguates
//! (doc 14 §4).

use crate::dns_admission::AdmittedAddr;
use crate::mark::{compose, Leg, MarkParts, DS_MARK_MASK};

/// Which lifecycle point a kernel flow event marks (doc 09 §3 NFT-5). The
/// conntrack stream carries `New`/`Destroy` (start/stop); the nflog stream carries
/// `Drop`. Frozen discriminator — new variants are additive only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowLifecycle {
    /// A `[NEW]` conntrack event — the flow's start (byte/packet counts ~0).
    New,
    /// A `[DESTROY]` conntrack event — the flow's stop, carrying the final
    /// accounting totals (`nf_conntrack_acct=1`) and duration.
    Destroy,
    /// An `nflog` drop/reject event — a packet the floor refused, attributed by
    /// the stamped `ct mark` (and the `dstap-*` tap it arrived on).
    Drop,
}

impl FlowLifecycle {
    /// The stable lower-case token used in the on-disk payload rendering and the
    /// conntrack `[NEW]`/`[DESTROY]` line prefix. Additive-only, mirrored on the
    /// LOG-1 proto enum names (doc 14 §2).
    pub fn token(self) -> &'static str {
        match self {
            FlowLifecycle::New => "new",
            FlowLifecycle::Destroy => "destroy",
            FlowLifecycle::Drop => "drop",
        }
    }
}

/// The L4 protocol of a flow. `Other` carries the raw IP protocol number for
/// anything past the two the boundary routinely accounts (tcp/udp).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    /// TCP (IP proto 6).
    Tcp,
    /// UDP (IP proto 17).
    Udp,
    /// Any other IP protocol, by number (e.g. ICMP 1).
    Other(u8),
}

impl Proto {
    /// The stable lower-case token used in the payload rendering.
    pub fn token(self) -> String {
        match self {
            Proto::Tcp => "tcp".to_string(),
            Proto::Udp => "udp".to_string(),
            Proto::Other(n) => format!("proto{n}"),
        }
    }
}

/// A single kernel-observed flow, the frozen LOG-1 `FlowRecord` shape (doc 14 §2).
/// Session attribution is the decoded D76 `ct mark` ([`Self::session`]); it is
/// `None` for an unmarked best-effort flow (the mark-only-adds degrade, doc 14
/// §5). The `ds-telemetry` conventions layer maps kernel text onto this shape and
/// wraps it with the `EventEnvelope` emission glue; this crate owns the shape and
/// its two deterministic renderings, nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRecord {
    /// Which lifecycle point this record marks (start/stop/drop).
    pub lifecycle: FlowLifecycle,
    /// The decoded per-session mark parts (leg + 14-bit index), or `None` when the
    /// flow carried no DS mark — unmarked best-effort (never a refusal).
    pub session: Option<MarkParts>,
    /// The L4 protocol.
    pub proto: Proto,
    /// The ORIGINAL-direction source address (family-agnostic, D75). Recorded for
    /// the record's 5-tuple; it is NEVER the attribution key (that is the mark).
    pub src: Option<AdmittedAddr>,
    /// The ORIGINAL-direction destination address (the "where the bytes went").
    pub dst: Option<AdmittedAddr>,
    /// The original-direction source port.
    pub sport: Option<u16>,
    /// The original-direction destination port.
    pub dport: Option<u16>,
    /// Total packets (original + reply where accounting reports both).
    pub packets: u64,
    /// Total bytes (original + reply where accounting reports both).
    pub bytes: u64,
    /// Flow duration in milliseconds (`nf_conntrack_timestamp=1`); `0` when the
    /// event carries no timestamp (a `NEW` event, or accounting/timestamp off).
    pub duration_ms: u64,
}

impl FlowRecord {
    /// The composed `value/mask` `ct mark` token this flow carries, or `None` for
    /// an unmarked best-effort flow. Rendered from [`crate::mark::compose`] +
    /// [`DS_MARK_MASK`] — never a typed-in literal, never re-derived arithmetic.
    pub fn ct_mark_token(&self) -> Option<String> {
        self.session
            .map(|parts| ct_mark_token(parts.leg, parts.session_index))
    }

    /// The scrubbed, deterministic on-disk payload body for this record. Carries
    /// the lifecycle, protocol, the composed `ct mark` (or the literal `unmarked`),
    /// the 5-tuple, and the accounting totals. No secret can appear here — a flow
    /// record references no credential (D73). Addresses render through the shared
    /// [`AdmittedAddr::to_dst_key`] form (`"<family>:<lower-hex-octets>"`), so a
    /// flow record's address string agrees byte-for-byte with the admission map's
    /// refcount key.
    pub fn payload(&self) -> Vec<u8> {
        let mark = self
            .ct_mark_token()
            .unwrap_or_else(|| "unmarked".to_string());
        let src = self
            .src
            .as_ref()
            .map(|a| a.to_dst_key().0)
            .unwrap_or_else(|| "?".to_string());
        let dst = self
            .dst
            .as_ref()
            .map(|a| a.to_dst_key().0)
            .unwrap_or_else(|| "?".to_string());
        let sport = self.sport.map(|p| p.to_string()).unwrap_or_default();
        let dport = self.dport.map(|p| p.to_string()).unwrap_or_default();
        format!(
            "nft5-flow|{life}|{proto}|mark={mark}|{src}:{sport}|{dst}:{dport}|\
             pkts={pkts}|bytes={bytes}|dur_ms={dur}",
            life = self.lifecycle.token(),
            proto = self.proto.token(),
            pkts = self.packets,
            bytes = self.bytes,
            dur = self.duration_ms,
        )
        .into_bytes()
    }
}

/// Render the composed `value/mask` `ct mark` token for a `(leg, session_index)`
/// pair — the textual form sourced ONLY from [`crate::mark`] constants (never a
/// raw literal, never re-derived arithmetic). The same `value/mask` shape
/// `ds-nft::mark_match` renders for the kernel side, so a flow record's mark token
/// agrees byte-for-byte with the stamping rule.
pub fn ct_mark_token(leg: Leg, session_index: u16) -> String {
    format!(
        "0x{:x}/0x{:x}",
        compose(leg, session_index as u32),
        DS_MARK_MASK
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_admission::AddressFamily;
    use crate::reject::RejectReason;

    fn v4(octets: [u8; 4]) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: octets.to_vec(),
        }
    }

    /// A fully-populated DESTROY record round-trips onto the frozen contract: the
    /// composed ct mark, the address keys, and the accounting totals all render
    /// deterministically from the shape's fields.
    #[test]
    fn destroy_record_renders_the_composed_mark_and_totals() {
        let rec = FlowRecord {
            lifecycle: FlowLifecycle::Destroy,
            session: Some(crate::mark::decompose(compose(Leg::AgentVm, 7)).unwrap()),
            proto: Proto::Tcp,
            src: Some(v4([10, 0, 0, 5])),
            dst: Some(v4([203, 0, 113, 10])),
            sport: Some(51514),
            dport: Some(443),
            packets: 22,
            bytes: 1840 + 5120,
            duration_ms: 110_000,
        };

        // The composed per-session ct mark is sourced from the frozen constants.
        let parts = rec.session.expect("attributed to a session");
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(parts.session_index, 7);
        assert_eq!(rec.ct_mark_token().unwrap(), ct_mark_token(Leg::AgentVm, 7));
        assert!(rec.ct_mark_token().unwrap().starts_with("0xd1"));

        // The payload is a total function of the fields — mark, hex address keys,
        // and accounting totals all present, byte-exact.
        let body = String::from_utf8(rec.payload()).unwrap();
        assert!(body.contains("nft5-flow|destroy|tcp|"));
        assert!(body.contains(&format!("mark={}", ct_mark_token(Leg::AgentVm, 7))));
        assert!(body.contains("v4:0a000005:51514"));
        assert!(body.contains("v4:cb00710a:443"));
        assert!(body.contains("bytes=6960"));
        assert!(body.contains("dur_ms=110000"));
    }

    /// An unmarked flow is a valid shape — session `None`, mark renders `unmarked`,
    /// the record still carries its 5-tuple (mark-only-adds, doc 14 §5).
    #[test]
    fn unmarked_flow_is_a_valid_best_effort_shape() {
        let rec = FlowRecord {
            lifecycle: FlowLifecycle::Destroy,
            session: None,
            proto: Proto::Udp,
            src: Some(v4([203, 0, 113, 9])),
            dst: Some(v4([8, 8, 8, 8])),
            sport: Some(5000),
            dport: Some(53),
            packets: 2,
            bytes: 120,
            duration_ms: 0,
        };
        assert!(rec.session.is_none(), "unmarked best-effort, not a refusal");
        assert_eq!(rec.ct_mark_token(), None);
        assert!(String::from_utf8(rec.payload())
            .unwrap()
            .contains("mark=unmarked"));
    }

    /// The D75 128-bit path survives the shape's rendering: a full v6 address is
    /// carried and keyed with no truncation (a `u32` field could never do this).
    #[test]
    fn full_v6_address_survives_the_payload_rendering() {
        let octets: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let rec = FlowRecord {
            lifecycle: FlowLifecycle::New,
            session: None,
            proto: Proto::Tcp,
            src: None,
            dst: Some(AdmittedAddr {
                family: AddressFamily::V6,
                octets: octets.to_vec(),
            }),
            sport: None,
            dport: Some(443),
            packets: 0,
            bytes: 0,
            duration_ms: 0,
        };
        let body = String::from_utf8(rec.payload()).unwrap();
        assert!(body.contains("v6:20010db8000000000000000000000001:443"));
    }

    #[test]
    fn lifecycle_and_proto_tokens_are_stable() {
        assert_eq!(FlowLifecycle::New.token(), "new");
        assert_eq!(FlowLifecycle::Destroy.token(), "destroy");
        assert_eq!(FlowLifecycle::Drop.token(), "drop");
        assert_eq!(Proto::Tcp.token(), "tcp");
        assert_eq!(Proto::Udp.token(), "udp");
        assert_eq!(Proto::Other(1).token(), "proto1");
    }

    /// The reject-reason path is the sibling frozen contract, unchanged by this
    /// shape: `RejectReason` stays distinct and reachable (doc 14 §2, D70).
    #[test]
    fn reject_reason_path_is_unchanged() {
        assert!(RejectReason::QuicBlocked.is_quic_carveout());
        assert!(!RejectReason::DefaultDeny.is_quic_carveout());
        assert_eq!(RejectReason::QuicBlocked.as_str(), "quic_blocked");
    }
}
