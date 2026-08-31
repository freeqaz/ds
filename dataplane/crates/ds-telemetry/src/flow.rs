// SPDX-License-Identifier: Apache-2.0

//! NFT-5 kernel-flow → LOG-1 `FlowRecord` mapping (doc 09 §3 NFT-5; doc 14
//! §2/§5; D43/D76).
//!
//! # What this module is
//!
//! NFT-5 turns on conntrack accounting and stamps every agent-VM flow with the
//! D76 composite `ct mark` (the stamping rule lives in `ds-nft::flowtag`). The
//! kernel then emits two event streams the Stage-1 local event log consumes:
//!
//!   * **conntrack flow events** — `NEW` / `DESTROY` accounting records carrying
//!     the per-flow 5-tuple, packet/byte counts (`nf_conntrack_acct=1`), a
//!     duration (`nf_conntrack_timestamp=1`), AND the stamped `ct mark`.
//!   * **nflog drop events** — the packets the floor dropped/rejected, carried up
//!     via `nflog` with the `iifname`-anchored session tap and (because the
//!     NFT-5 stamp runs at an earlier hook priority than the terminal drop) the
//!     same `ct mark`.
//!
//! This module is the CONVENTIONS-layer mapping from those kernel outputs onto the
//! FROZEN LOG-1 [`ds_contracts::flow::FlowRecord`] and then onto an
//! [`EventEnvelope`] the [`crate::spool`] feeds to disk. The carrier now lives in
//! `ds-contracts` (the single frozen shape, doc 14 §6); this module keeps ONLY the
//! text→record mapping (the `conntrack -E` / `nflog` parsers) and the
//! `EventEnvelope` emission glue. Per the migration rule, the carrier type was
//! replaced, never the mapping call sites — [`FlowRecord`] is a thin wrapper that
//! derefs to the frozen shape and adds the two emission methods that need this
//! crate's [`EventEnvelope`] (which can never cross into the dependency-empty
//! `ds-contracts`, D67/D40).
//!
//! # Attribution is interface-anchored, never source IP (doc 12 §2.1 invariant 2)
//!
//! The session a flow belongs to is recovered ONLY from the stamped D76 `ct mark`
//! (set on the unforgeable `dstap-*` attachment point) — never from the packet's
//! `src=` address, which the VM forges freely. The mark is decoded through
//! [`ds_contracts::mark`] (`is_ds_mark` + `decompose`); the mask/nibble/shift
//! arithmetic is NEVER re-derived here.
//!
//! # Mark-only-adds: an unresolvable session degrades, never refuses (doc 14 §5)
//!
//! A flow whose mark is absent or is not a DS mark (a host-origin flow, a
//! pre-stamp packet, a foreign fwmark) maps to a FlowRecord with `session = None`
//! — **unmarked best-effort**. The record is still emitted; the mapping never
//! drops a flow for want of a session (the transparent-path mark-only-adds
//! invariant). The authoritative join key stays the never-recycled tap name in
//! `ds-flowlog`; the 14-bit index is a disambiguator (doc 14 §4).
//!
//! # Offline / synthetic sources (D50)
//!
//! The parsers here consume TEXT — the same lines `conntrack -E` / `conntrack -L`
//! and an `nflog`-tailing collector print — so the whole mapping is exercised in
//! default `cargo test` against synthetic fixtures with no live kernel. The
//! live-kernel arm that proves a real flow rides the stamped mark is the
//! env-gated `ds-nft` netns test (deferred-manual, D50).
//!
//! License: OSS — Apache-2.0 (D25/D15; LOG-1 events are data-plane and open).

use core::ops::Deref;

use ds_contracts::dns_admission::{AddressFamily, AdmittedAddr};
use ds_contracts::mark::{decompose, is_ds_mark, MarkParts, DS_MARK_MASK};

use crate::event::{EventEnvelope, EventKind, EventSink};
use crate::provenance::Provenance;

// The lifecycle / protocol discriminators and the free `ct_mark_token(leg, idx)`
// renderer are the frozen contract's — re-exported so `ds_telemetry::flow::…`
// call sites (and the `flow_spool` integration test) resolve them unchanged.
pub use ds_contracts::flow::{ct_mark_token, FlowLifecycle, Proto};

/// The emitter's carrier for a single kernel-observed flow — a thin wrapper over
/// the FROZEN [`ds_contracts::flow::FlowRecord`] shape (doc 14 §2). It derefs to
/// the frozen record (so every field and the frozen [`FlowRecord::ct_mark_token`]
/// / [`FlowRecord::payload`] rendering read through unchanged) and adds the two
/// emission methods that need this crate's [`EventEnvelope`] — the one thing that
/// can never live in the dependency-empty `ds-contracts` (D67/D40).
///
/// This is the "replace the carrier, never the call sites" migration: the schema
/// moved to `ds-contracts`; the parsers below still build a `FlowRecord` and the
/// call sites still call `.payload()`, `.to_envelope()`, `.emit_into()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRecord(pub ds_contracts::flow::FlowRecord);

impl Deref for FlowRecord {
    type Target = ds_contracts::flow::FlowRecord;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FlowRecord {
    /// Build the LOG-1 [`EventEnvelope`] for this flow — always
    /// [`EventKind::FlowRecord`], carrying the mandatory POL-3 `provenance` and the
    /// frozen [`ds_contracts::flow::FlowRecord::payload`] rendering. A flow record
    /// references no credential, so no fingerprint is attached (D73: the only
    /// credential path is a fingerprint, and this event has none).
    pub fn to_envelope(&self, provenance: Provenance) -> EventEnvelope {
        EventEnvelope::new(EventKind::FlowRecord, provenance, self.0.payload())
    }

    /// Construct + emit this flow record into `sink` under `provenance`. Emission
    /// is fire-and-forget (telemetry never fails the data path — doc 14 §12.4).
    pub fn emit_into<S: EventSink>(&self, sink: &S, provenance: Provenance) {
        sink.emit(self.to_envelope(provenance));
    }
}

/// Decode a raw kernel `ct mark` register value into its session parts, or `None`
/// when it is not a DS mark (unmarked best-effort — doc 14 §5). The magic nibble
/// is checked with [`is_ds_mark`]; the value is masked by [`DS_MARK_MASK`] before
/// [`decompose`] so a mark carrying foreign bits in the permanently-unclaimed gap
/// still decodes (the Tailscale PR-5606 coexistence lesson). All arithmetic is the
/// frozen contract's — none is re-hardcoded here.
pub fn decode_session(raw_mark: u32) -> Option<MarkParts> {
    if !is_ds_mark(raw_mark) {
        return None;
    }
    decompose(raw_mark & DS_MARK_MASK).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Synthetic / offline parsers (D50): text in, FlowRecord out.
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the conntrack textual protocol token (`tcp` / `udp`) or an IP proto
/// number into the frozen [`Proto`] discriminator.
fn parse_proto(tok: &str) -> Option<Proto> {
    match tok {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        other => other.parse::<u8>().ok().map(Proto::Other),
    }
}

/// Parse an ADDRESS token into the frozen family-agnostic [`AdmittedAddr`] (D75).
/// Accepts a dotted-quad v4 or a colon v6 through the stdlib parser; the octets are
/// the identity, so the round-trip is loss-free for a full 128-bit v6 address.
fn parse_addr(s: &str) -> Option<AdmittedAddr> {
    match s.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(a) => Some(AdmittedAddr {
            family: AddressFamily::V4,
            octets: a.octets().to_vec(),
        }),
        std::net::IpAddr::V6(a) => Some(AdmittedAddr {
            family: AddressFamily::V6,
            octets: a.octets().to_vec(),
        }),
    }
}

/// Pull the FIRST value for a `key=` token on a whitespace-split conntrack/nflog
/// line (the original-direction tuple lists its fields before the reply tuple).
fn first_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
}

/// Collect EVERY value for a repeated `key=` token (conntrack lists e.g. `bytes=`
/// once per direction), parsed as `u64`.
fn all_u64_fields(line: &str, key: &str) -> Vec<u64> {
    line.split_whitespace()
        .filter_map(|tok| tok.strip_prefix(key))
        .filter_map(|v| v.parse::<u64>().ok())
        .collect()
}

/// The lifecycle a conntrack `-E` line declares in its leading `[STATE]` token, or
/// `None` for a bare `-L`/accounting line (which we treat as a `Destroy`-style
/// terminal accounting snapshot).
fn conntrack_lifecycle(line: &str) -> FlowLifecycle {
    let l = line.trim_start();
    if l.starts_with("[NEW]") {
        FlowLifecycle::New
    } else if l.starts_with("[DESTROY]") {
        FlowLifecycle::Destroy
    } else {
        // A `-L` accounting snapshot / `[UPDATE]` carries the running totals; the
        // stop-style terminal accounting shape. `[UPDATE]` folds here so its
        // running byte/packet totals are still emitted (never dropped).
        FlowLifecycle::Destroy
    }
}

/// Parse ONE conntrack accounting/event line into a [`FlowRecord`], or `None`
/// when the line is not a per-flow tuple (a blank line or the `-E`/`-D` summary).
///
/// Handles both `conntrack -E` event lines (a leading `[NEW]`/`[DESTROY]` token)
/// and `conntrack -L` accounting snapshots. The `mark=` field is decoded to the
/// session via [`decode_session`]; a line with no DS `mark=` maps to an unmarked
/// best-effort record (doc 14 §5). Byte/packet counts sum the original + reply
/// directions; `delta-time=` (or `[DESTROY]` timestamp) becomes the duration.
pub fn parse_conntrack_line(line: &str) -> Option<FlowRecord> {
    let line = line.trim();
    if line.is_empty()
        || line.contains("flow entries have been")
        || line.contains("conntrack-tools")
    {
        return None;
    }
    // A per-flow line carries an original-direction tuple: proto token + src=/dst=.
    if !line.contains("src=") && !line.contains("dst=") {
        return None;
    }

    let lifecycle = conntrack_lifecycle(line);

    // The protocol token is the FIRST whitespace token that is a known proto name
    // (or, on `-E` lines, the token after the `[STATE]` and the `<l3proto>` word).
    let proto = line
        .split_whitespace()
        .find_map(parse_proto)
        .unwrap_or(Proto::Other(0));

    let bytes: u64 = all_u64_fields(line, "bytes=").iter().sum();
    let packets: u64 = all_u64_fields(line, "packets=").iter().sum();

    let src = first_field(line, "src=").and_then(parse_addr);
    let dst = first_field(line, "dst=").and_then(parse_addr);
    let sport = first_field(line, "sport=").and_then(|v| v.parse::<u16>().ok());
    let dport = first_field(line, "dport=").and_then(|v| v.parse::<u16>().ok());

    // Duration: conntrack `-o timestamp` prints `delta-time=<secs>` on a DESTROY;
    // convert to ms. Absent (a NEW event, or timestamp off) → 0.
    let duration_ms = first_field(line, "delta-time=")
        .and_then(|v| v.parse::<u64>().ok())
        .map(|secs| secs.saturating_mul(1000))
        .unwrap_or(0);

    let session = first_field(line, "mark=")
        .and_then(|v| v.parse::<u32>().ok())
        .and_then(decode_session);

    Some(FlowRecord(ds_contracts::flow::FlowRecord {
        lifecycle,
        session,
        proto,
        src,
        dst,
        sport,
        dport,
        packets,
        bytes,
        duration_ms,
    }))
}

/// Parse a batch of conntrack accounting/event lines into flow records, skipping
/// non-flow lines (blanks, the deletion summary). Order-preserving.
pub fn parse_conntrack_events(lines: &[String]) -> Vec<FlowRecord> {
    lines
        .iter()
        .filter_map(|l| parse_conntrack_line(l))
        .collect()
}

/// Parse ONE `nflog`-carried drop line into a [`FlowRecord`] with
/// [`FlowLifecycle::Drop`], or `None` when it is not a drop line.
///
/// The line is the shape an `nflog`-tailing collector (or `ulogd`) prints for a
/// packet the floor dropped/rejected: a `PREFIX="ds-nft5-drop ..."` marker, the
/// `IN=dstap-<idx>` ingress tap, the `MARK=<hex>` the NFT-5 stamp set BEFORE the
/// drop, and `SRC=`/`DST=` addresses. Session attribution is the decoded `MARK`
/// (interface-anchored, set on the tap) — the `SRC=` address is recorded but is
/// NEVER the key (doc 12 §2.1 invariant 2). A drop line whose mark is absent maps
/// to an unmarked best-effort drop (doc 14 §5); it is still emitted.
pub fn parse_nflog_drop_line(line: &str) -> Option<FlowRecord> {
    let line = line.trim();
    // The NFT-5 drop nflog rule stamps this prefix; only lines carrying it (and an
    // ingress tap) are drop records this mapping owns.
    if !line.contains("ds-nft5-drop") {
        return None;
    }

    let proto = first_field(line, "PROTO=")
        .map(|p| p.to_ascii_lowercase())
        .and_then(|p| parse_proto(&p))
        .unwrap_or(Proto::Other(0));

    let src = first_field(line, "SRC=").and_then(parse_addr);
    let dst = first_field(line, "DST=").and_then(parse_addr);
    let sport = first_field(line, "SPT=").and_then(|v| v.parse::<u16>().ok());
    let dport = first_field(line, "DPT=").and_then(|v| v.parse::<u16>().ok());

    // MARK is printed as hex by the kernel log target (e.g. MARK=0xd1000007).
    let session = first_field(line, "MARK=")
        .and_then(parse_hex_or_dec_u32)
        .and_then(decode_session);

    Some(FlowRecord(ds_contracts::flow::FlowRecord {
        lifecycle: FlowLifecycle::Drop,
        session,
        proto,
        src,
        dst,
        sport,
        dport,
        packets: 1,
        bytes: 0,
        duration_ms: 0,
    }))
}

/// Parse a batch of nflog lines into drop records, skipping any line that is not a
/// `ds-nft5-drop`-prefixed drop. Order-preserving.
pub fn parse_nflog_drops(lines: &[String]) -> Vec<FlowRecord> {
    lines
        .iter()
        .filter_map(|l| parse_nflog_drop_line(l))
        .collect()
}

/// Parse a u32 that may be written as `0x…` hex (the kernel log target's `MARK=`
/// form) or plain decimal (conntrack's `mark=` form).
fn parse_hex_or_dec_u32(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::NullSink;
    use ds_contracts::mark::{compose, Leg};

    fn provenance() -> Provenance {
        Provenance::new("nft5/ct-mark-flowtag", "pol1-session", "2026-07-01").expect("valid triple")
    }

    // compose(AgentVm, 7) == 0xD100_0007 == 3506962439 (matches the outcome.rs
    // canned conntrack mark) — the VM-leg stamp for host session index 7.
    fn agentvm7_decimal() -> String {
        compose(Leg::AgentVm, 7).to_string()
    }

    #[test]
    fn decode_session_recovers_the_leg_and_index_from_a_real_mark() {
        let raw = compose(Leg::AgentVm, 7);
        let parts = decode_session(raw).expect("a real DS mark decodes");
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(parts.session_index, 7);
    }

    #[test]
    fn decode_session_ignores_foreign_bits_in_the_unclaimed_gap() {
        // A WireGuard fwmark coexisting in the unclaimed gap must not stop the DS
        // decode (mask drops those bits before decompose).
        let raw = compose(Leg::TlsproxyUpstream, 42) | (0x0000_c000 & !DS_MARK_MASK);
        let parts = decode_session(raw).expect("DS mark decodes past foreign bits");
        assert_eq!(parts.leg, Leg::TlsproxyUpstream);
        assert_eq!(parts.session_index, 42);
    }

    #[test]
    fn a_non_ds_mark_is_unmarked_best_effort_never_a_refusal() {
        // A bare fwmark with no DS magic → None (unmarked), the record still maps.
        assert!(decode_session(0x0000_0007).is_none());
        assert!(decode_session(0).is_none());
    }

    #[test]
    fn conntrack_destroy_line_carries_the_composed_ct_mark_and_totals() {
        // A DESTROY accounting line: original bytes=1840, reply bytes=5120; mark is
        // the AgentVm index-7 stamp; timestamp gives a 110s duration.
        let line = format!(
            "[DESTROY] tcp 6 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 \
             packets=12 bytes=1840 src=203.0.113.10 dst=10.0.0.5 sport=443 \
             dport=51514 packets=10 bytes=5120 [ASSURED] mark={mark} delta-time=110",
            mark = agentvm7_decimal()
        );
        let rec = parse_conntrack_line(&line).expect("a per-flow line parses");
        assert_eq!(rec.lifecycle, FlowLifecycle::Destroy);
        assert_eq!(rec.proto, Proto::Tcp);
        assert_eq!(rec.bytes, 1840 + 5120);
        assert_eq!(rec.packets, 12 + 10);
        assert_eq!(rec.duration_ms, 110_000);
        assert_eq!(rec.dport, Some(443));
        // The address is carried as the frozen family-agnostic AdmittedAddr; its
        // canonical key agrees with the admission map's refcount key.
        assert_eq!(rec.dst.as_ref().unwrap().to_dst_key().0, "v4:cb00710a");

        // The flow carries the composed per-session ct mark, sourced from the
        // frozen constants — the LOG-2 attribution key.
        let parts = rec.session.expect("the flow is attributed to a session");
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(parts.session_index, 7);
        assert_eq!(rec.ct_mark_token().unwrap(), ct_mark_token(Leg::AgentVm, 7));
        // The composed value leads with the magic 0xD nibble.
        assert!(rec.ct_mark_token().unwrap().starts_with("0xd1"));
    }

    #[test]
    fn conntrack_new_line_is_a_start_event_with_the_mark() {
        let line = format!(
            "[NEW] tcp 6 src=10.0.0.9 dst=198.51.100.7 sport=40000 dport=443 \
             [UNREPLIED] src=198.51.100.7 dst=10.0.0.9 sport=443 dport=40000 mark={mark}",
            mark = compose(Leg::AgentVm, 3).to_string()
        );
        let rec = parse_conntrack_line(&line).expect("a NEW line parses");
        assert_eq!(rec.lifecycle, FlowLifecycle::New);
        assert_eq!(rec.bytes, 0, "a NEW event has no accounting yet");
        assert_eq!(rec.session.unwrap().session_index, 3);
    }

    #[test]
    fn an_unmarked_conntrack_flow_still_maps_best_effort() {
        // A host-origin flow with no DS mark — still emitted, session None.
        let line = "[DESTROY] tcp 6 src=203.0.113.9 dst=8.8.8.8 sport=5000 \
                    dport=53 packets=2 bytes=120 mark=0";
        let rec = parse_conntrack_line(line).expect("an unmarked flow still maps");
        assert!(rec.session.is_none(), "unmarked best-effort, not a refusal");
        assert_eq!(rec.ct_mark_token(), None);
        assert!(String::from_utf8(rec.payload())
            .unwrap()
            .contains("mark=unmarked"));
    }

    #[test]
    fn the_summary_line_and_blanks_are_skipped() {
        let lines = vec![
            "".to_string(),
            "conntrack v1.4.7 (conntrack-tools): 2 flow entries have been deleted.".to_string(),
        ];
        assert!(parse_conntrack_events(&lines).is_empty());
    }

    #[test]
    fn nflog_drop_line_carries_the_stamped_mark_via_the_interface_not_src() {
        // The drop nflog line: the NFT-5 stamp set MARK before the terminal drop, so
        // the dropped packet carries the session mark; IN= is the tap. SRC is a
        // FORGED private address — it must not be the attribution key.
        let mark_hex = format!("0x{:x}", compose(Leg::AgentVm, 7));
        let line = format!(
            "ds-nft5-drop IN=dstap-7 OUT= MAC=... SRC=10.0.0.5 DST=185.199.108.153 \
             LEN=60 PROTO=TCP SPT=52000 DPT=443 MARK={mark_hex}"
        );
        let rec = parse_nflog_drop_line(&line).expect("a drop line parses");
        assert_eq!(rec.lifecycle, FlowLifecycle::Drop);
        assert_eq!(rec.proto, Proto::Tcp);
        assert_eq!(rec.dport, Some(443));
        // Attribution is the decoded MARK (interface-stamped), NOT the forged SRC.
        let parts = rec.session.expect("the drop is attributed to a session");
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(parts.session_index, 7);
        assert_eq!(rec.ct_mark_token().unwrap(), ct_mark_token(Leg::AgentVm, 7));
    }

    #[test]
    fn a_non_drop_nflog_line_is_ignored() {
        assert!(parse_nflog_drop_line("some unrelated kernel log line").is_none());
        assert!(parse_nflog_drops(&["noise".to_string()]).is_empty());
    }

    #[test]
    fn to_envelope_is_a_flowrecord_with_mandatory_provenance() {
        let rec = parse_conntrack_line(&format!(
            "[DESTROY] udp 17 src=10.0.0.5 dst=1.1.1.1 sport=5353 dport=53 \
             packets=1 bytes=64 mark={}",
            agentvm7_decimal()
        ))
        .unwrap();
        let env = rec.to_envelope(provenance());
        assert_eq!(env.kind(), EventKind::FlowRecord);
        assert_eq!(env.provenance().rule_id(), "nft5/ct-mark-flowtag");
        // The composed ct mark rides the envelope payload — the on-disk record the
        // spool flushes carries the per-session attribution.
        let body = String::from_utf8(env.payload().to_vec()).unwrap();
        assert!(body.contains(&ct_mark_token(Leg::AgentVm, 7)));
        assert!(env.credential_fingerprint().is_none());
    }

    #[test]
    fn emit_into_a_sink_is_fire_and_forget() {
        // Emission never panics / never fails the data path (NullSink stand-in).
        let rec = parse_nflog_drop_line(&format!(
            "ds-nft5-drop IN=dstap-1 SRC=10.0.0.5 DST=9.9.9.9 PROTO=UDP SPT=1 \
             DPT=443 MARK=0x{:x}",
            compose(Leg::AgentVm, 1)
        ))
        .unwrap();
        rec.emit_into(&NullSink, provenance());
    }
}
