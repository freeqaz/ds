//! The `flush_session` IMPLEMENTATION (doc 14 §5; doc 11 §5.4; D76/D68/D53).
//!
//! [`NftWriter`] implements the frozen [`ds_contracts::flush::FlushSession`]
//! trait once, serving all three callers — D68 revocation, D72 sweep, NFT-6
//! teardown — with ONE body. The differences between callers are entirely in
//! the ARGUMENTS they pass (`dst_filter`, `legs`); ds-nft executes mechanism
//! only and encodes no rung/policy logic (README "What must NOT live here":
//! rung-conditionality per D53 is the caller's decision).
//!
//! What the body does, mechanically:
//!
//! 1. Resolve the legs to span. `LegSelector::All` → every assigned leg nibble;
//!    `LegSelector::Some([..])` → exactly those (revocation passes
//!    `LegSelector::sever_pair()` = `0x1`+`0x2`).
//! 2. For each leg, compose the **masked** conntrack match
//!    ([`crate::mark_match::MarkMatch`]) from `(leg, session_index)` — a
//!    bare-index match never fires (the high magic/leg bits are always present
//!    under [`ds_contracts::mark::DS_MARK_MASK`]).
//! 3. Narrow per `dst_filter`: `All` → one destroy per leg over every
//!    destination carrying the mark (teardown, NFT-6); `Only([keys])` → one
//!    destroy per (leg, dst-key) (revocation of refcount-zero keys, doc 11
//!    §5.2 reverse index).
//! 4. Issue each destroy through the backend, parse the conntrack accounting
//!    output ([`crate::outcome`]) into per-entry destroy records, and aggregate
//!    into a [`crate::outcome::FlushReport`].
//! 5. Return the frozen [`ds_contracts::flush::FlushOutcome`] (entry count). The
//!    caller keeps the richer report via [`NftWriter::flush_session_report`] for
//!    the ds-flowlog byte-count events (NFT-6).
//!
//! Effectiveness requires `nf_conntrack_tcp_loose=0` (doc 14 §11): without it a
//! flushed flow's mid-stream packets are re-picked-up as ESTABLISHED and **the
//! flush is a no-op**. ds-nft consumes that host-baseline precondition (see
//! [`crate::precondition`]); it does not set the sysctl, and it does not refuse
//! the mechanism — it surfaces the state for the caller to act on.

use ds_contracts::flush::{DstFilter, FlushError, FlushOutcome, FlushSession, LegSelector};
use ds_contracts::mark::Leg;
use ds_contracts::session::SessionRef;

use crate::backend::{BackendError, ConntrackDestroy, NftBackend};
use crate::mark_match::MarkMatch;
use crate::outcome::{parse_destroy_output, FlushReport};

/// Every assigned leg nibble (doc 14 §5 table). `LegSelector::All` (teardown)
/// spans all of these; `Reserved` (0xF) is included so a diagnostic-marked
/// entry is also swept at teardown.
pub const ALL_LEGS: [Leg; 5] = [
    Leg::AgentVm,
    Leg::TlsproxyUpstream,
    Leg::DnsgateUpstream,
    Leg::InfraEgress,
    Leg::Reserved,
];

/// The error this writer surfaces to callers: a backend (nft/conntrack) failure.
/// Opaque above the [`FlushSession`] trait (callers only `Debug`-propagate it),
/// per the `ds-contracts` [`FlushError`] contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftFlushError {
    /// The underlying backend error.
    pub backend: BackendError,
}

impl From<BackendError> for NftFlushError {
    fn from(backend: BackendError) -> NftFlushError {
        NftFlushError { backend }
    }
}

impl FlushError for NftFlushError {}

/// The one nft/netlink writer. Generic over the [`NftBackend`] so production
/// wires the spawned `nft -f` / `conntrack -D` backend and tests wire the
/// recording fake — the flush body is identical either way.
#[derive(Debug, Default)]
pub struct NftWriter<B: NftBackend> {
    backend: B,
}

impl<B: NftBackend> NftWriter<B> {
    /// Build a writer over a backend.
    pub fn new(backend: B) -> NftWriter<B> {
        NftWriter { backend }
    }

    /// Borrow the backend (tests inspect the recorded destroys through this).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Resolve a [`LegSelector`] to the concrete legs to span. `All` →
    /// [`ALL_LEGS`]; `Some` → exactly the listed legs (preserving order,
    /// deduplicated so a caller-supplied duplicate does not double-destroy).
    fn legs_to_span(legs: &LegSelector) -> Vec<Leg> {
        match legs {
            LegSelector::All => ALL_LEGS.to_vec(),
            LegSelector::Some(list) => {
                let mut out: Vec<Leg> = Vec::with_capacity(list.len());
                for &leg in list {
                    if !out.contains(&leg) {
                        out.push(leg);
                    }
                }
                out
            }
        }
    }

    /// Build the destroy requests for one leg, narrowing per `dst_filter`.
    fn destroys_for_leg(
        session: &SessionRef,
        leg: Leg,
        dst_filter: &DstFilter,
    ) -> Vec<ConntrackDestroy> {
        let mark = MarkMatch::for_leg(leg, session.host_session_index);
        let mark_arg = mark.to_value_mask_token();
        match dst_filter {
            // Teardown / NFT-6: one destroy per leg, every destination carrying
            // the mark.
            DstFilter::All => vec![ConntrackDestroy {
                mark_arg,
                dst: None,
            }],
            // Revocation: one destroy per (leg, dst-key). The dst keys are the
            // refcount-zero set elements the caller resolved from the §5.2
            // reverse index.
            DstFilter::Only(keys) => keys
                .iter()
                .map(|k| ConntrackDestroy {
                    mark_arg: mark_arg.clone(),
                    // `--dst` needs an address literal: the DstKey carries the
                    // frozen `v4:<hex>` identity, which `conntrack` rejects.
                    // address_literal() yields the dotted/colon form (and passes
                    // an already-literal key through). See DstKey::address_literal.
                    dst: Some(k.address_literal()),
                })
                .collect(),
        }
    }

    /// The full flush, returning the RICH internal report (per-entry destroy
    /// records with byte counts) — the NFT-6 path the caller maps into
    /// ds-flowlog. [`FlushSession::flush_session`] collapses this to the frozen
    /// [`FlushOutcome`].
    pub fn flush_session_report(
        &self,
        session: &SessionRef,
        dst_filter: &DstFilter,
        legs: &LegSelector,
    ) -> Result<FlushReport, NftFlushError> {
        let mut report = FlushReport::default();
        for leg in Self::legs_to_span(legs) {
            for destroy in Self::destroys_for_leg(session, leg, dst_filter) {
                let output = self.backend.destroy_conntrack(&destroy)?;
                let mut leg_report = parse_destroy_output(&output.lines);
                report.records.append(&mut leg_report.records);
            }
        }
        Ok(report)
    }
}

impl<B: NftBackend> FlushSession for NftWriter<B> {
    type Error = NftFlushError;

    fn flush_session(
        &self,
        session: &SessionRef,
        dst_filter: &DstFilter,
        legs: &LegSelector,
    ) -> Result<FlushOutcome, Self::Error> {
        Ok(self
            .flush_session_report(session, dst_filter, legs)?
            .to_outcome())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ConntrackOutput, RecordingBackend};
    use ds_contracts::flush::DstKey;
    use ds_contracts::mark::{compose, decompose, DS_MARK_MASK};

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    fn writer() -> NftWriter<RecordingBackend> {
        NftWriter::new(RecordingBackend::new())
    }

    // One destroyed-entry accounting line for the given dst (inline; no fixtures).
    fn acct_line(dst: &str, orig: u64, reply: u64) -> String {
        format!(
            "tcp 6 110 src=10.0.0.5 dst={dst} sport=51514 dport=443 packets=12 \
             bytes={orig} src={dst} dst=10.0.0.5 sport=443 dport=51514 packets=10 \
             bytes={reply} [ASSURED]"
        )
    }

    #[test]
    fn teardown_spans_all_legs_with_all_dst() {
        let w = writer();
        let out = w
            .flush_session(&session(7), &DstFilter::All, &LegSelector::All)
            .expect("flush");
        // entries_flushed is 0 because no canned output was seeded — but the
        // mechanism still issued one destroy per leg.
        assert_eq!(out.entries_flushed, 0);

        let destroys = w.backend().destroys();
        assert_eq!(destroys.len(), ALL_LEGS.len());
        // every destroy is dst=None (All) and carries the masked token.
        for d in &destroys {
            assert!(d.dst.is_none());
            assert!(d.mark_arg.ends_with(&format!("/0x{:x}", DS_MARK_MASK)));
        }
    }

    #[test]
    fn sever_pair_spans_exactly_the_two_nibbles() {
        let w = writer();
        w.flush_session(
            &session(42),
            &DstFilter::Only(vec![DstKey("203.0.113.10".into())]),
            &LegSelector::sever_pair(),
        )
        .expect("flush");

        let destroys = w.backend().destroys();
        // sever_pair = {AgentVm 0x1, TlsproxyUpstream 0x2}; one dst key → 2 destroys.
        assert_eq!(destroys.len(), 2);

        // decode each destroy's value field back to its leg and assert it is one
        // of the severed legs and NOT any other.
        let mut legs_seen = Vec::new();
        for d in &destroys {
            let value_hex = d.mark_arg.split('/').next().unwrap();
            let value = u32::from_str_radix(value_hex.trim_start_matches("0x"), 16).unwrap();
            let parts = decompose(value).expect("composed value decodes");
            legs_seen.push(parts.leg);
            assert_eq!(parts.session_index, 42);
            assert_eq!(d.dst.as_deref(), Some("203.0.113.10"));
        }
        assert!(legs_seen.contains(&Leg::AgentVm));
        assert!(legs_seen.contains(&Leg::TlsproxyUpstream));
        // never the dnsgate/infra/reserved legs.
        assert!(!legs_seen.contains(&Leg::DnsgateUpstream));
        assert!(!legs_seen.contains(&Leg::InfraEgress));
    }

    #[test]
    fn dst_only_narrows_to_each_listed_destination() {
        let w = writer();
        w.flush_session(
            &session(3),
            &DstFilter::Only(vec![
                DstKey("198.51.100.7".into()),
                DstKey("203.0.113.9".into()),
            ]),
            // single leg keeps the destroy count == number of dst keys.
            &LegSelector::Some(vec![Leg::AgentVm]),
        )
        .expect("flush");

        let destroys = w.backend().destroys();
        assert_eq!(destroys.len(), 2);
        let dsts: Vec<_> = destroys.iter().map(|d| d.dst.clone().unwrap()).collect();
        assert!(dsts.contains(&"198.51.100.7".to_string()));
        assert!(dsts.contains(&"203.0.113.9".to_string()));
    }

    #[test]
    fn the_match_is_mask_aware_a_bare_index_value_is_never_emitted() {
        let w = writer();
        w.flush_session(
            &session(7),
            &DstFilter::All,
            &LegSelector::Some(vec![Leg::AgentVm]),
        )
        .expect("flush");
        let d = &w.backend().destroys()[0];
        let value_hex = d.mark_arg.split('/').next().unwrap();
        let value = u32::from_str_radix(value_hex.trim_start_matches("0x"), 16).unwrap();
        // the emitted value is the FULL composite (magic+leg+index), never the
        // bare index 7.
        assert_eq!(value, compose(Leg::AgentVm, 7));
        assert_ne!(value, 7);
        // and it carries the explicit mask suffix.
        assert!(d.mark_arg.ends_with(&format!("/0x{:x}", DS_MARK_MASK)));
    }

    #[test]
    fn teardown_destroy_records_carry_byte_counts() {
        let w = writer();
        // Seed accounting output for ONE leg's destroy (AgentVm), the others
        // return empty. The richer report aggregates per-entry byte counts.
        let backend = w.backend();
        backend.push_conntrack_output(ConntrackOutput {
            lines: vec![
                acct_line("203.0.113.10", 1840, 5120),
                acct_line("198.51.100.7", 400, 900),
            ],
        });

        let report = w
            .flush_session_report(
                &session(7),
                &DstFilter::All,
                &LegSelector::Some(vec![Leg::AgentVm]),
            )
            .expect("flush report");

        assert_eq!(report.entries_flushed(), 2);
        assert_eq!(report.total_bytes(), 1840 + 5120 + 400 + 900);
        assert_eq!(report.records[0].dst.as_deref(), Some("203.0.113.10"));
        assert_eq!(report.records[0].orig_bytes, Some(1840));
        assert_eq!(report.records[1].reply_bytes, Some(900));

        // the frozen contract still collapses to the entry count.
        assert_eq!(report.to_outcome().entries_flushed, 2);
    }

    #[test]
    fn outcome_entry_count_matches_destroyed_entries() {
        let w = writer();
        w.backend().push_conntrack_output(ConntrackOutput {
            lines: vec![acct_line("203.0.113.10", 10, 20)],
        });
        let out = w
            .flush_session(
                &session(1),
                &DstFilter::Only(vec![DstKey("203.0.113.10".into())]),
                &LegSelector::Some(vec![Leg::AgentVm]),
            )
            .expect("flush");
        assert_eq!(out.entries_flushed, 1);
    }

    #[test]
    fn conntrack_dst_uses_address_literal_not_dst_key_hex() {
        // Regression (live-found 2026-06-14): the revocation DstFilter::Only
        // carries the frozen DstKey hex (v4:cb007105 == 203.0.113.5);
        // `conntrack -D --dst` rejects the hex form. The destroy request must
        // narrow on the dotted literal, or targeted revocation silently no-ops.
        let w = writer();
        w.backend().push_conntrack_output(ConntrackOutput {
            lines: vec![acct_line("203.0.113.5", 10, 20)],
        });
        w.flush_session(
            &session(1),
            &DstFilter::Only(vec![DstKey("v4:cb007105".into())]),
            &LegSelector::Some(vec![Leg::AgentVm]),
        )
        .expect("flush");
        let destroys = w.backend().destroys();
        assert_eq!(destroys.len(), 1);
        assert_eq!(destroys[0].dst.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn a_backend_failure_propagates_as_the_writer_error() {
        let w = writer();
        w.backend()
            .arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let err = w
            .flush_session(&session(1), &DstFilter::All, &LegSelector::All)
            .expect_err("must propagate");
        assert!(err.backend.message.contains("EPERM"));
    }

    #[test]
    fn duplicate_legs_in_selector_do_not_double_destroy() {
        let w = writer();
        w.flush_session(
            &session(1),
            &DstFilter::All,
            &LegSelector::Some(vec![Leg::AgentVm, Leg::AgentVm]),
        )
        .expect("flush");
        // deduplicated → exactly one destroy.
        assert_eq!(w.backend().destroys().len(), 1);
    }

    // The whole point of the contract split: a caller links the signature with
    // NO nft/netlink types — only ds-contracts shapes — via static dispatch.
    #[test]
    fn implements_the_frozen_contract_signature() {
        fn use_it<F: FlushSession>(f: &F, s: &SessionRef) -> Result<FlushOutcome, F::Error> {
            f.flush_session(s, &DstFilter::All, &LegSelector::All)
        }
        let w = writer();
        let out = use_it(&w, &session(9)).expect("contract call");
        assert_eq!(out, FlushOutcome { entries_flushed: 0 });
    }
}
