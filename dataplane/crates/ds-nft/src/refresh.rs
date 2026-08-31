//! Both kernel refresh paths behind one internal API (D68; doc 14 §6/§11; doc
//! 11 §8.3 step 3).
//!
//! NFT-3 allow-set elements carry a timeout (the W2 shared deadline). When a
//! live name is re-resolved the deadline extends — `max(existing, new)`, never
//! shortened (W2). Two kernel mechanisms achieve the SAME observable result:
//!
//! - **`InPlace` (kernel ≥6.12, commit 4201f3938914).** An element timeout is
//!   updated in place — one `add element` op with the new timeout replaces the
//!   element's deadline without a destroy. The fast path.
//! - **`DeleteAdd` (pre-6.12 fallback, OQ5).** Delete the element and re-add it
//!   with the new timeout, in ONE batch so there is no window where the element
//!   is absent (doc 11 §8.3 step 3: "the same observable result within one
//!   transaction"). The spike (doc 14 TODO / doc 11 OQ5) verifies the
//!   delete+add-in-one-batch semantics.
//!
//! Both live behind [`RefreshStrategy`] and produce an [`crate::backend::NftBatch`]
//! the backend applies. The strategy is chosen by a kernel probe
//! ([`KernelProbe`]) with an explicit test override, so CI exercises BOTH batch
//! shapes on any kernel (GitHub `ubuntu-latest` runs 6.8; the ≥6.12 in-place
//! path's REAL execution is M0-host work, but its generated batch is the CI
//! assertion).
//!
//! Mechanism is FREE (doc 11 §4): the batch text below is the spawned-`nft -f`
//! shape; an `nftnl-rs` mechanism would emit the equivalent netlink ops behind
//! the same [`RefreshStrategy`].

use crate::backend::NftBatch;
use crate::mark_match::MarkMatch;
use ds_contracts::mark::Leg;

/// The first kernel version with in-place nft element-timeout update
/// (commit 4201f3938914) — the D68 baseline. Below this, the delete+add
/// fallback is required.
pub const INPLACE_MIN_KERNEL: (u32, u32) = (6, 12);

/// Which refresh mechanism a batch uses. Selected by [`KernelProbe`]; both are
/// always reachable for testing via [`RefreshStrategy::for_kernel`] /
/// [`RefreshStrategy::Forced`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshStrategy {
    /// Kernel ≥6.12: in-place element-timeout update (no destroy).
    InPlace,
    /// Pre-6.12: delete the element then re-add it with the new timeout, in one
    /// batch (OQ5 spike).
    DeleteAdd,
}

impl RefreshStrategy {
    /// The strategy a `(major, minor)` kernel selects (D68 boundary at 6.12).
    pub fn for_kernel(major: u32, minor: u32) -> RefreshStrategy {
        if (major, minor) >= INPLACE_MIN_KERNEL {
            RefreshStrategy::InPlace
        } else {
            RefreshStrategy::DeleteAdd
        }
    }
}

/// A request to refresh one NFT-3 allow-set element's timeout to a new deadline.
///
/// The element key is the masked DS mark (the `(leg, index)` the session's
/// flows carry) — the same mask-aware identity the flush uses, so refresh and
/// flush never diverge on which element they mean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRequest {
    /// The set name the element lives in (e.g. `allow4`), authored by the
    /// caller — ds-nft does not invent set names.
    pub set_name: String,
    /// The composed mark/mask identifying the element.
    pub mark: MarkMatch,
    /// The element value (the admitted destination key) as the set stores it,
    /// authored by the caller — opaque to ds-nft.
    pub element: String,
    /// The new timeout in seconds (the W2 deadline, already clamped by the
    /// caller; refresh never recomputes a timer — doc 11 §8.3 step 1).
    pub timeout_secs: u32,
}

/// The table the per-session NFT objects live under. Authored once here so both
/// refresh-batch shapes name the same table; the caller supplies the set name.
const TABLE: &str = "inet ds_filter";

/// Generate the `nft -f` batch that refreshes `req`'s element under `strategy`.
///
/// Both shapes are deterministic and contain no raw DS-mark literal — the
/// element comment carries the masked `value/mask` token from `ds_contracts`.
pub fn refresh_batch(strategy: RefreshStrategy, req: &RefreshRequest) -> NftBatch {
    let token = req.mark.to_value_mask_token();
    // Render the element to its address literal for the nft batch text.
    // `RefreshRequest::element` carries the frozen `DstKey` hex identity
    // (`v4:<hex>`), which `nft` rejects as a set-element key (`syntax error`);
    // `address_literal()` yields the dotted/colon form nft accepts (an
    // already-literal key passes through unchanged). Without this every
    // admission/refresh fails closed — see `DstKey::address_literal`.
    let elem = ds_contracts::flush::DstKey(req.element.clone()).address_literal();
    let add_line = format!(
        "add element {table} {set} {{ {elem} timeout {to}s comment \"ds-mark {token}\" }}",
        table = TABLE,
        set = req.set_name,
        elem = elem,
        to = req.timeout_secs,
        token = token,
    );
    let text = match strategy {
        // ≥6.12: a single in-place add with the new timeout replaces the
        // element's deadline. nftables treats `add element` on an existing key
        // as an in-place timeout update on these kernels.
        RefreshStrategy::InPlace => format!(
            "# refresh:inplace (kernel >= {maj}.{min})\n{add}\n",
            maj = INPLACE_MIN_KERNEL.0,
            min = INPLACE_MIN_KERNEL.1,
            add = add_line,
        ),
        // pre-6.12: delete then add, in ONE batch so the element is never
        // absent between ops (OQ5 invariant).
        RefreshStrategy::DeleteAdd => format!(
            "# refresh:delete+add (kernel < {maj}.{min}, one batch)\n\
             delete element {table} {set} {{ {elem} }}\n{add}\n",
            maj = INPLACE_MIN_KERNEL.0,
            min = INPLACE_MIN_KERNEL.1,
            table = TABLE,
            set = req.set_name,
            elem = elem,
            add = add_line,
        ),
    };
    NftBatch::new(text)
}

/// Probes the running kernel to choose a [`RefreshStrategy`], with an explicit
/// test/ops override (doc 14 §6: "selected by a kernel probe with an explicit
/// test override").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelProbe {
    /// Probe the live kernel version (reads `uname` release at call time).
    Live,
    /// Force a strategy regardless of the live kernel — the test/ops override.
    /// This is what lets CI assert BOTH batch shapes on a single kernel.
    Forced(RefreshStrategy),
}

impl KernelProbe {
    /// Resolve to a concrete strategy. `Forced` returns its strategy verbatim;
    /// `Live` parses `parse_uname_release` over the kernel release string and
    /// falls back to the conservative [`RefreshStrategy::DeleteAdd`] when the
    /// version cannot be determined (fail-safe: never assume the fast path).
    pub fn resolve(self, live_release: &str) -> RefreshStrategy {
        match self {
            KernelProbe::Forced(s) => s,
            KernelProbe::Live => match parse_uname_release(live_release) {
                Some((maj, min)) => RefreshStrategy::for_kernel(maj, min),
                None => RefreshStrategy::DeleteAdd,
            },
        }
    }
}

/// Parse `(major, minor)` from a `uname -r` release string like
/// `6.12.3-arch1-1` or `5.15.0-105-generic`. Returns `None` if the leading two
/// dotted integers cannot be read — the caller treats that as "assume the
/// fallback path".
pub fn parse_uname_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

/// Both leg-nibbles a teardown/sever refresh touches, exposed so a caller that
/// refreshes per-leg can mirror the flush's leg spanning. Mechanism helper, not
/// policy.
pub fn sever_legs() -> [Leg; 2] {
    [Leg::AgentVm, Leg::TlsproxyUpstream]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_req() -> RefreshRequest {
        RefreshRequest {
            set_name: "allow4".into(),
            mark: MarkMatch::for_leg(Leg::AgentVm, 7),
            element: "203.0.113.10".into(),
            timeout_secs: 900,
        }
    }

    #[test]
    fn strategy_boundary_is_6_12() {
        assert_eq!(RefreshStrategy::for_kernel(6, 12), RefreshStrategy::InPlace);
        assert_eq!(RefreshStrategy::for_kernel(6, 13), RefreshStrategy::InPlace);
        assert_eq!(RefreshStrategy::for_kernel(7, 0), RefreshStrategy::InPlace);
        assert_eq!(
            RefreshStrategy::for_kernel(6, 11),
            RefreshStrategy::DeleteAdd
        );
        assert_eq!(
            RefreshStrategy::for_kernel(5, 15),
            RefreshStrategy::DeleteAdd
        );
    }

    #[test]
    fn inplace_batch_is_a_single_add_with_timeout() {
        let batch = refresh_batch(RefreshStrategy::InPlace, &sample_req());
        assert!(batch.text.contains("refresh:inplace"));
        // one add element, no delete (in-place update).
        assert!(batch.text.contains("add element inet ds_filter allow4"));
        assert!(!batch.text.contains("delete element"));
        assert!(batch.text.contains("timeout 900s"));
    }

    #[test]
    fn batch_renders_dst_key_hex_element_as_an_nft_address_literal() {
        // Regression (live-found 2026-06-14): production passes
        // `SetInsert::element = AdmittedAddr::to_dst_key()` — the frozen
        // `"v4:<hex>"` identity, NOT a dotted literal. `nft` rejects
        // `v4:a04f680a` as a set-element key (`syntax error`), so the atomic
        // batch fails and every admission/refresh fails closed (SERVFAIL). The
        // batch text MUST carry the dotted form (a04f680a == 160.79.104.10).
        let req = RefreshRequest {
            set_name: "allow4".into(),
            mark: MarkMatch::for_leg(Leg::AgentVm, 7),
            element: "v4:a04f680a".into(),
            timeout_secs: 900,
        };
        for strat in [RefreshStrategy::InPlace, RefreshStrategy::DeleteAdd] {
            let batch = refresh_batch(strat, &req);
            assert!(
                batch.text.contains("160.79.104.10"),
                "{strat:?} batch must use the nft address literal, got: {}",
                batch.text
            );
            assert!(
                !batch.text.contains("v4:a04f680a"),
                "{strat:?} batch must NOT leak the DstKey hex form into nft"
            );
        }
    }

    #[test]
    fn delete_add_batch_is_delete_then_add_in_one_batch() {
        let batch = refresh_batch(RefreshStrategy::DeleteAdd, &sample_req());
        assert!(batch.text.contains("refresh:delete+add"));
        let del = batch.text.find("delete element").expect("has delete");
        let add = batch.text.find("add element").expect("has add");
        // delete precedes add, and both are in the SAME batch text (one apply).
        assert!(del < add, "delete must precede add within the one batch");
        assert!(batch.text.contains("timeout 900s"));
    }

    #[test]
    fn both_batches_carry_the_masked_token_not_a_raw_literal() {
        let token = sample_req().mark.to_value_mask_token();
        for strat in [RefreshStrategy::InPlace, RefreshStrategy::DeleteAdd] {
            let batch = refresh_batch(strat, &sample_req());
            assert!(
                batch.text.contains(&token),
                "{strat:?} batch must carry the masked value/mask token"
            );
            // the token always carries the mask suffix.
            assert!(batch.text.contains("/0xff003fff"));
        }
    }

    #[test]
    fn kernel_probe_forced_override_selects_either_path() {
        // The explicit test override: force each strategy regardless of kernel.
        assert_eq!(
            KernelProbe::Forced(RefreshStrategy::InPlace).resolve("6.8.0-generic"),
            RefreshStrategy::InPlace
        );
        assert_eq!(
            KernelProbe::Forced(RefreshStrategy::DeleteAdd).resolve("7.0.0-arch1"),
            RefreshStrategy::DeleteAdd
        );
    }

    #[test]
    fn kernel_probe_live_parses_the_release() {
        assert_eq!(
            KernelProbe::Live.resolve("6.12.3-arch1-1"),
            RefreshStrategy::InPlace
        );
        // GitHub ubuntu-latest runs 6.8 → fallback path.
        assert_eq!(
            KernelProbe::Live.resolve("6.8.0-1021-azure"),
            RefreshStrategy::DeleteAdd
        );
        // unparseable → conservative fallback, never the fast path.
        assert_eq!(
            KernelProbe::Live.resolve("weird"),
            RefreshStrategy::DeleteAdd
        );
    }

    #[test]
    fn parse_uname_release_handles_common_shapes() {
        assert_eq!(parse_uname_release("6.12.3-arch1-1"), Some((6, 12)));
        assert_eq!(parse_uname_release("5.15.0-105-generic"), Some((5, 15)));
        assert_eq!(parse_uname_release("7.0.10-arch1-1"), Some((7, 0)));
        assert_eq!(parse_uname_release(""), None);
        assert_eq!(parse_uname_release("notaversion"), None);
    }

    #[test]
    fn sever_legs_are_the_two_nibbles() {
        assert_eq!(sever_legs(), [Leg::AgentVm, Leg::TlsproxyUpstream]);
    }
}
