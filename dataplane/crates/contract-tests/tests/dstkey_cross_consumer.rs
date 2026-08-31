//! Cross-consumer `DstKey` contract test (security-relevant).
//!
//! The frozen `ds_contracts::flush::DstKey` is an opaque `String` placeholder
//! (`ds-contracts/src/flush.rs:47` — "the concrete address representation is
//! owned by ds-nft / the §3 admission map"). Two `FlushSession` consumers narrow
//! a revocation by that key:
//!
//! - **ds-nft** `NftWriter`: `DstFilter::Only([key])` → `conntrack -D --dst
//!   <key>` (the kernel destroys only flows whose dst equals `<key>`);
//! - **ds-tlsproxy** `SeveringRegistry`: stores `key` at register time, severs a
//!   handle only when a sweep passes back an EXACTLY-equal `key`.
//!
//! Both compare the key by string equality. This file proves, across BOTH
//! consumers at once:
//!
//! - (a) `positive_round_trip_*` — when register-time and revoke-time keys share
//!   the one canonical admission-map shape, BOTH consumers report a non-empty
//!   severing outcome;
//! - (b) `negative_key_mismatch_*` — a deliberately mismatched representation of
//!   the SAME logical destination severs NOTHING on BOTH consumers (the silent
//!   guardrail no-op the test exists to catch);
//! - (c) `parity_canonical_key_shape_is_pinned` — pins the canonical key shape
//!   (the ds-nft / §3 representation, per the existing ds-nft test vectors like
//!   `"203.0.113.10"`) and asserts both consumers round-trip on it.
//!
//! D76 frozen non-edge: this crate is the only place that may depend on both
//! consumers (doc 12 §4.2, doc 14 §5). It adds NO edge between ds-nft and
//! ds-tlsproxy — each remains ignorant of the other; only this downstream
//! test-only member links the two.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ds_contracts::flush::{DstFilter, DstKey, FlushSession, LegSelector};
use ds_contracts::session::SessionRef;

use ds_nft::backend::{BackendError, ConntrackDestroy, ConntrackOutput, NftBackend};
use ds_nft::flush::NftWriter;

use ds_tlsproxy::{RevocationSweep, RevokedAdmission, Rung, Severable, SeveringRegistry};

/// The canonical destination-key shape both consumers must agree on: the bare
/// dotted-quad address, exactly as the ds-nft `flush` test vectors and the §3
/// admission-map reverse index spell it. Pinned here (see `parity_*` and the
/// crate README); any deviation between register-time and revoke-time keys is
/// the silent no-op this file guards.
const CANONICAL_KEY: &str = "203.0.113.10";

/// A deliberately MISMATCHED representation of the SAME logical destination: the
/// `host:port` form a careless caller might pass when the admission map keys on
/// the bare address. Same destination, different string → no string-equality
/// match on EITHER consumer.
const MISMATCHED_KEY: &str = "203.0.113.10:443";

fn session(idx: u32) -> SessionRef {
    SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        idx,
        format!("dstap-{idx}"),
    )
}

// ----------------------------------------------------------------------------
// ds-nft side: a LOCAL implementation of ds-nft's public `NftBackend` trait.
//
// The brief forbids modifying ds-nft to export a test helper; this is the
// "implement its public backend trait locally" path. The fake models the ONE
// conntrack property the contract turns on: `conntrack -D --dst <key>` destroys
// only flows whose destination equals `<key>` (string equality, the same
// comparison the proxy registry makes). So a key mismatch at the ds-nft layer
// produces exactly the same silent no-op the kernel would: the destroy matches
// no live flow, conntrack prints nothing, and `entries_flushed == 0`.
// ----------------------------------------------------------------------------

/// A fake `NftBackend` that models conntrack's `--dst` narrowing over a fixed
/// set of "live flows" keyed by destination address. A destroy with
/// `dst = Some(k)` emits one accounting line per live flow whose dst == `k`
/// (mirroring `conntrack -D --dst k`); `dst = None` (teardown) destroys every
/// live flow. The mark token is recorded but, like the real kernel for this
/// test's purposes, the dst narrowing is what decides whether anything is hit.
struct DstFilteringBackend {
    /// Destinations with a live conntrack entry for this session.
    live_dsts: Vec<String>,
}

impl DstFilteringBackend {
    fn new(live_dsts: &[&str]) -> DstFilteringBackend {
        DstFilteringBackend {
            live_dsts: live_dsts.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// One conntrack accounting line for a destroyed entry to `dst` (the same
    /// shape ds-nft's `outcome` parser reads — `dst=` plus two `bytes=` tuples).
    fn acct_line(dst: &str) -> String {
        format!(
            "tcp 6 110 src=10.0.0.5 dst={dst} sport=51514 dport=443 packets=12 \
             bytes=1840 src={dst} dst=10.0.0.5 sport=443 dport=51514 packets=10 \
             bytes=5120 [ASSURED]"
        )
    }
}

impl NftBackend for DstFilteringBackend {
    fn apply_batch(&self, _batch: &ds_nft::backend::NftBatch) -> Result<(), BackendError> {
        Ok(())
    }

    fn destroy_conntrack(
        &self,
        destroy: &ConntrackDestroy,
    ) -> Result<ConntrackOutput, BackendError> {
        let lines = match &destroy.dst {
            // `conntrack -D --dst <key>`: only flows whose dst == key are hit.
            // A mismatched key matches nothing → no accounting lines → no-op.
            Some(key) => self
                .live_dsts
                .iter()
                .filter(|d| *d == key)
                .map(|d| Self::acct_line(d))
                .collect(),
            // Teardown (dst_filter = All): every live flow is destroyed.
            None => self.live_dsts.iter().map(|d| Self::acct_line(d)).collect(),
        };
        Ok(ConntrackOutput { lines })
    }

    // Tap lifecycle is not under test in this dst-key cross-consumer contract
    // test (it exercises allow-set dst-keying + conntrack accounting); satisfy
    // the grown NftBackend trait with no-ops, mirroring the no-op `apply_batch`.
    fn create_tap(&self, _spec: &ds_nft::backend::TapSpec) -> Result<(), BackendError> {
        Ok(())
    }

    fn delete_tap(&self, _name: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// ds-tlsproxy side: a fake `Severable` (the documented pingora wiring seam).
// ----------------------------------------------------------------------------

/// A fake severable userspace handle: a live flag the registry flips on sever.
struct FakeHandle {
    live: AtomicBool,
}

impl FakeHandle {
    fn new() -> Arc<FakeHandle> {
        Arc::new(FakeHandle {
            live: AtomicBool::new(true),
        })
    }
}

impl FakeHandle {
    fn sever_inner(&self) -> bool {
        // live → severed transition returns true; idempotent re-sever returns false.
        self.live.swap(false, Ordering::SeqCst)
    }
    fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }
}

/// A registry-owned, shared view of a [`FakeHandle`]. The registry takes a
/// `Box<dyn Severable>`, while the test keeps an `Arc` to inspect liveness after
/// the sweep. A local newtype carries the `Severable` impl (the orphan rule
/// forbids `impl Severable for Arc<FakeHandle>` directly, since both `Arc` and
/// the trait are foreign to this test crate).
struct SharedHandle(Arc<FakeHandle>);

impl Severable for SharedHandle {
    fn sever(&self) -> bool {
        self.0.sever_inner()
    }
    fn is_live(&self) -> bool {
        self.0.is_live()
    }
}

/// Drive the ds-nft consumer's flush for a revocation narrowed to `revoke_key`,
/// over a backend whose live flow is registered under `register_key`. Returns
/// the frozen `entries_flushed` count (the ds-nft "severing outcome").
fn nft_revoke(register_key: &str, revoke_key: &str) -> u64 {
    let writer = NftWriter::new(DstFilteringBackend::new(&[register_key]));
    let out = writer
        .flush_session(
            &session(7),
            &DstFilter::Only(vec![DstKey(revoke_key.into())]),
            // the block-rung sever pair {agent-VM 0x1, upstream 0x2} (doc 14 §5).
            &LegSelector::sever_pair(),
        )
        .expect("nft flush is infallible over the recording backend");
    out.entries_flushed
}

/// Drive the ds-tlsproxy consumer's revocation sweep for a tunnel + pooled
/// upstream registered under `register_key`, revoking `revoke_key` at a severing
/// rung. Returns the count of registry handles newly severed (its "severing
/// outcome"). The fake handles are returned so the caller can inspect liveness.
fn proxy_revoke(register_key: &str, revoke_key: &str) -> (u64, Arc<FakeHandle>, Arc<FakeHandle>) {
    let reg = SeveringRegistry::new();
    let s = session(7);
    let tunnel = FakeHandle::new();
    let pool = FakeHandle::new();
    reg.register_tunnel(
        &s,
        &DstKey(register_key.into()),
        Box::new(SharedHandle(tunnel.clone())),
    );
    reg.register_pooled_upstream(
        &s,
        &DstKey(register_key.into()),
        Box::new(SharedHandle(pool.clone())),
    );

    let sweep = RevocationSweep::new(&reg);
    let out = sweep.apply(&[RevokedAdmission {
        session: s,
        dst_keys: vec![DstKey(revoke_key.into())],
        // block-or-higher → the sweep actually severs (D53). The mismatch, not
        // the rung, is what makes the negative case a no-op.
        rung: Rung::BlockLog,
    }]);
    (out.entries_severed, tunnel, pool)
}

// ---- (a) positive round-trip ------------------------------------------------

#[test]
fn positive_round_trip_matching_key_severs_on_both_consumers() {
    // Register and revoke under the SAME canonical key on both consumers.

    // ds-nft: the revocation narrows to the canonical key, which matches the
    // one live conntrack flow → a non-empty severing outcome.
    let nft_severed = nft_revoke(CANONICAL_KEY, CANONICAL_KEY);
    assert!(
        nft_severed > 0,
        "ds-nft must sever a non-empty set when register/revoke keys match \
         (got {nft_severed})"
    );

    // ds-tlsproxy: the same canonical key severs the tunnel AND the pooled socket.
    let (proxy_severed, tunnel, pool) = proxy_revoke(CANONICAL_KEY, CANONICAL_KEY);
    assert!(
        proxy_severed > 0,
        "ds-tlsproxy must sever a non-empty set when register/revoke keys match \
         (got {proxy_severed})"
    );
    assert!(
        !tunnel.is_live(),
        "matched revoke must tear down the tunnel"
    );
    assert!(
        !pool.is_live(),
        "matched revoke must drop the pooled socket"
    );

    // The contract is honoured on BOTH consumers under one key shape.
    assert!(nft_severed > 0 && proxy_severed > 0);
}

// ---- (b) negative — the documented silent no-op ----------------------------

#[test]
fn negative_key_mismatch_severs_nothing_on_both_consumers() {
    // Register under the canonical bare-address key, revoke under a mismatched
    // host:port representation of the SAME logical destination.

    // ds-nft: `conntrack -D --dst 203.0.113.10:443` matches no live flow (the
    // flow's dst is the bare address) → ZERO entries flushed. Silent no-op.
    let nft_severed = nft_revoke(CANONICAL_KEY, MISMATCHED_KEY);
    assert_eq!(
        nft_severed, 0,
        "ds-nft silently severs NOTHING on a key-representation mismatch \
         (this is the guardrail no-op the contract test guards)"
    );

    // ds-tlsproxy: the registry stored the bare address; a sweep on the
    // host:port key matches no entry → the tunnel and pool stay LIVE. Same
    // silent no-op, on the userspace twin.
    let (proxy_severed, tunnel, pool) = proxy_revoke(CANONICAL_KEY, MISMATCHED_KEY);
    assert_eq!(
        proxy_severed, 0,
        "ds-tlsproxy silently severs NOTHING on a key-representation mismatch"
    );
    assert!(
        tunnel.is_live(),
        "mismatched revoke leaves the tunnel LIVE — bytes keep flowing (the bug)"
    );
    assert!(
        pool.is_live(),
        "mismatched revoke leaves the pooled socket LIVE"
    );

    // BOTH consumers exhibit the SAME silent no-op — a divergence in key shape
    // between register and revoke is a cross-consumer guardrail failure.
    assert_eq!(nft_severed, 0);
    assert_eq!(proxy_severed, 0);
}

// ---- (c) parity — pin the canonical key shape ------------------------------

#[test]
fn parity_canonical_key_shape_is_pinned() {
    // The pinned canonical shape is the bare dotted-quad address — the exact
    // form the ds-nft `flush` test vectors and the §3 admission-map reverse
    // index use (e.g. "203.0.113.10"), NOT a host:port or CIDR rendering.
    assert_eq!(CANONICAL_KEY, "203.0.113.10");
    assert!(
        !CANONICAL_KEY.contains(':'),
        "the pinned key shape carries NO port — the §3 admission map keys on the \
         bare address"
    );
    assert!(
        !CANONICAL_KEY.contains('/'),
        "the pinned key shape is a single address, NOT a CIDR"
    );

    // The two consumers wrap the SAME pinned string into the SAME frozen DstKey.
    let nft_side = DstKey(CANONICAL_KEY.into());
    let proxy_side = DstKey(CANONICAL_KEY.into());
    assert_eq!(
        nft_side, proxy_side,
        "both consumers must mint an EQUAL DstKey from the pinned shape — \
         equality is the entire contract"
    );

    // And the pinned shape round-trips (severs) on both consumers — the positive
    // case, re-pinned to the canonical constant so a future shape change that
    // breaks parity fails HERE with the pin in view.
    assert!(nft_revoke(CANONICAL_KEY, CANONICAL_KEY) > 0);
    let (proxy_severed, _t, _p) = proxy_revoke(CANONICAL_KEY, CANONICAL_KEY);
    assert!(proxy_severed > 0);

    // Sanity: the mismatched shape is genuinely a DIFFERENT key (so the negative
    // test is testing a real divergence, not an accident of formatting).
    assert_ne!(DstKey(CANONICAL_KEY.into()), DstKey(MISMATCHED_KEY.into()));
}

// A compile-time witness, kept inert behind a never-called helper: the SAME
// `DstFilter::Only([key])` value drives BOTH frozen `FlushSession`
// implementations. If a future edit made the consumers disagree on the contract
// SIGNATURE (not just the key value), this stops compiling — the structural
// half of the cross-consumer guarantee.
#[allow(dead_code)]
fn both_consumers_share_the_frozen_signature() {
    fn drive<F: FlushSession>(f: &F, s: &SessionRef, filter: &DstFilter) {
        let _ = f.flush_session(s, filter, &LegSelector::sever_pair());
    }
    let filter = DstFilter::Only(vec![DstKey(CANONICAL_KEY.into())]);
    let nft = NftWriter::new(DstFilteringBackend::new(&[CANONICAL_KEY]));
    let proxy = SeveringRegistry::new();
    drive(&nft, &session(1), &filter);
    drive(&proxy, &session(1), &filter);
}
