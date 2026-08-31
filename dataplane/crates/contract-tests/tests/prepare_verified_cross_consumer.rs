// SPDX-License-Identifier: Apache-2.0

//! Cross-consumer `prepare_verified` UNIFORMITY conformance test (POL-4 part 2;
//! D72/D120, doc 13 §5.1) — security-relevant.
//!
//! loop-2 (credswapfu2) made [`ds_contracts::consumer::Consumer::prepare_verified`]
//! the NON-VACUOUS identity gate in all THREE host-side policy consumers:
//! verify-the-SEPARATELY-transported-hash-BEFORE-parse, NACK
//! [`PrepareError::HashMismatch`] fail-closed (the parse / stage / admission-map /
//! allow-set step NEVER runs on a hash-failing snapshot, and the consumer stays on
//! `vN`). The hash is non-vacuous because it is supplied SEPARATELY by the producer
//! and transported ALONGSIDE the bytes — re-hashing the bytes and comparing to their
//! own hash could never NACK.
//!
//! This file proves, ACROSS ALL THREE consumers at once, that they reject the SAME
//! transported-hash mismatch IDENTICALLY (`HashMismatch` fail-closed) and accept the
//! SAME matching hash IDENTICALLY (stage). It drives:
//!
//! - **ds-tlsproxy** (`apply::PolicyConsumer`) — the REAL enforcer consumer, via its
//!   PUBLIC `prepare_verified` override directly;
//! - **ds-dnsgate** (`apply::PolicyConsumer`) — the REAL admitter consumer, via its
//!   PUBLIC `prepare_verified` override directly;
//! - **the ds-nft programmer** — via its LIVE-INGEST entrypoint
//!   [`ds_nft::ingest::ingest_snapshot`], which threads the transported `content_hash`
//!   into `prepare_verified` exactly as the host fan-out does. (The ds-nft
//!   `apply::PolicyConsumer` is seeded only from WITHIN its own crate — its
//!   `RulesetSource` has no public constructor — so the ds-nft leg drives the SAME
//!   frozen seam through the public entrypoint over a `Consumer`; a parse-panicking
//!   consumer proves the verify SHORT-CIRCUITS before parse on a mismatch, the exact
//!   fail-closed property the two real consumers exhibit.)
//!
//! D76 frozen non-edge: this crate is the only place that may depend on all three
//! consumers at once (doc 12 §4.2, doc 14 §5). It adds NO edge between any two
//! consumer crates — each remains ignorant of the others; only this downstream
//! test-only member links them to assert the cross-consumer uniformity.
//!
//! NEVER-LOG-THE-SECRET: this test mints only synthetic POL-1 text fixtures and never
//! logs snapshot bytes.

use ds_contracts::consumer::{ApplyError, ApplyToken, Consumer, PolicyVersion, PrepareError};
use ds_contracts::pol1::{self, PolicyLayer};
use ds_contracts::snapshot_verify::{sha256, ContentHash};

use ds_dnsgate::apply::{Evaluator as DnsEvaluator, PolicyConsumer as DnsConsumer};
use ds_nft::ingest::{ingest_snapshot, NftSnapshotIngest};
use ds_tlsproxy::apply::{Evaluator as TlsEvaluator, PolicyConsumer as TlsConsumer};

/// A clean POL-1 session document — parses with zero PolicyErrors (so the consumers
/// seed cleanly and a MATCHING-hash prepare_verified stages rather than schema-NACKs).
const BOOT_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                        dns:\n  boundary_zone: corp.example.\n";

/// The `vN+1` document the host fans out — distinct from the boot doc, so a stage is a
/// real version change. Parses cleanly, so a MATCHING transported hash stages.
const NEXT_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                        dns:\n  boundary_zone: next.example.\n";

/// The version (`vN+1` seq) the conformance round drives — the SAME seq across all
/// three consumers (one monotonic policy version, no per-service namespace; D72).
const VN1: PolicyVersion = PolicyVersion(2);

fn boot_layer() -> PolicyLayer {
    pol1::parse_layer(BOOT_DOC).expect("boot doc parses with zero PolicyErrors")
}

fn dns_consumer() -> DnsConsumer {
    DnsConsumer::new(DnsEvaluator::from_layer(&boot_layer()), PolicyVersion(1))
}

fn tls_consumer() -> TlsConsumer {
    TlsConsumer::new(TlsEvaluator::from_layer(&boot_layer()), PolicyVersion(1))
}

/// The matching transported hash for `NEXT_DOC` (the producer-pinned `content_hash`
/// over those exact bytes) and a TAMPERED one that does NOT match the bytes.
fn next_bytes() -> &'static [u8] {
    NEXT_DOC.as_bytes()
}
fn matching_hash() -> ContentHash {
    sha256(next_bytes())
}
fn tampered_hash() -> ContentHash {
    let mut h = sha256(next_bytes());
    h[0] ^= 0x01; // one flipped byte → no longer hashes the bytes
    h
}

// ----------------------------------------------------------------------------
// The ds-nft leg: a Consumer driven through the LIVE-INGEST entrypoint.
//
// `PanicOnParse` proves the verify-before-parse SHORT-CIRCUIT: its `prepare`
// (parse / stage / allow-set re-derive) PANICS, so a `HashMismatch` returned by
// `ingest_snapshot` proves the gate NACKed BEFORE entering parse — the exact
// fail-closed property the two real consumers exhibit. It inherits the FROZEN
// `prepare_verified` default from ds-contracts (the single-source gate), so this
// drives the same verify-before-parse contract the host fan-out routes into.
// ----------------------------------------------------------------------------

struct PanicOnParse;

impl Consumer for PanicOnParse {
    fn prepare(
        &self,
        _snapshot: &[u8],
        _version: PolicyVersion,
    ) -> Result<ApplyToken, PrepareError> {
        panic!("parse/stage (allow-set re-derive) must NOT run past the verify gate on a hash mismatch");
    }
    fn commit(&self, _token: &ApplyToken) -> Result<(), ApplyError> {
        unreachable!()
    }
    fn sweep_and_advance_applied_seq(
        &self,
        _token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError> {
        unreachable!()
    }
}

/// A Consumer that STAGES on any verified bytes — proves the ds-nft ingest entrypoint
/// forwards a MATCHING-hash snapshot into parse/stage (the happy path), so the ds-nft
/// leg's accept case is exercised, not just its NACK case.
#[derive(Default)]
struct StagingConsumer {
    staged: std::sync::Mutex<Option<ApplyToken>>,
}

impl Consumer for StagingConsumer {
    fn prepare(&self, snapshot: &[u8], version: PolicyVersion) -> Result<ApplyToken, PrepareError> {
        let token = ApplyToken::new(version, sha256(snapshot));
        *self.staged.lock().unwrap() = Some(token.clone());
        Ok(token)
    }
    fn commit(&self, _token: &ApplyToken) -> Result<(), ApplyError> {
        unreachable!()
    }
    fn sweep_and_advance_applied_seq(
        &self,
        _token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError> {
        unreachable!()
    }
}

// ---- (a) the NACK uniformity: all three reject the SAME transported-hash mismatch --

#[test]
fn all_three_consumers_reject_the_same_transported_hash_mismatch_fail_closed() {
    let bytes = next_bytes();
    let wrong = tampered_hash();

    // ds-tlsproxy (REAL enforcer): prepare_verified on the tampered hash → HashMismatch,
    // and the consumer stays on vN (applied_seq untouched).
    let tls = tls_consumer();
    match tls.prepare_verified(bytes, VN1, &wrong) {
        Err(PrepareError::HashMismatch { version }) => assert_eq!(version, VN1),
        other => panic!("ds-tlsproxy: expected HashMismatch, got {other:?}"),
    }
    assert_eq!(
        tls.applied_seq(),
        PolicyVersion(1),
        "ds-tlsproxy stays on vN after a HashMismatch NACK"
    );

    // ds-dnsgate (REAL admitter): same fail-closed HashMismatch, stays on vN.
    let dns = dns_consumer();
    match dns.prepare_verified(bytes, VN1, &wrong) {
        Err(PrepareError::HashMismatch { version }) => assert_eq!(version, VN1),
        other => panic!("ds-dnsgate: expected HashMismatch, got {other:?}"),
    }
    assert_eq!(
        dns.applied_seq(),
        PolicyVersion(1),
        "ds-dnsgate stays on vN after a HashMismatch NACK"
    );

    // ds-nft (via the LIVE-INGEST entrypoint): the SAME tampered (bytes, wrong_hash)
    // threaded through ingest_snapshot → HashMismatch, and PanicOnParse proves the
    // parse/stage/allow-set re-derive behind the gate is NEVER entered.
    let nft_ingest = NftSnapshotIngest::new(VN1.seq(), wrong, bytes.to_vec());
    match ingest_snapshot(&PanicOnParse, &nft_ingest) {
        Err(PrepareError::HashMismatch { version }) => assert_eq!(version, VN1),
        other => panic!("ds-nft: expected HashMismatch, got {other:?}"),
    }

    // The uniformity statement: the THREE consumers map the SAME transported-hash
    // mismatch onto the SAME structural reason (HashMismatch) at the SAME version.
    // (Asserted per-consumer above; this is the cross-consumer guarantee the test
    // exists to pin — a divergence would be a guardrail failure.)
}

// ---- (b) the ACCEPT uniformity: all three STAGE the SAME matching transported hash --

#[test]
fn all_three_consumers_stage_the_same_matching_transported_hash() {
    let bytes = next_bytes();
    let good = matching_hash();

    // ds-tlsproxy: a matching hash verifies + stages (token pins the verified hash),
    // and the consumer stays on vN (stage, never flip — applied_seq unchanged).
    let tls = tls_consumer();
    let tls_token = tls
        .prepare_verified(bytes, VN1, &good)
        .expect("ds-tlsproxy stages a matching hash");
    assert_eq!(tls_token.version(), VN1);
    assert_eq!(tls_token.content_hash, good);
    assert_eq!(
        tls.applied_seq(),
        PolicyVersion(1),
        "ds-tlsproxy stages, never flips"
    );

    // ds-dnsgate: same — verifies + stages on the matching hash, stays on vN.
    let dns = dns_consumer();
    let dns_token = dns
        .prepare_verified(bytes, VN1, &good)
        .expect("ds-dnsgate stages a matching hash");
    assert_eq!(dns_token.version(), VN1);
    assert_eq!(dns_token.content_hash, good);
    assert_eq!(
        dns.applied_seq(),
        PolicyVersion(1),
        "ds-dnsgate stages, never flips"
    );

    // ds-nft (via the entrypoint): the matching hash forwards into parse/stage and the
    // staging consumer records the SAME (version, content_hash) identity token.
    let staging = StagingConsumer::default();
    let nft_ingest = NftSnapshotIngest::new(VN1.seq(), good, bytes.to_vec());
    let nft_token = ingest_snapshot(&staging, &nft_ingest).expect("ds-nft stages a matching hash");
    assert_eq!(nft_token.version(), VN1);
    assert_eq!(nft_token.content_hash, good);
    assert_eq!(staging.staged.lock().unwrap().as_ref(), Some(&nft_token));

    // Uniformity: all three minted the SAME identity token (version + verified hash)
    // off the SAME matching transported hash.
    assert_eq!(tls_token, dns_token);
    assert_eq!(dns_token, nft_token);
}

// ---- (c) the gate is NON-VACUOUS: the same bytes pass with the right hash and ------
//          fail with the wrong hash, on EACH consumer (the property that makes the
//          separately-transported hash matter — re-hashing the bytes could never NACK).

#[test]
fn the_gate_is_non_vacuous_same_bytes_accept_on_match_reject_on_mismatch() {
    let bytes = next_bytes();
    let good = matching_hash();
    let wrong = tampered_hash();
    // The wrong hash is genuinely a DIFFERENT value (so the negative case is real).
    assert_ne!(
        good, wrong,
        "the tampered hash must differ from the matching hash"
    );

    // ds-tlsproxy: same bytes → Ok with `good`, HashMismatch with `wrong`.
    let tls = tls_consumer();
    assert!(tls.prepare_verified(bytes, VN1, &good).is_ok());
    assert!(matches!(
        tls_consumer().prepare_verified(bytes, VN1, &wrong),
        Err(PrepareError::HashMismatch { .. })
    ));

    // ds-dnsgate: same.
    let dns = dns_consumer();
    assert!(dns.prepare_verified(bytes, VN1, &good).is_ok());
    assert!(matches!(
        dns_consumer().prepare_verified(bytes, VN1, &wrong),
        Err(PrepareError::HashMismatch { .. })
    ));

    // ds-nft (via the entrypoint): same bytes → stages with `good`, HashMismatch with
    // `wrong`. The staging consumer accepts the match; PanicOnParse proves the mismatch
    // short-circuits before parse.
    let good_ingest = NftSnapshotIngest::new(VN1.seq(), good, bytes.to_vec());
    assert!(ingest_snapshot(&StagingConsumer::default(), &good_ingest).is_ok());
    let wrong_ingest = NftSnapshotIngest::new(VN1.seq(), wrong, bytes.to_vec());
    assert!(matches!(
        ingest_snapshot(&PanicOnParse, &wrong_ingest),
        Err(PrepareError::HashMismatch { .. })
    ));
}

// A compile-time witness, kept inert behind a never-called helper: the SAME public
// `prepare_verified` signature drives BOTH real consumers (and the ds-nft entrypoint
// threads into the same seam). If a future edit made the consumers disagree on the
// frozen seam SIGNATURE, this stops compiling — the structural half of the guarantee.
#[allow(dead_code)]
fn all_consumers_share_the_frozen_prepare_verified_signature() {
    fn drive<C: Consumer>(c: &C, bytes: &[u8], v: PolicyVersion, h: &ContentHash) {
        let _ = c.prepare_verified(bytes, v, h);
    }
    let h = matching_hash();
    drive(&tls_consumer(), next_bytes(), VN1, &h);
    drive(&dns_consumer(), next_bytes(), VN1, &h);
    drive(&StagingConsumer::default(), next_bytes(), VN1, &h);
}
