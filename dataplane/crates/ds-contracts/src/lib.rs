//! ds-contracts — the single home for everything two or more services must
//! agree on (doc 14 §6 crate map).
//!
//! This crate defines *shapes*; it decides nothing (evaluation logic is
//! `policy-core`). It holds the cross-service contracts the boundary stack must
//! agree on at compile time rather than by review:
//!
//! - [`mark`] — the D76 32-bit mark-space layout: magic/leg/index bit fields,
//!   [`mark::DS_MARK_MASK`], and compose/decompose helpers (doc 14 §5);
//! - [`flush`] — the `flush_session(session, dst_filter, legs)` SIGNATURE only;
//!   the implementation lives in `ds-nft` (doc 14 §5, §6);
//! - [`reject`] — [`reject::RejectReason`], distinguishing `QUIC_BLOCKED` from
//!   generic default-deny (D70);
//! - [`session`] — [`session::SessionRef`], the D66/D44 join-key quartet
//!   (doc 14 §2/§4);
//! - [`conn_origin`] — the frozen mechanism-agnostic [`conn_origin::ConnOrigin`]
//!   recovery seam the transparent path resolves at accept time (D69, doc 09 §3
//!   NFT-2): kernel-sourced `original_dst`, interface-anchored `session`,
//!   recovery-failure-refuses — the TLS-1 `allow = f(session, sni, original_dst)`
//!   tuple and the D70 QUIC carveout's clean lane;
//! - [`dns_admission`] — the DNS-2b versioned admission-map API skeleton:
//!   [`dns_admission::AdmissionType`], the versioned map, and the per-session
//!   IP↔domain reverse index, from day one (doc 14 §3);
//! - [`dns_soa`] — the D71 SOA MNAME signature-name constant (doc 14 §8,
//!   doc 11 §3.2);
//! - [`flow`] — the FROZEN LOG-1 `FlowRecord` shape (doc 09 §3 NFT-5, doc 14
//!   §2/§5): the NFT-5 kernel-flow field set ([`flow::FlowRecord`],
//!   [`flow::FlowLifecycle`], [`flow::Proto`]) and its two deterministic
//!   renderings (the composed `ct mark` token + the on-disk payload). The
//!   `ds-telemetry` conventions layer maps kernel text onto this shape and owns
//!   the `EventEnvelope` emission — the carrier is here, the mapping is there;
//! - [`nft_lint`] — the NFT-1 mark-discipline lint (doc 14 §5): the constants
//!   are the source of truth the `artifacts/nft/` rulesets are checked against
//!   in CI.
//! - [`consumer`] — the FROZEN D72 two-phase apply seam (POL-4 part 2, doc 13
//!   §5, doc 15 §5.2): the [`consumer::Consumer`] trait the host agent's apply
//!   driver invokes and the three consumers (ds-dnsgate / ds-tlsproxy / `ds-nft`)
//!   implement — `prepare` (validate + stage while serving vN) → `commit`
//!   (atomic admitter-last flip) → `sweep_and_advance_applied_seq` (post-commit
//!   revocation sweep through the shared [`flush`] primitive, applied_seq
//!   advancing LAST). The single-source Rust counterpart of the Go
//!   `hostagent.ConsumerBarrier`/`Sweeper` seam — no per-service re-declaration.
//! - [`snapshot_verify`] — the VERIFY-ONLY consumer side of the snapshot
//!   `content_hash` (doc 13 §5.1, D120): hash the transported bytes
//!   ([`snapshot_verify::sha256`], hand-rolled, zero-dep), compare to the
//!   identity-tuple hash, NACK host-wide on mismatch
//!   ([`snapshot_verify::verify_snapshot_bytes`]), then parse — NEVER
//!   re-serialize. The Go `nftbridge` producer pins the bytes; this side
//!   verifies the byte-identical golden fixture without re-canonicalizing.
//! - [`scopes`] — D127 token scope taxonomy (doc 23 §6): the eight `v1:` scope
//!   strings that `dreamserpent.auth.v1` sub-tokens carry; used by the TLS
//!   proxy `tls_connect_decision` admission gate (`v1:network:egress`).
//! - [`pol1`] — the POL-1 v0 policy schema (doc 13 §1–§3, §7): the schema types,
//!   the stdlib-only document reader ([`pol1::parse_layer`]), the tunable-default
//!   constants, and the parse-time structural validators (rung-cap, fail-open
//!   legality, bare-CIDR, and mandatory-provenance rejections — §8.1). The
//!   `policy-core` evaluator consumes these types for the §7 parse→evaluate
//!   round-trip; address fields reuse [`dns_admission::AdmittedAddr`] (D75).
//!
//! Not yet here, by design:
//! - **Generated protos.** The Stage-0 proto freeze is one-shot (doc 14 §1);
//!   generated LOG-1 + digest-feed + control-plane code lands under `src/gen/`
//!   ONLY via freeze PRs driven from `proto/buf.gen.yaml`. `src/gen/` does not
//!   exist until then.
//!
//! FROZEN RULE (doc 14 §6): no hickory or pingora types ever cross this crate —
//! neither in its API nor its dependency graph (D67/D40). `[dependencies]` is
//! empty; the crate is `#![no_std]`-clean apart from the few `std` collection
//! types named in [`dns_admission`].

#![forbid(unsafe_code)]

pub mod conn_origin;
pub mod consumer;
pub mod dns_admission;
pub mod dns_soa;
pub mod flow;
pub mod flush;
pub mod mark;
pub mod nft_lint;
pub mod pol1;
pub mod reject;
pub mod scopes;
pub mod session;
pub mod snapshot_verify;
