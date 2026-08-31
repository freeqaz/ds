//! policy-core — THE one policy evaluation engine (doc 14 §6 crate map).
//!
//! Skeleton stub: doc-comment only, no items. Code lands per the doc 09 POL-1..5
//! steps; the frozen invariants live in this crate's README.md and may not be
//! renegotiated by implementation.
//!
//! When built, this crate holds (doc 14 §6):
//! - the single evaluator embedded in ds-dnsgate, ds-tlsproxy, and the NFT
//!   programming path (POL-3 — no consumer reimplements a rule);
//! - verdict types (`DnsQueryCtx -> Verdict ∈ {Allow{admit, ttl_clamp},
//!   Deny{rcode_policy}, Ask{prompt_ref}}`) carrying POL-3 provenance
//!   (rule id, policy layer, policy version) on every verdict;
//! - the `SecretMatcher` trait + frozen verdict semantics
//!   `{Pass, Hold, Block, Flag, Redact-reserved}` with the hold-back invariant
//!   (D73; doc 12 §5.1) — engines are free behind the trait.
//!
//! Landed so far:
//! - [`secret_matcher`] freezes the TLS-7 `SecretMatcher` trait, the `Verdict`
//!   enum, provenance/plane types, and the fail-mode legality rule (D73, doc 12
//!   §5.1–§5.2);
//! - [`pol1_eval`] is the POL-1 v0 evaluator: it consumes the
//!   [`ds_contracts::pol1`] schema types (the schema, reader, and parse-time
//!   validators live in ds-contracts per doc 13 §1 rule 1), composes a layer
//!   stack with deny-overrides (§1.2), and evaluates a domain query to a verdict
//!   carrying POL-3 provenance — with capability-gate inertness (§1.7: a
//!   `requires:` entry whose capability is absent admits nothing). This is the
//!   consumer side of the §7 parse→evaluate round-trip; the `ds-contracts` path
//!   dep that doc 14 §6 anticipated lands with it.
//! - [`consumer`] is the consumer-facing decision API on top of [`pol1_eval`]:
//!   the three query surfaces each embedder needs — a DNS admission query
//!   (ds-dnsgate), a TLS/egress-gateway connect decision (ds-tlsproxy), and the
//!   NFT ruleset-derivation inputs (the NFTables programmer) — all routing the ONE
//!   [`pol1_eval::evaluate_domain`] verdict (doc 13 §1.1: no consumer reimplements
//!   a rule). It surfaces the composed-document host-snapshot carry (rule 2), the
//!   single policy-version namespace (rule 3), mandatory provenance on every
//!   decision (rule 4), tunables as policy values (rule 5), the D53 rung +
//!   `is_block_or_higher` severing predicate on every decision (rule 6), and
//!   expiry-is-not-revocation semantics (rule 8). It does NOT re-derive
//!   composition, deny-overrides, or the capability gate — those stay in
//!   [`pol1_eval`].
//! - [`dns_gate`] is the FROZEN ds-dnsgate verdict API (doc 11 §4 frozen column /
//!   this crate's README "Verdict API shape"): `evaluate(DnsQueryCtx{session,
//!   qname, qtype, source}) -> DnsVerdict ∈ {Allow{admit, ttl_clamp},
//!   Deny{rcode_policy}, Ask{prompt_ref}}`, every arm carrying POL-3 provenance. It
//!   is a thin DNS-gate-shaped PROJECTION over [`consumer::dns_admission_decision`]
//!   (which routes the ONE [`pol1_eval::evaluate_domain`]) — it re-decides nothing,
//!   so a DNS admission can never disagree with the TLS connect or the NFT allow-set
//!   derivation (POL-3). It is the name ds-dnsgate's `RequestHandler` binds against;
//!   no hickory type crosses it (D67).
//! - [`role`] is the `role/v0` machine validator (doc 18 §5/§7/§11): a stdlib-only
//!   reader + the parse-time rejection set (raw credential material and
//!   pass-through entries are refused at parse, D39/D74) + `role_content_hash`.
//!   The rung-cap check DELEGATES to the doc 13 §7 suite
//!   ([`ds_contracts::pol1::validate_layer`]) by projecting the role's axis (c)
//!   into a session-layer document — one rung-cap machinery, not two — and
//!   `role_content_hash` rides the SAME canonical-serialization machinery the
//!   PolicySnapshot `content_hash` uses ([`ds_contracts::snapshot_verify::sha256`]
//!   over a produce-once RFC 8785 (JCS) payload; doc 18 §7, "one spec, not two").
//!   The `roles/` tree owns the documents; this is the validation code path doc 18
//!   §5 routes here because axis (c) needs policy-core.
//!
//! The frozen DNS-gate verdict shape (`DnsQueryCtx -> DnsVerdict`) now lands in
//! [`dns_gate`] as a projection over the POL-1 engine; the rest of the HTTP-side
//! POL-2..5 evaluator surface is still skeleton.

pub mod consumer;
pub mod dns_gate;
pub mod pol1_eval;
pub mod role;
pub mod secret_matcher;
