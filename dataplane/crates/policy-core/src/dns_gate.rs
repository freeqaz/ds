//! The frozen ds-dnsgate verdict API — `evaluate(DnsQueryCtx) -> DnsVerdict`
//! (doc 11 §4 frozen column; policy-core README "Verdict API shape").
//!
//! This is the ONE seam ds-dnsgate's `RequestHandler` calls per query. The doc 11
//! §4 frozen verdict shape is:
//!
//! ```text
//! evaluate(DnsQueryCtx{session, qname, qtype, source})
//!   -> Verdict ∈ { Allow{admit, ttl_clamp} | Deny{rcode_policy} | Ask{prompt_ref} }
//! ```
//!
//! every verdict carrying POL-3 provenance (rule id, layer, policy version). This
//! module lands exactly that shape — as a thin DNS-gate-shaped PROJECTION over the
//! one engine the rest of policy-core already owns ([`crate::pol1_eval`] /
//! [`crate::consumer`]): it does NOT re-decide anything. [`evaluate`] routes the
//! single [`crate::consumer::dns_admission_decision`] verdict (which itself routes
//! the ONE [`crate::pol1_eval::evaluate_domain`]) into the gate-facing verdict
//! family, so a DNS admission can never disagree with the TLS connect or the NFT
//! allow-set derivation (POL-3: no consumer reimplements a rule).
//!
//! # Why a distinct verdict type from [`crate::consumer::Decision`]
//!
//! [`crate::consumer::Decision`] is the family-agnostic, three-surface consumer
//! projection (DNS / TLS / NFT). This module is the DNS-GATE-SPECIFIC frozen shape
//! doc 11 §4 names: it carries the two things the gate's wire authoring needs that a
//! generic `Decision` does not — the W2 `ttl_clamp` window on an admit (the clamped
//! TTL the gate answers the VM, doc 11 §3.1/W2) and the gate's `rcode_policy` /
//! `prompt_ref` discriminants (§3.2: Deny → NXDOMAIN, Ask → REFUSED). It is the
//! frozen NAME the gate's handler binds against; [`crate::consumer`] stays the
//! shared engine underneath.
//!
//! No hickory or pingora types cross this module (D67/D40): `DnsQueryCtx` carries
//! plain `String` / `u16` / `&str` only — never a hickory `Name`, `LowerQuery`, or
//! `RecordType` — so the gate's documented raw-tokio fallback (doc 11 §2) stays a
//! library migration, and the verdict API is engine-agnostic by construction.

use crate::consumer::{dns_admission_decision, DecisionKind};
use crate::pol1_eval::{ComposedPolicy, Provenance};
use ds_contracts::pol1::Rung;

/// The frozen DNS query context the gate hands the evaluator (doc 11 §4:
/// `DnsQueryCtx{session, qname, qtype, source}`). Plain `std`/`String` types only —
/// no hickory type appears, so the seam is engine-agnostic (D67).
///
/// The gate's `handler/` destructures a hickory `Request` into this at the listen
/// boundary; the evaluator never sees a hickory wire type (doc 11 §8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQueryCtx {
    /// The interface-anchored session identity (doc 11 §5.1, D44): the never-recycled
    /// per-session tap join key the gate resolved from the redirect's interface
    /// signal, NEVER a raw source IP. A `String` so the seam carries the tap name /
    /// session record id, not a network address the attribution rule forbids keying on.
    pub session: String,
    /// The resolved query name (lower-cased, trailing-dot FQDN form), the name
    /// policy evaluates and the name the client presents in SNI (doc 11 §3.1, W3:
    /// admission is keyed on the ORIGINAL query name).
    pub qname: String,
    /// The queried record type as its IANA numeric code (1 = A, 28 = AAAA, ...). A
    /// `u16`, never a hickory `RecordType`, keeps the seam engine-agnostic.
    pub qtype: u16,
    /// The query source as a plain string (the per-session tap / source descriptor).
    /// Carried for the §5.1 three-keys disambiguation and LOG-1 attribution; it is
    /// NEVER the sole attribution key (that is `session`, the interface-anchored id).
    pub source: String,
}

/// The admit payload of an [`DnsVerdict::Allow`] (doc 11 §4 `Allow{admit, ttl_clamp}`).
///
/// `admit` is the W1 obligation flag: an allow MUST be admitted (NFT set element +
/// DNS-2b map entry made visible) before the answer leaves (doc 11 §3.1/W1). At THIS
/// unit — the policy-verdict seam — admission (the insert-then-answer transaction) is
/// the separate `txn/` unit, so `admit` is the recorded OBLIGATION the gate carries
/// into that transaction, not the transaction itself. `ttl_clamp` is the W2 clamp
/// WINDOW the gate answers the VM with (doc 11 §3.1: "answer the VM (clamped TTL)").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admit {
    /// The W2 TTL clamp floor (seconds) — the admission TTL is never shorter than
    /// this (doc 11 §3.1/W2; the POL-1 `ttl_floor` policy value).
    pub ttl_floor: u32,
    /// The W2 TTL clamp ceiling (seconds) — the admission TTL is never longer than
    /// this (doc 11 §3.1/W2; the POL-1 `ttl_ceil` policy value).
    pub ttl_ceil: u32,
}

impl Admit {
    /// Clamp a chain-minimum upstream TTL into the W2 admission window
    /// `clamp(chain_min_ttl, FLOOR, CEIL)` (doc 11 §3.1/W2/§8.3 step 1). This is the
    /// TTL the gate answers the VM WITHOUT grace (the GRACE is added only to the
    /// kernel/map deadline, not the wire TTL — W2). A pure function so the clamp is
    /// the same value the `txn/` unit computes its deadline base from.
    pub fn clamp_ttl(&self, chain_min_ttl: u32) -> u32 {
        chain_min_ttl.clamp(self.ttl_floor, self.ttl_ceil)
    }
}

/// The policy rcode an [`DnsVerdict::Deny`] authors on the wire (doc 11 §3.2 / §4
/// `Deny{rcode_policy}`). The gate's `respond/` maps this to the frozen §3.2 shape;
/// it is NEVER a SERVFAIL (SERVFAIL is reserved for genuine ds-dnsgate failure, doc
/// 11 §3.2: "SERVFAIL is never a policy verdict").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcodePolicy {
    /// **NXDOMAIN** (RCODE 3) — the doc 11 §3.2 hard-deny shape: empty answer
    /// section, an authored signature SOA in authority, EDE 15 when the query
    /// carried OPT. The frozen hard-deny wire answer (D71).
    NxDomain,
}

/// An opaque reference to the ask-user prompt an [`DnsVerdict::Ask`] travels (doc 11
/// §4 `Ask{prompt_ref}` / §3.2: the prompt rides the Stage-0 ask-user seam, D18).
///
/// The wire answer for an Ask is an immediate **REFUSED** (doc 11 §3.2) — the
/// prompt_ref is the join key onto the D18 seam, NOT a wire field. At this unit the
/// ask-user seam itself is the separate D18 unit, so the ref carries the
/// session-scoped prompt identity (`session`/`qname` derived) the seam keys off; the
/// gate emits the REFUSED here and the prompt over the seam there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptRef {
    /// The interface-anchored session the prompt is scoped to (approvals return as
    /// session-scoped TTL'd grants on the policy stream, doc 11 §5.5).
    pub session: String,
    /// The qname the prompt asks the human to approve.
    pub qname: String,
}

/// The frozen ds-dnsgate verdict (doc 11 §4 frozen column / policy-core README):
/// `Verdict ∈ {Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}`, every
/// arm carrying POL-3 [`Provenance`] (rule id, layer, policy version) — missing
/// provenance fails CI (doc 11 §6.7). The gate's `handler/` binds against THIS.
///
/// The `InertCapabilityGated` engine state (§1.7: a capability-gated entry admits
/// NOTHING until its capability lands) is FOLDED into `Deny` here — on the DNS wire
/// an inert entry is indistinguishable from a policy deny (it admits nothing, so it
/// gets the §3.2 NXDOMAIN hard-deny shape), and its provenance carries the inert
/// rule id so a LOG-1 join can still tell it apart. The DNS gate has no fourth wire
/// shape for inertness; the distinction lives in provenance, not the rcode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsVerdict {
    /// Admit the flow: forward, scrub, transact (W1), answer the VM the clamped TTL
    /// (W2). Carries the W1 admit obligation + W2 `ttl_clamp` window and provenance.
    Allow {
        /// The W1 admit obligation + W2 `ttl_clamp` window (doc 11 §4 `Allow{admit,
        /// ttl_clamp}`).
        admit: Admit,
        /// POL-3 provenance: matched rule id + composing layer + policy version.
        provenance: Provenance,
    },
    /// Deny the flow: author the §3.2 `rcode_policy` wire shape (NXDOMAIN + signature
    /// SOA + EDE 15 iff OPT), no admission. Carries the D53 rung the deny was reached
    /// at (the §5 severing predicate) and provenance.
    Deny {
        /// The §3.2 wire rcode the gate authors (doc 11 §4 `Deny{rcode_policy}`).
        rcode_policy: RcodePolicy,
        /// The D53 rung the deny carries (`None` = no explicit rule rung); drives
        /// the §5 revocation severing predicate ([`DnsVerdict::severs_established_flows`]).
        rung: Option<Rung>,
        /// POL-3 provenance.
        provenance: Provenance,
    },
    /// Ask the user: author an immediate **REFUSED** (doc 11 §3.2), travel the prompt
    /// over the D18 ask-user seam. Carries the `prompt_ref` + provenance.
    Ask {
        /// The ask-user prompt reference (doc 11 §4 `Ask{prompt_ref}`).
        prompt_ref: PromptRef,
        /// POL-3 provenance.
        provenance: Provenance,
    },
}

impl DnsVerdict {
    /// The POL-3 provenance every verdict carries (doc 11 §6.7: present on every
    /// path, CI-fatal if missing).
    pub fn provenance(&self) -> &Provenance {
        match self {
            DnsVerdict::Allow { provenance, .. }
            | DnsVerdict::Deny { provenance, .. }
            | DnsVerdict::Ask { provenance, .. } => provenance,
        }
    }

    /// Whether this verdict ADMITS the flow (only [`DnsVerdict::Allow`]). An inert
    /// capability-gated entry folds into `Deny` here, so it correctly does NOT admit
    /// (doc 11 §1.7 inertness).
    pub fn admits(&self) -> bool {
        matches!(self, DnsVerdict::Allow { .. })
    }

    /// Whether this verdict, applied as a revocation, severs established flows (doc 11
    /// §5.4 / D53 rule 6): true iff it is a `Deny` at a block-or-higher rung. An
    /// `Allow` / `Ask` never severs; a deny with no explicit rung gates new flows only.
    pub fn severs_established_flows(&self) -> bool {
        match self {
            DnsVerdict::Deny { rung, .. } => rung.map(Rung::is_block_or_higher).unwrap_or(false),
            _ => false,
        }
    }
}

/// The frozen ds-dnsgate verdict evaluation (doc 11 §4 / policy-core README):
/// `evaluate(DnsQueryCtx{session, qname, qtype, source}) -> DnsVerdict`.
///
/// It is a thin PROJECTION over the one shared engine — it routes the single
/// [`dns_admission_decision`] verdict (itself the one [`crate::pol1_eval::evaluate_domain`])
/// into the gate-facing [`DnsVerdict`] family, so no rule is re-evaluated (POL-3).
/// The `ctx.qtype` does not change the policy verdict in v0 (admission is keyed on
/// the name, doc 11 §3.1/W3 — the AAAA/HTTPS scrub is a record-type behavior in the
/// gate's `scrub/`, not a policy verdict); it rides the ctx so the LOG-1 event and a
/// future qtype-sensitive rule have it. The `admit` window's `ttl_floor`/`ttl_ceil`
/// are the POL-1 W2 policy VALUES (`tunables`), threaded through so the gate answers
/// the clamped TTL off policy, never a code constant.
pub fn evaluate(policy: &ComposedPolicy, ctx: &DnsQueryCtx, admit: Admit) -> DnsVerdict {
    // The gate's qname is the wire FQDN — trailing-dot form (hickory `Name`s carry
    // the root dot). The POL-1 document keys domains in hostname form (no trailing
    // dot), so the projection normalizes the single trailing dot before the engine
    // lookup. This is the ONLY normalization: case is already lower-cased by the
    // gate's `listen/` destructure (doc 11 §8.1), and W3 keeps admission keyed on the
    // original (un-CNAME-chased) name — normalization touches only the root-dot form,
    // never the labels.
    let lookup_name = ctx.qname.strip_suffix('.').unwrap_or(&ctx.qname);
    let decision = dns_admission_decision(policy, lookup_name);
    let provenance = decision.provenance;
    match decision.kind {
        DecisionKind::Admit => DnsVerdict::Allow { admit, provenance },
        DecisionKind::Deny => DnsVerdict::Deny {
            rcode_policy: RcodePolicy::NxDomain,
            rung: decision.rung,
            provenance,
        },
        // §1.7 inertness folds into the §3.2 NXDOMAIN hard-deny on the DNS wire: an
        // inert entry admits NOTHING, so it is a deny on the wire. The provenance
        // (the inert rule id) is the only place the LOG-1 join sees the distinction;
        // there is no fourth DNS wire shape. The rung is `None` (an inert entry has
        // no explicit deny rung — it is not a policy block, it severs nothing).
        DecisionKind::InertCapabilityGated { .. } => DnsVerdict::Deny {
            rcode_policy: RcodePolicy::NxDomain,
            rung: None,
            provenance,
        },
        DecisionKind::Ask => DnsVerdict::Ask {
            prompt_ref: PromptRef {
                session: ctx.session.clone(),
                qname: ctx.qname.clone(),
            },
            provenance,
        },
    }
}

#[cfg(test)]
mod tests;
