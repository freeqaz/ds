//! The service-internal ASK-USER seam (doc 09 §4 DNS-3; doc 11 §3.2/§5.5; doc 14 §2b;
//! D18/D53/D77).
//!
//! # What this is
//!
//! When the policy verdict is `Ask` (an unknown-domain posture), the gate authors an
//! immediate **REFUSED** on the DNS wire (no cacheable negative signal — doc 11 §3.2) AND
//! emits a **one-way `AskUserRequest` notification** boundary → orchestrator over THIS
//! seam (doc 14 §2b). The VM is NEVER suspended (doc 09 §4 DNS-3: "the VM is not
//! suspended; the agent experiences a normal DNS failure and keeps running"). An approval,
//! when it arrives, returns ONLY as a session-scoped, TTL'd allow grant on the
//! ALREADY-FROZEN policy stream (the D72 `WatchPolicies` feed → a `PolicyCorePolicy`
//! reload), so the next DNS retry resolves — there is **no second response contract** on
//! this seam (doc 14 §2b; POL-5).
//!
//! # Why a service-internal seam, not the boundary.v1 proto type
//!
//! `proto/dreamserpent/boundary/v1/ask.proto` freezes the WIRE `AskUserRequest`
//! (boundary → orchestrator). The gate's `DnsEvent` is deliberately service-internal and
//! `ds-contracts`/proto-free (the D67 corollary; the LOG-1 Stage-0 freeze is a SEPARATE
//! seam) — and the same discipline holds here: [`AskUserRequest`] below is a
//! hickory-free, proto-free MIRROR of the frozen proto field set
//! (`session` / `resource_kind` / `resource_name` / POL-3 `matched_rule_id` /
//! `policy_layer` / `policy_version`), so the emission SITE exists and is testable at the
//! pre-stage ahead of the proto wiring. [`AskUserSink`] mirrors the [`crate::event::
//! EventSink`] discipline exactly: one method, no async, no hickory type — the production
//! orchestrator transport replaces the impl WITHOUT touching the handler emission site.
//!
//! # Attendedness downgrade (D53 as revised by D77)
//!
//! D77 (revising D53) narrows the unknown-domain handling by ATTENDEDNESS:
//!   * **Attended** session → the human is notified async (the `AskUserRequest`); the
//!     DNS layer authors REFUSED, the post-approval retry succeeds. (The 30–60 s
//!     socket-hold that gives the human a real-time window is the TLS-1 mechanism — "DNS
//!     itself cannot hold a query, so denial-then-retry is the DNS layer's contribution
//!     to that flow", doc 09 §4 DNS-3. The DNS gate's job is the REFUSED + the notify.)
//!   * **Unattended** session → unknown-domain is DOWNGRADED to immediate **block+log**
//!     (doc 09 §4 DNS-3 / D77: "unattended downgrades unknown-domain to immediate
//!     block+log"). The wire answer is still REFUSED (the §3.2 ask-posture shape — never
//!     a cacheable signal), but NO human is interrupted: no `AskUserRequest` is emitted,
//!     and the LOG-1 `DnsEvent` records the downgrade. The VM is never suspended in either
//!     posture (D77: suspension is reserved for genuine threats, not policy questions).
//!
//! The gate does NOT decide attendedness itself — it is a per-session property the
//! orchestrator owns and the handler is configured with ([`AskPosture`]); this module
//! only models the two outcomes so the downgrade is explicit and tested.

use std::sync::{Arc, Mutex};

/// The session-attendedness posture (D53/D77) the handler applies to an unknown-domain
/// `Ask`. A per-session property owned by the orchestrator; the gate is configured with
/// it (it does not infer it). The DEFAULT is [`AskPosture::Unattended`] — the
/// conservative posture (no human to interrupt → block+log, never an open ask that no one
/// will answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AskPosture {
    /// **Attended** (D77): a human is present. An unknown-domain `Ask` notifies the human
    /// async via the [`AskUserSink`] and authors REFUSED; the post-approval retry resolves
    /// once the grant lands on the policy stream. The VM keeps running.
    Attended,
    /// **Unattended** (D77, the default): no human to interrupt — the unknown-domain `Ask`
    /// is DOWNGRADED to immediate block+log. REFUSED on the wire, the downgrade recorded in
    /// LOG-1, and NO `AskUserRequest` emitted (interrupting an absent human is pointless).
    #[default]
    Unattended,
}

impl AskPosture {
    /// Whether this posture raises an async human ask (attended), vs downgrades to
    /// immediate block+log (unattended). The single predicate the handler branches on.
    pub fn notifies_human(&self) -> bool {
        matches!(self, AskPosture::Attended)
    }
}

/// The one-way ask-user notification (boundary → orchestrator), a service-internal,
/// hickory-free, proto-free MIRROR of the frozen `boundary.v1.AskUserRequest`
/// (`proto/dreamserpent/boundary/v1/ask.proto`).
///
/// STRICTLY ONE-WAY (POL-5): there is no paired response on this seam. The handler emits
/// it on an ATTENDED unknown-domain `Ask` and authors REFUSED; the orchestrator
/// terminates the notification and relays it into the D18 client. An approval returns ONLY
/// as a session-scoped TTL'd allow grant on the policy stream (a `PolicyCorePolicy`
/// reload), never as a reply here.
///
/// The field set mirrors the proto exactly so the production wiring is a 1:1 encode:
/// `session` / `resource_kind` / `resource_name` and the inline POL-3 triple. Plain
/// `String`s only — no hickory type, no proto type, no secret value (an ask names a
/// domain, never a credential).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskUserRequest {
    /// The asking session (the D66/D44 interface-anchored join key — `SessionRef` in the
    /// proto). The session the approval grant is scoped to.
    pub session: String,
    /// The resource KIND being asked about (proto `resource_kind`). For a DNS ask this is
    /// the frozen [`RESOURCE_KIND_DOMAIN`] marker — the gate asks about a domain.
    pub resource_kind: String,
    /// The resource NAME being asked about (proto `resource_name`) — the unknown FQDN the
    /// human is asked to approve.
    pub resource_name: String,
    /// POL-3 matched-rule id (proto `matched_rule_id`) — the rule that raised the ask.
    pub matched_rule_id: String,
    /// POL-3 policy layer (proto `policy_layer`).
    pub policy_layer: String,
    /// POL-3 policy version (proto `policy_version`).
    pub policy_version: String,
}

/// The frozen `resource_kind` a DNS ask carries: the gate asks the human to approve a
/// **domain** (proto `resource_kind` value for the DNS path). A `const` so a consumer can
/// match the kind without a magic string.
pub const RESOURCE_KIND_DOMAIN: &str = "domain";

impl AskUserRequest {
    /// Build the notification for an unknown-domain `Ask`: the resource is the qname (a
    /// domain), the POL-3 triple is the verdict's matched rule. The handler calls this on
    /// the ATTENDED ask path with the verdict's [`crate::policy::PromptRef`]-derived
    /// session/qname and the verdict provenance.
    pub fn for_domain(
        session: impl Into<String>,
        qname: impl Into<String>,
        matched_rule_id: impl Into<String>,
        policy_layer: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        Self {
            session: session.into(),
            resource_kind: RESOURCE_KIND_DOMAIN.to_string(),
            resource_name: qname.into(),
            matched_rule_id: matched_rule_id.into(),
            policy_layer: policy_layer.into(),
            policy_version: policy_version.into(),
        }
    }
}

/// The ask-user emission seam — the handler hands every raised [`AskUserRequest`] to a
/// sink. One method, no async, no hickory type — mirrors the [`crate::event::EventSink`]
/// discipline so the production orchestrator transport replaces the impl WITHOUT touching
/// the handler emission site (doc 14 §2b: the seam, not a second response contract).
///
/// `Send + Sync + 'static` so the sink can live behind the `Arc` the handler shares across
/// the UDP `Server` and the capped TCP accept loop.
pub trait AskUserSink: Send + Sync + 'static {
    /// Notify the human (async, fire-and-forget at this seam). Infallible by construction:
    /// a dropped notification never fails the DNS query (the REFUSED is authoritative; the
    /// retry path succeeds once the grant lands). Durability of the notification is the
    /// orchestrator transport's concern, not the gate's.
    fn ask(&self, request: AskUserRequest);
}

/// The default pre-stage ask sink: a no-op. `main` runs with this — there is no
/// orchestrator transport at the pre-stage, only the obligation that the emission SITE
/// exists and fires on the attended ask path (proven against [`CapturingAskSink`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullAskSink;

impl AskUserSink for NullAskSink {
    fn ask(&self, _request: AskUserRequest) {}
}

/// An in-memory ask sink that records every raised [`AskUserRequest`], for the seam tests
/// (and any future in-process assertion). Clones share the same backing buffer, so a test
/// can hand a clone to the handler and read the asks back through its own handle.
/// SERVICE-INTERNAL test/inspection seam; never a transport.
#[derive(Debug, Clone, Default)]
pub struct CapturingAskSink {
    asks: Arc<Mutex<Vec<AskUserRequest>>>,
}

impl CapturingAskSink {
    /// A fresh, empty capturing ask sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the asks raised so far (in emission order).
    pub fn asks(&self) -> Vec<AskUserRequest> {
        self.asks.lock().expect("ask buffer mutex poisoned").clone()
    }

    /// How many asks have been raised.
    pub fn len(&self) -> usize {
        self.asks.lock().expect("ask buffer mutex poisoned").len()
    }

    /// Whether no ask has been raised yet (the unattended downgrade NEVER raises one).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AskUserSink for CapturingAskSink {
    fn ask(&self, request: AskUserRequest) {
        self.asks
            .lock()
            .expect("ask buffer mutex poisoned")
            .push(request);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_is_the_conservative_default_posture() {
        // No human to interrupt → block+log, never an ask no one will answer.
        assert_eq!(AskPosture::default(), AskPosture::Unattended);
        assert!(!AskPosture::default().notifies_human());
        assert!(AskPosture::Attended.notifies_human());
    }

    #[test]
    fn for_domain_mirrors_the_frozen_proto_field_set() {
        let ask = AskUserRequest::for_domain(
            "dstap-7/sess-1",
            "unknown.example.",
            "baseline-pack:core/unknown.example",
            "pol2-system-baseline",
            "2026-06-13",
        );
        assert_eq!(ask.session, "dstap-7/sess-1");
        // The DNS ask is always about a DOMAIN (the frozen resource_kind).
        assert_eq!(ask.resource_kind, RESOURCE_KIND_DOMAIN);
        assert_eq!(ask.resource_name, "unknown.example.");
        // POL-3 triple carried verbatim (the "why was this asked?" answer).
        assert_eq!(ask.matched_rule_id, "baseline-pack:core/unknown.example");
        assert_eq!(ask.policy_layer, "pol2-system-baseline");
        assert_eq!(ask.policy_version, "2026-06-13");
    }

    #[test]
    fn capturing_ask_sink_records_in_order() {
        let sink = CapturingAskSink::new();
        assert!(sink.is_empty());
        sink.ask(AskUserRequest::for_domain("s", "a.example.", "r", "l", "v"));
        sink.ask(AskUserRequest::for_domain("s", "b.example.", "r", "l", "v"));
        let asks = sink.asks();
        assert_eq!(asks.len(), 2);
        assert_eq!(asks[0].resource_name, "a.example.");
        assert_eq!(asks[1].resource_name, "b.example.");
    }
}
