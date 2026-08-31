//! TLS-1 admission core — the SNI-checked transparent-tunnel decision
//! (doc 09 §5 TLS-1; doc 12 §2.1/§4.1; doc 03 §3 OQ1; D68/D69/D40).
//!
//! # What this is
//!
//! The transparent path ([`crate::transparent`]) recovers a [`ConnOrigin`]
//! `{ original_dst, session }` at accept time and, at the TLS-1 *prestage*, opens
//! an opaque tunnel. This module is the prestage the `accept/` layer's comments
//! name as "the SNI/admission check": the gate that runs **after** `ConnOrigin`
//! recovery and **before** the opaque tunnel opens, on `:18443`.
//!
//! It answers one question, `decide(...)`, over three inputs and nothing more:
//!
//! 1. the **peeked ClientHello bytes** (the client's first record, read but not
//!    consumed — the listener replays them upstream so the VM's TLS handshake
//!    still reaches the origin),
//! 2. the recovered [`ConnOrigin`] (the unforgeable kernel `original_dst` + the
//!    interface-anchored `session`), and
//! 3. the injected [`ds_contracts::dns_admission::AdmissionMap`] (the per-session
//!    DNS-2b map ds-dnsgate writes) + an injected [`PolicyOracle`] (the
//!    `policy-core` verdict).
//!
//! # The CDN shared-IP hole this closes (doc 03 §3 OQ1, doc 09 §5 TLS-1)
//!
//! An allowed IP on a shared CDN must NOT admit every domain behind it. The check
//! is therefore a **FORWARD lookup** keyed on the SNI domain:
//!
//! ```text
//!   AdmissionMap.lookup(AdmissionKey { session, sni_domain }) -> Some(entry)
//!     AND original_dst ∈ entry.admitted_ips      (membership of the KERNEL fact)
//!     AND !entry.is_expired_at(now)              (the caller's expiry gate, D68)
//!     AND policy allows sni_domain               (policy-core verdict)
//!   -> ADMIT (the listener tunnels opaquely)
//! ```
//!
//! It is **never** a reverse-index "is `original_dst` admitted for ANY domain"
//! check — that reverse query IS the hole (domain B riding domain A's CDN IP).
//! Here the SNI domain selects the entry and the *kernel* `original_dst` is
//! checked **against** that entry's admitted set; a client SNI claim is a claim,
//! `original_dst` is the unforgeable fact (D69 invariant 1). SNI is checked
//! against `original_dst`, never substituted for it.
//!
//! # Edge refusals (doc 12 §3, doc 09 §5 — refuse by default)
//!
//! Before any admission lookup:
//!
//! - **ECH ClientHello** (`encrypted_client_hello` extension present) → refuse: an
//!   encrypted inner name would show us only the CDN outer name, reopening the
//!   shared-IP hole. DNS-4 rule 4 strips the HTTPS/SVCB configs that trigger real
//!   ECH, so what remains is browser GREASE — refused, documented, acceptable for
//!   the curl/git/npm/SDK client set.
//! - **absent SNI** → refuse (no `server_name` extension, or an empty host).
//! - **IP-literal SNI** → refuse (an IPv4/IPv6 literal in `server_name` is not a
//!   domain we can policy-evaluate or admit by name).
//!
//! # D68 re-admit-not-refuse (doc 12 §4.1, doc 09 §5; OQ3 → D68)
//!
//! A **policy-allowed** SNI with **no live admission** — `lookup` returned `None`,
//! or returned an entry that `is_expired_at(now)` — is **RE-ADMITTED, not
//! refused** (the resolve-once client: a JVM / pooled redialer whose DNS cache
//! outlived the map entry). The DECISION is implemented here ([`Tls1Decision::ReAdmit`]);
//! the actual synchronous DNS-2 re-resolve (policy re-eval + DNS-4 filter, connect
//! to a freshly admitted address) is a **cross-service SEAM** into ds-dnsgate's
//! DNS-2 path, modelled as the [`ReResolve`] hook. This module implements the
//! decision and the seam honestly: it returns `ReAdmit` and names the hook; it
//! does NOT itself perform the cross-service re-resolve (that wiring is M0-host
//! integration, the same class as the §13.1 listener seam). Refusal is **only**
//! on a non-`Admit` policy verdict (and the edge refusals above) — and that one
//! policy refusal is split across three secret-free reason codes (deny vs ask vs
//! inert-capability-gated) for the §10/LOG-1 telemetry, see [`PolicyVerdict`].
//!
//! # D40 pingora confinement (structural)
//!
//! This module speaks the internal [`ConnOrigin`] + the [`PolicyOracle`] verdict +
//! the `ds_contracts` [`ds_contracts::dns_admission::AdmissionMap`] **only** — no
//! `pingora-core` type is named here. The listener layer ([`crate::main`]) owns
//! every pingora type: it peeks the bytes off the `Stream`, calls [`decide`], and
//! acts on the returned [`Tls1Decision`]. The ClientHello is parsed from a plain
//! `&[u8]` so the same decision is exercised end-to-end with synthetic bytes in
//! `#[cfg(test)]` and against a mock [`AdmissionMap`] + mock [`PolicyOracle`], with
//! no live network, kernel, or TLS stack (the curl/git-over-HTTPS conformance is a
//! CI/manual harness — see the module-level note in [`crate::main`]).

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionKey, AdmissionMap, AdmittedAddr, Instant,
};

use crate::transparent::ConnOrigin;

/// The TLS-1 projection of the one policy-core engine verdict — the small,
/// pingora-free, secret-free verdict class this module distinguishes for the §10
/// refusal telemetry (doc 12 §10 / LOG-1). It is a narrowing of
/// `policy_core::consumer::DecisionKind` to exactly the four outcomes TLS-1 acts
/// on, dropping the `InertCapabilityGated { requires }` payload (the unmet
/// capability name is a policy-document detail that does not belong in the
/// boundary's reason code — keep the §10 code secret-free).
///
/// Fail-closed is preserved: only [`PolicyVerdict::Admit`] proceeds to the
/// admission lookup; every other class REFUSES. The class only changes which
/// stable reason code the refusal carries (deny vs ask vs inert-capability-gated),
/// never *whether* it refuses (§1.7: an inert capability-gated entry admits
/// NOTHING and is distinct from a policy deny).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Policy ADMITS the upstream connect — proceed to the admission lookup.
    Admit,
    /// Policy DENY (an explicit block) — refuse [`RefuseReason::PolicyDeny`].
    Deny,
    /// Policy ASK (unknown-domain posture: the user would be prompted). TLS-1
    /// admits nothing on an Ask, so it REFUSES — but with its own reason code so
    /// the operator sees an ask-posture refusal, not a hard deny.
    Ask,
    /// The domain matched ONLY a capability-gated (inert) entry: it admits NOTHING
    /// (§1.7) and is DISTINCT from a policy deny. TLS-1 refuses with its own
    /// reason code so the operator sees the inert-capability cause, not a deny.
    CapabilityGated,
}

impl PolicyVerdict {
    /// Whether this verdict ADMITS the upstream connect (the ONLY class that
    /// proceeds past policy to the admission lookup). Every other class refuses —
    /// the refusal *reason* differs, the fail-closed outcome does not.
    pub fn admits(self) -> bool {
        matches!(self, PolicyVerdict::Admit)
    }

    /// The [`RefuseReason`] a non-`Admit` verdict refuses with, or `None` for
    /// `Admit` (which proceeds and never refuses on policy grounds). This is the
    /// single mapping site for the policy refusal taxonomy — deny / ask /
    /// capability-gated each carry their own stable reason code, all still refuse.
    pub fn refuse_reason(self) -> Option<RefuseReason> {
        match self {
            PolicyVerdict::Admit => None,
            PolicyVerdict::Deny => Some(RefuseReason::PolicyDeny),
            PolicyVerdict::Ask => Some(RefuseReason::PolicyAsk),
            PolicyVerdict::CapabilityGated => Some(RefuseReason::PolicyCapabilityGated),
        }
    }
}

/// The policy-core verdict surface this module consumes, abstracted so the
/// decision is testable with a mock and the production adapter routes the SAME
/// engine verdict the DNS admission used (POL-3 — no consumer reimplements a
/// rule). The production impl ([`PolicyCoreOracle`]) delegates to
/// `policy_core::consumer::tls_connect_decision`; tests implement it over a fixed
/// verdict map.
///
/// Deliberately a trait taking only the SNI domain string and returning the small
/// [`PolicyVerdict`] projection: it keeps this module free of `ComposedPolicy` (a
/// policy-core engine type) so the unit tests need no policy document, and it
/// surfaces the *class* of the policy outcome — admit vs deny vs ask vs inert
/// capability-gated — so the §10 refusal telemetry can name an accurate cause
/// (doc 12 §10) instead of conflating three refusals under one code. The
/// production wiring binds a `ComposedPolicy` behind it at the listener layer.
pub trait PolicyOracle {
    /// The TLS-1 [`PolicyVerdict`] projection of the one engine verdict for
    /// `sni_domain` (the `policy_core::consumer::DecisionKind` narrowed to what
    /// TLS-1 acts on). Only [`PolicyVerdict::Admit`] proceeds; every other class
    /// refuses with its own stable reason code (same fail-closed boundary, richer
    /// telemetry).
    fn verdict(&self, sni_domain: &str) -> PolicyVerdict;

    /// **Operator-diagnostic seam (doc 12 §10.2) — off the §10/LOG-1 wire.** The
    /// policy-supplied *unmet capability name* when `sni_domain` matched ONLY a
    /// capability-gated (inert) entry (the engine's `InertCapabilityGated { requires }`
    /// payload — e.g. `"http-policy"`), or `None` for every other verdict class
    /// (including a `CapabilityGated` verdict whose name the oracle does not surface).
    ///
    /// This is the seam that lets an operator learn WHICH capability is missing —
    /// the name deliberately DROPPED from [`PolicyVerdict`] (which keeps the §10
    /// reason code secret-free, §10.2). It is a SEPARATE accessor from [`verdict`]:
    /// [`verdict`] stays byte-identical (the boundary refusal event never carries the
    /// name), and this name is captured ONLY through the operator-diagnostic entry
    /// point [`decide_with_diagnostic`], into a [`CapabilityGateDiagnostic`] sink —
    /// never onto the returned [`Tls1Decision`] / [`RefuseReason`] / `reason_code`.
    ///
    /// Defaults to `None`: a plain [`PolicyOracle`] that does not opt into the
    /// diagnostic (every non-diagnostic caller) surfaces no capability name, so the
    /// diagnostic seam is inert unless an oracle deliberately implements it. The
    /// production adapter [`PolicyCoreOracle`] overrides it to return the engine's
    /// `requires` string; the ordinary [`decide`] path never calls it.
    fn capability_requirement(&self, _sni_domain: &str) -> Option<String> {
        None
    }
}

/// The **operator-diagnostic sink (doc 12 §10.2)** for the dropped inert-capability
/// `requires` name — an access-controlled, operator-only facility that is OFF the
/// §10/LOG-1 refusal event. When [`decide_with_diagnostic`] refuses a connect with
/// [`RefuseReason::PolicyCapabilityGated`], it captures the policy-supplied unmet
/// capability name (available at `decide()`-time, before the [`PolicyVerdict`]
/// projection drops it) into this sink — and ONLY into this sink. The returned
/// [`Tls1Decision`], the [`RefuseReason`], and its `reason_code()` are byte-identical
/// whether or not a sink is attached (§10.2 fenced invariant: the boundary refusal
/// event stays secret-free `tls1-policy-capability-gated`; the name rides ONLY the
/// separate operator seam).
///
/// The name written here is a **policy-document detail for a human debugging the
/// policy pack**, not a flow-log field — an implementor MUST route it to an
/// operator-access-controlled surface (the same class as the §3.1 upstream-trust
/// runbook or the §8.2 operator CRL posture), never to a session-reachable channel
/// or the LOG-1 wire.
pub trait CapabilityGateDiagnostic {
    /// Record that `sni_domain` refused as inert-capability-gated because the policy
    /// entry `requires` the named capability. Called ONLY on the
    /// [`RefuseReason::PolicyCapabilityGated`] path of [`decide_with_diagnostic`],
    /// with the name the [`PolicyOracle::capability_requirement`] accessor surfaced.
    /// Off the §10 event — an operator-only diagnostic record.
    fn record_capability_gate(&self, sni_domain: &str, requires: &str);
}

/// The TLS-4 pass-through list SEAM (doc 12 §3, §13.4; doc 09 §5 TLS-4; D17/D74).
///
/// The pass-through list is a **policy artifact, not code**: a session's policy
/// snapshot names the (cert-pinned) domains whose flows are forwarded as an opaque
/// tunnel *without* TLS termination, inspection, credential swap, or secret
/// scanning (the §3/§5 stated non-claim). Because it lives in policy, adding or
/// removing an entry is a policy-snapshot change reconciled through POL-4 hot
/// reload — never a rebuild of this binary. This trait is the read seam the TLS-1
/// decision consults; the production impl binds it to the live policy snapshot's
/// pass-through set, tests implement it over a fixed set.
///
/// **D74 frozen invariant: the list ships EMPTY.** The D64 baseline pack carries
/// an empty pass-through list — nothing in the baseline endpoint set certificate-
/// pins, and the supported client set explicitly trusts TLS-inspection proxies via
/// its `bundled,system` cert store. An entry is added ONLY with attached
/// reproduction evidence of a pinning failure under TLS-3 inspection. The empty
/// default is encoded structurally: [`is_passthrough`](PassthroughList::is_passthrough)
/// returns `false` for every domain unless a snapshot deliberately lists it, so the
/// shipped behavior is "everything allowed is inspected (or opaquely tunneled at
/// TLS-1), nothing is passed through".
///
/// Kept SEPARATE from [`PolicyOracle`] on purpose: the spec freezes the
/// `policy-core` connect-verdict contract, so the pass-through read is its OWN seam
/// rather than a new method on the verdict trait. The pass-through check is a
/// tunnel-MODE refinement applied to an already-admitted flow — it never changes
/// the admission verdict (doc 12 §3: "pass-through changes tunnel mode, never the
/// admission verdict"), so it is consulted only after policy admits AND a live
/// admission includes the kernel dst.
pub trait PassthroughList {
    /// Whether `sni_domain` is on the session's policy-configured pass-through
    /// list. The D74 default is `false` for EVERY domain (the list ships empty);
    /// only a snapshot that deliberately lists `sni_domain` returns `true`.
    fn is_passthrough(&self, sni_domain: &str) -> bool;
}

/// The frozen-EMPTY pass-through list (D74): the default a session runs with until
/// a snapshot deliberately lists a domain. Every domain is `false` — so every
/// admitted flow opaquely tunnels (TLS-1) or is inspected (TLS-3), and NOTHING is
/// passed through. This is the structural encoding of the D74 invariant: the
/// shipped binary's pass-through behavior is "empty" by construction, not by a
/// runtime check that could be misconfigured to a non-empty default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmptyPassthroughList;

impl PassthroughList for EmptyPassthroughList {
    fn is_passthrough(&self, _sni_domain: &str) -> bool {
        // D74: the baseline pack ships the list EMPTY — no domain passes through.
        false
    }
}

/// The cross-service re-resolve SEAM (doc 12 §4.1, D68). A policy-allowed SNI with
/// no live admission is RE-ADMITTED: re-resolve `sni_domain` through ds-dnsgate's
/// full DNS-2 admission path (policy re-eval + DNS-4 filter), which writes a fresh
/// admission and returns a freshly admitted address to dial.
///
/// **This is a documented hook, not a wired cross-service call.** The actual
/// re-resolve is owned by ds-dnsgate and reached over an intra-Boundary seam (doc
/// 14 §3); this trait is where that wiring lands at M0-host integration. The
/// TLS-1 decision ([`decide`]) produces [`Tls1Decision::ReAdmit`] and names this
/// hook; a production listener that has the seam wired calls
/// [`ReResolve::reresolve`] on a `ReAdmit` and dials the returned address, while a
/// listener without it surfaces the honest "re-admit decided, re-resolve seam not
/// wired" state. The seam is defined here so the decision and its consumer are one
/// compile unit; the cross-service body is not in this module's scope.
pub trait ReResolve {
    /// Re-resolve `sni_domain` for `session_uuid` through DNS-2 admission, dialing
    /// a freshly admitted address. Returns the freshly admitted addresses on
    /// success (the listener connects to one of them), or `None` when the
    /// re-resolve itself denied / failed (the listener then refuses).
    fn reresolve(&self, session_uuid: &str, sni_domain: &str) -> Option<Vec<AdmittedAddr>>;
}

/// Why a TLS-1 connection was refused — the stable, secret-free reason codes for
/// the §10 refusal event (the same event class as the [`crate::transparent`]
/// recovery-failure refusal). NEVER carries a client byte or the SNI value beyond
/// what the reason class names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason {
    /// The ClientHello could not be parsed as a TLS handshake ClientHello (a
    /// non-TLS first record on `:18443`, or a truncated/garbage record). Refuse —
    /// we cannot extract an SNI to check.
    ///
    /// **Over-cap collapses here (decided 8AMX-u2, not a separate variant).** A
    /// ClientHello whose complete handshake message would exceed the 16 KiB peek cap
    /// (`CLIENT_HELLO_PEEK_MAX`; the `HandshakeSpan::OverCap` arm in `src/main.rs`)
    /// also refuses with THIS code, not its own. Rationale: over-cap is observably a
    /// parse-level truncation — the peek returns the truncated-to-cap prefix and the
    /// bounds-checked parser hits underrun, so an over-cap prefix is INDISTINGUISHABLE
    /// from any other truncated/garbage first record at the byte level. That
    /// indistinguishability is inherent to the byte cap, so a distinct code would carry
    /// no telemetry signal the bytes don't already justify lumping together. This is
    /// the deliberate CONTRAST with [`RefuseReason::ClientHelloFlood`]: a flood's
    /// record-COUNT cause is a fact only the coalescing loop holds (invisible to the
    /// byte parser), so it earns a distinct code; over-cap's truncation IS the parse
    /// failure, with no hidden signal to surface. See the `OverCap` arm in `src/main.rs`
    /// for the full decision + tradeoff.
    NotAClientHello,
    /// The ClientHello-prefix peek hit a **tiny-record flood** before the handshake
    /// message was whole: the record-coalescing loop crossed the `MAX_CLIENT_HELLO_RECORDS`
    /// (too many records) or `MAX_CLIENT_HELLO_EMPTY_RECORDS` (too many zero-progress /
    /// empty records) bound. This is DISTINCT from [`RefuseReason::NotAClientHello`] (a
    /// malformed / truncated / over-byte-cap prefix): a flood is a bounded-cost
    /// resource-exhaustion edge the peek refuses on record COUNT, never on the byte cap,
    /// so the listener surfaces this reason instead of collapsing the flood into the
    /// generic not-a-ClientHello refusal. Same fail-closed outcome — both refuse with NO
    /// upstream opened — but the §10/LOG-1 telemetry can now tell a tiny-record flood
    /// apart from ordinary garbage. Mirrors the §7 `QuicBlocked` pattern: a dedicated
    /// stable code for a distinct refusal cause. Carries ZERO client bytes (the reason
    /// code names only the cause class — the record counts are a peek-local detail).
    ClientHelloFlood,
    /// The ClientHello carried an `encrypted_client_hello` extension (ECH). Refuse
    /// (doc 12 §3): an encrypted inner name defeats the SNI check behind a shared
    /// CDN IP.
    EchPresent,
    /// No `server_name` extension, or an empty host name. Refuse by default (doc
    /// 12 §3 — absent-SNI).
    AbsentSni,
    /// The `server_name` host was an IP literal (v4 or v6). Refuse by default (doc
    /// 12 §3 — IP-literal TLS): an IP literal is not a domain we admit by name.
    IpLiteralSni,
    /// The SNI domain was policy-DENIED — an explicit policy block (doc 12 §4.1).
    /// One of the three policy-refusal classes the §10 telemetry distinguishes
    /// ([`PolicyVerdict::Deny`]); deny / ask / capability-gated all refuse, only
    /// the reason code differs.
    PolicyDeny,
    /// The SNI domain reached a policy ASK posture (the unknown-domain prompt path
    /// — [`PolicyVerdict::Ask`]). TLS-1 admits nothing on an Ask, so it refuses,
    /// but with its own reason code so the operator sees an ask-posture refusal
    /// rather than a hard deny. Same fail-closed boundary; richer §10 telemetry.
    PolicyAsk,
    /// The SNI domain matched ONLY a capability-gated (inert) policy entry: it
    /// admits NOTHING (§1.7, [`PolicyVerdict::CapabilityGated`]) and is DISTINCT
    /// from a policy deny. TLS-1 refuses with its own reason code so the operator
    /// can tell an inert-capability gate apart from an explicit deny. The unmet
    /// capability name is deliberately NOT carried — the §10 code stays
    /// secret-free.
    PolicyCapabilityGated,
    /// Policy ALLOWS the SNI domain and a live admission exists, but the kernel
    /// `original_dst` is NOT in that admission's admitted set — the SNI claims a
    /// domain the kernel destination was not admitted for. This is the CDN
    /// shared-IP hole closing shut: SNI domain A, kernel dst admitted only for
    /// domain B → refuse (never silently substitute the SNI claim for the fact).
    SniDstMismatch,
    /// A D68 RE-ADMIT path FAILED its re-resolve: policy allowed the SNI domain but
    /// there was no live admission, so the listener drove the [`ReResolve`] seam
    /// (DNS-2 admission) — and the re-resolve itself DENIED / returned nothing.
    /// Refuse fail-closed (never admit a domain DNS-2 declined to re-admit). This is
    /// DISTINCT from [`RefuseReason::SniDstMismatch`] (a present-but-wrong admission,
    /// the CDN-hole case): a re-admit denial is an ABSENT admission the re-resolve
    /// could not freshly establish, so it earns its own reason code rather than
    /// overloading the SNI/dst-mismatch signal — the §10/LOG-1 telemetry attributes a
    /// re-admit failure to its true cause. Same fail-closed outcome (no upstream
    /// opened); carries ZERO client bytes.
    ReAdmitDenied,
    /// A D68 RE-ADMIT path fired on an UN-JOINED ref: policy allowed the SNI domain
    /// and there was no live admission (→ `ReAdmit`), but the origin ref carried an
    /// EMPTY `session_uuid` (the address-derived accept-path ref before the
    /// orchestrator session-record join lands). A re-admit is a fresh DNS-2 admission
    /// keyed on the GLOBAL session identity; a ref that cannot even supply that
    /// identity is short-circuited fail-closed BEFORE the re-resolve seam is dialled
    /// (the guard in `src/main.rs`'s `ReAdmit` arm), so NO empty-key seam dial ever
    /// happens. This is DISTINCT from [`RefuseReason::ReAdmitDenied`] (a JOINED ref
    /// whose re-resolve the DNS-2 seam actively DECLINED): an un-joined ref never
    /// reached the seam at all — the refusal is a missing session identity, not a
    /// seam decline — so it earns its own reason code and the §10/LOG-1 telemetry can
    /// tell "ref never joined" apart from "seam declined". Same fail-closed outcome
    /// (no upstream opened, no seam dialled); carries ZERO client bytes.
    ReAdmitUnjoinedRef,
}

impl RefuseReason {
    /// A stable, secret-free reason code for the §10 refusal LOG-1 event.
    pub fn reason_code(self) -> &'static str {
        match self {
            RefuseReason::NotAClientHello => "tls1-not-a-clienthello",
            RefuseReason::ClientHelloFlood => "tls1-clienthello-flood",
            RefuseReason::EchPresent => "tls1-ech-refused",
            RefuseReason::AbsentSni => "tls1-absent-sni",
            RefuseReason::IpLiteralSni => "tls1-ip-literal-sni",
            RefuseReason::PolicyDeny => "tls1-policy-deny",
            RefuseReason::PolicyAsk => "tls1-policy-ask",
            RefuseReason::PolicyCapabilityGated => "tls1-policy-capability-gated",
            RefuseReason::SniDstMismatch => "tls1-sni-dst-mismatch",
            RefuseReason::ReAdmitDenied => "tls1-readmit-denied",
            RefuseReason::ReAdmitUnjoinedRef => "tls1-readmit-unjoined-ref",
        }
    }
}

impl std::fmt::Display for RefuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS-1 refused: {}", self.reason_code())
    }
}

/// The TLS-1 admission decision — what the listener does after the SNI/admission
/// check and before opening the opaque tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tls1Decision {
    /// ADMIT, opaque tunnel (the TLS-1 default): policy allows the SNI domain AND a
    /// live (non-expired) admission for that domain includes the kernel
    /// `original_dst`, AND the domain is NOT on the pass-through list. The listener
    /// replays the peeked ClientHello upstream to `original_dst` and tunnels
    /// opaquely (no TLS termination at TLS-1). This is the
    /// `boundary/tlsproxy` `ActionTunnelOpaque` verdict.
    Tunnel,
    /// ADMIT, TLS-4 pass-through (doc 12 §3, D17/D74): policy allows the SNI domain
    /// AND a live admission includes the kernel `original_dst`, AND the domain IS on
    /// the policy-configured pass-through list. The flow is forwarded as an opaque
    /// tunnel EXACTLY like [`Tls1Decision::Tunnel`] at the byte level — SNI +
    /// admission enforced and netflow-accounted — but it is FROZEN against ever
    /// being TLS-terminated: no inspection, no credential swap, no secret scanning
    /// (the §3/§5 stated non-claim). The distinct verdict is what lets the listener
    /// keep a pass-through flow off the TLS-3 inspected path even when inspection is
    /// live. This is the `boundary/tlsproxy` `ActionPassThrough` verdict. The list
    /// ships EMPTY (D74), so this verdict NEVER fires under the baseline pack — it
    /// fires only for a domain a policy snapshot deliberately lists.
    Passthrough,
    /// D68 RE-ADMIT (not refuse): policy ALLOWS the SNI domain but there is no live
    /// admission for it (`lookup` was `None`, or the entry is expired). The
    /// listener re-resolves `sni_domain` through the [`ReResolve`] seam (DNS-2
    /// admission) and dials the freshly admitted address. Carries the SNI domain
    /// so the listener can drive the seam; never refuses on its own.
    ReAdmit {
        /// The policy-allowed SNI domain to re-resolve through DNS-2 admission.
        sni_domain: String,
        /// Why re-admission was reached, for the §10 event (no live admission vs
        /// an expired one — both re-admit; the distinction is diagnostic only).
        cause: ReAdmitCause,
    },
    /// REFUSE: an edge rule fired (ECH / absent-SNI / IP-literal / not-a-
    /// ClientHello) or policy DENIED, or the SNI/dst mismatch closed the CDN hole.
    /// The listener closes the connection without opening any upstream.
    Refuse(RefuseReason),
}

/// Why a [`Tls1Decision::ReAdmit`] was reached (D68). Both re-admit; the cause is
/// for the §10 event only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReAdmitCause {
    /// `lookup` returned `None` — no admission for `(session, sni_domain)` (the
    /// resolve-once client whose admission never landed / was naturally cleaned
    /// up).
    NoLiveAdmission,
    /// `lookup` returned an entry, but it `is_expired_at(now)` — the resolve-once
    /// client whose cached answer outlived the map deadline. Re-admit, not refuse
    /// (D68: expiry gates new flows by re-resolving, never by refusing a
    /// policy-allowed domain).
    Expired,
}

/// Convert a [`ConnOrigin`]'s kernel `original_dst` into the family-agnostic
/// [`AdmittedAddr`] contract shape, for membership-testing against an admission
/// entry's `admitted_ips`. The octets are network byte order (4 for v4, 16 for
/// v6), matching [`AdmittedAddr`]'s frozen wire shape. Mechanism-independent: it
/// derives only from the [`ConnOrigin`] field (D69 invariant 4).
///
/// `pub(crate)` so the listener's seam-hardening sites (the D68 ReAdmit
/// membership re-check and the TLS-3 inspected/swap FORWARD-admission coupling)
/// reuse the SAME byte-exact projection rather than re-deriving it — one
/// kernel-fact → [`AdmittedAddr`] mapping, no drift (01KV9N17NN).
pub(crate) fn original_dst_as_admitted_addr(origin: &ConnOrigin) -> AdmittedAddr {
    match origin.original_dst.ip() {
        std::net::IpAddr::V4(v4) => AdmittedAddr {
            family: AddressFamily::V4,
            octets: v4.octets().to_vec(),
        },
        std::net::IpAddr::V6(v6) => AdmittedAddr {
            family: AddressFamily::V6,
            octets: v6.octets().to_vec(),
        },
    }
}

/// Whether `origin.original_dst` is a member of `entry.admitted_ips` — the FORWARD
/// admission's membership half (doc 09 §5). The kernel fact is checked AGAINST the
/// entry the SNI domain selected; this is never a reverse "admitted for any
/// domain" query. Compares family + octets (network byte order), the same
/// byte-exact identity [`AdmittedAddr::to_dst_key`] encodes.
fn dst_is_admitted(origin: &ConnOrigin, entry: &AdmissionEntry) -> bool {
    let want = original_dst_as_admitted_addr(origin);
    entry.admitted_ips.contains(&want)
}

/// Whether `origin.original_dst` is a member of `addrs` — the membership half of a
/// FORWARD admission, taken over a freshly-resolved address LIST rather than an
/// [`AdmissionEntry`] (doc 09 §5). The D68 ReAdmit path uses this on the addresses
/// the [`ReResolve`] seam returns: a re-resolve that admits a fresh set MUST still
/// contain the kernel `original_dst` the client dialed, or the client is dialing an
/// address DNS-2 did not freshly admit (the CDN shared-IP hole reopening on the
/// re-admit leg — refuse, never substitute the re-resolved set for the kernel fact).
/// Byte-exact (family + network-byte-order octets), the SAME identity
/// [`dst_is_admitted`] uses against an entry.
pub fn original_dst_in_admitted_addrs(origin: &ConnOrigin, addrs: &[AdmittedAddr]) -> bool {
    let want = original_dst_as_admitted_addr(origin);
    addrs.contains(&want)
}

/// Whether a LIVE, non-expired FORWARD admission for `(session, sni_domain)`
/// includes the kernel `origin.original_dst` (doc 09 §5; the CDN shared-IP hole
/// close, doc 03 §3 OQ1) — the standalone membership half of [`decide`], for a
/// call-site that has ALREADY made the policy/edge decision and needs only the
/// admitted-IP coupling.
///
/// This is the FORWARD-admission coupling the TLS-3 inspected/credential-swap path
/// requires (01KV9N17NN CV1-credswap): the inspected path is armed by `DS_TLS3_LIVE`
/// INDEPENDENTLY of the `DS_TLS1_LIVE` FORWARD check, so without this an inspected /
/// swapped flow could proceed to a destination the FORWARD CDN-hole close never
/// admitted. The check is keyed on the SNI (a FORWARD lookup, NEVER a reverse
/// any-domain query) and the kernel `original_dst` is tested AGAINST the entry the
/// SNI selected — the SAME discipline [`decide`] enforces.
///
/// Returns `true` ONLY when an entry exists, is not expired at `now`, AND contains
/// the kernel dst. Every other outcome (`None`, expired, or a member miss) is
/// `false` — FAIL-CLOSED: a re-admittable-but-currently-absent admission (the D68
/// case [`decide`] would re-resolve) is NOT a live admission, so an inspected flow
/// must not proceed on it; the inspected path has no re-resolve seam of its own and
/// closes rather than swapping a credential onto an un-admitted destination.
///
/// PURE over its inputs (no I/O, no pingora type) so it is unit-tested directly
/// against an injected in-process map, exactly like [`decide`].
pub fn origin_is_admitted<M>(origin: &ConnOrigin, sni_domain: &str, map: &M, now: Instant) -> bool
where
    M: AdmissionMap + ?Sized,
{
    let key = AdmissionKey {
        session_uuid: origin.session.session_uuid.clone(),
        original_query_fqdn: sni_domain.to_string(),
    };
    match map.lookup(&key) {
        // A live admission for THIS domain whose admitted set includes the kernel
        // fact: the only admitting outcome.
        Some(entry) if !entry.is_expired_at(now) => dst_is_admitted(origin, &entry),
        // None, or an expired entry (the D68 re-admit case for `decide`): there is
        // no LIVE admission, so the inspected/swap path fails closed.
        _ => false,
    }
}

/// The TLS-1 admission decision (doc 09 §5 TLS-1; doc 12 §4.1; the CDN shared-IP
/// hole close, doc 03 §3 OQ1). Pure over its inputs — no I/O, no pingora type.
///
/// `client_hello` is the peeked first record (read but not consumed by the
/// listener; replayed upstream on a `Tunnel`/`ReAdmit`). `origin` is the recovered
/// [`ConnOrigin`]. `map` is the injected per-session DNS-2b admission map (sync
/// read). `policy` is the injected [`PolicyOracle`]. `now` is the caller's clock
/// for the expiry gate (D68 — expiry is the CALLER's gate; a `lookup` returning an
/// expired entry is correct and TLS-1 re-admits it, never a silent map drop).
///
/// Order (refuse-by-default at every edge before any admission lookup):
///
/// 1. Parse the ClientHello → refuse [`RefuseReason::NotAClientHello`] on failure.
/// 2. ECH present → refuse [`RefuseReason::EchPresent`].
/// 3. Absent SNI → refuse [`RefuseReason::AbsentSni`].
/// 4. IP-literal SNI → refuse [`RefuseReason::IpLiteralSni`].
/// 5. A non-`Admit` policy [`PolicyVerdict`] for the SNI domain → refuse with the
///    class's reason code (the only non-edge refusal): [`PolicyVerdict::Deny`] →
///    [`RefuseReason::PolicyDeny`], [`PolicyVerdict::Ask`] →
///    [`RefuseReason::PolicyAsk`], [`PolicyVerdict::CapabilityGated`] →
///    [`RefuseReason::PolicyCapabilityGated`]. All three refuse (fail-closed); the
///    reason code distinguishes them for the §10 telemetry.
/// 6. FORWARD `lookup(session, sni_domain)`:
///    - `Some(entry)` not expired AND `original_dst ∈ entry.admitted_ips` → ADMIT;
///      the tunnel MODE is then refined by the [`PassthroughList`] (step 7).
///    - `Some(entry)` not expired but `original_dst ∉ entry.admitted_ips` → refuse
///      [`RefuseReason::SniDstMismatch`] (the CDN hole closing — the SNI claims a
///      domain the kernel dst was not admitted for).
///    - `None` → [`Tls1Decision::ReAdmit { NoLiveAdmission }`] (D68).
///    - `Some(entry)` expired → [`Tls1Decision::ReAdmit { Expired }`] (D68).
/// 7. TLS-4 pass-through MODE (doc 12 §3, D17/D74), applied ONLY to an
///    already-admitted flow (so pass-through never changes the admission verdict —
///    a non-admitted or mismatched flow refuses BEFORE this step):
///    - `passthrough.is_passthrough(sni_domain)` → [`Tls1Decision::Passthrough`]
///      (opaque tunnel, frozen against TLS termination).
///    - otherwise → [`Tls1Decision::Tunnel`] (opaque tunnel, eligible for the TLS-3
///      inspected path). The list ships EMPTY (D74), so the empty default sends
///      EVERY admitted flow down this `Tunnel` arm.
///
/// The three admitting-vs-refusing outcomes are EXHAUSTIVE: a flow is REFUSED (an
/// edge rule / policy non-Admit / SNI-dst mismatch), RE-ADMITTED (D68), or ADMITTED
/// — and an admitted flow is exactly one of [`Tls1Decision::Passthrough`] (listed)
/// or [`Tls1Decision::Tunnel`] (not listed). The deny / pass-through / opaque-tunnel
/// three-way is decided by the `is_passthrough` boolean alone, with no fourth arm.
///
/// This is the ORIGINAL 5-input entry point, preserved byte-for-byte for the
/// listener (`src/main.rs`): it runs the decision under the D74 frozen-EMPTY
/// pass-through list ([`EmptyPassthroughList`]), so an admitted flow always returns
/// [`Tls1Decision::Tunnel`] — identical to pre-TLS-4 behavior. The pass-through-aware
/// path is the additive [`decide_with_passthrough`]; the listener migrates onto it
/// (binding the live snapshot's pass-through set) when the TLS-4 mode is wired,
/// exactly as it migrates the [`ReResolve`] seam. Keeping the empty-list path as the
/// default means adding TLS-4 cannot silently change the shipped tunnel mode.
pub fn decide<M, P>(
    client_hello: &[u8],
    origin: &ConnOrigin,
    map: &M,
    policy: &P,
    now: Instant,
) -> Tls1Decision
where
    M: AdmissionMap,
    P: PolicyOracle,
{
    // D74: the shipped default runs the empty pass-through list — every admitted
    // flow opaquely tunnels (Tunnel), byte-identical to the pre-TLS-4 decision.
    decide_with_passthrough(
        client_hello,
        origin,
        map,
        policy,
        &EmptyPassthroughList,
        now,
    )
}

/// The TLS-4-aware admission decision: identical to [`decide`] but with the
/// [`PassthroughList`] seam injected, so an admitted flow whose SNI is on the list
/// returns [`Tls1Decision::Passthrough`] instead of [`Tls1Decision::Tunnel`] (doc 12
/// §3, D17/D74). The pass-through check is a tunnel-MODE refinement applied ONLY to
/// an already-admitted flow — it never changes the admission verdict, never rescues
/// a refused or re-admit flow (a non-Admit verdict / SNI-dst mismatch / no live
/// admission is decided BEFORE this step). See [`decide`] for the full step order;
/// step 7 (the pass-through mode) is the only behavioral difference, and it is inert
/// under the D74 empty list.
pub fn decide_with_passthrough<M, P, L>(
    client_hello: &[u8],
    origin: &ConnOrigin,
    map: &M,
    policy: &P,
    passthrough: &L,
    now: Instant,
) -> Tls1Decision
where
    M: AdmissionMap,
    P: PolicyOracle,
    L: PassthroughList,
{
    // 1–4: parse + edge refusals (refuse by default, before any admission lookup).
    let sni = match parse_client_hello_sni(client_hello) {
        Ok(s) => s,
        Err(reason) => return Tls1Decision::Refuse(reason),
    };

    // 5: a non-Admit policy verdict is the ONLY non-edge refusal (doc 12 §4.1). An
    // allowed domain with no live admission RE-ADMITS, so policy is consulted
    // FIRST — a non-admitted domain never reaches the admission map or the
    // re-resolve seam. The verdict CLASS (deny / ask / inert-capability-gated)
    // picks the §10 reason code; all non-Admit classes refuse (fail-closed).
    if let Some(reason) = policy.verdict(&sni).refuse_reason() {
        return Tls1Decision::Refuse(reason);
    }

    // 6: FORWARD lookup keyed on the SNI domain (NEVER a reverse any-domain query).
    let key = AdmissionKey {
        session_uuid: origin.session.session_uuid.clone(),
        original_query_fqdn: sni.clone(),
    };
    match map.lookup(&key) {
        // A live admission for THIS domain: the kernel original_dst must be a
        // member of its admitted set, or the SNI claims a domain the dst was not
        // admitted for (the CDN shared-IP hole — refuse, never substitute).
        Some(entry) if !entry.is_expired_at(now) => {
            if dst_is_admitted(origin, &entry) {
                // ── THE THREE-WAY ADMISSION-POINT DECISION (doc 12 §3 / §5.3;
                //    D17/D74) ────────────────────────────────────────────────────
                // Every TLS-1 flow lands in EXACTLY ONE of three named outcomes; the
                // first was already decided ABOVE, this site decides the other two:
                //
                //   1. DENY → REFUSE — an edge rule (ECH / absent-SNI / IP-literal /
                //      non-ClientHello), a non-`Admit` policy verdict, or the CDN
                //      SNI-dst mismatch closed the connection with NO upstream opened.
                //      Decided BEFORE this branch (steps 1–6); a denied flow never
                //      reaches here, so a deny CANNOT degrade into a tunnel.
                //   2. PASS-THROUGH → OPAQUE TUNNEL, no-swap / no-inspect — the SNI is
                //      on the policy pass-through list: forwarded byte-identically to a
                //      plain tunnel but FROZEN against ever being TLS-terminated (no
                //      inspection, no credential swap, no secret scanning — the §3/§5.3
                //      stated non-claims). [`Tls1Decision::Passthrough`].
                //   3. OPAQUE TUNNEL → INSPECT-PATH ELIGIBLE — the SNI is NOT on the
                //      list: an ordinary opaque tunnel that the listener may route onto
                //      the TLS-3 inspected path when inspection is armed.
                //      [`Tls1Decision::Tunnel`].
                //
                // Step 7 is a tunnel-MODE refinement only — it never rescues a
                // non-admitted flow (that refused above) and never changes the
                // admission verdict (doc 12 §3: pass-through changes the tunnel mode,
                // never the verdict).
                //
                // FROZEN NON-CLAIMS that hold by construction here (doc 12 §3 / §5.3):
                //   - SNI + admission are enforced BEFORE the tunnel opens — steps 1–6
                //     (policy `Admit`, a live admission, and `original_dst ∈
                //     admitted_ips`) ALL passed before this branch.
                //   - The list ships EMPTY in the D64 baseline pack (D74), so under the
                //     baseline `is_passthrough` is `false` for every domain and EVERY
                //     admitted flow takes outcome 3 (`Tunnel`).
                //   - An entry is added to the list ONLY with attached reproduction
                //     evidence of a pinning failure — the list is a POLICY artifact
                //     (an external snapshot), NOT code, so this binary never grows a
                //     pass-through entry through a rebuild.
                //
                // DEFENSIVE EMPTY-LIST EDGE CASE (the load-bearing nil-handling): a
                // domain NOT FOUND on the list MUST take the inspect-eligible opaque
                // tunnel (outcome 3) — it must NEVER default to pass-through. The `if`
                // is therefore phrased on the POSITIVE predicate (`is_passthrough` ->
                // `true`) so the `else` (every not-found / empty-list domain) is the
                // SAFE inspect-eligible outcome. A future refactor MUST keep this
                // polarity: an absent list entry is "inspect", never "bypass".
                if passthrough.is_passthrough(&sni) {
                    // Outcome 2: on the list -> opaque pass-through, frozen against
                    // termination (no swap, no inspect — doc 12 §3 / §5.3).
                    Tls1Decision::Passthrough
                } else {
                    // Outcome 3: NOT on the list (the empty-list default, D74) ->
                    // opaque tunnel, eligible for the TLS-3 inspected path. This is
                    // the defensive fall-through: a domain the list does not name
                    // takes the inspect-eligible path, never pass-through.
                    Tls1Decision::Tunnel
                }
            } else {
                Tls1Decision::Refuse(RefuseReason::SniDstMismatch)
            }
        }
        // D68: a policy-allowed domain with an EXPIRED admission re-admits (the
        // resolve-once client whose cache outlived the deadline) — never refuses.
        Some(_expired) => Tls1Decision::ReAdmit {
            sni_domain: sni,
            cause: ReAdmitCause::Expired,
        },
        // D68: a policy-allowed domain with NO admission re-admits — re-resolve
        // through DNS-2 admission and dial a freshly admitted address.
        None => Tls1Decision::ReAdmit {
            sni_domain: sni,
            cause: ReAdmitCause::NoLiveAdmission,
        },
    }
}

/// The **operator-diagnostic** decision entry point (doc 12 §10.2): identical to
/// [`decide_with_passthrough`] in EVERY returned value, but with an additional
/// access-controlled operator-diagnostic sink attached that captures the dropped
/// inert-capability `requires` name off the §10/LOG-1 wire.
///
/// The decision itself is computed by the UNCHANGED [`decide_with_passthrough`], so
/// the returned [`Tls1Decision`] — and, on a refusal, the [`RefuseReason`] and its
/// `reason_code()` — are byte-identical whether or not a diagnostic sink is
/// attached. The ONLY additional behavior is a pure side-channel: when (and only
/// when) the decision is [`RefuseReason::PolicyCapabilityGated`] AND the
/// [`PolicyOracle`] surfaces an unmet capability name via
/// [`PolicyOracle::capability_requirement`], that name is recorded into `diagnostic`
/// (a [`CapabilityGateDiagnostic`]) — the SEPARATE, operator-access-controlled
/// surface, never the boundary refusal event (§10.2 fenced invariant).
///
/// This is the honest realization of the §10.2 split: the §10 refusal event stays
/// secret-free (`tls1-policy-capability-gated`, unchanged — the name is DROPPED from
/// the [`PolicyVerdict`] projection [`decide_with_passthrough`] acts on), while an
/// operator debugging the policy pack learns WHICH capability is missing through
/// this opt-in seam. The name flows `PolicyOracle::capability_requirement`
/// (available at `decide()`-time) → this side-channel → the sink; it NEVER touches
/// the returned decision. A caller with no diagnostic need uses the plain
/// [`decide`] / [`decide_with_passthrough`] path, which never opens this seam.
pub fn decide_with_diagnostic<M, P, L, D>(
    client_hello: &[u8],
    origin: &ConnOrigin,
    map: &M,
    policy: &P,
    passthrough: &L,
    diagnostic: &D,
    now: Instant,
) -> Tls1Decision
where
    M: AdmissionMap,
    P: PolicyOracle,
    L: PassthroughList,
    D: CapabilityGateDiagnostic,
{
    // The decision is computed by the UNCHANGED path — the returned value (and its
    // RefuseReason/reason_code on a refusal) is byte-identical to the non-diagnostic
    // caller. The diagnostic is a pure side-channel layered on top of it.
    let decision = decide_with_passthrough(client_hello, origin, map, policy, passthrough, now);

    // Operator-diagnostic side-channel, ON THE INERT-CAPABILITY REFUSAL ARM ONLY:
    // surface the dropped `requires` name into the access-controlled sink, off the
    // §10/LOG-1 event (§10.2). Re-derive the SNI from the same peeked bytes (the
    // parse is total + deterministic; on any other decision arm — including a parse
    // failure — the name is irrelevant and never captured), then ask the oracle for
    // the capability name it dropped from the secret-free PolicyVerdict. If the
    // oracle does not surface a name (the default), nothing is recorded — the
    // decision is unchanged either way.
    if decision == Tls1Decision::Refuse(RefuseReason::PolicyCapabilityGated) {
        if let Ok(sni) = parse_client_hello_sni(client_hello) {
            if let Some(requires) = policy.capability_requirement(&sni) {
                diagnostic.record_capability_gate(&sni, &requires);
            }
        }
    }

    decision
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientHello SNI peek (no TLS termination).
// ─────────────────────────────────────────────────────────────────────────────
//
// Parse just enough of the TLS record + handshake to (a) confirm this is a
// ClientHello, (b) extract the `server_name` (SNI) extension's first host_name,
// and (c) detect the `encrypted_client_hello` extension. We never decrypt, never
// continue the handshake, and never read past the buffered first record — the
// bytes are replayed upstream verbatim so the VM's real TLS handshake reaches the
// origin (opaque tunnel). All parsing is bounds-checked and total: any malformed/
// truncated input is a `NotAClientHello` refusal, never a panic.

/// The TLS `server_name` extension type (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;
/// The `encrypted_client_hello` extension type (RFC 9180 / draft-ietf-tls-esni —
/// the IANA-assigned code point `0xfe0d`). Its PRESENCE is the ECH signal we
/// refuse on (doc 12 §3); we do not parse its body.
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// The `server_name` NameType for a DNS host name (RFC 6066 — the only type we
/// admit; any other name type is treated as absent-SNI).
const SNI_NAME_TYPE_HOST: u8 = 0x00;
/// TLS record content type for a handshake record.
const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
/// Handshake message type for ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// A tiny bounds-checked byte cursor — every read returns `None` on underrun, so
/// the whole parser is total (a truncated ClientHello refuses, never panics).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }

    /// A 24-bit big-endian length (the handshake-message length field).
    fn u24(&mut self) -> Option<u32> {
        let a = self.u8()? as u32;
        let b = self.u8()? as u32;
        let c = self.u8()? as u32;
        Some((a << 16) | (b << 8) | c)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Skip `n` bytes (a field we do not inspect), failing on underrun.
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

/// Parse the peeked ClientHello and return its SNI host name, or the
/// [`RefuseReason`] for the first edge rule that fires.
///
/// Returns:
/// - `Err(NotAClientHello)` — not a handshake record / not a ClientHello /
///   truncated or malformed (total: never panics).
/// - `Err(EchPresent)` — the `encrypted_client_hello` extension is present.
/// - `Err(AbsentSni)` — no `server_name` extension, or an empty host name.
/// - `Err(IpLiteralSni)` — the host name is an IPv4/IPv6 literal.
/// - `Ok(domain)` — the lowercased SNI host name.
///
/// ECH detection takes precedence over the SNI it shadows: if ECH is present we
/// refuse regardless of any (outer) `server_name`, because the *inner* name is
/// what we would need and cannot see.
pub fn parse_client_hello_sni(buf: &[u8]) -> Result<String, RefuseReason> {
    let mut c = Cursor::new(buf);

    // ── TLS record header: type(1) version(2) length(2) ──────────────────────
    if c.u8().ok_or(RefuseReason::NotAClientHello)? != RECORD_TYPE_HANDSHAKE {
        return Err(RefuseReason::NotAClientHello);
    }
    c.skip(2).ok_or(RefuseReason::NotAClientHello)?; // legacy record version
    let _record_len = c.u16().ok_or(RefuseReason::NotAClientHello)?;

    // ── Handshake header: msg_type(1) length(3) ──────────────────────────────
    if c.u8().ok_or(RefuseReason::NotAClientHello)? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(RefuseReason::NotAClientHello);
    }
    let _hs_len = c.u24().ok_or(RefuseReason::NotAClientHello)?;

    // ── ClientHello body ──────────────────────────────────────────────────────
    // client_version(2) + random(32)
    c.skip(2 + 32).ok_or(RefuseReason::NotAClientHello)?;
    // legacy_session_id: u8 length-prefixed
    let sid_len = c.u8().ok_or(RefuseReason::NotAClientHello)? as usize;
    c.skip(sid_len).ok_or(RefuseReason::NotAClientHello)?;
    // cipher_suites: u16 length-prefixed
    let cs_len = c.u16().ok_or(RefuseReason::NotAClientHello)? as usize;
    c.skip(cs_len).ok_or(RefuseReason::NotAClientHello)?;
    // compression_methods: u8 length-prefixed
    let cm_len = c.u8().ok_or(RefuseReason::NotAClientHello)? as usize;
    c.skip(cm_len).ok_or(RefuseReason::NotAClientHello)?;

    // extensions: u16 length-prefixed block. A ClientHello with no extensions
    // block at all has no SNI → absent-SNI refusal (doc 12 §3).
    let ext_total = match c.u16() {
        Some(n) => n as usize,
        None => return Err(RefuseReason::AbsentSni),
    };
    let ext_block = c.take(ext_total).ok_or(RefuseReason::NotAClientHello)?;

    // Walk the extensions ONCE: detect ECH (refuse takes precedence) and capture
    // the server_name. We scan the whole block before deciding, so an ECH
    // extension that appears after server_name still wins.
    let mut ech_present = false;
    let mut server_name: Option<Result<String, RefuseReason>> = None;
    let mut e = Cursor::new(ext_block);
    // `e.u16()` yields `None` at the clean end of the extension block.
    while let Some(ext_type) = e.u16() {
        let ext_len = e.u16().ok_or(RefuseReason::NotAClientHello)? as usize;
        let ext_data = e.take(ext_len).ok_or(RefuseReason::NotAClientHello)?;
        match ext_type {
            EXT_ENCRYPTED_CLIENT_HELLO => ech_present = true,
            EXT_SERVER_NAME => {
                // Parse only the FIRST host_name entry of the server_name_list.
                server_name = Some(parse_server_name_ext(ext_data));
            }
            _ => {}
        }
    }

    // ECH refusal takes precedence over the SNI it shadows (doc 12 §3).
    if ech_present {
        return Err(RefuseReason::EchPresent);
    }
    match server_name {
        Some(result) => result,
        None => Err(RefuseReason::AbsentSni),
    }
}

/// Parse a `server_name` extension body (RFC 6066 `ServerNameList`) and return its
/// first DNS host name, or the refusal reason. The body is:
/// `server_name_list<2..2^16-1>` of `ServerName { name_type(1), HostName<1..2^16-1> }`.
fn parse_server_name_ext(data: &[u8]) -> Result<String, RefuseReason> {
    let mut c = Cursor::new(data);
    // server_name_list length (u16). An empty/absent list is absent-SNI.
    let list_len = c.u16().ok_or(RefuseReason::AbsentSni)? as usize;
    if list_len == 0 {
        return Err(RefuseReason::AbsentSni);
    }
    let list = c.take(list_len).ok_or(RefuseReason::AbsentSni)?;
    let mut l = Cursor::new(list);
    // First ServerName entry.
    let name_type = l.u8().ok_or(RefuseReason::AbsentSni)?;
    if name_type != SNI_NAME_TYPE_HOST {
        // A non-host_name name type carries no domain we can admit → absent-SNI.
        return Err(RefuseReason::AbsentSni);
    }
    let host_len = l.u16().ok_or(RefuseReason::AbsentSni)? as usize;
    if host_len == 0 {
        return Err(RefuseReason::AbsentSni);
    }
    let host_bytes = l.take(host_len).ok_or(RefuseReason::AbsentSni)?;
    // host_name must be valid UTF-8 (a DNS name is ASCII; non-UTF-8 is garbage we
    // cannot policy-evaluate → absent-SNI, never a guess).
    let host = std::str::from_utf8(host_bytes).map_err(|_| RefuseReason::AbsentSni)?;
    classify_host(host)
}

/// Classify a non-empty SNI host string: an IP literal refuses (IP-literal SNI);
/// otherwise the lowercased domain is returned. A trailing dot is stripped so
/// `example.com.` and `example.com` key the admission map identically (the map is
/// keyed on the original query FQDN in hostname form, doc 11/§dns_gate).
fn classify_host(host: &str) -> Result<String, RefuseReason> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() {
        return Err(RefuseReason::AbsentSni);
    }
    // IP-literal refusal (doc 12 §3): a v4 or v6 literal is not a domain we admit
    // by name. A bracketed v6 literal (`[::1]`) cannot appear in SNI (RFC 6066
    // forbids it) but we strip brackets defensively before the parse.
    let ip_candidate = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        return Err(RefuseReason::IpLiteralSni);
    }
    Ok(trimmed.to_ascii_lowercase())
}

// ─────────────────────────────────────────────────────────────────────────────
// Production policy adapter — confined here so the listener wires a ComposedPolicy
// behind the PolicyOracle trait. This is the ONLY place a policy-core engine type
// is named (still no pingora type — D40); it routes the SAME engine verdict the
// DNS admission used (POL-3, no reimplemented rule).
// ─────────────────────────────────────────────────────────────────────────────

/// The production [`PolicyOracle`]: a borrowed `ComposedPolicy` whose `verdict`
/// delegates to `policy_core::consumer::tls_connect_decision` — the connect-shaped
/// projection of the one engine verdict (doc 13 §1.1) — and narrows its
/// `DecisionKind` to the TLS-1 [`PolicyVerdict`]. The listener constructs one of
/// these per accepted connection from the live host policy snapshot and hands it
/// to [`decide`].
///
/// This is the ONLY place a `policy_core::consumer::DecisionKind` is named: the
/// `DecisionKind` → [`PolicyVerdict`] projection is confined to this adapter
/// (D40 — no pingora type, and now the policy-core verdict-class projection too),
/// so [`decide`] and the rest of this module speak only the small TLS-1 verdict.
pub struct PolicyCoreOracle<'a> {
    policy: &'a policy_core::pol1_eval::ComposedPolicy,
    /// The presenting sub-token's `ds_scopes` claim (doc 23 §6), threaded from the
    /// connect context. The scope-gated connect decision
    /// (`policy_core::consumer::tls_connect_decision_scoped`) asserts
    /// `v1:network:egress` on THIS set as an ADDITIONAL predicate BEFORE the domain
    /// engine runs: a connect whose token lacks egress is DENIED on the fast path
    /// (no domain lookup), fail-closed. When the set carries egress the scoped
    /// decision delegates verbatim to the unscoped engine verdict, so the domain
    /// verdict/rung/provenance are byte-identical to the pre-scope surface (POL-3 —
    /// no rule is re-decided).
    token_scopes: Vec<String>,
}

impl<'a> PolicyCoreOracle<'a> {
    /// Wrap a borrowed composed host policy for TLS-1 connect decisions, PRESENTING
    /// the network-egress scope. Equivalent to [`with_scopes`](Self::with_scopes)
    /// with an egress-carrying token: the scoped connect decision then delegates
    /// verbatim to the unscoped engine verdict, so this constructor's `verdict` /
    /// `capability_requirement` are BYTE-IDENTICAL to the pre-scope surface. Used
    /// where scope enforcement is not the subject under test (e.g. the §10.2
    /// capability-diagnostic tests); the live egress connect path threads the real
    /// presented `ds_scopes` via [`with_scopes`](Self::with_scopes).
    pub fn new(policy: &'a policy_core::pol1_eval::ComposedPolicy) -> PolicyCoreOracle<'a> {
        PolicyCoreOracle::with_scopes(
            policy,
            vec![ds_contracts::scopes::SCOPE_NETWORK_EGRESS.to_string()],
        )
    }

    /// Wrap a borrowed composed host policy with the connect's presented sub-token
    /// `ds_scopes` (doc 23 §6). The oracle's [`verdict`](PolicyOracle::verdict) then
    /// routes the scope-gated connect decision: a token lacking `v1:network:egress`
    /// DENIES before the domain engine (and, at the gate layer, before the
    /// admission-map lookup — a scope [`PolicyVerdict::Deny`] refuses at `decide`
    /// step 5, ahead of step 6's `map.lookup`); a token carrying it is byte-identical
    /// to the unscoped surface (POL-3). This is the constructor the live egress
    /// FORWARD path uses.
    pub fn with_scopes(
        policy: &'a policy_core::pol1_eval::ComposedPolicy,
        token_scopes: Vec<String>,
    ) -> PolicyCoreOracle<'a> {
        PolicyCoreOracle {
            policy,
            token_scopes,
        }
    }
}

impl PolicyOracle for PolicyCoreOracle<'_> {
    fn verdict(&self, sni_domain: &str) -> PolicyVerdict {
        // Route the SCOPE-GATED connect decision (doc 23 §6): the presenting
        // sub-token's `ds_scopes` gate `v1:network:egress` as an ADDITIONAL predicate
        // BEFORE the domain engine — a token lacking egress DENIES on the fast path
        // (no domain lookup), and a token carrying it delegates VERBATIM to the SAME
        // engine verdict the DNS admission used (POL-3 — no rule is reimplemented).
        // The DecisionKind is then narrowed to the TLS-1 verdict class. The match is
        // total over the READ-ONLY policy-core DecisionKind: any new engine kind would
        // fail to compile here rather than silently admit, so a future kind cannot
        // quietly weaken the boundary (fail-closed by construction). A scope-gate deny
        // surfaces as `DecisionKind::Deny` → `PolicyVerdict::Deny` (a hard refuse, not
        // an ask/hold). The InertCapabilityGated `requires` payload is dropped — the
        // unmet capability name is a policy detail, not a §10 reason code.
        let kind = policy_core::consumer::tls_connect_decision_scoped(
            self.policy,
            sni_domain,
            &self.token_scopes,
        )
        .kind;
        match kind {
            policy_core::consumer::DecisionKind::Admit => PolicyVerdict::Admit,
            policy_core::consumer::DecisionKind::Deny => PolicyVerdict::Deny,
            policy_core::consumer::DecisionKind::Ask => PolicyVerdict::Ask,
            policy_core::consumer::DecisionKind::InertCapabilityGated { .. } => {
                PolicyVerdict::CapabilityGated
            }
        }
    }

    fn capability_requirement(&self, sni_domain: &str) -> Option<String> {
        // Operator-diagnostic seam (doc 12 §10.2): surface the `requires` name the
        // secret-free `verdict` projection above DROPS from the InertCapabilityGated
        // arm. A scope-refused connect has NO capability diagnostic — the refusal is a
        // credential-scope deny, not an inert capability gate — so guard on the SAME
        // egress predicate the scoped decision applies (POL-3, no rule re-decided) and
        // surface `None` when the token lacks egress, WITHOUT reaching the domain
        // engine. When egress IS present the scoped decision is byte-identical to the
        // unscoped surface, so this routes the SAME engine verdict as before and
        // returns the capability name ONLY for the inert-capability-gated kind; every
        // other kind (including Admit/Deny/Ask) surfaces `None`. This is consumed
        // exclusively by `decide_with_diagnostic`, off the §10/LOG-1 event — the
        // boundary refusal event's `reason_code` stays `tls1-policy-capability-gated`,
        // secret-free, unchanged.
        if !policy_core::consumer::egress_scope_satisfied(&self.token_scopes) {
            return None;
        }
        match policy_core::consumer::tls_connect_decision(self.policy, sni_domain).kind {
            policy_core::consumer::DecisionKind::InertCapabilityGated { requires } => {
                Some(requires)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ds_contracts::dns_admission::{
        AddressFamily, AdmissionEntry, AdmissionError, AdmissionType, Provenance, ReverseIndex,
    };
    use ds_contracts::session::SessionRef;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    // ── synthetic ClientHello builder ─────────────────────────────────────────
    //
    // Build a minimal-but-well-formed TLS 1.2-shaped ClientHello with a chosen
    // extension list, so the parser is exercised on real wire bytes with no TLS
    // stack. `extensions` is a flat list of (ext_type, ext_body) already encoded.

    fn ext(ext_type: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ext_type.to_be_bytes());
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A `server_name` extension body carrying one host_name.
    fn server_name_body(host: &str) -> Vec<u8> {
        let mut name = Vec::new();
        name.push(SNI_NAME_TYPE_HOST);
        name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        name.extend_from_slice(host.as_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&(name.len() as u16).to_be_bytes()); // list length
        body.extend_from_slice(&name);
        body
    }

    /// Assemble a ClientHello record from an extensions byte block.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        // ClientHello body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + one suite
        body.push(1); // compression_methods length 1
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        // Handshake header
        let mut hs = Vec::new();
        hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = body.len() as u32;
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(&body);

        // Record header
        let mut rec = Vec::new();
        rec.push(RECORD_TYPE_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A ClientHello whose only extension is a host_name SNI.
    fn ch_with_sni(host: &str) -> Vec<u8> {
        client_hello(&ext(EXT_SERVER_NAME, &server_name_body(host)))
    }

    // ── mock AdmissionMap ─────────────────────────────────────────────────────

    #[derive(Default)]
    struct MockReverse;
    impl ReverseIndex for MockReverse {
        fn incref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
            0
        }
        fn decref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
            0
        }
        fn refcount(&self, _s: &str, _ip: &AdmittedAddr) -> u32 {
            0
        }
    }

    #[derive(Default)]
    struct MockMap {
        entries: HashMap<(String, String), AdmissionEntry>,
        reverse: MockReverse,
    }

    impl MockMap {
        fn insert(&mut self, session: &str, fqdn: &str, entry: AdmissionEntry) {
            self.entries
                .insert((session.to_string(), fqdn.to_string()), entry);
        }
    }

    impl AdmissionMap for MockMap {
        type Reverse = MockReverse;
        fn admit(
            &mut self,
            key: AdmissionKey,
            entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            self.entries
                .insert((key.session_uuid, key.original_query_fqdn), entry);
            Ok(())
        }
        fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
            // No self-eviction (W4): returns expired entries too — the caller's
            // is_expired_at gate is what re-admits them (D68).
            self.entries
                .get(&(key.session_uuid.clone(), key.original_query_fqdn.clone()))
                .cloned()
        }
        fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            self.entries
                .remove(&(key.session_uuid.clone(), key.original_query_fqdn.clone()));
            Ok(vec![])
        }
        fn reverse_index(&self) -> &Self::Reverse {
            &self.reverse
        }
    }

    // ── mock PolicyOracle ─────────────────────────────────────────────────────
    //
    // The mock returns a per-domain PolicyVerdict; an unlisted domain defaults to
    // Deny (fail-closed, the same default the engine takes for an unknown domain
    // under a deny posture). `allowing` keeps the common "these domains admit, all
    // else deny" shape every pre-existing test uses; `with_verdicts` lets the
    // taxonomy tests pin a domain to Ask or CapabilityGated.

    struct MockPolicy {
        verdicts: HashMap<String, PolicyVerdict>,
        // The operator-diagnostic `requires` name per domain (doc 12 §10.2): what
        // `capability_requirement` surfaces for a CapabilityGated verdict — the name
        // the secret-free `verdict` projection drops. Empty unless a test pins it, so
        // every pre-existing test surfaces `None` (the diagnostic seam is inert).
        requires: HashMap<String, String>,
    }
    impl MockPolicy {
        fn allowing(domains: &[&str]) -> MockPolicy {
            MockPolicy {
                verdicts: domains
                    .iter()
                    .map(|s| (s.to_string(), PolicyVerdict::Admit))
                    .collect(),
                requires: HashMap::new(),
            }
        }
        fn deny_all() -> MockPolicy {
            MockPolicy {
                verdicts: HashMap::new(),
                requires: HashMap::new(),
            }
        }
        fn with_verdicts(pairs: &[(&str, PolicyVerdict)]) -> MockPolicy {
            MockPolicy {
                verdicts: pairs.iter().map(|(d, v)| (d.to_string(), *v)).collect(),
                requires: HashMap::new(),
            }
        }
        /// Pin a domain to a CapabilityGated verdict whose operator-diagnostic
        /// `requires` name is `capability` — the fixture the §10.2 diagnostic-seam
        /// test drives. `verdict` still returns the secret-free CapabilityGated
        /// projection; only `capability_requirement` surfaces the name.
        fn capability_gated(domain: &str, capability: &str) -> MockPolicy {
            let mut requires = HashMap::new();
            requires.insert(domain.to_string(), capability.to_string());
            MockPolicy {
                verdicts: [(domain.to_string(), PolicyVerdict::CapabilityGated)]
                    .into_iter()
                    .collect(),
                requires,
            }
        }
    }
    impl PolicyOracle for MockPolicy {
        fn verdict(&self, sni_domain: &str) -> PolicyVerdict {
            // Unlisted → Deny: the fail-closed default (an absent allow is a deny).
            self.verdicts
                .get(sni_domain)
                .copied()
                .unwrap_or(PolicyVerdict::Deny)
        }
        fn capability_requirement(&self, sni_domain: &str) -> Option<String> {
            // Surface the dropped `requires` name (doc 12 §10.2) ONLY when this
            // domain is a CapabilityGated verdict with a pinned name — the same shape
            // the production PolicyCoreOracle uses. Every other domain → None.
            self.requires.get(sni_domain).cloned()
        }
    }

    // ── mock PassthroughList ──────────────────────────────────────────────────
    //
    // A configurable pass-through set, so the taxonomy tests can pin a domain ONTO
    // the list (it then passes through) while the empty default (the D74 invariant)
    // is the production [`EmptyPassthroughList`] every pre-existing test uses via
    // [`empty_passthrough`].

    struct MockPassthrough {
        listed: std::collections::HashSet<String>,
    }
    impl MockPassthrough {
        fn listing(domains: &[&str]) -> MockPassthrough {
            MockPassthrough {
                listed: domains.iter().map(|s| s.to_string()).collect(),
            }
        }
    }
    impl PassthroughList for MockPassthrough {
        fn is_passthrough(&self, sni_domain: &str) -> bool {
            self.listed.contains(sni_domain)
        }
    }

    /// The production D74 empty list — what every test that is not exercising the
    /// pass-through path itself runs with (the shipped default: no domain passes
    /// through, every admitted flow opaquely tunnels).
    fn empty_passthrough() -> EmptyPassthroughList {
        EmptyPassthroughList
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    const SESSION_UUID: &str = "11111111-2222-3333-4444-555555555555";

    fn session() -> SessionRef {
        SessionRef::new(SESSION_UUID.into(), "host-a".into(), 7, "dstap-7".into())
    }

    fn origin_to(dst: &str) -> ConnOrigin {
        let original_dst: SocketAddr = dst.parse().unwrap();
        ConnOrigin {
            original_dst,
            session: session(),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![a, b, c, d],
        }
    }

    fn entry(ips: Vec<AdmittedAddr>, expires_at: u64) -> AdmissionEntry {
        AdmissionEntry {
            admitted_ips: ips,
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            expires_at: Instant::from_unix_nanos(expires_at),
            admitted_at: Instant::from_unix_nanos(0),
            provenance: Provenance {
                rule_id: "r1".into(),
                policy_layer: "org".into(),
                policy_version: "v0".into(),
            },
        }
    }

    fn now(t: u64) -> Instant {
        Instant::from_unix_nanos(t)
    }

    // ── 1. mismatched-SNI refused (the CDN shared-IP hole close) ──────────────

    #[test]
    fn mismatched_sni_refused_dst_admitted_for_a_but_sni_claims_b() {
        // The hole: original_dst 203.0.113.10 is admitted for domain A
        // (a.example) on a shared CDN, but the client's SNI claims b.example.
        // A FORWARD lookup keyed on the SNI (b.example) selects b.example's entry,
        // and 203.0.113.10 is NOT in it → refuse. A reverse "is 203.0.113.10
        // admitted for any domain" check would WRONGLY admit (that is the hole).
        let mut map = MockMap::default();
        // a.example is admitted on the shared IP...
        map.insert(
            SESSION_UUID,
            "a.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        // b.example is admitted, but on a DIFFERENT IP (198.51.100.7).
        map.insert(
            SESSION_UUID,
            "b.example",
            entry(vec![v4(198, 51, 100, 7)], 10_000),
        );
        // policy allows both domains.
        let policy = MockPolicy::allowing(&["a.example", "b.example"]);

        // client dials the shared CDN IP (admitted for a.example) but SNIs b.example.
        let hello = ch_with_sni("b.example");
        let origin = origin_to("203.0.113.10:443");
        let d = decide(&hello, &origin, &map, &policy, now(0));
        assert_eq!(
            d,
            Tls1Decision::Refuse(RefuseReason::SniDstMismatch),
            "SNI b.example over a.example's admitted IP must refuse (CDN hole closed)"
        );

        // and the legitimate pairing (SNI a.example over a.example's IP) tunnels.
        let hello_a = ch_with_sni("a.example");
        assert_eq!(
            decide(&hello_a, &origin, &map, &policy, now(0)),
            Tls1Decision::Tunnel
        );
    }

    // ── 2. ECH refused ────────────────────────────────────────────────────────

    #[test]
    fn ech_clienthello_refused_even_with_outer_sni() {
        // An ECH extension shadows the real (inner) name; the outer server_name is
        // the CDN's. Refuse regardless of the outer SNI (doc 12 §3) — and the
        // refusal wins even though the server_name extension is also present.
        let mut exts = ext(EXT_SERVER_NAME, &server_name_body("cdn.example"));
        exts.extend_from_slice(&ext(EXT_ENCRYPTED_CLIENT_HELLO, &[0x00, 0x01, 0x02]));
        let hello = client_hello(&exts);

        let map = MockMap::default();
        let policy = MockPolicy::allowing(&["cdn.example"]);
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::EchPresent)
        );
        // and the parser-level check agrees.
        assert_eq!(
            parse_client_hello_sni(&hello),
            Err(RefuseReason::EchPresent)
        );
    }

    // ── 3. absent-SNI / IP-literal refused ────────────────────────────────────

    #[test]
    fn absent_sni_refused() {
        // A ClientHello with NO server_name extension at all.
        let hello = client_hello(&[]);
        assert_eq!(parse_client_hello_sni(&hello), Err(RefuseReason::AbsentSni));

        let map = MockMap::default();
        let policy = MockPolicy::allowing(&["anything"]);
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::AbsentSni)
        );

        // An empty host_name is also absent-SNI.
        let empty = client_hello(&ext(EXT_SERVER_NAME, &server_name_body("")));
        assert_eq!(parse_client_hello_sni(&empty), Err(RefuseReason::AbsentSni));
    }

    #[test]
    fn ip_literal_sni_refused_v4_and_v6() {
        let map = MockMap::default();
        let policy = MockPolicy::allowing(&["203.0.113.10", "2001:db8::1"]);

        let v4_hello = ch_with_sni("203.0.113.10");
        assert_eq!(
            parse_client_hello_sni(&v4_hello),
            Err(RefuseReason::IpLiteralSni)
        );
        assert_eq!(
            decide(
                &v4_hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::IpLiteralSni)
        );

        let v6_hello = ch_with_sni("2001:db8::1");
        assert_eq!(
            parse_client_hello_sni(&v6_hello),
            Err(RefuseReason::IpLiteralSni)
        );
    }

    // ── 4. admitted-pair tunnels ──────────────────────────────────────────────

    #[test]
    fn admitted_pair_tunnels_opaquely() {
        // policy allows the SNI, a live admission for that SNI includes the kernel
        // original_dst → Tunnel.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "api.example",
            entry(vec![v4(203, 0, 113, 10), v4(203, 0, 113, 11)], 10_000),
        );
        let policy = MockPolicy::allowing(&["api.example"]);
        let hello = ch_with_sni("api.example");

        // both admitted IPs tunnel.
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Tunnel
        );
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.11:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Tunnel
        );
        // a NON-admitted IP for the same admitted domain refuses (dst mismatch).
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.99:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::SniDstMismatch)
        );
    }

    #[test]
    fn trailing_dot_sni_keys_the_map_identically() {
        // `api.example.` (FQDN form) must key the same admission as `api.example`.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "api.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let policy = MockPolicy::allowing(&["api.example"]);
        let hello = ch_with_sni("api.example.");
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Tunnel
        );
    }

    // ── 5. expired-entry re-admit-signal (D68) ────────────────────────────────

    #[test]
    fn expired_entry_re_admits_not_refuses() {
        // A policy-allowed SNI whose admission EXPIRED at t=1000 is RE-ADMITTED at
        // t=2000 (the resolve-once client) — NOT refused. The decision is ReAdmit;
        // the cross-service re-resolve is the documented seam.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "api.example",
            entry(vec![v4(203, 0, 113, 10)], 1_000),
        );
        let policy = MockPolicy::allowing(&["api.example"]);
        let hello = ch_with_sni("api.example");

        let d = decide(
            &hello,
            &origin_to("203.0.113.10:443"),
            &map,
            &policy,
            now(2_000),
        );
        assert_eq!(
            d,
            Tls1Decision::ReAdmit {
                sni_domain: "api.example".to_string(),
                cause: ReAdmitCause::Expired,
            }
        );

        // BEFORE expiry (t=999) the SAME pair tunnels — expiry is the caller's gate.
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(999)
            ),
            Tls1Decision::Tunnel
        );
    }

    #[test]
    fn no_live_admission_re_admits_not_refuses() {
        // policy ALLOWS the SNI but there is NO admission at all → re-admit (D68),
        // never refuse. This is the resolve-once client whose admission never
        // landed / was cleaned up.
        let map = MockMap::default();
        let policy = MockPolicy::allowing(&["api.example"]);
        let hello = ch_with_sni("api.example");
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::ReAdmit {
                sni_domain: "api.example".to_string(),
                cause: ReAdmitCause::NoLiveAdmission,
            }
        );
    }

    // ── 6. policy-deny refused ────────────────────────────────────────────────

    #[test]
    fn policy_deny_refused_even_with_live_admission() {
        // policy DENY is the only non-edge refusal. Even a live admission for the
        // dst does not rescue a denied domain — policy is consulted first.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "blocked.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let policy = MockPolicy::deny_all();
        let hello = ch_with_sni("blocked.example");
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::PolicyDeny)
        );
    }

    #[test]
    fn policy_deny_is_checked_before_the_admission_map() {
        // A denied domain must NEVER reach the admission map or the re-resolve seam
        // (no admission, no re-admit) — it refuses on policy alone.
        let map = MockMap::default(); // empty: a re-admit would fire if we reached it
        let policy = MockPolicy::deny_all();
        let hello = ch_with_sni("blocked.example");
        // empty map + allowed would ReAdmit; deny short-circuits to Refuse.
        assert_eq!(
            decide(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::PolicyDeny)
        );
    }

    // ── the policy refusal TAXONOMY: deny vs ask vs inert-capability-gated ─────
    //
    // The whole point of this unit: a hard deny, an ask-posture, and an inert
    // capability-gated verdict each REFUSE (fail-closed), but each carries its OWN
    // §10 reason code so the operator sees an accurate refusal cause — never one
    // `tls1-policy-deny` conflating all three.

    #[test]
    fn policy_ask_and_capability_gated_refuse_with_distinct_reason_codes() {
        // Same kernel dst, same live admission, three SNIs — one Deny, one Ask, one
        // CapabilityGated. All three REFUSE; the three reason codes are DISTINCT.
        let mut map = MockMap::default();
        for sni in ["deny.example", "ask.example", "gated.example"] {
            map.insert(SESSION_UUID, sni, entry(vec![v4(203, 0, 113, 10)], 10_000));
        }
        let policy = MockPolicy::with_verdicts(&[
            ("deny.example", PolicyVerdict::Deny),
            ("ask.example", PolicyVerdict::Ask),
            ("gated.example", PolicyVerdict::CapabilityGated),
        ]);
        let origin = origin_to("203.0.113.10:443");

        let deny = decide(&ch_with_sni("deny.example"), &origin, &map, &policy, now(0));
        let ask = decide(&ch_with_sni("ask.example"), &origin, &map, &policy, now(0));
        let gated = decide(
            &ch_with_sni("gated.example"),
            &origin,
            &map,
            &policy,
            now(0),
        );

        // All three REFUSE (fail-closed: only Admit proceeds, even with a live
        // admission for the kernel dst).
        assert_eq!(deny, Tls1Decision::Refuse(RefuseReason::PolicyDeny));
        assert_eq!(ask, Tls1Decision::Refuse(RefuseReason::PolicyAsk));
        assert_eq!(
            gated,
            Tls1Decision::Refuse(RefuseReason::PolicyCapabilityGated)
        );

        // The three reason codes are pairwise DISTINCT (telemetry fidelity).
        let codes = [
            RefuseReason::PolicyDeny.reason_code(),
            RefuseReason::PolicyAsk.reason_code(),
            RefuseReason::PolicyCapabilityGated.reason_code(),
        ];
        assert_eq!(codes[0], "tls1-policy-deny");
        assert_eq!(codes[1], "tls1-policy-ask");
        assert_eq!(codes[2], "tls1-policy-capability-gated");
        // distinctness, made explicit (no two policy classes share a code).
        assert_ne!(codes[0], codes[1]);
        assert_ne!(codes[1], codes[2]);
        assert_ne!(codes[0], codes[2]);
    }

    #[test]
    fn inert_capability_gated_stays_distinct_from_deny_not_a_deny() {
        // §1.7: an inert capability-gated verdict admits NOTHING and is DISTINCT
        // from a deny. It refuses (fail-closed) but NEVER under the deny code —
        // the operator must be able to tell an unmet-capability gate apart from an
        // explicit policy block.
        let map = MockMap::default(); // empty: an Admit here would ReAdmit, not refuse
        let policy =
            MockPolicy::with_verdicts(&[("gated.example", PolicyVerdict::CapabilityGated)]);
        let d = decide(
            &ch_with_sni("gated.example"),
            &origin_to("203.0.113.10:443"),
            &map,
            &policy,
            now(0),
        );
        assert_eq!(
            d,
            Tls1Decision::Refuse(RefuseReason::PolicyCapabilityGated),
            "an inert capability-gated verdict refuses with its OWN code, not as a deny"
        );
        // and the code is NOT the deny code.
        let Tls1Decision::Refuse(reason) = d else {
            panic!("expected a refusal");
        };
        assert_ne!(reason.reason_code(), RefuseReason::PolicyDeny.reason_code());
    }

    #[test]
    fn ask_verdict_short_circuits_before_the_admission_map() {
        // Like deny, a non-Admit verdict (here Ask) never reaches the admission
        // map or the re-resolve seam — an empty map would ReAdmit a policy-ALLOWED
        // domain, but Ask refuses on policy alone (no re-admit).
        let map = MockMap::default();
        let policy = MockPolicy::with_verdicts(&[("ask.example", PolicyVerdict::Ask)]);
        assert_eq!(
            decide(
                &ch_with_sni("ask.example"),
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                now(0)
            ),
            Tls1Decision::Refuse(RefuseReason::PolicyAsk)
        );
    }

    #[test]
    fn policy_verdict_admits_only_admit_and_maps_each_class_to_its_reason() {
        // The single mapping site: only Admit proceeds (refuse_reason None); every
        // other class maps to its distinct reason code.
        assert!(PolicyVerdict::Admit.admits());
        assert!(!PolicyVerdict::Deny.admits());
        assert!(!PolicyVerdict::Ask.admits());
        assert!(!PolicyVerdict::CapabilityGated.admits());

        assert_eq!(PolicyVerdict::Admit.refuse_reason(), None);
        assert_eq!(
            PolicyVerdict::Deny.refuse_reason(),
            Some(RefuseReason::PolicyDeny)
        );
        assert_eq!(
            PolicyVerdict::Ask.refuse_reason(),
            Some(RefuseReason::PolicyAsk)
        );
        assert_eq!(
            PolicyVerdict::CapabilityGated.refuse_reason(),
            Some(RefuseReason::PolicyCapabilityGated)
        );
    }

    // ── the FORWARD-not-reverse discipline, made explicit ─────────────────────

    #[test]
    fn admission_is_a_forward_lookup_by_sni_never_a_reverse_any_domain_query() {
        // Two domains share one CDN IP. Only a.example is admitted on it; b.example
        // is admitted on a different IP. A reverse "is 203.0.113.10 admitted for
        // ANY domain" query would admit BOTH SNIs to 203.0.113.10 — the hole. The
        // forward lookup admits ONLY the SNI whose entry contains the dst.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "a.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        map.insert(
            SESSION_UUID,
            "b.example",
            entry(vec![v4(198, 51, 100, 7)], 10_000),
        );
        let policy = MockPolicy::allowing(&["a.example", "b.example"]);
        let dst = origin_to("203.0.113.10:443");

        // SNI a.example → the dst is in a.example's entry → Tunnel.
        assert_eq!(
            decide(&ch_with_sni("a.example"), &dst, &map, &policy, now(0)),
            Tls1Decision::Tunnel
        );
        // SNI b.example over the SAME dst → b.example's entry does NOT contain it
        // → refuse. (b IS admitted somewhere, so a reverse query would mis-admit.)
        assert_eq!(
            decide(&ch_with_sni("b.example"), &dst, &map, &policy, now(0)),
            Tls1Decision::Refuse(RefuseReason::SniDstMismatch)
        );
    }

    // ── parser robustness: every malformed input refuses, never panics ────────

    #[test]
    fn malformed_or_truncated_inputs_refuse_not_panic() {
        // empty
        assert_eq!(
            parse_client_hello_sni(&[]),
            Err(RefuseReason::NotAClientHello)
        );
        // not a handshake record
        assert_eq!(
            parse_client_hello_sni(&[0x17, 0x03, 0x03, 0x00, 0x05]),
            Err(RefuseReason::NotAClientHello)
        );
        // a handshake record but not a ClientHello (e.g. ServerHello type 0x02)
        let mut not_ch = client_hello(&[]);
        // flip the handshake msg_type byte (record header is 5 bytes; msg_type is byte 5)
        not_ch[5] = 0x02;
        assert_eq!(
            parse_client_hello_sni(&not_ch),
            Err(RefuseReason::NotAClientHello)
        );
        // truncate a valid ClientHello at every length: never a panic, always Err.
        let full = ch_with_sni("api.example");
        for n in 0..full.len() {
            let _ = parse_client_hello_sni(&full[..n]); // must not panic
        }
    }

    #[test]
    fn parser_extracts_and_lowercases_the_sni() {
        // mixed-case SNI is lowercased so it keys the map canonically.
        assert_eq!(
            parse_client_hello_sni(&ch_with_sni("API.Example.COM")).unwrap(),
            "api.example.com"
        );
    }

    // ── the re-resolve seam is honest: the decision names it, does not wire it ─

    #[test]
    fn re_admit_carries_the_domain_for_the_reresolve_seam() {
        // The ReAdmit decision carries the SNI domain the listener feeds to the
        // ReResolve seam (the cross-service DNS-2 re-resolve). A mock seam stands
        // in for ds-dnsgate; the wiring (decision → seam → dial) is what the
        // listener does, proven here with a fake.
        struct FakeReResolve;
        impl ReResolve for FakeReResolve {
            fn reresolve(&self, session: &str, domain: &str) -> Option<Vec<AdmittedAddr>> {
                assert_eq!(session, SESSION_UUID);
                assert_eq!(domain, "api.example");
                Some(vec![v4(203, 0, 113, 55)])
            }
        }
        let map = MockMap::default();
        let policy = MockPolicy::allowing(&["api.example"]);
        let d = decide(
            &ch_with_sni("api.example"),
            &origin_to("203.0.113.10:443"),
            &map,
            &policy,
            now(0),
        );
        let Tls1Decision::ReAdmit { sni_domain, .. } = d else {
            panic!("expected ReAdmit, got {d:?}");
        };
        // the listener drives the seam with the carried domain.
        let seam = FakeReResolve;
        let fresh = seam
            .reresolve(SESSION_UUID, &sni_domain)
            .expect("re-admitted");
        assert_eq!(fresh, vec![v4(203, 0, 113, 55)]);
    }

    #[test]
    fn refuse_reason_codes_are_stable_and_secret_free() {
        assert_eq!(
            RefuseReason::NotAClientHello.reason_code(),
            "tls1-not-a-clienthello"
        );
        assert_eq!(
            RefuseReason::ClientHelloFlood.reason_code(),
            "tls1-clienthello-flood"
        );
        assert_eq!(RefuseReason::EchPresent.reason_code(), "tls1-ech-refused");
        assert_eq!(RefuseReason::AbsentSni.reason_code(), "tls1-absent-sni");
        assert_eq!(
            RefuseReason::IpLiteralSni.reason_code(),
            "tls1-ip-literal-sni"
        );
        assert_eq!(RefuseReason::PolicyDeny.reason_code(), "tls1-policy-deny");
        assert_eq!(RefuseReason::PolicyAsk.reason_code(), "tls1-policy-ask");
        assert_eq!(
            RefuseReason::PolicyCapabilityGated.reason_code(),
            "tls1-policy-capability-gated"
        );
        assert_eq!(
            RefuseReason::SniDstMismatch.reason_code(),
            "tls1-sni-dst-mismatch"
        );
        assert_eq!(
            RefuseReason::ReAdmitDenied.reason_code(),
            "tls1-readmit-denied"
        );
        // A tiny-record flood is a DISTINCT refusal cause from generic garbage: its
        // stable code must not collide with NotAClientHello (the §10 telemetry tells
        // a flood apart from a malformed/truncated prefix).
        assert_ne!(
            RefuseReason::ClientHelloFlood.reason_code(),
            RefuseReason::NotAClientHello.reason_code()
        );
        // A re-admit denial (an ABSENT admission the re-resolve could not freshly
        // establish) is a DISTINCT cause from an SNI/dst mismatch (a PRESENT but
        // wrong admission — the CDN hole): the two codes must not collide so the §10
        // telemetry attributes a re-admit failure to its own cause.
        assert_ne!(
            RefuseReason::ReAdmitDenied.reason_code(),
            RefuseReason::SniDstMismatch.reason_code()
        );
    }

    // ── the operator-diagnostic seam for the dropped capability name (§10.2) ───
    //
    // The whole point of THIS unit: an inert-capability refusal keeps the §10 event
    // secret-free (`tls1-policy-capability-gated`, byte-identical), while a SEPARATE
    // access-controlled operator-diagnostic sink surfaces WHICH capability is missing
    // — the `requires` name dropped from the PolicyVerdict projection.

    /// A recording operator-diagnostic sink: captures the (sni, requires) pairs the
    /// §10.2 seam records, so the test can assert the capability name reached the
    /// operator surface. Stands in for a real access-controlled operator facility.
    #[derive(Default)]
    struct RecordingDiagnostic {
        captured: std::cell::RefCell<Vec<(String, String)>>,
    }
    impl CapabilityGateDiagnostic for RecordingDiagnostic {
        fn record_capability_gate(&self, sni_domain: &str, requires: &str) {
            self.captured
                .borrow_mut()
                .push((sni_domain.to_string(), requires.to_string()));
        }
    }

    #[test]
    fn operator_diagnostic_surfaces_capability_name_while_event_stays_secret_free() {
        // A domain that matches ONLY a capability-gated (inert) entry requiring
        // "http-policy". The §10 refusal event MUST stay byte-identical
        // (`tls1-policy-capability-gated`, no name), and the operator-diagnostic sink
        // MUST receive the dropped `requires` name — off the boundary event.
        let map = MockMap::default(); // empty: an Admit here would ReAdmit, not refuse
        let policy = MockPolicy::capability_gated("gated.example", "http-policy");
        let hello = ch_with_sni("gated.example");
        let origin = origin_to("203.0.113.10:443");

        // The plain (non-diagnostic) decision — the byte-exact reference the §10
        // event carries. No name is captured, no sink is consulted.
        let plain = decide(&hello, &origin, &map, &policy, now(0));
        assert_eq!(
            plain,
            Tls1Decision::Refuse(RefuseReason::PolicyCapabilityGated),
            "an inert capability-gated verdict refuses with the secret-free code"
        );

        // The operator-diagnostic decision — IDENTICAL returned value, plus the sink.
        let sink = RecordingDiagnostic::default();
        let diag = decide_with_diagnostic(
            &hello,
            &origin,
            &map,
            &policy,
            &EmptyPassthroughList,
            &sink,
            now(0),
        );

        // (1) The §10 RefuseReason + reason_code stay BYTE-IDENTICAL to the plain
        //     path — no capability name leaks into the boundary refusal event.
        assert_eq!(
            diag, plain,
            "the diagnostic path returns the byte-identical decision as the plain path"
        );
        let Tls1Decision::Refuse(reason) = diag else {
            panic!("expected a refusal");
        };
        assert_eq!(
            reason.reason_code(),
            "tls1-policy-capability-gated",
            "the §10 reason code stays secret-free (unchanged) with the sink attached"
        );
        // the capability name is NOT anywhere in the §10 reason code (secret-free).
        assert!(
            !reason.reason_code().contains("http-policy"),
            "the unmet capability name must NEVER appear in the §10 reason code"
        );

        // (2) The operator-diagnostic sink DID receive the dropped `requires` name —
        //     surfacing WHICH capability is missing, off the §10 event.
        let captured = sink.captured.borrow();
        assert_eq!(
            captured.as_slice(),
            &[("gated.example".to_string(), "http-policy".to_string())],
            "the operator-diagnostic seam surfaces the dropped capability name off the §10 wire"
        );
    }

    #[test]
    fn operator_diagnostic_is_inert_on_non_capability_gated_decisions() {
        // The diagnostic side-channel fires ONLY on the inert-capability refusal arm:
        // an admitted tunnel, a policy deny, and a re-admit all leave the sink empty,
        // and the returned decision is byte-identical to the plain path.
        let origin = origin_to("203.0.113.10:443");
        let sink = RecordingDiagnostic::default();

        // ADMIT → Tunnel: no capability gate, sink stays empty.
        let (map, policy, hello) = admitted_flow("api.example");
        let d = decide_with_diagnostic(
            &hello,
            &origin,
            &map,
            &policy,
            &EmptyPassthroughList,
            &sink,
            now(0),
        );
        assert_eq!(d, Tls1Decision::Tunnel);
        assert!(sink.captured.borrow().is_empty());

        // DENY: refuses, but under the DENY code — not a capability gate, sink empty.
        let deny_policy = MockPolicy::deny_all();
        let deny_map = MockMap::default();
        let d = decide_with_diagnostic(
            &ch_with_sni("blocked.example"),
            &origin,
            &deny_map,
            &deny_policy,
            &EmptyPassthroughList,
            &sink,
            now(0),
        );
        assert_eq!(d, Tls1Decision::Refuse(RefuseReason::PolicyDeny));
        assert!(sink.captured.borrow().is_empty());

        // CapabilityGated verdict WITHOUT a surfaced name (the default oracle): still
        // the secret-free refusal, and nothing recorded (the seam records only when a
        // name is available — an oracle that surfaces None captures nothing).
        let nameless =
            MockPolicy::with_verdicts(&[("gated.example", PolicyVerdict::CapabilityGated)]);
        let nameless_map = MockMap::default();
        let d = decide_with_diagnostic(
            &ch_with_sni("gated.example"),
            &origin,
            &nameless_map,
            &nameless,
            &EmptyPassthroughList,
            &sink,
            now(0),
        );
        assert_eq!(d, Tls1Decision::Refuse(RefuseReason::PolicyCapabilityGated));
        assert!(
            sink.captured.borrow().is_empty(),
            "an oracle that surfaces no capability name records nothing — the decision is unchanged"
        );
    }

    #[test]
    fn policy_verdict_projection_still_drops_the_capability_name() {
        // The secret-free PolicyVerdict projection is unchanged: a CapabilityGated
        // verdict carries NO name (the name rides only the separate diagnostic seam).
        // PolicyVerdict has no payload variant, so a name cannot be attached to it.
        let policy = MockPolicy::capability_gated("gated.example", "http-policy");
        assert_eq!(
            policy.verdict("gated.example"),
            PolicyVerdict::CapabilityGated
        );
        // the verdict maps to the secret-free reason with no name.
        assert_eq!(
            policy.verdict("gated.example").refuse_reason(),
            Some(RefuseReason::PolicyCapabilityGated)
        );
        // the name is available ONLY through the separate operator-diagnostic accessor.
        assert_eq!(
            policy.capability_requirement("gated.example"),
            Some("http-policy".to_string())
        );
        // and only for the gated domain — every other domain surfaces None.
        assert_eq!(policy.capability_requirement("other.example"), None);
    }

    #[test]
    fn production_oracle_capability_requirement_surfaces_the_engine_requires_name() {
        // The PRODUCTION adapter, not the mock: PolicyCoreOracle::capability_requirement
        // must surface the REAL engine's `requires` string through the same
        // parse → compose path the proxy boots with (POL-3 — no rule reimplemented),
        // and ONLY for the inert-capability-gated kind. This pins the §10.2 seam to
        // the engine payload, so the mock above cannot drift from what production
        // actually returns.
        // The capability gate (`requires:`) rides a BASELINE-PACK entry (doc 13 §3;
        // §1.7/§8.2) — the same document shape policy-core's own consumer tests pin.
        let doc = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 30
  ttl_ceil: 600
  grace: 45
  max_ips_per_domain: 256
dns:
  negative_ttl: 7
allowlist:
  - domain: api.example
baseline_pack:
  pack_version: "test-pack"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: gated.example
      family: core
      ports: [443]
      requires: http-policy
      provenance_source_url: https://example.invalid/gated
      evidence: vendor-doc
"#;
        let layer =
            ds_contracts::pol1::parse_layer(doc).expect("the capability-gated layer parses");

        // Composed WITHOUT the capability: the gated entry is INERT (§1.7). The
        // secret-free verdict projection stays nameless; the diagnostic accessor
        // surfaces the engine's `requires` string — and nothing else.
        let inert = policy_core::pol1_eval::compose(std::slice::from_ref(&layer), &[]);
        let oracle = PolicyCoreOracle::new(&inert);
        assert_eq!(
            oracle.verdict("gated.example"),
            PolicyVerdict::CapabilityGated,
            "the secret-free projection drops the name (verdict unchanged)"
        );
        assert_eq!(
            oracle.capability_requirement("gated.example"),
            Some("http-policy".to_string()),
            "the production adapter surfaces the engine's requires name on the seam"
        );
        // an ADMITTED domain and an unlisted (denied) domain both surface None.
        assert_eq!(oracle.capability_requirement("api.example"), None);
        assert_eq!(oracle.capability_requirement("denied.example"), None);

        // Composed WITH the capability available: the entry admits, and the
        // diagnostic seam goes fully inert — no stale name once the capability lands.
        let armed = policy_core::pol1_eval::compose(&[layer], &["http-policy"]);
        let oracle = PolicyCoreOracle::new(&armed);
        assert_eq!(oracle.verdict("gated.example"), PolicyVerdict::Admit);
        assert_eq!(oracle.capability_requirement("gated.example"), None);
    }

    // ── D127 scope-gated egress connect (doc 23 §6) ────────────────────────────
    //
    // The live egress connect path wraps the production oracle with the presenting
    // sub-token's `ds_scopes` (`PolicyCoreOracle::with_scopes`), so the scope gate
    // asserts `v1:network:egress` as an ADDITIONAL predicate BEFORE the domain
    // engine — and, at `decide`, BEFORE the admission-map lookup (step 5 policy
    // verdict runs ahead of step 6 `map.lookup`). A connect whose token lacks egress
    // is DENIED without ever touching the admission map.

    /// A one-layer host policy that ALLOWS `allowed.example` — enough to prove the
    /// scope gate pre-empts even a policy-admitted domain.
    fn allowing_composed_policy() -> policy_core::pol1_eval::ComposedPolicy {
        let text = r#"
schema_version: pol1/v0
layer: system-baseline
posture: standard
allowlist:
  - domain: allowed.example
"#;
        let layer = ds_contracts::pol1::parse_layer(text).expect("layer parses clean");
        policy_core::pol1_eval::compose(std::slice::from_ref(&layer), &[])
    }

    /// An [`AdmissionMap`] whose `lookup` PANICS — a tripwire proving `decide` never
    /// reaches step 6 (the admission-map lookup) when the scope gate denies at step
    /// 5. If any test wiring reached the lookup, the panic would fail the test.
    #[derive(Default)]
    struct TripwireMap {
        reverse: MockReverse,
    }
    impl AdmissionMap for TripwireMap {
        type Reverse = MockReverse;
        fn admit(
            &mut self,
            _key: AdmissionKey,
            _entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            Ok(())
        }
        fn lookup(&self, _key: &AdmissionKey) -> Option<AdmissionEntry> {
            panic!("admission-map lookup MUST NOT run when the scope gate denies pre-lookup");
        }
        fn revoke(&mut self, _key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            Ok(vec![])
        }
        fn reverse_index(&self) -> &Self::Reverse {
            &self.reverse
        }
    }

    #[test]
    fn missing_egress_scope_denies_before_the_admission_lookup() {
        // A synthetic connect whose presented sub-token carries NO `v1:network:egress`
        // scope (here `v1:code:read` only): the scope gate DENIES on the fast path,
        // ahead of the admission-map lookup. The TripwireMap's `lookup` panics, so the
        // test would fail if `decide` reached step 6 — proving the pre-lookup deny.
        let policy = allowing_composed_policy();
        let oracle = PolicyCoreOracle::with_scopes(
            &policy,
            vec![ds_contracts::scopes::SCOPE_CODE_READ.to_string()],
        );
        // Directly: the scope-refused verdict is a hard Deny (not Ask), even for a
        // policy-ADMITTED domain — the scope predicate pre-empts the domain engine.
        assert_eq!(oracle.verdict("allowed.example"), PolicyVerdict::Deny);
        // And through `decide` over the tripwire map: Refuse(PolicyDeny) with the
        // admission map NEVER consulted (a panic would fire otherwise).
        let map = TripwireMap::default();
        let hello = ch_with_sni("allowed.example");
        let origin = origin_to("203.0.113.10:443");
        assert!(
            matches!(
                decide(&hello, &origin, &map, &oracle, now(0)),
                Tls1Decision::Refuse(RefuseReason::PolicyDeny)
            ),
            "a missing-egress-scope connect must Refuse(PolicyDeny) before the lookup"
        );
        // The scope-refused connect has no capability diagnostic (it is a credential
        // deny, not an inert capability gate).
        assert_eq!(oracle.capability_requirement("allowed.example"), None);
        // An EMPTY presented scope set behaves identically (no egress authority).
        let bare = PolicyCoreOracle::with_scopes(&policy, vec![]);
        assert_eq!(bare.verdict("allowed.example"), PolicyVerdict::Deny);
    }

    #[test]
    fn scope_carrying_connect_is_unaffected_and_reaches_the_admission_path() {
        // The COMPLEMENT: a connect whose presented sub-token carries
        // `v1:network:egress` is byte-identical to the unscoped surface — the scope
        // gate adds nothing. The oracle admits `allowed.example` (POL-3 engine verdict)
        // and, with a present admission for the kernel dst, `decide` Tunnels; an
        // un-allowed SNI still Denies. The scope-carrying flow is unaffected.
        let policy = allowing_composed_policy();
        let oracle = PolicyCoreOracle::with_scopes(
            &policy,
            vec![ds_contracts::scopes::SCOPE_NETWORK_EGRESS.to_string()],
        );
        assert_eq!(oracle.verdict("allowed.example"), PolicyVerdict::Admit);

        // Present admission for the dst → Tunnel (admitted, opaque tunnel).
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "allowed.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let hello = ch_with_sni("allowed.example");
        let origin = origin_to("203.0.113.10:443");
        assert!(
            matches!(
                decide(&hello, &origin, &map, &oracle, now(0)),
                Tls1Decision::Tunnel
            ),
            "an egress-scoped connect to an admitted domain Tunnels — scope adds nothing"
        );

        // `PolicyCoreOracle::new` (the egress-presenting constructor) is byte-identical
        // to the scoped oracle above for the same policy — the pre-scope surface.
        let plain = PolicyCoreOracle::new(&policy);
        assert_eq!(plain.verdict("allowed.example"), PolicyVerdict::Admit);
        assert_eq!(
            plain.verdict("evil.example"),
            oracle.verdict("evil.example")
        );
    }

    // ── TLS-4 pass-through list (doc 12 §3, D17/D74) ──────────────────────────
    //
    // The pass-through check refines the tunnel MODE of an already-admitted flow:
    // a listed domain passes through (frozen against TLS termination), an unlisted
    // domain opaquely tunnels (eligible for the TLS-3 inspected path). It never
    // changes the admission verdict, and the list ships EMPTY (D74) so the shipped
    // default sends every admitted flow down the opaque-tunnel arm.

    /// Set up one admitted (policy-allowed + live admission for the kernel dst)
    /// flow for `domain` on `203.0.113.10`, returning the map/policy/hello a
    /// pass-through test drives `decide` with. The flow is ADMITTED; the only thing
    /// the pass-through list changes is Tunnel vs Passthrough.
    fn admitted_flow(domain: &str) -> (MockMap, MockPolicy, Vec<u8>) {
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            domain,
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let policy = MockPolicy::allowing(&[domain]);
        let hello = ch_with_sni(domain);
        (map, policy, hello)
    }

    #[test]
    fn acceptance_a_listed_passthrough_domain_returns_passthrough_not_tunnel() {
        // (a) a policy-allowed domain WITH a matching pass-through entry returns
        // Passthrough — and it is DISTINCT from the opaque-tunnel verdict.
        let (map, policy, hello) = admitted_flow("pinned.example");
        let listed = MockPassthrough::listing(&["pinned.example"]);
        let d = decide_with_passthrough(
            &hello,
            &origin_to("203.0.113.10:443"),
            &map,
            &policy,
            &listed,
            now(0),
        );
        assert_eq!(d, Tls1Decision::Passthrough);
        assert_ne!(
            d,
            Tls1Decision::Tunnel,
            "a listed pass-through domain must NOT opaque-tunnel: the verdict is distinct"
        );
    }

    #[test]
    fn acceptance_b_same_domain_without_a_passthrough_entry_returns_tunnel() {
        // (b) the SAME admitted domain WITHOUT a pass-through entry returns the
        // opaque-tunnel verdict (eligible for TLS-3 inspection) — distinct from
        // Passthrough. Same map/policy/dst as (a); only the list membership differs.
        let (map, policy, hello) = admitted_flow("pinned.example");
        let not_listed = MockPassthrough::listing(&[]); // explicitly empty set
        let d = decide_with_passthrough(
            &hello,
            &origin_to("203.0.113.10:443"),
            &map,
            &policy,
            &not_listed,
            now(0),
        );
        assert_eq!(d, Tls1Decision::Tunnel);
        assert_ne!(
            d,
            Tls1Decision::Passthrough,
            "an unlisted admitted domain must opaque-tunnel, never pass through"
        );

        // and the membership boolean is the SOLE thing that flips the mode: the
        // identical (map, policy, dst, hello) with a list that DOES carry the
        // domain returns Passthrough (proving the pass-through entry is decisive).
        let listed = MockPassthrough::listing(&["pinned.example"]);
        assert_eq!(
            decide_with_passthrough(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                &listed,
                now(0)
            ),
            Tls1Decision::Passthrough
        );
    }

    #[test]
    fn acceptance_c_empty_list_tunnels_every_allowed_domain_opaquely() {
        // (c) the D74 frozen-EMPTY list (the production EmptyPassthroughList) sends
        // EVERY policy-allowed + admitted domain down the opaque-tunnel arm — no
        // domain passes through under the baseline pack.
        for domain in ["api.example", "github.com", "pinned.example", "cdn.example"] {
            let (map, policy, hello) = admitted_flow(domain);
            let d = decide_with_passthrough(
                &hello,
                &origin_to("203.0.113.10:443"),
                &map,
                &policy,
                &empty_passthrough(), // the shipped D74 empty list
                now(0),
            );
            assert_eq!(
                d,
                Tls1Decision::Tunnel,
                "under the empty list, {domain} must opaque-tunnel, never pass through"
            );
            assert_ne!(d, Tls1Decision::Passthrough);
        }
        // structural: the empty list answers `false` for every domain.
        assert!(!EmptyPassthroughList.is_passthrough("anything.example"));
        assert!(!EmptyPassthroughList.is_passthrough("pinned.example"));
    }

    #[test]
    fn acceptance_d_the_three_way_decision_is_exhaustive() {
        // (d) deny / pass-through / opaque-tunnel are EXHAUSTIVE over an
        // otherwise-identical (session, kernel dst) — the same admitted-IP entry,
        // the same listed pass-through entry; only the policy verdict and the
        // pass-through membership move. Every admitting flow lands in exactly one
        // of {Passthrough, Tunnel}; a non-Admit policy verdict refuses BEFORE the
        // pass-through check ever runs (pass-through never rescues a denied domain).
        let dst = origin_to("203.0.113.10:443");

        // DENY: even a listed pass-through entry does not rescue a denied domain —
        // policy is consulted first, and a non-Admit verdict refuses.
        let mut deny_map = MockMap::default();
        deny_map.insert(
            SESSION_UUID,
            "denied.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let deny_policy = MockPolicy::deny_all();
        let listed_denied = MockPassthrough::listing(&["denied.example"]);
        assert_eq!(
            decide_with_passthrough(
                &ch_with_sni("denied.example"),
                &dst,
                &deny_map,
                &deny_policy,
                &listed_denied,
                now(0),
            ),
            Tls1Decision::Refuse(RefuseReason::PolicyDeny),
            "deny wins over a pass-through listing — pass-through never changes the verdict"
        );

        // PASS-THROUGH: admitted + listed.
        let (pt_map, pt_policy, pt_hello) = admitted_flow("pinned.example");
        let pt_list = MockPassthrough::listing(&["pinned.example"]);
        assert_eq!(
            decide_with_passthrough(&pt_hello, &dst, &pt_map, &pt_policy, &pt_list, now(0)),
            Tls1Decision::Passthrough,
        );

        // OPAQUE TUNNEL: admitted + NOT listed.
        let (op_map, op_policy, op_hello) = admitted_flow("ordinary.example");
        let op_list = MockPassthrough::listing(&[]);
        assert_eq!(
            decide_with_passthrough(&op_hello, &dst, &op_map, &op_policy, &op_list, now(0)),
            Tls1Decision::Tunnel,
        );

        // Exhaustiveness made explicit: a match on the verdict has exactly the
        // three admitting/denying arms plus the orthogonal re-admit path; the
        // `match` below compiles ONLY because the enum is fully covered, so a new
        // variant could not be added without revisiting this three-way.
        for (label, d) in [
            ("deny", Tls1Decision::Refuse(RefuseReason::PolicyDeny)),
            ("passthrough", Tls1Decision::Passthrough),
            ("tunnel", Tls1Decision::Tunnel),
        ] {
            let arm = match d {
                Tls1Decision::Refuse(_) => "deny-or-edge-refuse",
                Tls1Decision::Passthrough => "passthrough",
                Tls1Decision::Tunnel => "opaque-tunnel",
                Tls1Decision::ReAdmit { .. } => "re-admit",
            };
            let want = match label {
                "deny" => "deny-or-edge-refuse",
                "passthrough" => "passthrough",
                "tunnel" => "opaque-tunnel",
                _ => unreachable!(),
            };
            assert_eq!(arm, want, "the {label} flow must land in its own arm");
        }
    }

    #[test]
    fn passthrough_never_rescues_a_mismatched_or_re_admit_flow() {
        // A pass-through listing applies ONLY to an admitted flow: it never rescues
        // an SNI/dst mismatch (the CDN hole stays closed) and never turns a D68
        // re-admit into a pass-through (the flow has no live admission to tunnel).
        let listed = MockPassthrough::listing(&["pinned.example"]);

        // mismatch: admitted for pinned.example on .10, but the kernel dst is .99.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "pinned.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let policy = MockPolicy::allowing(&["pinned.example"]);
        assert_eq!(
            decide_with_passthrough(
                &ch_with_sni("pinned.example"),
                &origin_to("203.0.113.99:443"),
                &map,
                &policy,
                &listed,
                now(0),
            ),
            Tls1Decision::Refuse(RefuseReason::SniDstMismatch),
            "a listed domain still refuses on an SNI/dst mismatch — pass-through never rescues it"
        );

        // re-admit: a listed domain with NO live admission re-admits (D68), it does
        // NOT pass through (nothing to tunnel yet).
        let empty_map = MockMap::default();
        assert_eq!(
            decide_with_passthrough(
                &ch_with_sni("pinned.example"),
                &origin_to("203.0.113.10:443"),
                &empty_map,
                &policy,
                &listed,
                now(0),
            ),
            Tls1Decision::ReAdmit {
                sni_domain: "pinned.example".to_string(),
                cause: ReAdmitCause::NoLiveAdmission,
            },
            "a listed domain with no live admission re-admits — pass-through is a tunnel-mode refinement, not an admission"
        );
    }

    // ── seam-hardening (01KV9N17NN): the standalone membership helpers ─────────
    //
    // `original_dst_in_admitted_addrs` is the D68 ReAdmit re-check: the addresses
    // the ReResolve seam freshly admits MUST still contain the kernel original_dst.
    // `origin_is_admitted` is the inspected/swap FORWARD-admission coupling: a live,
    // non-expired entry for the SNI must include the kernel dst — fail-closed
    // otherwise (no entry / expired / member miss all → false).

    #[test]
    fn original_dst_in_admitted_addrs_is_a_byte_exact_membership_check() {
        let origin = origin_to("203.0.113.10:443");
        // present (the re-resolve admitted the kernel dst) → true.
        assert!(original_dst_in_admitted_addrs(
            &origin,
            &[v4(198, 51, 100, 7), v4(203, 0, 113, 10)]
        ));
        // absent (the re-resolve admitted a DIFFERENT address set) → false: the
        // client is dialing an address DNS-2 did not freshly admit.
        assert!(!original_dst_in_admitted_addrs(
            &origin,
            &[v4(198, 51, 100, 7), v4(203, 0, 113, 11)]
        ));
        // an empty re-resolved set never admits.
        assert!(!original_dst_in_admitted_addrs(&origin, &[]));
    }

    #[test]
    fn origin_is_admitted_true_only_for_a_live_entry_that_contains_the_dst() {
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "api.example",
            entry(vec![v4(203, 0, 113, 10)], 10_000),
        );
        let origin = origin_to("203.0.113.10:443");
        // live entry + dst member → admitted.
        assert!(origin_is_admitted(&origin, "api.example", &map, now(0)));

        // member MISS (the CDN hole — dst admitted only for another domain) → false.
        let other_dst = origin_to("203.0.113.99:443");
        assert!(!origin_is_admitted(&other_dst, "api.example", &map, now(0)));

        // a DIFFERENT SNI with no entry → false (FORWARD lookup, never reverse).
        assert!(!origin_is_admitted(&origin, "other.example", &map, now(0)));
    }

    #[test]
    fn origin_is_admitted_fails_closed_on_absent_and_expired_admissions() {
        // No admission at all (the inspected path has no re-resolve seam of its own,
        // so a D68-re-admittable absence is NOT a live admission here) → false.
        let empty = MockMap::default();
        assert!(!origin_is_admitted(
            &origin_to("203.0.113.10:443"),
            "api.example",
            &empty,
            now(0)
        ));

        // An EXPIRED entry (would re-admit under `decide`) is not LIVE here → false.
        let mut map = MockMap::default();
        map.insert(
            SESSION_UUID,
            "api.example",
            entry(vec![v4(203, 0, 113, 10)], 1_000), // expires at t=1000
        );
        let origin = origin_to("203.0.113.10:443");
        assert!(
            !origin_is_admitted(&origin, "api.example", &map, now(2_000)),
            "an expired admission is not LIVE — the inspected/swap path fails closed"
        );
        // before expiry the SAME pair IS admitted (expiry is the caller's gate).
        assert!(origin_is_admitted(&origin, "api.example", &map, now(999)));
    }
}
