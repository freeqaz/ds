//! The hickory bridge — the ONLY place hickory wire/resolver types touch the gate.
//!
//! `StubRequestHandler<P>` implements hickory's `RequestHandler`. It is the seam
//! where engine-specific types (`Request`, `LowerQuery`, `RecordType`, `Record`,
//! `MessageResponse`) AND the upstream forwarder pool (`hickory_resolver::Resolver`)
//! are translated to/from the hickory-free `crate::policy` types. Keeping the
//! translation localized here is what makes D67 hold: the cross-service `PolicyHook`
//! surface — and every other pub signature in this crate — never sees a hickory
//! type, so the documented raw-tokio fallback (doc 11 §2) is a library migration,
//! not a contract change. The `ForwarderConfig` knob below is the ONLY pub-facing
//! handle on the forwarder, and it carries plain `std` types (a `Vec<SocketAddr>`
//! of upstreams + a timeout) — never a `ResolverConfig`/`NameServerConfig`.
//!
//! This handler wires the doc 11 §4 frozen admission seam, the doc 11 §2 / §8.1
//! forwarder, and the doc 11 §3.3 (D70/D75) record scrub. Per query it builds the
//! hickory-free [`DnsQueryCtx`] (session + qname + qtype + source), asks the
//! [`PolicyHook`] for the frozen [`Verdict`], and authors each arm's wire shape:
//!  * **Allow{admit, ttl_clamp}** -> resolve the original query name against the D64
//!    host-side upstream resolvers (1.1.1.1 / 8.8.8.8), follow the CNAME chain
//!    internally (doc 11 §3.1), §3.3-scrub, and author the answer (the W1/W2
//!    insert-then-answer transaction behind `admit` is the later `txn/` seam).
//!  * **Deny{rcode_policy}** -> the §3.2 hard-deny shape: NXDOMAIN (RCODE 3) + the D71
//!    authored signature SOA in the authority section (D71).
//!  * **Ask{prompt_ref}** -> REFUSED immediately (no cacheable negative signal, §3.2);
//!    the prompt travels the Stage-0 ask-user seam out of band (D18) — not authored as
//!    a second wire response here.
//!
//! SERVFAIL is NEVER a policy verdict (§3.2): it is authored only for genuine failure
//! (an upstream timeout / error, or the request-info-less no-forward path).
//!
//! §3.3 record scrubbing authored HERE on this answer path (never via hickory
//! internals — the suppression is the gate's, not the resolver's):
//!  * **AAAA (type 28)** — an AAAA query is answered as a **fast NOERROR/NODATA**:
//!    no upstream round-trip, the AAAA never reaches the VM, and the D71 authored
//!    SOA rides the authority section (§3.2: the SOA in any negative response is
//!    always present and always authored by ds-dnsgate). NEVER drop/SERVFAIL/REFUSED
//!    (a dropped AAAA stalls glibc *and* musl ~5s per fresh name, RFC 4074). AAAA
//!    RRs that ride an upstream answer to some OTHER qtype are stripped too.
//!  * **HTTPS (type 65) / SVCB (type 64)** — suppressed ENTIRELY on the forwarded
//!    answer path: a forwarded A (or any) answer that carries HTTPS/SVCB records
//!    arrives at the VM WITHOUT them (they advertise ECH configs that defeat the
//!    TLS-1 SNI check, and `alpn=h3` steering at QUIC — D70). An explicit type-65 /
//!    type-64 query is never forwarded; it returns NODATA with an authored SOA. This
//!    is the steering control for COOPERATIVE clients; the NFT-4 udp/443 reject is
//!    the SOLE control for non-cooperative clients (a separate, independent test).
//!
//! These invariants hold IDENTICALLY over UDP and TCP/53, including the TC-bit retry
//! path (doc 11 §3.4): the same handler serves both transports (server.rs), so the
//! scrub runs once, before any byte is authored, on whichever transport carries it.
//!
//! What this still does NOT do (DNS-1+ work, deliberately out of scope — see the crate
//! docs): the W1/W2 insert-then-answer transaction behind `Allow{admit}` and its single
//! shared deadline (W2/D68), full-admission-on-every-answer (W3), interface-anchored
//! session attribution (D44 — the [`DnsQueryCtx::session`] / `source` are threaded from
//! the request's recorded address at the pre-stage, not the three-keys-agree tap join),
//! nft / DNS-2b map writes, and the `ds-contracts` LOG-1 Stage-0 schema freeze (the
//! `DnsEvent` here is service-internal, not that proto). The verdict SHAPE is frozen
//! (doc 11 §4); the admission transaction is the later `txn/` seam.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
// The POL-1 schema home (already a direct dep, hickory-free): the authored-SOA
// boundary-zone suffix is the policy-pushed `dns.boundary_zone` field the gate reads
// in place of its handler-local const default (D71 VALUE source moves; SHAPE frozen).
use ds_contracts::pol1;
// The forwarder pool. hickory_resolver is reached through the direct dep; its types
// are confined to this module so no hickory type appears in any pub signature (D67).
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::Resolver;
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::rdata::opt::EdnsOption;
use hickory_server::proto::rr::rdata::SOA;
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::ask::{AskPosture, AskUserRequest, AskUserSink, NullAskSink};
use crate::attrib::{AttributionError, AttributionTable, SessionAttribution};
use crate::event::{
    AaaaOnly, DeferralReason, DnsEvent, EventPath, EventProvenance, EventSink, NullSink,
};
use crate::policy::{DnsQueryCtx, PolicyHook, PromptRef, RcodePolicy, SeamProvenance, Verdict};
use crate::txn::{
    is_plumbable, AdmissionInputs, AdmissionOutcome, AdmissionStores, InMemoryAdmissionMap,
    NftSetProgrammer, RecordingSetProgrammer,
};
use ds_contracts::dns_admission::{
    AdmissionMap, AdmissionType, Instant as AdmissionInstant, Provenance,
};

// `SeamProvenance` is the frozen POL-3 triple (`policy_core::pol1_eval::Provenance`,
// re-exported by `crate::policy`); `Verdict` is the frozen `policy_core::dns_gate::
// DnsVerdict`. The handler binds the ONE frozen verdict type — there is no second
// service-internal verdict to keep in lockstep.

/// The two D64 host-side upstream resolvers (`1.1.1.1` / `8.8.8.8`), as the plain
/// `SocketAddr` defaults the forwarder pool points at. Standard DNS port 53. These
/// are the only upstreams the baseline ever grants the gate (doc 11 §1) — the VM
/// never gets direct resolver access.
pub const D64_UPSTREAMS: [SocketAddr; 2] = [
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        53,
    ),
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        53,
    ),
];

/// The default per-query upstream timeout. A query the upstream pool does not answer
/// within this window resolves to SERVFAIL (doc 11 §8.5: "Upstream resolve failure /
/// timeout -> SERVFAIL", a genuine-failure rcode, never a policy verdict).
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// The D71 frozen authored-SOA MNAME signature SHAPE — the always-`denied.policy.`
/// label prefix, before the boundary-zone suffix (doc 11 §3.2: "`SOA MNAME =` the
/// frozen signature name, working name `denied.policy.<boundary-zone>.`"). D71 freezes
/// this PREFIX and the always-authored-SOA / TTL==MINIMUM==negative-TTL shape; only the
/// `<boundary-zone>` suffix is a policy-push VALUE. The prefix never changes.
pub const SOA_MNAME_PREFIX: &str = "denied.policy.";

/// The FALLBACK boundary zone — the D71 WORKING NAME `boundary.` the gate authors
/// with when the policy snapshot does not push a boundary-zone suffix. The
/// boundary-zone suffix is a policy-push value: it is now carried as the POL-1
/// `dns.boundary_zone` field (`ds-contracts`) and lifted onto the host policy
/// snapshot (`ds-policy-snapshot::PolicySnapshot::boundary_zone`), and the gate reads
/// it via [`StubRequestHandler::with_forwarder_and_boundary_zone`]. This const is the
/// fallback ONLY — the value the snapshot's own default carries when a layer omits
/// the field, so the two agree by construction. Swapping in the policy-pushed boundary
/// zone is a VALUE change, not a SHAPE change (D71): the `denied.policy.` prefix, the
/// always-authored SOA, and TTL==MINIMUM==the POL-1 negative-TTL all stay frozen — only
/// WHERE the suffix value comes from moves.
pub const DEFAULT_BOUNDARY_ZONE: &str = "boundary.";

/// The pre-stage default authored-SOA MNAME, `denied.policy.boundary.` — the
/// [`SOA_MNAME_PREFIX`] applied to the [`DEFAULT_BOUNDARY_ZONE`] working name. Kept as
/// a `pub const` so the suppression-shape tests and external tooling can assert the
/// default fingerprint without re-deriving it; a handler built with a non-default
/// boundary zone carries the derived value instead (the VALUE-change derivation point).
pub const SOA_SIGNATURE_MNAME: &str = "denied.policy.boundary.";

/// The RNAME (responsible mailbox) of the authored SOA — a non-routed placeholder in
/// the same signature zone (doc 11 §4-free: SOA RNAME is filler, the MNAME is the
/// load-bearing fingerprint). Like the MNAME it is derived from the configured boundary
/// zone (`hostmaster.denied.policy.<boundary-zone>.`); this `pub const` is the default
/// for the working name.
pub const SOA_SIGNATURE_RNAME: &str = "hostmaster.denied.policy.boundary.";

/// Derive the authored-SOA MNAME from the configured boundary zone: the
/// [`SOA_MNAME_PREFIX`] (`denied.policy.`) concatenated with the boundary zone (D71
/// VALUE change, not a SHAPE change). The boundary zone is normalized to a single
/// trailing dot so the result is a valid FQDN regardless of whether the configured
/// value carried one. This is the load-bearing derivation point the constructor
/// parameter exercises; with the default working name it reproduces
/// [`SOA_SIGNATURE_MNAME`] exactly.
fn derive_soa_mname(boundary_zone: &str) -> String {
    format!("{SOA_MNAME_PREFIX}{}.", boundary_zone.trim_matches('.'))
}

/// Derive the authored-SOA RNAME from the configured boundary zone —
/// `hostmaster.denied.policy.<boundary-zone>.` (filler in the same signature zone).
fn derive_soa_rname(boundary_zone: &str) -> String {
    format!(
        "hostmaster.{SOA_MNAME_PREFIX}{}.",
        boundary_zone.trim_matches('.')
    )
}

/// The D71 authored-SOA signature names a handler signs its negative responses with — the
/// boundary-zone-derived MNAME (`denied.policy.<zone>.`) and RNAME
/// (`hostmaster.denied.policy.<zone>.`). Held behind the handler's shared lock so the doc
/// 13 §5.3 admitter-LAST D72 hot-reload re-derives BOTH from a new live snapshot
/// boundary-zone in one swap (a VALUE change, never a SHAPE change — the `denied.policy.`
/// prefix, always-authored SOA, and TTL==MINIMUM==negative-TTL stay frozen, D71).
#[derive(Debug, Clone)]
struct SoaSignature {
    mname: String,
    rname: String,
}

impl SoaSignature {
    /// Derive the signature from a boundary zone (the D71 VALUE source — startup or a D72
    /// hot-reload). The default working-name zone reproduces [`SOA_SIGNATURE_MNAME`] /
    /// [`SOA_SIGNATURE_RNAME`] exactly.
    fn from_boundary_zone(boundary_zone: &str) -> Self {
        Self {
            mname: derive_soa_mname(boundary_zone),
            rname: derive_soa_rname(boundary_zone),
        }
    }
}

/// A cloneable handle to ONE handler's hot-reloadable authored-SOA signature — the doc 13
/// §5.3 admitter-LAST D72 reload seam. `spawn_gate` builds the UDP and TCP handlers and
/// keeps each handler's handle on the [`crate::server::RunningGate`], so a single
/// `RunningGate::reload_boundary_zone` re-sources the authored SOA on BOTH transports from
/// the new live snapshot value — admitter-LAST, never per-transport skew (the gate is the
/// admitter, committing the new boundary zone last).
#[derive(Clone)]
pub(crate) struct BoundaryZoneReload {
    signature: Arc<std::sync::RwLock<SoaSignature>>,
}

impl BoundaryZoneReload {
    /// Re-derive the authored-SOA signature from a NEW live snapshot boundary zone and
    /// swap it under the shared lock (D72 admitter-LAST reload). A VALUE change only — the
    /// D71 SHAPE (the `denied.policy.` prefix, always-authored SOA, TTL==MINIMUM) stays
    /// frozen. This is the ONE per-handler reload primitive the gate's single reload path
    /// ([`crate::server::RunningGate::reload_boundary_zone`]) drives across both transports.
    pub(crate) fn reload(&self, boundary_zone: &str) {
        let mut sig = self.signature.write().expect("SOA signature lock poisoned");
        *sig = SoaSignature::from_boundary_zone(boundary_zone);
    }

    /// The authored-SOA MNAME this handle CURRENTLY signs with (the live value after the
    /// most recent [`reload`](Self::reload)). The `WatchPolicies` subscriber tests assert
    /// the committed suffix through this read; with the default working-name zone it
    /// reproduces [`SOA_SIGNATURE_MNAME`] exactly.
    pub(crate) fn current_mname(&self) -> String {
        self.signature
            .read()
            .expect("SOA signature lock poisoned")
            .mname
            .clone()
    }
}

/// The policy-controlled negative-TTL (doc 11 §3.2 / §4): `SOA TTL == SOA.MINIMUM ==`
/// the POL-1 negative-TTL field; the strawman default is **5s** (RFC 2308 makes this
/// the exact client-cache control). This is the POL-1 schema field's pinned default,
/// not a hardcode of behavior — the real value is a policy push (doc 11 §4: "tests
/// pin defaults: ... 5s").
pub const NEGATIVE_TTL_SECS: u32 = 5;

/// EDE INFO-CODE 15 (Blocked) — the doc 11 §3.2 hard-deny diagnostic (RFC 8914). It
/// attaches to a NXDOMAIN policy-deny **iff** the query carried an OPT record, with
/// EXTRA-TEXT prefixed `ds:` carrying POL-3 provenance. EDE is DIAGNOSTIC-ONLY (doc
/// 11 §3.2): no behavior, test, or product promise may depend on a client receiving
/// it — the guaranteed "why blocked" channel is the PolicyDecision (LOG-1) event.
pub const EDE_BLOCKED_INFO_CODE: u16 = 15;

/// The frozen `ds:` prefix on the EDE EXTRA-TEXT (doc 11 §3.2 / §4: the format beyond
/// the prefix is §4-free). The denial fingerprint a tool can grep for.
pub const EDE_EXTRA_TEXT_PREFIX: &str = "ds:";

// ── The `ds:` EDE-15 EXTRA-TEXT grammar — the SINGLE SOURCE OF TRUTH ──────────
//
// `ede_blocked_option` authors the §3.2 provenance EXTRA-TEXT as the four-part wire
// grammar
//
//     ds:rule=<rule-id> layer=<layer> version=<version>
//
// — the `ds:` prefix, then the POL-3 provenance triple as three SPACE-separated
// `<key>=<value>` tokens in the FIXED order rule / layer / version. The TOKEN
// SPELLINGS and their ORDER are the contract; consumers (the conformance tests in
// `tests/policy_verdict.rs`) parse this grammar and MUST reference these exported
// constants rather than re-spelling the tokens inline, so a reform of the grammar
// breaks ONE obvious place instead of silently skewing every hand-rolled parser.

/// The `rule=` token name (POL-3 rule-id axis), space-separated, FIRST after the
/// `ds:` prefix in the EDE-15 EXTRA-TEXT grammar.
pub const EDE_RULE_TOKEN: &str = "rule=";
/// The `layer=` token name (POL-3 policy-layer axis), space-separated, SECOND.
pub const EDE_LAYER_TOKEN: &str = "layer=";
/// The `version=` token name (POL-3 policy-version axis), space-separated, THIRD.
pub const EDE_VERSION_TOKEN: &str = "version=";

/// Render the §3.2 EDE-15 (Blocked) EXTRA-TEXT from a [`SeamProvenance`] triple, in the
/// canonical `ds:rule=<id> layer=<layer> version=<version>` grammar. This is the ONE
/// place the token spellings + order are assembled; `ede_blocked_option` (the emitter)
/// and the conformance tests both route through these exported constants, so the
/// producer and its parsers can never drift apart silently.
pub fn format_ede_extra_text(provenance: &SeamProvenance) -> String {
    format!(
        "{EDE_EXTRA_TEXT_PREFIX}{EDE_RULE_TOKEN}{} {EDE_LAYER_TOKEN}{} {EDE_VERSION_TOKEN}{}",
        provenance.rule_id, provenance.policy_layer, provenance.policy_version
    )
}

/// hickory 0.26.x has NO native Extended-DNS-Error type — EDE rides as a generic
/// `EdnsOption::Unknown(OPTION-CODE 15, wire-bytes)`. The RFC 8914 EDE option wire
/// shape is a 2-byte big-endian INFO-CODE followed by the UTF-8 EXTRA-TEXT (no length
/// prefix on the text — the option's own length delimits it). This builds those
/// bytes for INFO-CODE 15 (Blocked) with a `ds:`-prefixed POL-3 EXTRA-TEXT.
///
/// EDE OPTION-CODE is 15 (IANA "Extended DNS Error"); it is a coincidence that the
/// Blocked INFO-CODE is also 15. We carry BOTH explicitly: the option code 15
/// identifies an EDE option, the first two payload bytes are the Blocked info-code.
fn ede_blocked_option(provenance: &SeamProvenance) -> EdnsOption {
    // EXTRA-TEXT: the `ds:` denial fingerprint carrying POL-3 provenance (rule id /
    // layer / policy version). Format beyond the prefix is §4-free; this is a stable,
    // greppable rendering. Diagnostic-only — nothing depends on a client parsing it.
    let extra_text = format_ede_extra_text(provenance);
    let mut bytes = Vec::with_capacity(2 + extra_text.len());
    bytes.extend_from_slice(&EDE_BLOCKED_INFO_CODE.to_be_bytes());
    bytes.extend_from_slice(extra_text.as_bytes());
    // OPTION-CODE 15 = "Extended DNS Error".
    EdnsOption::Unknown(15, bytes)
}

/// The default ceiling on AAAA probes in flight at once (doc 11 §3.5 phase-B pre-step;
/// §1 single-resolver / DoS-chokepoint bound). The `aaaa_only` trigger settlement fires
/// a bounded explicit AAAA resolution on the SAME upstream forwarder (no second
/// resolver, no per-query fan-out) ONLY when the A-lookup returned NoData over a
/// policy-allowed name; this cap is the scope/rate bound that keeps a flood of
/// v6-only-NoData names from multiplying upstream load. When the budget is saturated the
/// probe is skipped and the trigger stays the honest `Deferred(ForwardedNoDataV6Invisible)`
/// — never a silent `false`. A §4-free VALUE (the obligation to bound resolver load is
/// structural to a single-resolver fleet, doc 11 §1/§8.5); it is an internal `Forwarder`
/// bound, deliberately NOT a [`ForwarderConfig`] field (the hickory-free config surface
/// stays the upstream list + timeout the D67 corollary fixes).
pub const DEFAULT_AAAA_PROBE_BUDGET: u32 = 32;

/// Author the D71 SOA the gate places in the authority section of every negative
/// response it owns (doc 11 §3.2): a `ds-dnsgate`-authored SOA, NEVER relayed from
/// upstream, with `MNAME` = the frozen signature name and `TTL == MINIMUM ==` the
/// policy negative-TTL. The owner name is the original query name (the zone the
/// negative answer is "for"); the serial/refresh/retry/expire are §4-free filler.
///
/// Used for the §3.3 AAAA fast-NODATA / HTTPS/SVCB explicit-query NODATA (NOERROR), AND
/// the §3.2 hard-deny NXDOMAIN (RCODE 3) the `Deny{rcode_policy}` verdict authors — the
/// authored SOA is always present in any negative response (§3.2, D71), only the rcode
/// differs (NOERROR for the §3.3 scrub, NXDOMAIN for a policy deny).
///
/// `mname` / `rname` are the boundary-zone-derived signature names (the D71 VALUE the
/// handler carries) — the default working-name handler reproduces
/// [`SOA_SIGNATURE_MNAME`] / [`SOA_SIGNATURE_RNAME`].
fn authored_negative_soa(owner: &Name, mname: &str, rname: &str) -> Record {
    let soa = SOA::new(
        Name::from_ascii(mname).expect("the derived SOA signature MNAME is a valid name"),
        Name::from_ascii(rname).expect("the derived SOA signature RNAME is a valid name"),
        // SERIAL / REFRESH / RETRY / EXPIRE are §4-free filler; the load-bearing
        // fields are MNAME (the signature) and TTL==MINIMUM (the negative-TTL).
        1,
        3600,
        600,
        86_400,
        NEGATIVE_TTL_SECS,
    );
    // RFC 2308: the negative-response SOA's record TTL must equal its MINIMUM, so the
    // client caches the negative answer for exactly the negative-TTL window.
    Record::from_rdata(owner.clone(), NEGATIVE_TTL_SECS, RData::SOA(soa))
}

/// Whether a record type is one the §3.3 scrub strips from EVERY forwarded answer
/// reaching a VM: AAAA (type 28), HTTPS (type 65), and SVCB (type 64). AAAA because
/// v0/phase-B guests are v4-only (D75); HTTPS/SVCB because they advertise ECH configs
/// and `alpn=h3` (D70). The suppression is authored on THIS answer path, so even when
/// a forwarded answer to some other qtype happens to carry one of these RRs (e.g. an
/// A answer with a bundled HTTPS record), it never reaches the VM.
fn is_scrubbed_record_type(rt: RecordType) -> bool {
    matches!(rt, RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB)
}

/// Whether a queried record type is one the gate answers WITHOUT a forward, as a fast
/// authored NODATA (doc 11 §3.3): AAAA (fast NODATA so the v4-only guest never stalls
/// on a v6 lookup), and HTTPS/SVCB (suppressed entirely — an explicit type-65/64
/// query is never forwarded and returns NODATA with the authored SOA).
fn is_fast_nodata_qtype(rt: RecordType) -> bool {
    is_scrubbed_record_type(rt)
}

/// Hickory-free configuration for the upstream forwarder pool (doc 11 §2 / §8.1).
///
/// This is the ONE pub handle on the forwarder. It carries plain `std` types only —
/// a list of upstream `SocketAddr`s and a per-query timeout — so the D67 corollary
/// holds: no `ResolverConfig`/`NameServerConfig`/`Resolver` ever crosses a pub
/// boundary. The upstreams are injectable (constructor / config) and default to the
/// D64 `1.1.1.1` / `8.8.8.8` pair; tests inject an in-process loopback mock upstream
/// on an ephemeral port through this same field, so the forwarder is exercised with
/// zero network and no default-route assumption.
#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    /// The upstream resolvers to forward to, in order. Each carries an explicit port
    /// (53 for the D64 pair; an ephemeral port for the test loopback mock).
    pub upstreams: Vec<SocketAddr>,
    /// Per-query upstream timeout; exceeding it yields SERVFAIL (doc 11 §8.5).
    pub timeout: Duration,
}

impl Default for ForwarderConfig {
    fn default() -> Self {
        Self {
            upstreams: D64_UPSTREAMS.to_vec(),
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
        }
    }
}

/// The upstream forwarder pool — a `hickory_resolver::Resolver` confined to this
/// module (no hickory type leaks past it, D67).
///
/// It is constructed from a [`ForwarderConfig`]'s plain `SocketAddr` list, builds a
/// per-upstream UDP+TCP `NameServerConfig` (so the CNAME chase and a large-answer
/// TCP fallback both work), and follows the CNAME chain internally per query
/// (hickory-resolver chases CNAMEs as part of `lookup`). The resolver's own cache is
/// irrelevant to the pre-stage contract (W3 admission is DNS-1+ work, not here).
struct Forwarder {
    resolver: Resolver<TokioRuntimeProvider>,
    timeout: Duration,
    /// The remaining AAAA-probe budget (doc 11 §3.5 phase-B pre-step). Starts at
    /// [`DEFAULT_AAAA_PROBE_BUDGET`] and is decremented for the duration of each in-flight
    /// probe, then restored — a simple in-flight ceiling that rides the SAME single
    /// upstream forwarder (no second resolver, no per-query fan-out) and bounds resolver
    /// load against the §1 single-resolver/DoS-chokepoint role.
    aaaa_probe_budget: AtomicU32,
}

impl Forwarder {
    /// Build the forwarder pool from the hickory-free config.
    ///
    /// `expect`s only if hickory rejects an internally-constructed config, which
    /// cannot happen for a plain UDP+TCP forwarder over valid `SocketAddr`s — the
    /// pool is a fixed list of explicit addresses, no system-config read, no TLS
    /// handshake (`build` only errors on system-config / TLS construction, neither
    /// of which this path exercises).
    fn new(config: &ForwarderConfig) -> Self {
        let name_servers = config
            .upstreams
            .iter()
            .map(|addr| {
                // One UDP + one TCP connection per upstream, both at the upstream's
                // explicit port. `NameServerConfig::udp_and_tcp` only takes an IP and
                // defaults the port to 53, so we author the connections directly to
                // honor an injected ephemeral test port.
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                NameServerConfig::new(addr.ip(), true, vec![udp, tcp])
            })
            .collect::<Vec<_>>();

        // No search domain, no search list — the gate forwards fully-qualified names
        // exactly as the VM asked (doc 11 §3.1: admission is keyed on the original
        // query name).
        let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
        let resolver =
            Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .build()
                .expect("forwarder pool over explicit upstream addresses always builds");

        Self {
            resolver,
            timeout: config.timeout,
            aaaa_probe_budget: AtomicU32::new(DEFAULT_AAAA_PROBE_BUDGET),
        }
    }

    /// Resolve `qname`/`qtype` against the upstream pool, following the CNAME chain
    /// internally, and return the answer records to author back to the VM.
    ///
    /// Maps the hickory result into a hickory-free-for-the-caller [`ForwardOutcome`]:
    /// * `Answer(records)` — one or more records (CNAME chain + terminal records).
    /// * `NoData` — the name resolved but carried no records of this type, or
    ///   NXDOMAIN. The pre-stage answers NOERROR/NODATA empty (the §3.2 authored
    ///   NXDOMAIN/SOA denial shapes are DNS-1+ work, out of scope here).
    /// * `ServFail` — a genuine upstream failure or timeout (doc 11 §8.5).
    async fn forward(&self, qname: &Name, qtype: RecordType) -> ForwardOutcome {
        let lookup =
            tokio::time::timeout(self.timeout, self.resolver.lookup(qname.clone(), qtype)).await;

        match lookup {
            // Upstream did not answer within the per-query timeout -> SERVFAIL.
            Err(_elapsed) => ForwardOutcome::ServFail,
            Ok(Ok(found)) => {
                // `answers()` carries the full answer section — the CNAME chain
                // (intermediate CNAME records) plus the terminal records hickory
                // chased to. We author them verbatim back to the VM.
                let records: Vec<Record> = found.answers().to_vec();
                if records.is_empty() {
                    ForwardOutcome::NoData
                } else {
                    ForwardOutcome::Answer(records)
                }
            }
            Ok(Err(err)) => {
                // A name that exists but has no record of this type, or an upstream
                // NXDOMAIN, is "no data" for this pre-stage (authored denial shapes
                // are out of scope). Any other error (refused, timeout surfaced as
                // an error, no connections, proto/io error) is a genuine failure.
                if err.is_no_records_found() {
                    ForwardOutcome::NoData
                } else {
                    ForwardOutcome::ServFail
                }
            }
        }
    }

    /// The doc 11 §3.5 phase-B pre-step: settle the genuine pure-v6-only `aaaa_only`
    /// trigger with a BOUNDED explicit AAAA probe on the SAME upstream forwarder.
    ///
    /// Fired ONLY when the A-lookup returned NoData over a policy-allowed name (the
    /// forward path is unreachable for Deny/Ask). It rides `self.resolver` — the one
    /// upstream pool the gate already holds — so there is no second resolver and no
    /// per-query fan-out (doc 11 §1: ds-dnsgate is the fleet single resolver / DoS
    /// chokepoint). A small in-flight budget ([`DEFAULT_AAAA_PROBE_BUDGET`]) bounds the
    /// added resolver load: while it is saturated the probe is skipped and the caller
    /// keeps the honest deferral (never a silent `false`).
    ///
    /// `Settled(true)` — the AAAA leg found records: a genuine pure-v6-only origin (the
    /// D75 trigger). `Settled(false)` — the AAAA leg also had no records (the name is
    /// genuinely empty / NXDOMAIN, not v6-only). `Unsettled` — the probe could not run
    /// (budget exhausted) or the AAAA leg failed/timed out, so the trigger stays unknown.
    async fn probe_aaaa(&self, qname: &Name) -> AaaaProbe {
        // Reserve one in-flight probe slot, or skip if the budget is saturated. The
        // compare-and-swap loop keeps the ceiling exact under concurrency without a lock.
        let mut budget = self.aaaa_probe_budget.load(Ordering::Acquire);
        loop {
            if budget == 0 {
                return AaaaProbe::Unsettled;
            }
            match self.aaaa_probe_budget.compare_exchange_weak(
                budget,
                budget - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => budget = observed,
            }
        }

        // The slot is reserved for exactly this probe's lifetime — a guard restores it
        // on every exit (settled, NoData, error, or timeout) so the ceiling is in-flight,
        // never a permanent decrement.
        let _slot = ProbeSlot {
            budget: &self.aaaa_probe_budget,
        };

        let lookup = tokio::time::timeout(
            self.timeout,
            self.resolver.lookup(qname.clone(), RecordType::AAAA),
        )
        .await;

        match lookup {
            // The probe is best-effort telemetry settlement: a timeout or genuine
            // failure leaves the trigger unknown, never a fabricated determination.
            Err(_elapsed) => AaaaProbe::Unsettled,
            Ok(Ok(found)) => {
                let has_aaaa = found
                    .answers()
                    .iter()
                    .any(|r| r.record_type() == RecordType::AAAA);
                AaaaProbe::Settled(has_aaaa)
            }
            Ok(Err(err)) => {
                // NoData / NXDOMAIN on the AAAA leg too → the name is genuinely empty,
                // not v6-only (a determined `false`). Any other error → unknown.
                if err.is_no_records_found() {
                    AaaaProbe::Settled(false)
                } else {
                    AaaaProbe::Unsettled
                }
            }
        }
    }
}

/// An RAII guard that restores one AAAA-probe budget slot when a probe finishes. Keeps
/// [`Forwarder::aaaa_probe_budget`] an IN-FLIGHT ceiling (released on every exit) rather
/// than a permanent decrement, so the bound is "concurrent probes", not "probes ever".
struct ProbeSlot<'a> {
    budget: &'a AtomicU32,
}

impl Drop for ProbeSlot<'_> {
    fn drop(&mut self) {
        self.budget.fetch_add(1, Ordering::Release);
    }
}

/// The result of the bounded AAAA probe (doc 11 §3.5 phase-B pre-step). Confined to this
/// module; the caller maps it onto the hickory-free [`AaaaOnly`] before any event leaves.
enum AaaaProbe {
    /// The AAAA leg ran: `true` == AAAA records exist (the genuine pure-v6-only trigger);
    /// `false` == the AAAA leg also had no records (genuinely empty, not v6-only).
    Settled(bool),
    /// The probe could not settle the answer — budget exhausted, or the AAAA leg
    /// failed/timed out. The caller keeps the honest deferral, never a silent `false`.
    Unsettled,
}

/// The hickory-free-for-the-caller result of a forward. Lives in this module only;
/// the records it carries are hickory `Record`s, so it is never exposed past the
/// handler seam.
enum ForwardOutcome {
    /// Answer records (the CNAME chain plus terminal records) to author to the VM.
    Answer(Vec<Record>),
    /// The name resolved with no records of this type (or NXDOMAIN): NOERROR/NODATA.
    NoData,
    /// A genuine upstream failure or timeout: SERVFAIL (doc 11 §8.5).
    ServFail,
}

/// How the handler derives the [`DnsQueryCtx::session`] for a query — the §5.1 / W6
/// (D44/D66) interface-anchored session-attribution wiring.
///
/// The frozen [`DnsQueryCtx`] shape (session / qname / qtype / source) is unchanged
/// across every variant: only HOW `session` is computed moves. Two production shapes
/// (doc 11 §8.2) plus the pre-stage fallback are modeled, so a deployment's attribution
/// posture is explicit on the handler — never an implicit bare-source-IP join.
enum SessionSource {
    /// PRE-STAGE fallback (no [`AttributionTable`] wired): the request's recorded source
    /// address rendered as a stable token (`src:<addr>`). This is the wave-1 behavior the
    /// non-attribution constructors keep, so the framework / forwarder / suppression
    /// harnesses (which dial from arbitrary loopback sources with no tap registry) stay
    /// green. It is NOT the W6 interface-anchored join — a deployment that wants the
    /// frozen §5.1 identity wires an [`AttributionTable`] via [`SessionSource::Table`].
    PreStage,
    /// SINGLE-SESSION FIXED UUID (testbed agreement, doc 11 §5.1 / D131-rollout): every
    /// query on this handler attributes to ONE operator-supplied `session_uuid`, regardless
    /// of source. This is the minimal cross-process AdmissionMap-key agreement for the
    /// single-VM nested-KVM testbed: ds-dnsgate stamps this exact string into the W1/W2
    /// AdmissionKey it writes to the DNS-2b shm, and a co-host ds-tlsproxy stamps the SAME
    /// string into the `SessionRef::session_uuid` it reads the shm with — so the FORWARD
    /// admission lookup HITS (it otherwise misses: PreStage writes `src:<addr>`, the
    /// transparent proxy reads `""`). Selected ONLY when the operator sets the agreed env
    /// (`DS_SESSION_UUID`, wired in `main`) and never by any default constructor; with the
    /// env unset the handler stays [`SessionSource::PreStage`] and the gate is byte-identical
    /// to today. Single-session-honest only: a second concurrent session would
    /// cross-attribute to this one uuid, so prefer interface-anchored [`Table`] attribution
    /// for multi-session. This carries NO orchestrator join and NO source/interface lookup —
    /// it is the operator asserting "this gate serves exactly this session".
    FixedUuid(String),
    /// LIVE-WIRE (doc 11 §5.1 / W6, D44): an [`AttributionTable`] (the orchestrator
    /// per-session tap registry / per-tap bind) resolved against the handler's own
    /// interface-anchored anchor. `query_ctx` resolves the session through
    /// [`AttributionTable::attribute_local`] (single-listener post-NAT local-address) or
    /// [`AttributionTable::attribute_per_tap`] (per-tap bind) — NEVER the raw source IP —
    /// and FAILS CLOSED to SERVFAIL on [`AttributionError::UnknownInterface`] (a genuine
    /// ds-dnsgate failure per W1/§3.2, never a policy NXDOMAIN). The never-recycled tap
    /// name is the join key; the source IP is never the key.
    Table {
        /// The interface-anchored tap registry (read view of the orchestrator session
        /// record). Keyed on the gate's own per-session LOCAL address, never the guest
        /// source IP.
        table: AttributionTable,
        /// The interface-anchored anchor THIS handler resolves against — the listener's
        /// own local address (single-listener, [`SessionSource::Table`] →
        /// `attribute_local`) or the tap the listener was bound for (per-tap bind →
        /// `attribute_per_tap`).
        anchor: AttributionAnchor,
    },
}

/// The interface-anchored anchor a [`SessionSource::Table`] handler attributes against —
/// the §8.2 socket-strategy choice made structural. Either the listener's own post-NAT
/// local address (single-listener shape) or the per-tap bind the listener was bound for
/// (per-tap-binds shape). Never the guest source IP in either shape.
enum AttributionAnchor {
    /// Single-listener + post-NAT local-address attribution (doc 11 §8.2): the session is
    /// the never-recycled tap the NFT-2 redirect landed on, keyed on this listener's own
    /// local address. Resolved via [`AttributionTable::attribute_local`].
    LocalAddress(std::net::IpAddr),
    /// Per-tap bind (doc 11 §8.2): one listener per `dstap-<idx>`; attribution is the bind
    /// itself, so the resolved session is fixed for this listener. Held pre-resolved so
    /// every query on this listener attributes to the same structural tap.
    PerTapBind(SessionAttribution),
}

/// The outcome of deriving a [`DnsQueryCtx`] for a request — distinguishes the FORMERR
/// (no query section) path from the §5.1 / W6 FAIL-CLOSED attribution-failure path, which
/// the §3.2 frozen disposition keeps SEPARATE: a query-less request is FORMERR, but a
/// query the gate cannot interface-anchor (an UnknownInterface) is a genuine ds-dnsgate
/// failure → SERVFAIL, NEVER a policy NXDOMAIN.
enum QueryCtxOutcome {
    /// The query was attributed and destructured into the frozen [`DnsQueryCtx`].
    Ctx(DnsQueryCtx),
    /// No query section (malformed / query-less): FORMERR (mirrors hickory's own
    /// empty-query handling).
    NoQuery,
    /// The query carried a question but could not be interface-anchored to a session
    /// (doc 11 §5.1 / W6, D44): fail closed to SERVFAIL. Never a policy NXDOMAIN — an
    /// unattributable query is a genuine ds-dnsgate failure (W1/§3.2), so it must not be
    /// confused with a policy deny.
    AttributionFailed,
}

/// A `RequestHandler` that, for the stub `Allow` ceiling, forwards every query to the
/// D64 upstream pool and authors the upstream answer back to the VM.
///
/// It also carries two pre-stage seams kept off `StubRequestHandler<P>`'s type
/// parameter list (so `server.rs` / the framework harness reference it unchanged):
///   * a boxed [`EventSink`] — the §5.5 LOG-1 `DnsEvent` emission target, defaulting
///     to [`NullSink`]; tests inject a `CapturingSink` to assert the §6.7 "every path
///     emits a DnsEvent with provenance" obligation.
///   * the boundary-zone-derived authored-SOA `mname` / `rname` (D71 VALUE), defaulting
///     to the [`DEFAULT_BOUNDARY_ZONE`] working name.
pub struct StubRequestHandler<
    P: PolicyHook,
    M: AdmissionMap = InMemoryAdmissionMap,
    S: NftSetProgrammer = RecordingSetProgrammer,
> {
    policy: P,
    forwarder: Forwarder,
    /// The §5.5 LOG-1 event sink (boxed so the sink type stays off the handler's type
    /// parameters — `server.rs` builds `StubRequestHandler<P>` unchanged). `NullSink`
    /// by default (no telemetry transport at the pre-stage; the emission SITES are what
    /// this unit lands).
    events: Arc<dyn EventSink>,
    /// The boundary-zone-derived authored-SOA signature (D71 MNAME/RNAME), behind a
    /// shared lock so the doc 13 §5.3 admitter-LAST D72 hot-reload can RE-SOURCE it from a
    /// new live snapshot WITHOUT re-binding the listeners. The `Arc` is shared across the
    /// UDP `Server` handler and the capped TCP accept-loop handler (both built in
    /// `spawn_gate`), reached through one [`BoundaryZoneReload`] handle per handler
    /// ([`boundary_zone_reload_handle`](Self::boundary_zone_reload_handle)), so the gate's
    /// single reload path ([`crate::server::RunningGate::reload_boundary_zone`], driven by
    /// the `WatchPolicies` subscriber) refreshes the authored SOA on BOTH transports at once
    /// — admitter-LAST, never per-transport skew.
    soa_signature: Arc<std::sync::RwLock<SoaSignature>>,
    /// How [`DnsQueryCtx::session`] is derived (doc 11 §5.1 / W6, D44): the pre-stage
    /// recorded-source fallback, or a LIVE interface-anchored [`AttributionTable`] join
    /// that fails closed to SERVFAIL on an unknown interface. The frozen ctx SHAPE is
    /// identical across both — only the `session` computation moves.
    session_source: SessionSource,
    /// The W1/W2 insert-then-answer admission stores (doc 11 §3.1 / §8.3): the DNS-2b
    /// map, the NFT-3 set programmer, and the §5.4 live-admission registry, behind shared
    /// handles so the UDP + TCP transports admit into the SAME state. On an `Allow`
    /// forwarded answer the handler runs the [`AdmissionStores::run_admission`]
    /// transaction over these BEFORE the answer leaves, and authors the W2-clamped TTL.
    /// A fail-closed admission yields SERVFAIL with zero residue (W1).
    ///
    /// The NFT-3 set programmer is the generic `S` type parameter: the DEFAULT
    /// [`RecordingSetProgrammer`] drives the reportable in-memory path (LOOPBACK/SYNTHETIC,
    /// no live kernel write — the offline/CI path), and a deployment binds the PRODUCTION
    /// `ds_nft::NftWriter` here behind `DS_NFTGATE_LIVE` (selected in `spawn_gate` /
    /// `main`) so the SAME W1/W2 admission insert that programs the recorder programs the
    /// real kernel allow-set element carrying the W2 deadline. The programmer rides behind
    /// `Arc<S>` inside [`AdmissionStores`], so both transports share one programmer handle.
    ///
    /// The DNS-2b map is the generic `M` type parameter: the DEFAULT
    /// [`InMemoryAdmissionMap`] is the in-process v0 body (every existing call site / test
    /// unchanged), and the D131 Candidate-A production path binds
    /// `M = ds_admission_shm::ShmAdmissionMap` (the live single-writer shm map ds-tlsproxy
    /// attaches its read-only `ShmAdmissionReader` to by name) via
    /// [`AdmissionStores::with_shm_writer`], selected in `main` behind `DS_ADMISSION_SHM_LIVE`.
    /// The W1/W2 insert-then-answer txn logic is unchanged — only the backing map swaps.
    admission: AdmissionStores<M, S>,
    /// The flat admission GRACE in seconds (POL-1 `admission.grace`, default 60s; doc 13
    /// §1.5 / D68) — the W2 shared-deadline grace, threaded from the snapshot, NEVER a
    /// code constant. Added to the kernel/map deadline only; the VM is answered the clamp
    /// WITHOUT grace (W2). FLOOR/CEIL ride the verdict's frozen `Admit`; this carries the
    /// one tunable the verdict does not (the `Admit` shape is frozen, doc 11 §4).
    grace_secs: u32,
    /// The DNS-3 ASK-USER seam (doc 09 §4 / doc 14 §2b / D18): on an ATTENDED unknown-domain
    /// `Ask` the handler raises an [`AskUserRequest`] here (boundary → orchestrator,
    /// one-way) and authors REFUSED; the post-approval retry resolves once the
    /// session-scoped grant lands on the policy stream. Boxed so the sink type stays off the
    /// handler's type parameters (mirrors `events`); [`NullAskSink`] by default — `main`
    /// runs without an orchestrator transport, only the emission SITE. A production
    /// deployment wires the orchestrator transport via [`with_ask_user`](Self::with_ask_user).
    ask_sink: Arc<dyn AskUserSink>,
    /// The session ATTENDEDNESS posture (D53 as revised by D77): an [`AskPosture::Attended`]
    /// session raises the async human ask; an [`AskPosture::Unattended`] session DOWNGRADES
    /// the unknown-domain `Ask` to immediate block+log (no human to interrupt). A per-session
    /// property the orchestrator owns and the handler is configured with — the gate never
    /// infers it. Defaults to the conservative [`AskPosture::Unattended`] (no open ask no
    /// one will answer); a deployment sets it via [`with_ask_posture`](Self::with_ask_posture).
    /// The VM is never suspended in EITHER posture (D77).
    ask_posture: AskPosture,
}

/// The DEFAULT-programmer constructors: every entry point here builds the reportable
/// in-memory [`RecordingSetProgrammer`] (LOOPBACK/SYNTHETIC, no live kernel write — the
/// offline/CI default). A deployment selects the PRODUCTION `ds_nft::NftWriter` programmer
/// by chaining [`with_admission`](StubRequestHandler::with_admission) — which is generic
/// over `S: NftSetProgrammer` and re-types the handler — onto any of these (the `spawn_gate`
/// / `main` path behind `DS_NFTGATE_LIVE`).
impl<P: PolicyHook> StubRequestHandler<P, InMemoryAdmissionMap, RecordingSetProgrammer> {
    /// Wrap a stub policy in a hickory request handler with the default D64 upstream
    /// forwarder pool (`1.1.1.1` / `8.8.8.8`, doc 11 §1 / D64).
    pub fn new(policy: P) -> Self {
        Self::with_forwarder(policy, ForwarderConfig::default())
    }

    /// Wrap a stub policy with an explicitly-configured forwarder pool — the
    /// injection seam tests use to point the pool at an in-process loopback mock
    /// upstream (zero network), and the seam a config push would use to override the
    /// D64 defaults. The config is hickory-free (plain `SocketAddr`s + a timeout).
    ///
    /// Uses the [`NullSink`] event sink and the [`DEFAULT_BOUNDARY_ZONE`] working-name
    /// SOA signature — the production-shell defaults (`server.rs` calls this).
    pub fn with_forwarder(policy: P, forwarder: ForwarderConfig) -> Self {
        Self::with_forwarder_and_boundary_zone(policy, forwarder, DEFAULT_BOUNDARY_ZONE)
    }

    /// Wrap a stub policy with an explicit forwarder pool AND an explicit boundary zone
    /// — the D71 authored-SOA MNAME derivation point. The MNAME/RNAME the gate authors
    /// become `denied.policy.<boundary_zone>.` / `hostmaster.denied.policy.<zone>.`; a
    /// VALUE change, not a SHAPE change (the prefix, always-authored SOA, and
    /// TTL==MINIMUM==negative-TTL stay frozen).
    ///
    /// The boundary-zone VALUE is now policy-pushed: it rides the POL-1
    /// `dns.boundary_zone` field onto the host policy snapshot
    /// (`ds-policy-snapshot::PolicySnapshot::boundary_zone`). Production callers read it
    /// off the composed POL-1 DNS block via
    /// [`with_forwarder_and_dns_config`](Self::with_forwarder_and_dns_config) (or pass
    /// `snapshot.boundary_zone()` straight in here); the [`DEFAULT_BOUNDARY_ZONE`]
    /// working name is the fallback ONLY, used when no boundary zone is pushed. Uses
    /// [`NullSink`].
    pub fn with_forwarder_and_boundary_zone(
        policy: P,
        forwarder: ForwarderConfig,
        boundary_zone: &str,
    ) -> Self {
        Self::with_forwarder_boundary_zone_and_sink(
            policy,
            forwarder,
            boundary_zone,
            Arc::new(NullSink),
        )
    }

    /// Wrap a stub policy reading the D71 authored-SOA boundary zone from the
    /// policy-pushed POL-1 DNS block — the production path that replaces the
    /// handler-local const default with the snapshot's value.
    ///
    /// [`pol1::DnsConfig::boundary_zone`] is the composed document's `dns.boundary_zone`,
    /// which the POL-1 reader already defaults to the working name
    /// ([`pol1::DEFAULT_BOUNDARY_ZONE`] == [`DEFAULT_BOUNDARY_ZONE`]) for a layer that
    /// omits it — so a snapshot WITHOUT the field reproduces the frozen
    /// [`SOA_SIGNATURE_MNAME`] exactly, and one WITH it drives the authored SOA. This is
    /// the same value `ds-policy-snapshot::PolicySnapshot::from_dns_config` lifts onto
    /// the host snapshot; the handler reads it through the
    /// [`with_forwarder_and_boundary_zone`](Self::with_forwarder_and_boundary_zone) seam
    /// rather than from the const. Uses [`NullSink`].
    pub fn with_forwarder_and_dns_config(
        policy: P,
        forwarder: ForwarderConfig,
        dns: &pol1::DnsConfig,
    ) -> Self {
        Self::with_forwarder_and_boundary_zone(policy, forwarder, &dns.boundary_zone)
    }

    /// The fully-explicit constructor: forwarder pool, boundary zone, AND the §5.5 LOG-1
    /// [`EventSink`]. The seam the event-surface tests use to inject a `CapturingSink`
    /// and assert emission on every path; the seam the real `ds-telemetry` spool would
    /// use to replace [`NullSink`] without touching any emission site.
    pub fn with_forwarder_boundary_zone_and_sink(
        policy: P,
        forwarder: ForwarderConfig,
        boundary_zone: &str,
        events: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            policy,
            forwarder: Forwarder::new(&forwarder),
            events,
            soa_signature: Arc::new(std::sync::RwLock::new(SoaSignature::from_boundary_zone(
                boundary_zone,
            ))),
            // No attribution table wired by this constructor: the pre-stage
            // recorded-source fallback (the framework / forwarder / suppression harnesses
            // and the wave-1 wire tests dial from arbitrary loopback sources with no tap
            // registry). A deployment wires the §5.1 / W6 live attribution via
            // [`with_attribution_local`] / [`with_attribution_per_tap`].
            session_source: SessionSource::PreStage,
            // A fresh in-memory admission-store bundle (loopback/synthetic; no live
            // kernel write). A deployment shares the gate's §5.4 live registry and binds
            // the production `ds-nft` writer via [`with_admission`].
            admission: AdmissionStores::new(),
            // The POL-1 `admission.grace` default (60s) until a snapshot pushes one
            // through [`with_admission_grace`] — a policy VALUE, not a behavior hardcode.
            grace_secs: ds_contracts::pol1::DEFAULT_GRACE_SECS,
            // No orchestrator ask-user transport at the pre-stage: the emission SITE exists
            // (the attended Ask path raises here) but lands in a NullAskSink. A deployment
            // wires the transport via [`with_ask_user`].
            ask_sink: Arc::new(NullAskSink),
            // The conservative default posture (D77): UNATTENDED → an unknown-domain Ask is
            // block+log, never an open ask no one will answer. A deployment sets the live
            // per-session posture via [`with_ask_posture`].
            ask_posture: AskPosture::default(),
        }
    }
}

/// The programmer-generic surface: the builders and accessors that operate over ANY
/// `S: NftSetProgrammer`. [`with_admission`](StubRequestHandler::with_admission) is the
/// type-changing transition — it RE-TYPES the handler from the constructor default
/// [`RecordingSetProgrammer`] to whatever programmer the supplied [`AdmissionStores`] carry
/// (the production `ds_nft::NftWriter` behind `DS_NFTGATE_LIVE`, selected in `spawn_gate` /
/// `main`); every other builder here preserves `S`.
impl<P: PolicyHook, M: AdmissionMap, S: NftSetProgrammer> StubRequestHandler<P, M, S> {
    /// Wire the W1/W2 admission stores explicitly — the seam a deployment uses to share
    /// the gate's §5.4 [`crate::server::LiveAdmissions`] registry (so the revocation
    /// sweep and the insert-then-answer transaction hold the SAME live set), to BIND the
    /// production `ds_nft::NftWriter` NFT-3 set programmer (the W1 set-program → live
    /// kernel allow-set element carrying the W2 deadline, behind `DS_NFTGATE_LIVE`), and to
    /// thread the POL-1 `admission.grace` value off the live snapshot. The `Admit` verdict
    /// carries FLOOR/CEIL (frozen shape, doc 11 §4); GRACE is the one tunable it does not,
    /// so it rides here from the snapshot — NEVER a code constant.
    ///
    /// This is the seam that RE-TYPES the handler to the supplied stores' map `M2` AND
    /// programmer `S2`: it consumes `self` and rebuilds with the new
    /// `AdmissionStores<M2, S2>`, carrying every other field forward unchanged. The
    /// constructor defaults are `M = InMemoryAdmissionMap` (in-process body) and
    /// `S = RecordingSetProgrammer` (reportable, no kernel); `spawn_gate` chains this with
    /// the recorder (the offline/CI default) or `ds_nft::NftWriter` (live, behind
    /// `DS_NFTGATE_LIVE`), and `main` chains the shm-backed stores
    /// (`M2 = ds_admission_shm::ShmAdmissionMap`) behind `DS_ADMISSION_SHM_LIVE`. Byte-exact
    /// key agreement and W1–W4 are properties of the transaction (doc 11 §3.1) — unchanged by
    /// which map or programmer the insert lands on.
    pub fn with_admission<M2: AdmissionMap, S2: NftSetProgrammer>(
        self,
        admission: AdmissionStores<M2, S2>,
        grace_secs: u32,
    ) -> StubRequestHandler<P, M2, S2> {
        StubRequestHandler {
            policy: self.policy,
            forwarder: self.forwarder,
            events: self.events,
            soa_signature: self.soa_signature,
            session_source: self.session_source,
            admission,
            grace_secs,
            ask_sink: self.ask_sink,
            ask_posture: self.ask_posture,
        }
    }

    /// Override only the POL-1 `admission.grace` value (seconds) — the W2 shared-deadline
    /// grace threaded from the snapshot (doc 13 §1.5). Keeps the default in-memory store
    /// bundle; a VALUE change, not a behavior hardcode.
    pub fn with_admission_grace(mut self, grace_secs: u32) -> Self {
        self.grace_secs = grace_secs;
        self
    }

    /// The shared admission stores this handler admits into — exposed so the gate can
    /// share the SAME DNS-2b map / NFT-3 set / live registry across both transports and
    /// assert the two-store lockstep end to end (the ds-tlsproxy synchronous-read shape).
    pub fn admission_stores(&self) -> &AdmissionStores<M, S> {
        &self.admission
    }

    /// Wire the DNS-3 ASK-USER seam (doc 09 §4 / doc 14 §2b / D18): the boundary →
    /// orchestrator one-way notification an ATTENDED unknown-domain `Ask` raises. The
    /// production orchestrator transport replaces the default [`NullAskSink`] WITHOUT
    /// touching the handler's Ask emission site (mirrors the [`EventSink`] discipline).
    /// The seam the seam-tests inject a `CapturingAskSink` through to assert the attended
    /// path raises an ask and the unattended path raises none.
    pub fn with_ask_user(mut self, ask_sink: Arc<dyn AskUserSink>) -> Self {
        self.ask_sink = ask_sink;
        self
    }

    /// Set the session ATTENDEDNESS posture (D53 as revised by D77) the handler applies to
    /// an unknown-domain `Ask`: [`AskPosture::Attended`] raises the async human ask,
    /// [`AskPosture::Unattended`] downgrades to immediate block+log. A per-session property
    /// the orchestrator owns; the gate is configured with it, never inferring it. The VM is
    /// never suspended in either posture (D77).
    pub fn with_ask_posture(mut self, ask_posture: AskPosture) -> Self {
        self.ask_posture = ask_posture;
        self
    }

    /// Wire the §5.1 / W6 LIVE interface-anchored session attribution against the
    /// listener's own post-NAT LOCAL address (doc 11 §8.2 single-listener shape, D44).
    ///
    /// The session for every query is resolved through
    /// [`AttributionTable::attribute_local`] keyed on `local_addr` — the interface-anchored
    /// address the NFT-2 redirect landed on, NEVER the guest source IP — and the handler
    /// FAILS CLOSED to SERVFAIL on [`AttributionError::UnknownInterface`] (a genuine
    /// ds-dnsgate failure per W1/§3.2, never a policy NXDOMAIN). This REPLACES the
    /// pre-stage raw-source-IP token (`src:<addr>`) with the never-recycled tap join the
    /// §5.1 freeze requires; the frozen [`DnsQueryCtx`] shape is unchanged (only `session`
    /// moves).
    pub fn with_attribution_local(
        mut self,
        table: AttributionTable,
        local_addr: std::net::IpAddr,
    ) -> Self {
        self.session_source = SessionSource::Table {
            table,
            anchor: AttributionAnchor::LocalAddress(local_addr),
        };
        self
    }

    /// Wire the §5.1 / W6 LIVE session attribution as a per-tap BIND (doc 11 §8.2 per-tap
    /// shape): attribution is the bind itself, so the resolved session is the structural
    /// tap this listener was bound for. Every query on this handler attributes to that
    /// never-recycled tap (no address lookup at all, the strongest shape). The frozen
    /// [`DnsQueryCtx`] shape is unchanged.
    pub fn with_attribution_per_tap(
        mut self,
        table: AttributionTable,
        attribution: SessionAttribution,
    ) -> Self {
        self.session_source = SessionSource::Table {
            table,
            anchor: AttributionAnchor::PerTapBind(attribution),
        };
        self
    }

    /// Wire the SINGLE-SESSION FIXED `session_uuid` agreement (doc 11 §5.1 / D131-rollout):
    /// every query on this handler attributes to `uuid` regardless of source, so the W1/W2
    /// admission writes its DNS-2b AdmissionKey under exactly that `session_uuid`. This is
    /// the minimal cross-process key agreement for the single-VM nested-KVM testbed — the
    /// gate writes `{uuid, fqdn}`, a co-host ds-tlsproxy reads `{uuid, fqdn}` (stamping the
    /// SAME `uuid` into its `SessionRef`), so the FORWARD admission lookup HITS instead of
    /// missing the `src:<addr>` ↔ `""` mismatch. Selected ONLY by `main` when the operator
    /// sets the agreed env (`DS_SESSION_UUID`); no default constructor reaches it, so with
    /// the env unset the handler stays [`SessionSource::PreStage`] and the gate is
    /// byte-identical to today. Single-session-honest only (see [`SessionSource::FixedUuid`]).
    /// The frozen [`DnsQueryCtx`] shape is unchanged — only how `session` is computed moves.
    pub fn with_session_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.session_source = SessionSource::FixedUuid(uuid.into());
        self
    }

    /// The boundary-zone-derived authored-SOA MNAME this handler CURRENTLY authors (D71).
    /// Exposed so the derivation point is assertable from the event-surface tests; returns
    /// an owned `String` because the value lives behind the hot-reload lock (a D72
    /// admitter-LAST reload swaps it). With the default working-name zone it reproduces
    /// [`SOA_SIGNATURE_MNAME`] exactly.
    pub fn soa_mname(&self) -> String {
        self.soa_signature
            .read()
            .expect("SOA signature lock poisoned")
            .mname
            .clone()
    }

    // The D72 admitter-LAST boundary-zone reload has ONE path: the gate's
    // `RunningGate::reload_boundary_zone` (driven by the `WatchPolicies` host-snapshot
    // subscriber, `crate::server::watch_policies`) re-derives the authored SOA on every
    // transport through one `BoundaryZoneReload` handle per handler
    // ([`boundary_zone_reload_handle`](Self::boundary_zone_reload_handle) →
    // [`BoundaryZoneReload::reload`]). The handler does NOT expose a second
    // `reload_boundary_zone` pub method: the UDP handler is moved into hickory's `Server`,
    // so the gate can only reach its signature through the cloned handle, and a parallel
    // handler-method path would let the two transports skew. The redundant method was folded
    // into the single `RunningGate` path.

    /// Snapshot the CURRENT authored-SOA `(mname, rname)` for one response — read once,
    /// owned, so the hot-reload lock is never held across the async authoring/send. A D72
    /// reload between two queries simply changes which suffix the NEXT query reads.
    fn soa_pair(&self) -> (String, String) {
        let sig = self
            .soa_signature
            .read()
            .expect("SOA signature lock poisoned");
        (sig.mname.clone(), sig.rname.clone())
    }

    /// A cloneable handle to this handler's hot-reloadable authored-SOA signature — the
    /// seam `server.rs` uses to refresh the boundary zone on a D72 admitter-LAST reload
    /// across every handler that shares it (the UDP `Server` handler is moved into hickory,
    /// so the gate keeps this handle to reach it). Re-derives the MNAME/RNAME via
    /// [`BoundaryZoneReload::reload`].
    pub(crate) fn boundary_zone_reload_handle(&self) -> BoundaryZoneReload {
        BoundaryZoneReload {
            signature: self.soa_signature.clone(),
        }
    }

    /// Emit one §5.5 LOG-1 [`DnsEvent`] to the sink. POL-3 provenance is attached on
    /// EVERY path (doc 11 §6.7, CI-fatal if missing) — it now carries the verdict's
    /// [`SeamProvenance`] (the matched rule id / layer / policy version), so the event
    /// names the rule that decided the query, not a fixed stub marker.
    fn emit_event(
        &self,
        ctx: &DnsQueryCtx,
        provenance: &SeamProvenance,
        path: EventPath,
        aaaa_stripped: u32,
        aaaa_only: AaaaOnly,
    ) {
        self.events.emit(DnsEvent {
            qname: ctx.qname.clone(),
            qtype: ctx.qtype,
            path,
            aaaa_stripped,
            aaaa_only,
            // OQ3 conservative default (doc 11 §5.5 / doc 14 §2, D69): `aimed_resolver` is
            // a RESERVED-OPTIONAL field left ALWAYS-`None` here. The original-destination
            // recovery (conntrack / IP_RECVORIGDSTADDR-class) that would populate it is the
            // SEPARATE ConnOrigin task (01KTWJ6N78), not this query-path unit — wiring it
            // here would pre-empt that task and the OQ3 ratification. The field is RESERVED
            // and READY (every event carries it) but never populated until OQ3 is decided.
            aimed_resolver: None,
            provenance: event_provenance(provenance),
        });
    }

    /// Raise the DNS-3 one-way ASK-USER notification for an ATTENDED unknown-domain `Ask`
    /// (doc 09 §4 / doc 14 §2b / D18). Builds the service-internal [`AskUserRequest`] from
    /// the verdict's frozen [`PromptRef`] (the session-scoped prompt identity) and POL-3
    /// provenance — the resource is the qname (a domain), the triple is the matched rule —
    /// and hands it to the ask-user sink. STRICTLY ONE-WAY (POL-5): nothing is awaited and
    /// no reply is expected; the approval returns out of band as a session-scoped grant on
    /// the policy stream. Called ONLY on the attended path (the unattended downgrade raises
    /// nothing — no human to interrupt).
    fn raise_ask_user(&self, prompt_ref: &PromptRef, provenance: &SeamProvenance) {
        self.ask_sink.ask(AskUserRequest::for_domain(
            prompt_ref.session.clone(),
            prompt_ref.qname.clone(),
            provenance.rule_id.clone(),
            provenance.policy_layer.clone(),
            provenance.policy_version.clone(),
        ));
    }

    /// Run the W1/W2 insert-then-answer admission transaction for a forwarded `Allow`
    /// answer (doc 11 §3.1 / §8.3). The single point a hickory `Record` meets the
    /// hickory-free [`crate::txn`] module: the terminal A/AAAA addresses and the
    /// chain-minimum TTL are destructured out HERE, then the transaction speaks only
    /// `std`/contract types.
    ///
    /// `ttl_floor`/`ttl_ceil` are the verdict's frozen `Admit` clamp window (POL-1
    /// values); GRACE is `self.grace_secs` (the POL-1 `admission.grace` the snapshot
    /// pushed). The admission is keyed on the ORIGINAL query name (`ctx.qname`, the name
    /// policy evaluated and the name the client presents in SNI) — NEVER an intermediate
    /// CNAME target (W3). POL-3 provenance is preserved on the entry.
    ///
    /// Returns the [`AdmissionOutcome`] the caller acts on: `Admitted{answered_ttl}` →
    /// answer with the clamped TTL (no grace); `FailClosed`/`NoPlumbableAddress` →
    /// SERVFAIL (a genuine ds-dnsgate failure, never a policy verdict).
    fn run_admission_for_answer(
        &self,
        ctx: &DnsQueryCtx,
        provenance: &SeamProvenance,
        ttl_floor: u32,
        ttl_ceil: u32,
        kept: &[Record],
    ) -> AdmissionOutcome {
        // The TERMINAL resolved addresses (post-CNAME-chase): every A/AAAA RR that
        // survived the §3.3 scrub. Intermediate CNAME records carry no address, so they
        // are naturally excluded — the admission is over the addresses the guest will
        // actually connect to, keyed on the ORIGINAL query name.
        //
        // IP-set canonicalization (W1 hardening): an upstream answer is untrusted input
        // and may carry the SAME terminal IP in multiple A/AAAA RRs (a malformed or
        // duplicate-stuffed answer). The admission transaction does NOT itself de-dupe —
        // each entry in `terminal_addrs` programs an NFT-3 set element AND increments the
        // §5.4 revocation-sweep refcount, so a duplicated IP would inflate the admitted
        // set and the reverse refcount, and a later single revoke would leave the kernel
        // element live (refcount > 0). De-duplicate to a DISTINCT IP set HERE, before the
        // transaction sees it, so each terminal IP is admitted exactly once. Order is
        // preserved deterministically (first occurrence wins) so any order-sensitive
        // downstream consumer sees a stable, answer-derived ordering.
        let mut seen: std::collections::HashSet<std::net::IpAddr> =
            std::collections::HashSet::new();
        let terminal_addrs: Vec<std::net::IpAddr> = kept
            .iter()
            .filter_map(|r| r.data.ip_addr())
            .filter(|addr| seen.insert(*addr))
            .collect();

        // The chain-minimum TTL the W2 clamp consumes (doc 11 §8.3 step 1): the smallest
        // TTL across the answer chain (CNAME hops + terminal records) — the most
        // conservative cache lifetime, so the admission never outlives the shortest-lived
        // RR. An empty/zero chain falls back to 0 (the clamp lifts it to FLOOR).
        let chain_min_ttl = kept.iter().map(|r| r.ttl).min().unwrap_or(0);

        let inputs = AdmissionInputs {
            session_uuid: ctx.session.clone(),
            // The host-local session index that composes the NFT-3 element mark. At the
            // pre-stage there is no orchestrator index registry threaded to the handler
            // (D44/D66 — the tap registry is a separate seam, see the crate docs), so the
            // index is derived deterministically from the session token. The NEVER-recycled
            // authoritative key is the session UUID on the map; the 14-bit index is a
            // disambiguator only (doc 11 §5.1), and the mark is composed under DS_MARK_MASK
            // regardless, so a bare-index match can never fire.
            session_index: session_index_from_token(&ctx.session),
            // Canonicalize the admission-key FQDN to the DOT-LESS form (doc 11 §5.1 /
            // D131-rollout cross-process key agreement). `ctx.qname` is the DNS canonical
            // TRAILING-DOT name (`api.anthropic.com.`), but a co-host ds-tlsproxy builds
            // its READ key from the SNI, which is dot-less (`classify_host` strips the
            // trailing dot). Stripping it HERE — at the single point the AdmissionKey FQDN
            // is composed (txn::admit keys directly on this field) — makes the WRITE key
            // dot-less too, so the two halves of the FORWARD lookup agree. The value is
            // normalized; the frozen AdmissionKey/SessionRef shapes are untouched.
            original_query_fqdn: admission_key_fqdn(&ctx.qname),
            terminal_addrs,
            chain_min_ttl,
            ttl_floor,
            ttl_ceil,
            grace: self.grace_secs,
            provenance: to_admission_provenance(provenance),
            // v0: every admission is NORMAL (the guest connects directly). The phase-B
            // synthetic-A path (D75) sets `Synthetic` + real_targets; it is a flag flip on
            // the SAME transaction, not a rewrite (doc 11 §8.3 step 5).
            admission_type: AdmissionType::Normal,
            real_targets: Vec::new(),
        };

        self.admission
            .run_admission(&inputs, admission_answer_time())
    }

    /// Translate a hickory request's query into the hickory-free [`DnsQueryCtx`] (doc 11
    /// §4: `DnsQueryCtx{session, qname, qtype, source}`).
    ///
    /// `session` is derived per [`SessionSource`] (doc 11 §5.1 / W6, D44): a LIVE
    /// interface-anchored [`AttributionTable`] join (`attribute_local` /
    /// `attribute_per_tap`) when one is wired, else the pre-stage recorded-source
    /// fallback. The interface-anchored join NEVER keys on the raw source IP, and FAILS
    /// CLOSED ([`QueryCtxOutcome::AttributionFailed`] → SERVFAIL) on an unknown interface.
    /// `qname` / `qtype` / `source` are unchanged across both — the frozen ctx SHAPE is
    /// intact, only the `session` computation moves.
    ///
    /// Returns [`QueryCtxOutcome::NoQuery`] for malformed requests with no query section
    /// (FORMERR, mirroring hickory's own empty-query handling), kept DISTINCT from the
    /// §5.1 fail-closed SERVFAIL so the two genuine-failure rcodes never blur.
    fn query_ctx(&self, request: &Request) -> QueryCtxOutcome {
        let Ok(info) = request.request_info() else {
            return QueryCtxOutcome::NoQuery;
        };
        let original = info.query.original();
        let source = request.src();
        let session = match self.derive_session(source) {
            Ok(session) => session,
            // §5.1 / W6 fail-closed: an un-attributable query is a genuine ds-dnsgate
            // failure (SERVFAIL), never a policy NXDOMAIN — see [`QueryCtxOutcome`].
            Err(_) => return QueryCtxOutcome::AttributionFailed,
        };
        QueryCtxOutcome::Ctx(DnsQueryCtx {
            session,
            qname: original.name().to_lowercase().to_ascii(),
            qtype: u16::from(original.query_type()),
            source,
        })
    }

    /// Derive the [`DnsQueryCtx::session`] token for a query's recorded `source`, per the
    /// handler's [`SessionSource`] (doc 11 §5.1 / W6, D44).
    ///
    /// * [`SessionSource::PreStage`]: the recorded-source fallback (`src:<addr>`) — the
    ///   wave-1 pre-stage token, kept only where no attribution table is wired.
    /// * [`SessionSource::FixedUuid`]: the operator-supplied single-session uuid (the
    ///   testbed cross-process key agreement, doc 11 §5.1 / D131-rollout) — returned verbatim
    ///   for every query, infallibly. NEVER selected by default; the env-unset path stays
    ///   `PreStage`.
    /// * [`SessionSource::Table`]: the LIVE interface-anchored join. `LocalAddress` resolves
    ///   the never-recycled tap via [`AttributionTable::attribute_local`] keyed on the
    ///   listener's own local address; `PerTapBind` returns the structural tap the listener
    ///   was bound for. In EITHER case the resolved session is the tap-name source
    ///   descriptor (never the raw source IP), and an [`AttributionError`] is propagated so
    ///   `query_ctx` can FAIL CLOSED to SERVFAIL. The raw `source` IP is NEVER the join key.
    fn derive_session(&self, source: SocketAddr) -> Result<String, AttributionError> {
        match &self.session_source {
            SessionSource::PreStage => Ok(pre_stage_session_token(source)),
            // The operator-supplied single-session uuid: returned verbatim for every query,
            // independent of `source`. Infallible — no interface lookup to fail (the operator
            // has asserted this gate serves exactly this session). It is the SAME string a
            // co-host ds-tlsproxy stamps into the read-side AdmissionKey, so the FORWARD
            // lookup agrees (doc 11 §5.1 / D131-rollout).
            SessionSource::FixedUuid(uuid) => Ok(uuid.clone()),
            SessionSource::Table { table, anchor } => match anchor {
                AttributionAnchor::LocalAddress(local_addr) => {
                    // Interface-anchored: key on the gate's OWN per-session local address
                    // (the NFT-2 redirect target), never the guest's spoofable source IP.
                    // UnknownInterface propagates → query_ctx fails closed to SERVFAIL.
                    let attribution = table.attribute_local(*local_addr)?;
                    Ok(attribution.source_descriptor())
                }
                AttributionAnchor::PerTapBind(attribution) => {
                    // Per-tap bind: attribution is the bind itself — the structural,
                    // never-recycled tap this listener was bound for. The table is held so
                    // the registry stays the single source of the join key even though the
                    // bind needs no lookup.
                    let _ = table;
                    Ok(attribution.source_descriptor())
                }
            },
        }
    }
}

/// Project the seam's [`SeamProvenance`] into the §5.5 event provenance. The two carry
/// the same POL-3 triple (matched rule id / composing layer / policy version); this is
/// the one bridge point so the event names the rule the verdict matched (doc 11 §6.7).
///
/// This bridge is also what keeps the INERT-vs-HARD-DENY distinction alive downstream.
/// The frozen `evaluate` folds an inert capability-gated entry into the SAME
/// `Deny{rcode_policy: NxDomain}` arm a hard `blocklist` deny takes — on the DNS wire
/// the two are indistinguishable (there is no fourth wire shape, `dns_gate.rs:130-135`).
/// The ONLY surviving signal is provenance: the inert arm carries its distinct
/// `baseline-pack:<family>/<fqdn>` rule id, the hard deny carries `blocklist:<domain>`.
/// Because this bridge copies the matched rule id VERBATIM (it never collapses the
/// inert id onto a generic deny marker), the LOG-1 `DnsEvent` and the §3.2 EDE-15 `ds:`
/// extra-text both carry the inert rule id intact through the NXDOMAIN authoring — so a
/// LOG-1 join can still tell an inert capability-gate apart from a hard block. The
/// `tests/policy_verdict.rs` inert-vs-deny regression pins this invariant.
fn event_provenance(p: &SeamProvenance) -> EventProvenance {
    EventProvenance {
        rule_id: p.rule_id.clone(),
        policy_layer: p.policy_layer.clone(),
        policy_version: p.policy_version.clone(),
    }
}

/// The pre-stage session token: the request's recorded source address rendered as a
/// stable string (doc 11 §5.1 — the real interface-anchored tap join is a later seam,
/// D44/D66). Kept on the frozen [`DnsQueryCtx`] so swapping in real attribution changes
/// only how this token is computed, never the ctx shape the evaluator consumes.
fn pre_stage_session_token(source: SocketAddr) -> String {
    format!("src:{source}")
}

/// Canonicalize a query name to the DOT-LESS admission-key FQDN form (doc 11 §5.1 /
/// D131-rollout). `ctx.qname` is the DNS canonical lower-cased TRAILING-DOT name; the
/// `AdmissionKey` the cross-process FORWARD lookup keys on must be DOT-LESS to match
/// the SNI form a co-host ds-tlsproxy reads with (`classify_host` strips the trailing
/// dot). Strip a SINGLE trailing `.` (root `.` collapses to `""`, an already-dot-less
/// name is unchanged). This normalizes the string VALUE only — the frozen
/// `AdmissionKey` shape is untouched. Both ds-dnsgate write sites (the live forward
/// path here and the D68 re-resolve seam) route through this same canonicalization so
/// they write the identical key.
pub(crate) fn admission_key_fqdn(qname: &str) -> String {
    qname.strip_suffix('.').unwrap_or(qname).to_string()
}

/// Project the verdict's POL-3 [`SeamProvenance`] onto the frozen admission-map
/// [`Provenance`] (doc 14 §3) — the same rule id / layer / version, carried onto the
/// DNS-2b entry so the §5.4 sweep and ds-tlsproxy read the provenance the verdict
/// authored (POL-3 preserved on every admission arm).
fn to_admission_provenance(p: &SeamProvenance) -> Provenance {
    Provenance {
        rule_id: p.rule_id.clone(),
        policy_layer: p.policy_layer.clone(),
        policy_version: p.policy_version.clone(),
    }
}

/// The gate's clock at answer authorship — the W2 shared-deadline base (doc 11 §8.3
/// step 1). Read once per admission and handed to BOTH stores so the kernel element
/// and the map entry share one instant (lockstep). `SystemTime` since the Unix epoch
/// in nanoseconds, the representation the frozen [`AdmissionInstant`] owns; a clock
/// before the epoch saturates at 0 (a deadline never moves earlier).
fn admission_answer_time() -> AdmissionInstant {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    AdmissionInstant::from_unix_nanos(nanos)
}

/// Derive the host-local 14-bit session index that composes the NFT-3 element mark
/// from the attributed session token (doc 11 §5.1 / D76). The NEVER-recycled
/// authoritative key is the session UUID the DNS-2b map keys on; the mark index is a
/// disambiguator only (`compose` reduces it `mod 2^14` and masks it), so a stable
/// deterministic derivation from the token is sufficient at the pre-stage until the
/// orchestrator tap-registry index is threaded in (a later seam, D44/D66). A simple
/// FNV-1a fold keeps the derivation total and dependency-free.
fn session_index_from_token(token: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in token.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// The PRODUCTION [`crate::reresolve::ReResolver`] adapter (D68 re-admit, doc 12 §4.1):
/// the live hickory upstream [`Forwarder`] pool, behind the hickory-free re-resolve seam.
///
/// This is the ONE place the re-resolve path meets hickory — the [`reresolve`] module
/// stays hickory-free (D67), and this adapter destructures the upstream `Record` answer
/// into the plain `std`/contract shape the seam consumes (the SAME `Record` →
/// `IpAddr` + `u32` projection the forward path's [`run_admission_for_answer`] performs).
///
/// `resolve()` is **synchronous** (the [`crate::reresolve::ReResolver`] trait is sync,
/// driven from the re-resolve server's `spawn_blocking` task): it drives the async
/// upstream lookup on the captured tokio runtime [`Handle`](tokio::runtime::Handle) via
/// `block_on`. That is safe and deadlock-free because the seam call runs on a
/// `spawn_blocking` pool thread (NOT a runtime worker), so blocking it parks no async
/// task. It resolves only the **A** leg (the SNI flow is v4-keyed; the §3.5 AAAA-only
/// settlement is the handler's, not the re-admit's), keyed on the ORIGINAL query name.
pub struct LiveReResolver {
    forwarder: Forwarder,
    handle: tokio::runtime::Handle,
}

impl LiveReResolver {
    /// Build the live re-resolver over the D64 upstream forwarder config, capturing the
    /// CURRENT tokio runtime handle (the re-resolve server is spawned inside `#[tokio::main]`,
    /// so a runtime is always current at construction).
    pub fn new(config: &ForwarderConfig) -> Self {
        Self {
            forwarder: Forwarder::new(config),
            handle: tokio::runtime::Handle::current(),
        }
    }
}

impl crate::reresolve::ReResolver for LiveReResolver {
    fn resolve(&self, sni_domain: &str) -> crate::reresolve::ReResolveResolved {
        use crate::reresolve::ReResolveResolved;
        // Project the SNI to a hickory `Name` (the seam already normalized it to the §3.1
        // lower-cased trailing-dot key; an unparseable name fails closed as Unresolved).
        let Ok(name) = Name::from_ascii(sni_domain) else {
            return ReResolveResolved::Unresolved;
        };
        // Drive the async upstream A lookup synchronously on the captured runtime — safe
        // on the re-resolve server's `spawn_blocking` thread (never a runtime worker).
        let outcome = self
            .handle
            .block_on(self.forwarder.forward(&name, RecordType::A));
        match outcome {
            ForwardOutcome::Answer(records) => {
                // The terminal resolved addresses (post-CNAME-chase); the chain-min TTL the
                // W2 clamp consumes — the SAME projection the forward path's
                // `run_admission_for_answer` performs.
                let terminal_addrs: Vec<std::net::IpAddr> =
                    records.iter().filter_map(|r| r.data.ip_addr()).collect();
                if terminal_addrs.is_empty() {
                    return ReResolveResolved::Unresolved;
                }
                let chain_min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0);
                ReResolveResolved::Resolved {
                    terminal_addrs,
                    chain_min_ttl,
                }
            }
            // No usable answer / upstream failure → the name resolves to nothing plumbable.
            ForwardOutcome::NoData | ForwardOutcome::ServFail => ReResolveResolved::Unresolved,
        }
    }
}

#[async_trait]
// `M: AdmissionMap + Send + Sync + 'static` and `S: NftSetProgrammer + Send + Sync + 'static`
// so the handler satisfies hickory's `RequestHandler: Send + Sync + Unpin + 'static` supertrait
// (the map rides behind `Arc<RwLock<M>>` and the programmer behind `Arc<S>`, both shared across
// the UDP `Server` + the capped TCP accept-loop tasks). The default `InMemoryAdmissionMap` +
// `RecordingSetProgrammer`, the production `ds_nft::NftWriter<SpawnBackend>` programmer, and the
// shm-backed `ds_admission_shm::ShmAdmissionMap` (its `SharedBase` carries the `Segment`'s
// `unsafe impl Send/Sync`) all satisfy it; selecting the live map or writer never changes this
// impl's shape.
impl<P, M, S> RequestHandler for StubRequestHandler<P, M, S>
where
    P: PolicyHook,
    M: AdmissionMap + Send + Sync + 'static,
    S: NftSetProgrammer + Send + Sync + 'static,
{
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut builder = MessageResponseBuilder::from_message_request(request);

        // Echo the request's EDNS OPT into the response. MEASURED (DNS-1, see the
        // README findings): hickory-server does NOT auto-echo EDNS, and the UDP
        // response encoder only honors the client's advertised buffer size when an
        // EDNS OPT is attached to the *response*. Without this, the UDP truncation
        // cap is always MAX_RECEIVE_BUFFER_SIZE (4096) regardless of what the client
        // advertised — so EDNS echo is mandatory for correct TC-bit behavior.
        if let Some(edns) = request.edns.as_ref() {
            builder.edns(edns);
        }

        // Derive the query ctx per the §5.1 / W6 attribution wiring. Three outcomes:
        //  * Ctx        → proceed to the verdict.
        //  * NoQuery    → FORMERR (malformed / query-less).
        //  * Attribution → SERVFAIL, FAIL CLOSED (doc 11 §5.1 / W6, D44): an
        //    un-interface-anchored query is a genuine ds-dnsgate failure, NEVER a policy
        //    NXDOMAIN. The never-recycled-tap join cannot be made, so no admission is
        //    minted — the same fail-closed posture as the W1 set-write failure.
        let ctx = match self.query_ctx(request) {
            QueryCtxOutcome::Ctx(ctx) => ctx,
            QueryCtxOutcome::NoQuery => {
                // §6.7: emit on EVERY path — a query-less request still gets a DnsEvent
                // (empty qname, the FormErr path). NO answer set, so `aaaa_only` is the
                // dedicated ErrorPathNoAnswerSet deferral; no verdict was reached, so the
                // fixed pre-stage error provenance rides it.
                self.emit_event(
                    &DnsQueryCtx {
                        session: pre_stage_session_token(request.src()),
                        qname: String::new(),
                        qtype: 0,
                        source: request.src(),
                    },
                    &error_path_provenance(),
                    EventPath::FormErr,
                    0,
                    AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
                );
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::FormErr;
                let response = builder.build_no_records(metadata);
                return match response_handle.send_response(response).await {
                    Ok(info) => info,
                    Err(_) => empty_response_info(request),
                };
            }
            QueryCtxOutcome::AttributionFailed => {
                // §5.1 / W6 fail-closed: the query carried a question but could not be
                // interface-anchored to a session — SERVFAIL (a genuine ds-dnsgate
                // failure, §3.2), and NO admission. §6.7: still emit on this path (no
                // verdict reached, so the fixed error-path provenance), with the
                // attributed source rendered in the event qname for diagnosis.
                self.emit_event(
                    &DnsQueryCtx {
                        session: String::new(),
                        qname: String::new(),
                        qtype: 0,
                        source: request.src(),
                    },
                    &attribution_failed_provenance(),
                    EventPath::ServFail,
                    0,
                    AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
                );
                return author_servfail(builder, request, &mut response_handle).await;
            }
        };

        // The frozen doc 11 §4 admission seam: evaluate(DnsQueryCtx) -> Verdict. The
        // verdict's POL-3 provenance rides every event this query emits.
        let verdict = self.policy.evaluate(&ctx);
        let provenance = verdict.provenance().clone();

        // Deny -> the §3.2 hard-deny shape (NXDOMAIN + authored SOA, D71); Ask ->
        // REFUSED immediately (no cacheable negative signal; the prompt travels the
        // Stage-0 ask-user seam out of band, D18). Neither forwards or admits, and both
        // carry NO answer set — so `aaaa_only` is the ErrorPathNoAnswerSet deferral and
        // the event carries the verdict's real rule provenance.
        match &verdict {
            Verdict::Deny { rcode_policy, .. } => {
                self.emit_event(
                    &ctx,
                    &provenance,
                    EventPath::Denied,
                    0,
                    AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
                );
                let owner = denial_owner_name(&ctx.qname);
                let (soa_mname, soa_rname) = self.soa_pair();
                return author_policy_denial(
                    builder,
                    request,
                    &owner,
                    *rcode_policy,
                    &soa_mname,
                    &soa_rname,
                    &provenance,
                    &mut response_handle,
                )
                .await;
            }
            Verdict::Ask { prompt_ref, .. } => {
                // DNS-3 ask-posture (doc 09 §4 / doc 11 §3.2, D18/D53/D77). The wire answer
                // is ALWAYS an immediate REFUSED (no cacheable negative signal — the first
                // post-approval retry reaches us), and the VM is NEVER suspended in either
                // posture (D77: suspension is reserved for genuine threats). The
                // ATTENDEDNESS posture (D53 as revised by D77) decides ONLY whether a human
                // is interrupted:
                //   * ATTENDED   → raise the one-way AskUserRequest over the ask-user seam
                //     (boundary → orchestrator, D18) and emit the `Asked` event. Approval
                //     returns as a session-scoped grant on the policy stream (no second
                //     response contract); the next DNS retry resolves.
                //   * UNATTENDED → DOWNGRADE to immediate block+log: NO ask is raised (no
                //     human to interrupt), and the `AskDowngradedBlock` event records the
                //     downgrade distinctly so a LOG-1 join tells the two apart.
                let path = if self.ask_posture.notifies_human() {
                    self.raise_ask_user(prompt_ref, &provenance);
                    EventPath::Asked
                } else {
                    EventPath::AskDowngradedBlock
                };
                self.emit_event(
                    &ctx,
                    &provenance,
                    path,
                    0,
                    AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
                );
                return author_refused(builder, request, &mut response_handle).await;
            }
            // Allow falls through to the forward + §3.3 scrub + answer path below; the
            // admit payload's W2 TTL clamp is applied to the authored answer TTL.
            Verdict::Allow { .. } => {}
        }

        // The W2 clamp window (FLOOR/CEIL) the verdict's frozen `Admit` carries (POL-1
        // `ttl_floor`/`ttl_ceil`, doc 11 §4) — captured here so the insert-then-answer
        // transaction below clamps the answer TTL and composes the shared deadline from
        // POLICY VALUES, never a code constant. GRACE is the handler's `grace_secs` (the
        // one §1.5 tunable the frozen `Admit` does not carry).
        let (ttl_floor, ttl_ceil) = match &verdict {
            Verdict::Allow { admit, .. } => (admit.ttl_floor, admit.ttl_ceil),
            // Unreachable: Deny/Ask returned above. The clamp window is only read on the
            // Allow answer path; a defensive default keeps the match total without a
            // panic (the values are never used off the Allow path).
            _ => (
                ds_contracts::pol1::DEFAULT_TTL_FLOOR_SECS,
                ds_contracts::pol1::DEFAULT_TTL_CEIL_SECS,
            ),
        };

        // Allow -> forward -> scrub -> respond. Resolve the original query name against
        // the upstream pool (CNAME chain followed internally), then author the
        // §3.3-scrubbed outcome.
        let Ok(info) = request.request_info() else {
            // No query info to forward — a genuine failure (SERVFAIL, never a policy
            // verdict, §3.2); still emit an event (§6.7 every path). This carries NO
            // answer set, so `aaaa_only` is the ErrorPathNoAnswerSet deferral.
            self.emit_event(
                &ctx,
                &provenance,
                EventPath::ServFail,
                0,
                AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
            );
            return author_servfail(builder, request, &mut response_handle).await;
        };
        let qname: Name = info.query.original().name().clone();
        let qtype: RecordType = info.query.original().query_type();

        // §3.3 fast NODATA: an AAAA / HTTPS(65) / SVCB(64) query is answered WITHOUT a
        // forward, as a NOERROR/NODATA with the D71 authored SOA in authority — never
        // drop/SERVFAIL/REFUSED. AAAA is a fast NODATA so the v4-only guest never
        // stalls a v6 lookup (RFC 4074); HTTPS/SVCB are suppressed entirely (D70), so
        // an explicit type-65/64 query also never leaves the gate. Identical over UDP
        // and TCP/53 — the same handler serves both transports (server.rs).
        if is_fast_nodata_qtype(qtype) {
            // §5.5 event: the AAAA fast-NODATA strips exactly the one AAAA the guest
            // asked for (aaaa_stripped = 1 for an AAAA query; HTTPS/SVCB strip no AAAA,
            // so 0). `aaaa_only` is the RECORDED DEFERRAL here — this path deliberately
            // never forwards AAAA upstream, so it cannot determine the A-count without
            // a parallel probe (rejected, see `AaaaOnly` docs).
            let aaaa_stripped = u32::from(qtype == RecordType::AAAA);
            self.emit_event(
                &ctx,
                &provenance,
                EventPath::FastNodata,
                aaaa_stripped,
                AaaaOnly::Deferred(DeferralReason::FastNodataNoForward),
            );
            let (soa_mname, soa_rname) = self.soa_pair();
            return author_nodata_with_soa(
                builder,
                request,
                &qname,
                &soa_mname,
                &soa_rname,
                &mut response_handle,
            )
            .await;
        }

        let outcome = self.forwarder.forward(&qname, qtype).await;

        let (rcode, answers, path, aaaa_stripped, aaaa_only): (
            ResponseCode,
            Vec<Record>,
            EventPath,
            u32,
            AaaaOnly,
        ) = match outcome {
            ForwardOutcome::Answer(records) => {
                // §3.3 forwarded-answer-path scrub: strip every AAAA / HTTPS(65) /
                // SVCB(64) RR before the answer reaches the VM. A forwarded A answer
                // that carried a bundled HTTPS/SVCB record (or an upstream that
                // appended AAAA to a non-AAAA answer) arrives WITHOUT them; the
                // suppression is authored HERE, on the gate's answer path, never via
                // a hickory resolver internal.
                //
                // §5.5: count the AAAA RRs the scrub removed (`aaaa_stripped`), and
                // settle `aaaa_only` from the answer set the gate already holds — the
                // ONE forward-free observable trigger shape: the answer literally
                // bundled AAAA RRs (a non-AAAA answer carrying AAAA in its answer
                // section) AND no A survived the scrub. (A pure v6-only origin does NOT
                // reach here — hickory's type-filtered A-lookup returns NoData and hides
                // the AAAA; that pure case is the `Deferred(ForwardedNoDataV6Invisible)`
                // arm below, deferred to the phase-B explicit AAAA probe per the
                // `AaaaOnly` design decision.)
                let upstream_had_aaaa = records.iter().any(|r| r.record_type() == RecordType::AAAA);
                let aaaa_stripped = u32::try_from(
                    records
                        .iter()
                        .filter(|r| r.record_type() == RecordType::AAAA)
                        .count(),
                )
                .unwrap_or(u32::MAX);
                let type_scrubbed: Vec<Record> = records
                    .into_iter()
                    .filter(|r| !is_scrubbed_record_type(r.record_type()))
                    .collect();

                // ── W5 / DNS-4 rule 2: the SANITY scrub on the ANSWER path ──────────
                // doc 09 §4 DNS-4 rule 2 (and doc 11 §3.3 W5): an admitted address must
                // pass the dual-stack sanity filter, and a martian "is never inserted AND
                // ALWAYS SCRUBBED FROM ANSWERS." The W1/W2 transaction below already
                // declines to ADMIT a martian (it admits only `is_plumbable` IPs), but
                // the ANSWER the VM sees must be scrubbed too — otherwise a rebinding
                // upstream could still hand the guest a private/loopback/embedded-IPv4
                // literal it would try to connect to (NFT default-deny would block it, but
                // the contract is to never ANSWER the martian, not to lean on the firewall
                // as the only line). So every A/AAAA RR whose address fails `is_plumbable`
                // is removed from the authored answer HERE, keeping CNAME chain records and
                // any non-address RR. `is_plumbable` is the SAME pure W5 predicate the
                // transaction admits against (the embedded-IPv4 unwrap for ::ffff:0:0/96 and
                // 64:ff9b::/96 included), so the answer set and the admitted set agree by
                // construction. A name that resolves ENTIRELY to martians yields an empty
                // address set here and `NoPlumbableAddress` from the transaction → SERVFAIL.
                let kept: Vec<Record> = type_scrubbed
                    .into_iter()
                    .filter(|r| match r.data.ip_addr() {
                        // An address record survives only if the address is plumbable.
                        Some(addr) => is_plumbable(addr),
                        // A non-address record (CNAME chain hop, etc.) is not an address to
                        // sanity-check — it is kept (it carries no IP the guest connects to).
                        None => true,
                    })
                    .collect();
                let any_a_survived = kept.iter().any(|r| r.record_type() == RecordType::A);
                // aaaa_only == upstream had AAAA but no A survived for the v4 guest.
                let aaaa_only = AaaaOnly::Determined(upstream_had_aaaa && !any_a_survived);

                // ── W1/W2/W3: the insert-then-answer admission transaction ──────────
                // EVERY forwarded answer (fresh or hickory-resolver-cached) traverses the
                // FULL admission path before a byte reaches the VM (W3). The terminal
                // A/AAAA addresses (post-CNAME-chase) and the chain-minimum TTL are
                // destructured out of the kept records here — the single point a hickory
                // type meets the hickory-free `txn` module (doc 11 §8.1). The transaction
                // runs the DNS-4 filter, composes the ONE shared deadline from the POL-1
                // FLOOR/CEIL (the verdict's `Admit`) + GRACE (`self.grace_secs`), and in
                // one fail-closed step programs the NFT-3 set + writes the DNS-2b map +
                // records the live admission, all keyed on the ORIGINAL query name.
                match self.run_admission_for_answer(&ctx, &provenance, ttl_floor, ttl_ceil, &kept) {
                    AdmissionOutcome::Admitted { answered_ttl, .. } => {
                        // W2: answer the VM the CLAMPED TTL, WITHOUT grace. The grace
                        // lives only on the kernel/map deadline, never on the wire TTL.
                        // `Record` has no in-place TTL setter, so each RR is rebuilt with
                        // the clamped TTL over its existing name + rdata (the CNAME chain
                        // and terminal records alike carry the one clamped lifetime).
                        let clamped: Vec<Record> = kept
                            .into_iter()
                            .map(|r| {
                                Record::from_rdata(r.name.clone(), answered_ttl, r.data.clone())
                            })
                            .collect();
                        (
                            ResponseCode::NoError,
                            clamped,
                            EventPath::ForwardedAnswer,
                            aaaa_stripped,
                            aaaa_only,
                        )
                    }
                    // W1 fail-closed: a set-programming or map failure withholds the
                    // answer — SERVFAIL (a genuine ds-dnsgate failure, never a policy
                    // verdict, §3.2), zero residue (the transaction rolled back). The
                    // NoPlumbableAddress arm is the W5 refusal: every resolved terminal
                    // address was a martian, so there is no plumbable IP to admit — the
                    // gate cannot answer a usable address, also SERVFAIL.
                    AdmissionOutcome::FailClosed | AdmissionOutcome::NoPlumbableAddress => (
                        ResponseCode::ServFail,
                        Vec::new(),
                        EventPath::ServFail,
                        0,
                        AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
                    ),
                }
            }
            ForwardOutcome::NoData => {
                // MEASURED: a type-filtered A-lookup returns NoData for a v6-only origin
                // and hides any AAAA, so the A-path alone cannot tell "truly no record"
                // from "AAAA-only". Settle it with the doc 11 §3.5 phase-B bounded
                // explicit AAAA probe on the SAME upstream forwarder (no second resolver,
                // no fan-out): AAAA present → the genuine pure-v6-only trigger
                // (Determined(true)); AAAA also empty → genuinely no record
                // (Determined(false)); the probe could not run/settle → the honest
                // deferral, never a silent `false` (which would mask a real v6-only domain
                // from the T-C3 join).
                let aaaa_only = match self.forwarder.probe_aaaa(&qname).await {
                    AaaaProbe::Settled(has_aaaa) => AaaaOnly::Determined(has_aaaa),
                    AaaaProbe::Unsettled => {
                        AaaaOnly::Deferred(DeferralReason::ForwardedNoDataV6Invisible)
                    }
                };
                (
                    ResponseCode::NoError,
                    Vec::new(),
                    EventPath::NoData,
                    0,
                    aaaa_only,
                )
            }
            ForwardOutcome::ServFail => (
                ResponseCode::ServFail,
                Vec::new(),
                EventPath::ServFail,
                0,
                // A genuine upstream failure carries NO answer set and never forwarded any
                // data — the dedicated ErrorPathNoAnswerSet deferral, not a forwarded
                // NoData. (The genuine forwarded-NoData arm above keeps
                // ForwardedNoDataV6Invisible — that one resolved with no records of the
                // type, which is the v6-invisible case the trigger defers to phase B.)
                AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
            ),
        };

        // §6.7: emit the DnsEvent for this forwarded-answer path BEFORE authoring the
        // wire response, so the signal is recorded even if the response send fails.
        self.emit_event(&ctx, &provenance, path, aaaa_stripped, aaaa_only);

        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.message_type = MessageType::Response;
        metadata.op_code = OpCode::Query;
        metadata.recursion_available = true;
        metadata.response_code = rcode;

        let response = builder.build(
            metadata,
            answers.iter(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );

        match response_handle.send_response(response).await {
            Ok(resp_info) => resp_info,
            Err(_) => empty_response_info(request),
        }
    }
}

/// Author the §3.3 fast NOERROR/NODATA: an empty answer section, NOERROR rcode, and
/// the D71 ds-dnsgate-authored SOA in the authority section (doc 11 §3.2: the SOA in
/// any negative response is always present and always authored here, never relayed).
/// This is the wire shape for an AAAA / HTTPS(65) / SVCB(64) query — NEVER
/// drop/SERVFAIL/REFUSED (RFC 4074: a dropped AAAA stalls glibc and musl ~5s). The
/// `soa` build slot is chained into the authority section by the encoder, so the SOA
/// lands in NSCOUNT exactly as §3.2 requires.
async fn author_nodata_with_soa<R: ResponseHandler>(
    builder: MessageResponseBuilder<'_>,
    request: &Request,
    qname: &Name,
    soa_mname: &str,
    soa_rname: &str,
    response_handle: &mut R,
) -> ResponseInfo {
    let soa = authored_negative_soa(qname, soa_mname, soa_rname);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.message_type = MessageType::Response;
    metadata.op_code = OpCode::Query;
    metadata.recursion_available = true;
    // NOERROR (NODATA): the name exists, it just has no record of this type for the
    // guest — NOT NXDOMAIN, and NOT a SERVFAIL/REFUSED (those stall RFC-4074 stubs).
    metadata.response_code = ResponseCode::NoError;

    let response = builder.build(
        metadata,
        std::iter::empty(), // empty answer section — the scrubbed type never appears
        std::iter::empty(), // no other authority records
        std::iter::once(&soa), // the D71 authored SOA, chained into the authority section
        std::iter::empty(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => empty_response_info(request),
    }
}

/// Author a SERVFAIL response (genuine-failure rcode, doc 11 §8.5).
async fn author_servfail<R: ResponseHandler>(
    builder: MessageResponseBuilder<'_>,
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.message_type = MessageType::Response;
    metadata.op_code = OpCode::Query;
    metadata.recursion_available = true;
    metadata.response_code = ResponseCode::ServFail;
    let response = builder.build_no_records(metadata);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => empty_response_info(request),
    }
}

/// Author the §3.2 policy-deny shape for a `Deny{rcode_policy}` verdict (D71): the
/// rcode the `rcode_policy` names (a HARD deny is NXDOMAIN, RCODE 3) with the always-
/// authored D71 signature SOA in the authority section — empty answer, never an
/// address record (§3.2), and **EDE INFO-CODE 15 (Blocked) iff the query carried an
/// OPT record**, with a `ds:`-prefixed POL-3 EXTRA-TEXT. The SOA is the SAME authored
/// shape the §3.3 scrub uses; only the rcode differs (NXDOMAIN here vs NOERROR for the
/// scrub). SERVFAIL is never a policy verdict (§3.2), so it is not reachable here.
///
/// The EDE rides as a generic `EdnsOption::Unknown(15, ...)` on the RESPONSE Edns
/// (hickory 0.26.x has no native EDE type); it attaches only when the request carried
/// OPT, because EDE only travels in an OPT record and is diagnostic-only (no behavior
/// may depend on it, §3.2 — the guaranteed channel is the LOG-1 PolicyDecision event).
/// The owned response `Edns` is constructed in THIS frame so the builder's `'q` borrow
/// is this frame, not the request — the lifetime the builder's `edns(&'q Edns)` wants;
/// the incoming `builder` is dropped and re-derived here for that reason.
#[allow(clippy::too_many_arguments)]
async fn author_policy_denial<R: ResponseHandler>(
    _builder: MessageResponseBuilder<'_>,
    request: &Request,
    owner: &Name,
    rcode_policy: RcodePolicy,
    soa_mname: &str,
    soa_rname: &str,
    provenance: &SeamProvenance,
    response_handle: &mut R,
) -> ResponseInfo {
    let rcode = match rcode_policy {
        RcodePolicy::NxDomain => ResponseCode::NXDomain,
    };
    let soa = authored_negative_soa(owner, soa_mname, soa_rname);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.message_type = MessageType::Response;
    metadata.op_code = OpCode::Query;
    metadata.recursion_available = true;
    metadata.response_code = rcode;

    // Re-derive the builder in THIS frame and an owned response Edns carrying the EDE
    // 15 option iff the request carried OPT. Both live in this frame, so the builder's
    // `'q` lifetime is this frame — satisfying the `edns(&'q Edns)` borrow.
    let mut builder = MessageResponseBuilder::from_message_request(request);
    let response_edns: Option<Edns> = request.edns.as_ref().map(|req_edns| {
        // Preserve the client's advertised buffer size (so a UDP deny is not needlessly
        // truncated), then attach the diagnostic EDE 15 (Blocked) with POL-3 provenance.
        let mut edns = Edns::new();
        edns.set_max_payload(req_edns.max_payload());
        edns.set_version(req_edns.version());
        edns.options_mut().insert(ede_blocked_option(provenance));
        edns
    });
    if let Some(edns) = response_edns.as_ref() {
        builder.edns(edns);
    }

    let response = builder.build(
        metadata,
        std::iter::empty(), // empty answer section — a deny never carries an address
        std::iter::empty(), // no other authority records
        std::iter::once(&soa), // the always-present D71 authored signature SOA (§3.2)
        std::iter::empty(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => empty_response_info(request),
    }
}

/// Author the §3.2 ASK-posture response: REFUSED (RCODE 5), immediately, with NO
/// cacheable negative signal (doc 11 §3.2: nothing in the surveyed stack caches
/// REFUSED, so the first post-approval retry reaches us). The prompt travels the
/// Stage-0 ask-user seam out of band (D18) — there is no second wire response on this
/// path. No SOA: REFUSED carries no authored negative-cache control (unlike NXDOMAIN).
async fn author_refused<R: ResponseHandler>(
    builder: MessageResponseBuilder<'_>,
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.message_type = MessageType::Response;
    metadata.op_code = OpCode::Query;
    metadata.recursion_available = true;
    metadata.response_code = ResponseCode::Refused;
    let response = builder.build_no_records(metadata);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => empty_response_info(request),
    }
}

/// Parse the (already lower-cased, trailing-dot) query name into a hickory `Name` for
/// the denial SOA owner. Confined to this module (not a pub item, so the D67 seam
/// holds). A query that reached the verdict stage always had a valid name; if parsing
/// somehow fails the root is a safe owner for the authored SOA.
fn denial_owner_name(qname: &str) -> Name {
    Name::from_ascii(qname).unwrap_or_else(|_| Name::root())
}

/// The provenance the error paths attach when NO policy verdict was reached (a
/// query-less FORMERR, or the request-info-less no-forward path): there is no rule to
/// name, so a clearly-marked error marker keeps the §6.7 "every event carries
/// provenance" invariant true without inventing a rule id. This is NOT a verdict
/// provenance — every path that DID reach the evaluator stamps the verdict's live POL-3
/// triple; this marker is reached only where there is no query to evaluate.
fn error_path_provenance() -> SeamProvenance {
    SeamProvenance {
        rule_id: "error-path".to_string(),
        policy_layer: "none".to_string(),
        policy_version: "no-verdict".to_string(),
    }
}

/// The provenance the §5.1 / W6 fail-closed SERVFAIL path attaches (doc 11 §5.1, D44).
/// An un-interface-anchored query reaches no policy verdict (it was never attributed to a
/// session, so it could not be evaluated), so — like [`error_path_provenance`] — a
/// clearly-marked attribution marker keeps the §6.7 "every event carries provenance"
/// invariant true without inventing a rule id. NOT a policy verdict (this is the
/// genuine-failure path, never a deny), and distinct from the no-query FORMERR marker so a
/// consumer can tell an unknown-interface SERVFAIL from a malformed-request FORMERR.
fn attribution_failed_provenance() -> SeamProvenance {
    SeamProvenance {
        rule_id: "attribution-failed".to_string(),
        policy_layer: "none".to_string(),
        policy_version: "no-verdict".to_string(),
    }
}

/// Fallback `ResponseInfo` when the response handle send fails mid-flight.
fn empty_response_info(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

#[cfg(test)]
mod boundary_zone_from_snapshot_tests {
    //! The D71 authored-SOA boundary-zone is now sourced from the policy-pushed POL-1
    //! `dns.boundary_zone` field (the same value `ds-policy-snapshot` lifts onto the
    //! host snapshot), read through the `with_forwarder_and_boundary_zone` seam. These
    //! unit tests assert the derivation point: a snapshot carrying a boundary zone
    //! drives the authored SOA MNAME, and a snapshot WITHOUT the field falls back to the
    //! frozen working-name default. The end-to-end authored-response coverage lives in
    //! `tests/event_surface.rs`.

    use super::*;
    use crate::policy::FixedStubPolicy;

    /// A POL-1 DNS block whose `boundary_zone` is whatever the layer pushes (or, with no
    /// `dns:` block at all, the working-name default the reader materializes).
    fn dns_from(doc: &str) -> pol1::DnsConfig {
        pol1::parse_layer(doc)
            .expect("clean POL-1 layer parses")
            .dns
    }

    #[test]
    fn pushed_boundary_zone_drives_the_authored_soa_mname() {
        let dns = dns_from(
            "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             dns:\n  boundary_zone: example.test.\n",
        );
        let handler = StubRequestHandler::with_forwarder_and_dns_config(
            FixedStubPolicy::new(),
            ForwarderConfig::default(),
            &dns,
        );
        assert_eq!(
            handler.soa_mname(),
            "denied.policy.example.test.",
            "a snapshot boundary_zone='example.test.' drives the authored SOA MNAME (D71 VALUE)"
        );
    }

    #[test]
    fn absent_boundary_zone_falls_back_to_the_working_name_default() {
        // No dns block => the POL-1 reader defaults boundary_zone to the working name,
        // so the handler reproduces the frozen pre-stage signature exactly.
        let dns = dns_from("schema_version: pol1/v0\nlayer: org\nposture: standard\n");
        assert_eq!(dns.boundary_zone, DEFAULT_BOUNDARY_ZONE);
        let handler = StubRequestHandler::with_forwarder_and_dns_config(
            FixedStubPolicy::new(),
            ForwarderConfig::default(),
            &dns,
        );
        assert_eq!(
            handler.soa_mname(),
            SOA_SIGNATURE_MNAME,
            "a snapshot WITHOUT a boundary_zone falls back to the frozen working-name MNAME"
        );
    }
}

#[cfg(test)]
mod attribution_live_wire_tests {
    //! The §5.1 / W6 live-wire (D44): `query_ctx` derives [`DnsQueryCtx::session`] from the
    //! LIVE [`AttributionTable`] (interface-anchored tap join) — NEVER the raw source IP —
    //! and FAILS CLOSED to SERVFAIL on an unknown interface (a genuine ds-dnsgate failure,
    //! never a policy NXDOMAIN). These are runtime assertions of the live wire: the same
    //! never-recycled-tap-as-join-key invariant attrib.rs unit-tests in isolation, now
    //! enforced through the handler's ctx derivation. The frozen [`DnsQueryCtx`] shape
    //! (session / qname / qtype / source) is unchanged — only `session` moves.

    use super::*;
    use crate::attrib::{AttributionTable, MarkIndex};
    use crate::policy::FixedStubPolicy;
    use std::net::{IpAddr, Ipv4Addr};

    fn handler_with_local_attribution(
        table: AttributionTable,
        local_addr: IpAddr,
    ) -> StubRequestHandler<FixedStubPolicy> {
        StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default())
            .with_attribution_local(table, local_addr)
    }

    #[test]
    fn local_attribution_derives_the_session_from_the_tap_not_the_source_ip() {
        // A registered interface-anchored local address resolves to the never-recycled tap
        // name; the session token is the tap-name source descriptor, NOT `src:<addr>`.
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let mut table = AttributionTable::new();
        table.register(local, "dstap-42", MarkIndex::from_counter(42));
        let handler = handler_with_local_attribution(table, local);

        // Two different guest source IPs, same interface-anchored local address → SAME
        // session (the tap), proving the session is NOT keyed on the raw source IP.
        let session_a = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)))
            .expect("registered interface resolves");
        let session_b = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 99), 5353)))
            .expect("registered interface resolves");
        assert_eq!(
            session_a, session_b,
            "session is the tap, not the source IP"
        );
        assert!(
            session_a.starts_with("dstap-42/"),
            "session is the never-recycled tap-name descriptor, not src:<addr>: {session_a}"
        );
        assert!(
            !session_a.contains("src:"),
            "the live-wire session is NOT the raw-source-IP pre-stage token: {session_a}"
        );
    }

    #[test]
    fn per_tap_bind_attribution_is_the_structural_tap() {
        // Per-tap bind: attribution is the bind itself, so every query on this handler
        // attributes to the same structural tap regardless of source IP.
        let attribution =
            AttributionTable::attribute_per_tap("dstap-7", MarkIndex::from_counter(7));
        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default())
                .with_attribution_per_tap(AttributionTable::new(), attribution);
        let session = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)))
            .expect("per-tap bind always resolves");
        assert!(
            session.starts_with("dstap-7/"),
            "per-tap session is the bound tap: {session}"
        );
    }

    #[test]
    fn unknown_interface_fails_closed_at_the_handler() {
        // An interface-anchored local address with NO registered tap is a fail-closed
        // condition at the handler: derive_session propagates UnknownInterface (the
        // handler then authors SERVFAIL, asserted on the wire below).
        let registered = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let mut table = AttributionTable::new();
        table.register(registered, "dstap-1", MarkIndex::from_counter(1));
        // The handler is anchored on an UNregistered local address.
        let unregistered = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
        let handler = handler_with_local_attribution(table, unregistered);
        let err = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)))
            .unwrap_err();
        assert!(
            matches!(err, AttributionError::UnknownInterface(_)),
            "an unregistered interface fails closed, never a default session: {err:?}"
        );
    }

    #[test]
    fn pre_stage_fallback_keeps_the_recorded_source_token_when_no_table_is_wired() {
        // With NO attribution table wired the pre-stage recorded-source token is kept (the
        // harness / framework path), so the existing tests stay green — but this is the
        // path the live wire REPLACES, not the production default.
        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default());
        let session = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)))
            .expect("pre-stage fallback is infallible");
        assert_eq!(session, "src:10.0.0.5:5353");
    }

    #[test]
    fn fixed_session_uuid_returns_the_operator_uuid_verbatim_for_every_source() {
        // The single-session fixed-uuid agreement (doc 11 §5.1 / D131-rollout): every query
        // attributes to the operator-supplied uuid, regardless of source IP/port — the exact
        // string a co-host ds-tlsproxy stamps into its read-side AdmissionKey. Infallible.
        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default())
                .with_session_uuid("sess-2026-testbed-0001");
        let session_a = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 54321)))
            .expect("fixed uuid is infallible");
        let session_b = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 12345)))
            .expect("fixed uuid is infallible");
        assert_eq!(
            session_a, "sess-2026-testbed-0001",
            "the fixed uuid is returned verbatim, never src:<addr>"
        );
        assert_eq!(
            session_a, session_b,
            "the fixed uuid is independent of source port/IP (single-session attribution)"
        );
        assert!(
            !session_a.contains("src:"),
            "the fixed-uuid session is NOT the pre-stage source token: {session_a}"
        );
    }
}

#[cfg(test)]
mod wire_tests {
    //! On-the-wire src-module tests driving the REAL gate over loopback (the
    //! conformance-corpus discipline, doc 11 §6 row 10 — dig/getaddrinfo-shaped, never a
    //! hickory/policy-core API): the §5.1 / W6 fail-closed SERVFAIL, the §3.4 forced-TC
    //! TCP-retry deny parity, and the live boundary_zone + D72 hot-reload. These live in
    //! `src/` (NOT `tests/`) because `tests/` belongs to the sibling dnsgate-inttest unit.

    use super::*;
    use crate::policy::{DnsQueryCtx, PolicyHook, RcodePolicy, SeamProvenance};
    use crate::server::{spawn_gate, GateConfig, RunningGate};
    use crate::AttributionTable;
    use hickory_server::proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_server::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_server::proto::rr::{
        Name as ProtoName, RData as ProtoRData, RecordType as ProtoRt,
    };
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};

    /// A policy that DENIES every query (NXDOMAIN) with a real POL-3 triple — the §3.2
    /// hard-deny path the forced-TC parity test drives. `Clone` so `spawn_gate` accepts it.
    #[derive(Clone)]
    struct AlwaysDenyPolicy;

    impl PolicyHook for AlwaysDenyPolicy {
        fn evaluate(&self, _ctx: &DnsQueryCtx) -> Verdict {
            Verdict::Deny {
                rcode_policy: RcodePolicy::NxDomain,
                // No explicit D53 rung on this synthetic deny — the wire shape (NXDOMAIN +
                // SOA + EDE-15) the parity test asserts is rung-independent.
                rung: None,
                provenance: SeamProvenance {
                    rule_id: "blocklist/denied.example".to_string(),
                    policy_layer: "system-baseline".to_string(),
                    policy_version: "2026-06-12".to_string(),
                },
            }
        }
    }

    fn query_bytes(id: u16, name: &str, with_edns: Option<u16>) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.metadata.message_type = MessageType::Query;
        msg.metadata.op_code = OpCode::Query;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            ProtoName::from_ascii(name).expect("valid query name"),
            ProtoRt::A,
        ));
        if let Some(payload) = with_edns {
            let mut edns = Edns::new();
            edns.set_max_payload(payload);
            edns.set_version(0);
            msg.set_edns(edns);
        }
        msg.to_vec().expect("query encodes")
    }

    async fn udp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("udp bind");
        sock.connect(server).await.expect("udp connect");
        sock.send(query).await.expect("udp send");
        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .expect("udp recv timed out")
            .expect("udp recv");
        buf.truncate(n);
        buf
    }

    async fn tcp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(server).await.expect("tcp connect");
        let len = u16::try_from(query.len()).expect("query fits a u16 length prefix");
        stream.write_all(&len.to_be_bytes()).await.expect("tcp len");
        stream.write_all(query).await.expect("tcp body");
        stream.flush().await.expect("tcp flush");
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
            .await
            .expect("tcp len read timed out")
            .expect("tcp len read");
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await.expect("tcp body read");
        resp
    }

    /// Assert the frozen §3.2 hard-deny shape on a parsed response: NXDOMAIN (never
    /// SERVFAIL / REFUSED), empty answer, the always-authored signature SOA with
    /// `MNAME == denied.policy.<zone>.` and `TTL == MINIMUM == NEGATIVE_TTL_SECS`, and never
    /// an address record.
    fn assert_deny_shape(msg: &Message, expected_mname: &str, transport: &str) {
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "policy deny is NXDOMAIN, never SERVFAIL/REFUSED ({transport})"
        );
        assert!(
            msg.answers.is_empty(),
            "a hard deny has an empty answer section ({transport})"
        );
        let (soa, soa_ttl) = msg
            .authorities
            .iter()
            .find_map(|r| match &r.data {
                ProtoRData::SOA(soa) => Some((soa, r.ttl)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("authored SOA present in authority ({transport}): {msg:?}"));
        assert_eq!(
            soa.mname.to_ascii(),
            expected_mname,
            "SOA MNAME is the denied.policy.<zone> signature ({transport})"
        );
        assert_eq!(
            soa.minimum, NEGATIVE_TTL_SECS,
            "SOA MINIMUM == the POL-1 negative-TTL ({transport})"
        );
        assert_eq!(
            soa_ttl, NEGATIVE_TTL_SECS,
            "SOA record TTL == MINIMUM == negative-TTL (RFC 2308) ({transport})"
        );
        assert!(
            msg.answers
                .iter()
                .all(|r| !matches!(&r.data, ProtoRData::A(_) | ProtoRData::AAAA(_))),
            "a deny never carries an address record ({transport})"
        );
    }

    /// The §3.2 EDE INFO-CODE 15 (Blocked) `ds:` provenance text, if present. hickory 0.26.x
    /// has no native EDE type, so EDE 15 rides as a generic `EdnsOption::Unknown(15, ...)`:
    /// the first two payload bytes are the Blocked INFO-CODE, the rest the UTF-8 EXTRA-TEXT.
    fn ede_blocked_text(msg: &Message) -> Option<String> {
        let edns = msg.edns.as_ref()?;
        let opt = edns.option(EdnsCode::Unknown(15))?;
        let EdnsOption::Unknown(_, bytes) = opt else {
            return None;
        };
        if bytes.len() < 2 || u16::from_be_bytes([bytes[0], bytes[1]]) != EDE_BLOCKED_INFO_CODE {
            return None;
        }
        Some(String::from_utf8_lossy(&bytes[2..]).into_owned())
    }

    async fn deny_gate(boundary_zone: &str) -> RunningGate<AlwaysDenyPolicy> {
        let config = GateConfig {
            boundary_zone: boundary_zone.to_string(),
            ..GateConfig::default()
        };
        spawn_gate(AlwaysDenyPolicy, config)
            .await
            .expect("deny gate binds")
    }

    #[tokio::test]
    async fn unknown_interface_is_servfail_on_the_wire_not_nxdomain() {
        // The §5.1 / W6 fail-closed wire assertion: a gate whose handler is anchored on an
        // interface-anchored local address with NO registered tap answers SERVFAIL — a
        // genuine ds-dnsgate failure — NEVER a policy NXDOMAIN. Built by spawning the gate
        // and wiring an empty AttributionTable on an unregistered anchor via the handler
        // seam; here we drive the handler-level wire directly through a one-shot gate whose
        // handlers carry the live attribution.
        //
        // The gate's handlers are constructed inside spawn_gate, so to exercise the live
        // attribution end-to-end we build a standalone handler with an empty table on an
        // unknown anchor and run it through the in-process UDP listener of a bespoke server.
        let local = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 250));
        // The gate's UDP and TCP listeners each own a handler; both are built with the SAME
        // empty attribution table on the SAME unregistered anchor, so both fail closed
        // identically (the §3.4 parity is the point — neither transport has a fast path).
        let make_handler = || {
            StubRequestHandler::with_forwarder(AlwaysDenyPolicy, ForwarderConfig::default())
                .with_attribution_local(AttributionTable::new(), local)
        };
        let gate = spawn_handler_gate(make_handler).await;

        let query = query_bytes(1, "denied.example.", Some(512));
        let udp = Message::from_vec(&udp_round_trip(gate.udp, &query).await).expect("udp parses");
        assert_eq!(
            udp.metadata.response_code,
            ResponseCode::ServFail,
            "unattributable query fails closed to SERVFAIL, NEVER a policy NXDOMAIN (udp): {udp:?}"
        );
        assert_ne!(
            udp.metadata.response_code,
            ResponseCode::NXDomain,
            "an attribution failure is a genuine ds-dnsgate failure, not a policy deny"
        );

        let tcp = Message::from_vec(&tcp_round_trip(gate.tcp, &query).await).expect("tcp parses");
        assert_eq!(
            tcp.metadata.response_code,
            ResponseCode::ServFail,
            "the same fail-closed SERVFAIL holds on TCP (§3.4 parity): {tcp:?}"
        );
        drop(gate);
    }

    #[tokio::test]
    async fn forced_tc_tcp_retry_carries_the_byte_identical_deny_shape() {
        // §3.4 freeze: an oversized UDP deny sets the TC bit; the client's TCP retry
        // receives the byte-identical NXDOMAIN + authored SOA(MNAME=denied.policy.<zone>,
        // TTL==MINIMUM==negative-TTL) + EDE-15(ds: provenance). NO UDP-only fast path skips
        // admission — the deny is authored on BOTH transports, identically.
        //
        // Forced TC: a long boundary zone + a long qname make the authored SOA owner/MNAME/
        // RNAME plus the EDE option overflow a 512-byte advertised EDNS buffer, so the UDP
        // encoder sets TC. The TCP retry (no size cap) carries the full deny.
        let zone = "very-long-boundary-zone-for-truncation.example.test.";
        let expected_mname = format!("denied.policy.{}.", zone.trim_matches('.'));
        let gate = deny_gate(zone).await;

        // A long qname (the SOA owner is the query name) to pad the response past 512.
        let long_label = "a".repeat(60);
        let qname = format!("{long_label}.{long_label}.{long_label}.denied-truncation.example.",);
        let query = query_bytes(7, &qname, Some(512));

        // UDP with the small advertised buffer: the deny overflows it → TC set.
        let udp_bytes = udp_round_trip(gate.udp_local_addr(), &query).await;
        let udp = Message::from_vec(&udp_bytes).expect("udp parses");
        assert!(
            udp.metadata.truncation,
            "the oversized deny over a 512-byte EDNS buffer sets the TC bit (udp size={})",
            udp_bytes.len()
        );
        // Even truncated, the UDP answer is still a NXDOMAIN deny — never a UDP-only fast
        // path that skipped the policy verdict.
        assert_eq!(
            udp.metadata.response_code,
            ResponseCode::NXDomain,
            "the truncated UDP deny is still NXDOMAIN — no admission-skipping fast path"
        );

        // The TCP retry (no size cap) carries the FULL, byte-identical deny shape.
        let tcp_bytes = tcp_round_trip(gate.tcp_local_addr(), &query).await;
        let tcp = Message::from_vec(&tcp_bytes).expect("tcp parses");
        assert!(
            !tcp.metadata.truncation,
            "the TCP retry is never truncated (no UDP size cap)"
        );
        assert_deny_shape(&tcp, &expected_mname, "tcp");

        // EDE-15 (Blocked) with `ds:` POL-3 provenance attaches on the TCP retry (the query
        // carried OPT). This is the §3.2 EDE-iff-OPT diagnostic, proven on the TCP path.
        let ede = ede_blocked_text(&tcp)
            .unwrap_or_else(|| panic!("EDE 15 present on the TCP deny retry: {tcp:?}"));
        assert!(
            ede.starts_with(EDE_EXTRA_TEXT_PREFIX),
            "EDE EXTRA-TEXT is `ds:`-prefixed: {ede:?}"
        );
        assert!(
            ede.contains("rule=blocklist/denied.example"),
            "EDE carries the POL-3 rule provenance: {ede:?}"
        );
        drop(gate);
    }

    #[tokio::test]
    async fn deny_shape_is_identical_over_udp_and_tcp_without_truncation() {
        // The non-truncated baseline of the §3.4 parity: a short deny is identical over UDP
        // and TCP with no TC bit — the truncation case above shares this exact shape.
        let zone = "boundary.";
        let expected_mname = "denied.policy.boundary.";
        let gate = deny_gate(zone).await;
        let query = query_bytes(8, "short-deny.example.", Some(1232));

        let udp = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), &query).await)
            .expect("udp parses");
        let tcp = Message::from_vec(&tcp_round_trip(gate.tcp_local_addr(), &query).await)
            .expect("tcp parses");
        assert!(
            !udp.metadata.truncation,
            "short deny is not truncated (udp)"
        );
        assert!(
            !tcp.metadata.truncation,
            "short deny is not truncated (tcp)"
        );
        assert_deny_shape(&udp, expected_mname, "udp");
        assert_deny_shape(&tcp, expected_mname, "tcp");
        // The EDE-15 ds: provenance is present on BOTH transports (query carried OPT).
        assert!(ede_blocked_text(&udp).is_some(), "EDE on udp deny");
        assert!(ede_blocked_text(&tcp).is_some(), "EDE on tcp deny");
        drop(gate);
    }

    #[tokio::test]
    async fn live_boundary_zone_drives_the_authored_soa_and_d72_hot_reload_re_sources_it() {
        // PART 3 wire assertion: the authored-SOA MNAME on the wire follows the LIVE
        // GateConfig.boundary_zone (sourced from the host PolicySnapshot), and a D72
        // admitter-LAST hot-reload re-sources it from a NEW snapshot value — every
        // subsequent deny signs with the freshly-applied suffix, on BOTH transports.
        let gate = deny_gate("alpha.example.").await;
        let query = query_bytes(9, "denied.example.", Some(1232));

        // Startup: the deny is signed with the live snapshot suffix, not the const default.
        let udp = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), &query).await)
            .expect("udp parses");
        assert_deny_shape(&udp, "denied.policy.alpha.example.", "udp/startup");

        // D72 admitter-LAST hot-reload: a new snapshot pushes a new boundary zone.
        gate.reload_boundary_zone("beta.example.");
        let udp2 = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), &query).await)
            .expect("udp parses");
        assert_deny_shape(&udp2, "denied.policy.beta.example.", "udp/reloaded");
        // The TCP handler shares the reload, so the new suffix holds there too.
        let tcp2 = Message::from_vec(&tcp_round_trip(gate.tcp_local_addr(), &query).await)
            .expect("tcp parses");
        assert_deny_shape(&tcp2, "denied.policy.beta.example.", "tcp/reloaded");
        drop(gate);
    }

    // ── A bespoke single-handler in-process gate (UDP + capped TCP) so a handler built with
    //    an explicit AttributionTable anchor can be driven on the wire. Mirrors the
    //    server.rs listener shell, scoped to one already-constructed handler. ─────────────
    struct HandlerGate {
        #[allow(dead_code)]
        udp_server: hickory_server::server::Server<StubRequestHandler<AlwaysDenyPolicy>>,
        udp: SocketAddr,
        tcp: SocketAddr,
        _tcp_task: tokio::task::JoinHandle<()>,
    }

    async fn spawn_handler_gate(
        make_handler: impl Fn() -> StubRequestHandler<AlwaysDenyPolicy>,
    ) -> HandlerGate {
        use hickory_server::net::runtime::TokioTime;
        use hickory_server::net::xfer::Protocol;
        use hickory_server::net::BufDnsStreamHandle;
        use hickory_server::server::{ResponseHandle, Server};

        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("udp bind");
        let udp = udp_sock.local_addr().expect("udp local addr");
        let tcp_listener =
            tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("tcp bind");
        let tcp = tcp_listener.local_addr().expect("tcp local addr");

        // UDP: hickory's Server owns its handler.
        let mut udp_server = Server::new(make_handler());
        udp_server.register_socket(udp_sock);

        // TCP: a tiny accept loop driving a second, identically-built handler (the §3.4
        // parity transport — same empty table, same anchor, so the same fail-closed shape).
        let tcp_handler = Arc::new(make_handler());
        let tcp_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, src)) = tcp_listener.accept().await else {
                    return;
                };
                let h = tcp_handler.clone();
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let msg_len = u16::from_be_bytes(len_buf) as usize;
                    if msg_len == 0 {
                        return;
                    }
                    let mut msg = vec![0u8; msg_len];
                    if stream.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    let Ok(request) =
                        hickory_server::server::Request::from_bytes(msg, src, Protocol::Tcp)
                    else {
                        return;
                    };
                    let (stream_handle, mut receiver) = BufDnsStreamHandle::new(src);
                    let response_handle = ResponseHandle::new(src, stream_handle, Protocol::Tcp);
                    let _ =
                        <StubRequestHandler<AlwaysDenyPolicy> as RequestHandler>::handle_request::<
                            _,
                            TokioTime,
                        >(&h, &request, response_handle)
                        .await;
                    use futures_util::StreamExt;
                    if let Ok(Some(serial)) =
                        tokio::time::timeout(Duration::from_millis(50), receiver.next()).await
                    {
                        let (bytes, _addr) = serial.into_parts();
                        if let Ok(len) = u16::try_from(bytes.len()) {
                            let _ = stream.write_all(&len.to_be_bytes()).await;
                            let _ = stream.write_all(&bytes).await;
                            let _ = stream.flush().await;
                        }
                    }
                });
            }
        });

        HandlerGate {
            udp_server,
            udp,
            tcp,
            _tcp_task: tcp_task,
        }
    }
}

#[cfg(test)]
mod terminal_addr_dedup_tests {
    //! W1 hardening: `run_admission_for_answer` canonicalizes the terminal addresses to a
    //! DISTINCT IP set BEFORE the admission transaction. An upstream answer is untrusted
    //! and may carry the SAME terminal IP in several A/AAAA RRs; the transaction itself
    //! does no IP-level de-dup, so without canonicalization a duplicate-stuffed answer
    //! would program the NFT-3 set element twice AND increment the §5.4 revocation-sweep
    //! refcount twice — inflating the admitted set and leaving the kernel element live
    //! after a single revoke (refcount > 0). These tests assert each distinct IP is
    //! admitted EXACTLY ONCE, deterministically, with the duplicates collapsed.

    use super::*;
    use crate::policy::FixedStubPolicy;
    use ds_contracts::dns_admission::{AddressFamily, AdmissionKey, AdmittedAddr};
    use hickory_server::proto::rr::rdata::{A, AAAA};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn ctx(session: &str, qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: session.to_string(),
            qname: qname.to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)),
        }
    }

    fn provenance() -> SeamProvenance {
        SeamProvenance {
            rule_id: "rule-allow-dedup".to_string(),
            policy_layer: "org".to_string(),
            policy_version: "2026-06-15".to_string(),
        }
    }

    fn a_record(name: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("valid name"),
            300,
            RData::A(A(ip)),
        )
    }

    fn aaaa_record(name: &str, ip: Ipv6Addr) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("valid name"),
            300,
            RData::AAAA(AAAA(ip)),
        )
    }

    fn admitted_v4(ip: Ipv4Addr) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: ip.octets().to_vec(),
        }
    }

    #[test]
    fn duplicate_ip_in_the_answer_admits_each_distinct_ip_exactly_once() {
        // An answer that carries the SAME public IP three times (a malformed / duplicate-
        // stuffed upstream answer). Pre-fix this inflated the admitted set, the NFT-3 set
        // elements, and the §5.4 refcount to 3; the dedup collapses it to 1.
        let dup = Ipv4Addr::new(93, 184, 216, 34);
        let kept = vec![
            a_record("example.test.", dup),
            a_record("example.test.", dup),
            a_record("example.test.", dup),
        ];

        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default());
        let ctx = ctx("sess-dedup-1", "example.test.");
        let outcome = handler.run_admission_for_answer(&ctx, &provenance(), 60, 900, &kept);

        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "a duplicate-IP answer still admits (the dedup is canonicalization, not a deny): {outcome:?}"
        );

        // The DNS-2b map entry records the DISTINCT admitted IP set — exactly one IP. The
        // admission-key fqdn is the DOT-LESS canonical form (`admission_key_fqdn` strips the
        // trailing dot of `ctx.qname` so the cross-process key agrees with the SNI reader).
        let key = AdmissionKey {
            session_uuid: "sess-dedup-1".to_string(),
            original_query_fqdn: "example.test".to_string(),
        };
        let entry = handler
            .admission_stores()
            .lookup(&key)
            .expect("the admission wrote a map entry");
        assert_eq!(
            entry.admitted_ips,
            vec![admitted_v4(dup)],
            "three identical A RRs collapse to a single admitted IP (no inflated set)"
        );

        // The §5.4 reverse-sweep refcount is 1, NOT 3 — a single revoke fully releases the
        // kernel element (no residual refcount holding an unrevoked allow-set entry).
        assert_eq!(
            handler
                .admission_stores()
                .reverse_refcount("sess-dedup-1", &admitted_v4(dup)),
            1,
            "the duplicated IP increments the revocation refcount exactly once"
        );
    }

    #[test]
    fn distinct_ips_are_all_kept_and_first_occurrence_order_is_preserved() {
        // Mixed answer with a duplicate interleaved among distinct IPs (and a v6): the
        // dedup keeps every DISTINCT address, drops only the repeat, and preserves
        // first-occurrence order deterministically.
        let a1 = Ipv4Addr::new(93, 184, 216, 34);
        let a2 = Ipv4Addr::new(93, 184, 216, 35);
        let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x1);
        let kept = vec![
            a_record("example.test.", a1),
            a_record("example.test.", a2),
            a_record("example.test.", a1), // duplicate of a1
            aaaa_record("example.test.", v6),
            a_record("example.test.", a2), // duplicate of a2
        ];

        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default());
        let ctx = ctx("sess-dedup-2", "example.test.");
        let outcome = handler.run_admission_for_answer(&ctx, &provenance(), 60, 900, &kept);
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "{outcome:?}"
        );

        let key = AdmissionKey {
            session_uuid: "sess-dedup-2".to_string(),
            // Dot-less canonical admission-key fqdn (see dedup-1).
            original_query_fqdn: "example.test".to_string(),
        };
        let entry = handler
            .admission_stores()
            .lookup(&key)
            .expect("the admission wrote a map entry");
        // Three distinct addresses, first-occurrence order: a1, a2, then the v6.
        assert_eq!(
            entry.admitted_ips,
            vec![
                admitted_v4(a1),
                admitted_v4(a2),
                AdmittedAddr {
                    family: AddressFamily::V6,
                    octets: v6.octets().to_vec(),
                },
            ],
            "distinct IPs are all admitted, in stable first-occurrence order, duplicates dropped"
        );
        // Each distinct IP carries refcount 1 — the repeats did not double-incref.
        for v4 in [a1, a2] {
            assert_eq!(
                handler
                    .admission_stores()
                    .reverse_refcount("sess-dedup-2", &admitted_v4(v4)),
                1,
                "distinct IP {v4} is refcounted exactly once despite repeated RRs"
            );
        }
    }

    #[test]
    fn served_allow_with_fixed_session_uuid_writes_the_admission_under_the_agreed_key() {
        // The cross-process key-agreement seam (doc 11 §5.1 / D131-rollout): when the gate is
        // wired with the operator's single-session uuid, the SAME derivation the serving path
        // runs (`derive_session`, the `query_ctx` session computation) yields that uuid, and the
        // W1/W2 admission writes the DNS-2b map entry under `{uuid, fqdn}` — the EXACT key a
        // co-host ds-tlsproxy reads with (`origin_is_admitted`/TLS-1 ReAdmit). Pre-fix the gate
        // wrote `{src:<addr>, fqdn}` and that read missed; this proves the write key now agrees.
        let fixed_uuid = "sess-2026-nested-testbed-0001";
        let public = Ipv4Addr::new(93, 184, 216, 34);
        let kept = vec![a_record("api.anthropic.com.", public)];

        let handler =
            StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default())
                .with_session_uuid(fixed_uuid);

        // The session is computed exactly as the serving path computes it (the `query_ctx`
        // derivation), NOT hand-set: a guest dialing from the m0 tap source resolves to the
        // operator uuid, never `src:<addr>`.
        let derived = handler
            .derive_session(SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 54321)))
            .expect("fixed-uuid derivation is infallible");
        assert_eq!(
            derived, fixed_uuid,
            "the served-path session derivation yields the agreed uuid"
        );
        assert!(
            !derived.contains("src:"),
            "the served key is NOT the pre-stage source token: {derived}"
        );

        let ctx = DnsQueryCtx {
            session: derived.clone(),
            qname: "api.anthropic.com.".to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 54321)),
        };
        let outcome = handler.run_admission_for_answer(&ctx, &provenance(), 60, 900, &kept);
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "an allowed served answer admits: {outcome:?}"
        );

        // The admission lands under the AGREED `{uuid, fqdn}` key — the identical key
        // ds-tlsproxy's `AdmissionKey { session_uuid, original_query_fqdn }` reads. BOTH key
        // halves now agree: the same DS_SESSION_UUID stamps the session, and the fqdn is the
        // DOT-LESS canonical form (`admission_key_fqdn` strips the trailing dot at the write,
        // matching ds-tlsproxy's `classify_host`-stripped SNI). So the cross-process FORWARD
        // lookup HITS under the dot-less key.
        let key = AdmissionKey {
            session_uuid: fixed_uuid.to_string(),
            original_query_fqdn: "api.anthropic.com".to_string(),
        };
        let entry = handler.admission_stores().lookup(&key).expect(
            "the served Allow query wrote a DNS-2b entry under the dot-less fixed-uuid key",
        );
        assert_eq!(
            entry.admitted_ips,
            vec![admitted_v4(public)],
            "the admitted terminal address is recorded under the agreed dot-less key"
        );

        // FAIL-CLOSED guard: the pre-stage `src:<addr>` key the gate would have written
        // WITHOUT the agreement is NOT present — proving the agreement moved the key, and a
        // read under the old key (or any non-agreed uuid) still misses.
        assert!(
            handler
                .admission_stores()
                .lookup(&AdmissionKey {
                    session_uuid: "src:10.77.0.1:54321".to_string(),
                    original_query_fqdn: "api.anthropic.com".to_string(),
                })
                .is_none(),
            "no entry under the pre-stage source key — the agreement replaced it, not duplicated it"
        );

        // FQDN-NORMALIZATION (the FIX-2 reconciliation, doc 11 §5.1 / D131-rollout): the gate
        // now canonicalizes the ORIGINAL query name to the DOT-LESS form before it composes
        // the AdmissionKey (`admission_key_fqdn` strips the single trailing dot hickory's
        // `to_ascii()` ABSOLUTE form carries). ds-tlsproxy's read side keys on the SNI
        // (`classify_host`, also dot-less), so the two fqdn halves AGREE. The DOTTED form the
        // gate used to write under is therefore NO LONGER present — proving the
        // canonicalization moved the key to the form the reader looks up, not duplicated it.
        assert!(
            handler
                .admission_stores()
                .lookup(&AdmissionKey {
                    session_uuid: fixed_uuid.to_string(),
                    // The OLD dotted write fqdn — must now MISS (the gate writes dot-less).
                    original_query_fqdn: "api.anthropic.com.".to_string(),
                })
                .is_none(),
            "the OLD dotted write fqdn now MISSES — the gate canonicalizes to the dot-less \
             form the tlsproxy reader presents (the FORWARD halves agree)"
        );
    }
}
