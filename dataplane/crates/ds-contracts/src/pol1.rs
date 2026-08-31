//! POL-1 v0 policy schema — types, a stdlib-only document reader, and the
//! parse-time structural validators (doc 13 §1–§3, §7, §8.1).
//!
//! **Home (doc 13 §1 rule 1 / doc 14 §6 "interface homes fixed"):** the schema
//! types, the document reader, the constants, and the structural validators live
//! HERE in `ds-contracts` — the package family the §3 strawman comment names
//! ("Schema lives in ds-contracts"). `policy-core` is the *evaluator* that
//! consumes these types (the §7 parse→evaluate round-trip); it gains a path dep
//! on this crate for that, never the reverse.
//!
//! **Stdlib-only (doc 14 §6, the crate's `[dependencies]`-empty fence).** There is
//! NO serde / serde_yaml here. The reader below ([`parse_layer`]) is a minimal,
//! purpose-built reader for the POL-1 document subset the §3 strawman shapes —
//! the precedent is `mark.rs`, `dns_admission.rs`, and `flush.rs`, all stdlib-only.
//! It is deliberately not a general YAML parser: it understands exactly the block
//! structure POL-1 layer documents use (two-space-indented mappings, `- ` list
//! items, scalars, inline `[a, b]` flow sequences) and rejects everything else.
//!
//! **Field names / casing are FREE; shapes and invariants are FROZEN (doc 13 §2,
//! §6).** The structural validators enforce the §7 / §8.1 rejection set at parse
//! time — a malformed layer never composes into a snapshot, so the host never
//! carries a document the validator would refuse:
//!
//! - (a) a D53 rung on every guardrail rule (§2 guardrails row, D52/D53);
//! - (b) generic content rules capped at `block+log` — `suspend+ask` /
//!   `kill+snapshot` are REJECTED at parse with the offending
//!   `(rule_id, declared_rung)` named (§8.1 "Rung-cap rejection", D73);
//! - (c) `fail_open: true` legal ONLY when every generic rule is `allow+log`
//!   (§8.1, D73) — this mirrors the
//!   [`policy_core::secret_matcher::fail_mode_is_legal`] semantics rather than
//!   re-deriving a different rule;
//! - (d) escape-hatch entries are `protocol+host+port`; a bare CIDR / address
//!   literal `host` is REJECTED (§8.1 "Bare-CIDR rejection", D45);
//! - (e) baseline-pack entries missing `provenance_source_url` + `evidence` fail
//!   (§8.1 "Mandatory provenance", D74);
//! - (f) `requires:` capability-gate entries are inert with a logged warning —
//!   tagged inert in the composed document, admitting NOTHING for that entry
//!   until the capability lands (§1.7 / §8.2, D74). The schema records the gate;
//!   the inertness is enforced by `policy-core` on the composed document.
//!
//! v6 literals are accepted in every address-shaped field (§2 IPv6 row, D75):
//! address fields reuse [`crate::dns_admission::AdmittedAddr`] /
//! [`crate::dns_admission::AddressFamily`] rather than minting a parallel address
//! type — parse now, enforcement phase-gated.
//!
//! No hickory or pingora types cross this module (D67/D40): every address is the
//! family-agnostic [`AdmittedAddr`] contract shape.

use crate::dns_admission::{AddressFamily, AdmittedAddr};
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (doc 13 §1.5: tunable defaults — tests pin them).
// ─────────────────────────────────────────────────────────────────────────────

/// The POL-1 v0 schema-version tag (doc 13 §3 `schema_version: pol1/v0`).
pub const SCHEMA_VERSION_V0: &str = "pol1/v0";

/// Default admission timer floor in seconds (doc 13 §1.5 / §3 `ttl_floor: 60`).
pub const DEFAULT_TTL_FLOOR_SECS: u32 = 60;
/// Default admission timer ceiling in seconds (doc 13 §3 `ttl_ceil: 900`).
pub const DEFAULT_TTL_CEIL_SECS: u32 = 900;
/// Default admission grace in seconds (doc 13 §3 `grace: 60`).
pub const DEFAULT_GRACE_SECS: u32 = 60;
/// Default per-session per-domain IP cap (doc 13 §3 `max_ips_per_domain: 1000`).
pub const DEFAULT_MAX_IPS_PER_DOMAIN: u32 = 1000;
/// Default negative TTL in seconds (doc 13 §3 `dns.negative_ttl: 5`; 0 permitted).
pub const DEFAULT_NEGATIVE_TTL_SECS: u32 = 5;
/// Default boundary zone — the D71 authored-SOA MNAME suffix working name
/// (`boundary.`; doc 11 §3.2 "`SOA MNAME = denied.policy.<boundary-zone>.`"). The
/// boundary-zone VALUE moves from a ds-dnsgate handler-local const to this
/// policy-pushed POL-1 field; the default preserves today's `boundary.` behaviour
/// when a layer omits it (additive, frozen-additive — D71 shape unchanged, only the
/// suffix source moves).
pub const DEFAULT_BOUNDARY_ZONE: &str = "boundary.";
/// Default attendedness activity window (doc 13 §3 `activity_window_minutes: 10`).
pub const DEFAULT_ACTIVITY_WINDOW_MINUTES: u32 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// Enumerations (doc 13 §2 / §3).
// ─────────────────────────────────────────────────────────────────────────────

/// Network posture (doc 13 §2 Posture row / §3 `posture`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Posture {
    /// `locked`.
    Locked,
    /// `standard`.
    Standard,
    /// `open`.
    Open,
}

impl Posture {
    /// Parse the posture token. Field casing is free; the token set is frozen.
    pub fn parse(s: &str) -> Result<Posture, PolicyError> {
        match s {
            "locked" => Ok(Posture::Locked),
            "standard" => Ok(Posture::Standard),
            "open" => Ok(Posture::Open),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadPosture,
                "posture",
                format!("unknown posture {other:?} (locked|standard|open)"),
            )),
        }
    }
}

/// The D53 rung ladder (doc 13 §1.6, §2; D52 `action` constrained to the D53
/// ladder). Ordered weakest → strongest; `block+log` is the structural cap for
/// generic content rules (§8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rung {
    /// `allow+log` — observe only, no enforcement; the only rung that admits a
    /// `fail_open: true` generic plane (§8.1 (c)).
    AllowLog,
    /// `block+log` — block the flow + log; the generic-content-rule cap (§8.1 (b)).
    BlockLog,
    /// `suspend+ask` — suspend + ask the user (D77 socket-hold/downgrade fork).
    SuspendAsk,
    /// `kill+snapshot` — kill + snapshot the session.
    KillSnapshot,
}

impl Rung {
    /// Parse a rung token (doc 13 §3 `rung:` fields). Token set frozen (D53).
    pub fn parse(s: &str) -> Result<Rung, PolicyError> {
        match s {
            "allow+log" => Ok(Rung::AllowLog),
            "block+log" => Ok(Rung::BlockLog),
            "suspend+ask" => Ok(Rung::SuspendAsk),
            "kill+snapshot" => Ok(Rung::KillSnapshot),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadRung,
                "rung",
                format!("unknown rung {other:?} (allow+log|block+log|suspend+ask|kill+snapshot)"),
            )),
        }
    }

    /// The canonical token, for error rendering ("the offending declared_rung").
    pub fn token(self) -> &'static str {
        match self {
            Rung::AllowLog => "allow+log",
            Rung::BlockLog => "block+log",
            Rung::SuspendAsk => "suspend+ask",
            Rung::KillSnapshot => "kill+snapshot",
        }
    }

    /// Whether this rung is "block-or-higher" — the severity at which the §5
    /// D53 revocation flush fires (doc 13 §5; mirrors
    /// `secret_matcher::Verdict::is_block_or_higher`).
    pub fn is_block_or_higher(self) -> bool {
        self >= Rung::BlockLog
    }
}

/// D52's five guardrail classes (doc 13 §2 Guardrail-rules row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuardrailClass {
    /// `egress`.
    Egress,
    /// `rate`.
    Rate,
    /// `quota`.
    Quota,
    /// `content`.
    Content,
    /// `credential`.
    Credential,
}

impl GuardrailClass {
    /// Parse a guardrail-class token. Five frozen classes (D52).
    pub fn parse(s: &str) -> Result<GuardrailClass, PolicyError> {
        match s {
            "egress" => Ok(GuardrailClass::Egress),
            "rate" => Ok(GuardrailClass::Rate),
            "quota" => Ok(GuardrailClass::Quota),
            "content" => Ok(GuardrailClass::Content),
            "credential" => Ok(GuardrailClass::Credential),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadGuardrailClass,
                "guardrails[].class",
                format!("unknown class {other:?} (egress|rate|quota|content|credential)"),
            )),
        }
    }
}

/// Which composition layer a document is (doc 13 §1.2, §3 `layer`). Composition
/// is `SystemBaseline -> Org -> Repo/Session` with deny-overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// `system-baseline` — the broadest, lowest-precedence layer.
    SystemBaseline,
    /// `org`.
    Org,
    /// `repo`.
    Repo,
    /// `session` — the most specific, highest-precedence layer.
    Session,
}

impl Layer {
    /// Parse a layer token (doc 13 §3 `layer:`).
    pub fn parse(s: &str) -> Result<Layer, PolicyError> {
        match s {
            "system-baseline" => Ok(Layer::SystemBaseline),
            "org" => Ok(Layer::Org),
            "repo" => Ok(Layer::Repo),
            "session" => Ok(Layer::Session),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadLayer,
                "layer",
                format!("unknown layer {other:?} (system-baseline|org|repo|session)"),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors — structured `{code, path, detail}` (doc 13 §8.1: shape is FREE; the
// SET of conditions that must reject is frozen). Collect-all (§8.1 recommendation).
// ─────────────────────────────────────────────────────────────────────────────

/// The class of a parse / validation rejection (doc 13 §8.1). The error-message
/// *shape* is free latitude; the *set of conditions that must reject* is frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyErrorCode {
    /// Reader could not interpret the document structure.
    Syntax,
    /// An unknown / malformed posture token.
    BadPosture,
    /// An unknown / malformed layer token.
    BadLayer,
    /// An unknown / malformed rung token.
    BadRung,
    /// An unknown / malformed guardrail class.
    BadGuardrailClass,
    /// A guardrail rule is missing its mandatory rung (§7 (a), D53).
    MissingRung,
    /// A generic content rule declares a rung above `block+log` (§7 (b), D73).
    GenericRungCap,
    /// `fail_open: true` with a non-`allow+log` generic rule or a keyed plane
    /// present (§7 (c), D73).
    FailOpenIllegal,
    /// An escape-hatch `host` is a bare CIDR / address literal (§7 (d), D45).
    EscapeHatchBareAddress,
    /// A baseline-pack entry is missing `provenance_source_url` or `evidence`
    /// (§7 (e), D74).
    MissingProvenance,
    /// A malformed numeric / required scalar field.
    BadValue,
    /// A malformed address literal in an address-shaped field.
    BadAddress,
}

/// A single structured rejection (doc 13 §8.1: `{code, path, detail}` triple).
///
/// `path` is a YAML-pointer-ish dotted path into the offending field; `detail`
/// is human-readable and, where the §7/§8.1 spec requires it, NAMES the offending
/// values (e.g. the `(rule_id, declared_rung)` for a rung-cap rejection).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    /// The rejection class.
    pub code: PolicyErrorCode,
    /// Dotted path into the offending field.
    pub path: String,
    /// Human-readable detail (names the offending values where §7 requires it).
    pub detail: String,
}

impl PolicyError {
    fn new(
        code: PolicyErrorCode,
        path: impl Into<String>,
        detail: impl Into<String>,
    ) -> PolicyError {
        PolicyError {
            code,
            path: path.into(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?} @ {}] {}", self.code, self.path, self.detail)
    }
}

impl std::error::Error for PolicyError {}

/// A collect-all bundle of rejections (§8.1 recommendation: a pack author sees
/// every violation in one CI run). A non-empty bundle means the document is
/// rejected; an empty bundle is never constructed (parse returns `Ok` instead).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyErrors(pub Vec<PolicyError>);

impl std::fmt::Display for PolicyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} POL-1 validation error(s):", self.0.len())?;
        for e in &self.0 {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyErrors {}

impl PolicyErrors {
    /// Whether any rejection of the given code is present (test/consumer helper).
    pub fn has(&self, code: PolicyErrorCode) -> bool {
        self.0.iter().any(|e| e.code == code)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema types (doc 13 §2 field inventory / §3 strawman).
// Field names are FREE; the shapes / invariants are FROZEN.
// ─────────────────────────────────────────────────────────────────────────────

/// Admission timers (doc 13 §2 Admission-timers row / §3 `admission`). VALUES
/// live here; `dns_admission.rs` already takes floor/ceil/grace as *parameters*
/// (do not touch it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionTimers {
    /// `ttl_floor` (default 60s).
    pub ttl_floor: u32,
    /// `ttl_ceil` (default 900s).
    pub ttl_ceil: u32,
    /// `grace` (default 60s; flat, not proportional).
    pub grace: u32,
    /// `max_ips_per_domain` (default 1000; per-session cap).
    pub max_ips_per_domain: u32,
    /// `per_domain_overrides` — `domain -> ttl_ceil` clamp override, IP-stable
    /// endpoints (doc 13 §3 `per_domain_overrides`).
    pub per_domain_overrides: Vec<PerDomainOverride>,
}

impl Default for AdmissionTimers {
    fn default() -> AdmissionTimers {
        AdmissionTimers {
            ttl_floor: DEFAULT_TTL_FLOOR_SECS,
            ttl_ceil: DEFAULT_TTL_CEIL_SECS,
            grace: DEFAULT_GRACE_SECS,
            max_ips_per_domain: DEFAULT_MAX_IPS_PER_DOMAIN,
            per_domain_overrides: Vec::new(),
        }
    }
}

/// A per-domain TTL-ceiling override (doc 13 §3 `per_domain_overrides[]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerDomainOverride {
    /// The domain the override pins.
    pub domain: String,
    /// The overriding `ttl_ceil` in seconds.
    pub ttl_ceil: u32,
}

/// DNS semantics block (doc 13 §2 DNS-denial / Upstream-resolution rows / §3 `dns`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsConfig {
    /// `negative_ttl` (default 5s; 0 permitted = uncached).
    pub negative_ttl: u32,
    /// `upstream_resolvers` — ds-dnsgate's OWN egress only (never granted to
    /// VMs). Address-shaped; v6 literals accepted (D75).
    pub upstream_resolvers: Vec<AdmittedAddr>,
    /// `boundary_zone` — the D71 authored-SOA MNAME suffix the gate signs every
    /// deny / NODATA with (`SOA MNAME = denied.policy.<boundary_zone>.`; doc 11
    /// §3.2). ADDITIVE / OPTIONAL: a layer that omits it materializes the
    /// [`DEFAULT_BOUNDARY_ZONE`] working name (`boundary.`), so every pre-existing
    /// fixture composes byte-identically. Only the suffix VALUE source moves from
    /// a handler-local const to this policy-pushed field — the `denied.policy.`
    /// prefix, the always-authored SOA, and TTL==MINIMUM==negative-TTL shape stay
    /// frozen (D71 shape unchanged).
    pub boundary_zone: String,
}

impl Default for DnsConfig {
    fn default() -> DnsConfig {
        DnsConfig {
            negative_ttl: DEFAULT_NEGATIVE_TTL_SECS,
            upstream_resolvers: Vec::new(),
            boundary_zone: DEFAULT_BOUNDARY_ZONE.to_string(),
        }
    }
}

/// QUIC / udp443 counters (doc 13 §2 QUIC row / §3 `quic`). The udp/443 *verdict*
/// is frozen (REJECT + count), not a field; these are the observable counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicConfig {
    /// `reject_counter` — per-session counter feeding the LOG-1 'quic-blocked'
    /// reason (doc 13 §3).
    pub reject_counter: bool,
    /// `canary_latency_budget_ms` (default 250).
    pub canary_latency_budget_ms: u32,
    /// `trigger_eval` cadence (free string, e.g. "weekly").
    pub trigger_eval: String,
}

impl Default for QuicConfig {
    fn default() -> QuicConfig {
        QuicConfig {
            reject_counter: true,
            canary_latency_budget_ms: 250,
            trigger_eval: "weekly".to_string(),
        }
    }
}

/// A blocklist entry (doc 13 §2 Allow/block-lists row / §3 `blocklist`).
/// Blocklists always win (deny-overrides). A `block-or-higher` rung severs
/// established flows on revocation (§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEntry {
    /// The blocked domain.
    pub domain: String,
    /// Why it is blocked (free string; e.g. "doh-resolver").
    pub reason: Option<String>,
    /// The severing rung (D53); a fleet malicious-domain block pins a severing
    /// rung so revocation provably severs established flows (§5).
    pub rung: Option<Rung>,
}

/// An allowlist entry (doc 13 §2 Allow/block-lists row / §3 `allowlist`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowEntry {
    /// The allowed domain.
    pub domain: String,
}

/// A baseline-pack family tier (doc 13 §2 Baseline-pack row / §3 `families`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tier {
    /// `enabled`.
    Enabled,
    /// `disabled` (disabled-by-default tiers: telemetry / binary-cdn / ghcr / lfs).
    Disabled,
}

impl Tier {
    /// Parse a tier token.
    pub fn parse(s: &str) -> Result<Tier, PolicyError> {
        match s {
            "enabled" => Ok(Tier::Enabled),
            "disabled" => Ok(Tier::Disabled),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadValue,
                "baseline_pack.families[].tier",
                format!("unknown tier {other:?} (enabled|disabled)"),
            )),
        }
    }
}

/// A baseline-pack entry (doc 13 §2 Baseline-pack row / §3 `entries[]`). Mandatory
/// `provenance_source_url` + `evidence` (§7 (e), D74).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackEntry {
    /// `fqdn` — exact FQDN (wildcards only for vendor-published forms; the
    /// reader does not expand them).
    pub fqdn: String,
    /// `family` — the family key this entry belongs to.
    pub family: String,
    /// `ports`.
    pub ports: Vec<u32>,
    /// `provenance_source_url` — MANDATORY (§7 (e)).
    pub provenance_source_url: Option<String>,
    /// `machine_source` — nullable poll target.
    pub machine_source: Option<String>,
    /// `passthrough` flag.
    pub passthrough: bool,
    /// `evidence` — MANDATORY (§7 (e)).
    pub evidence: Option<String>,
    /// `path_scope` — TLS-6-gated path patterns (optional).
    pub path_scope: Vec<String>,
    /// `requires` — a capability gate (e.g. "http-policy"); the entry is INERT
    /// until that capability lands (§1.7 / §8.2, D74). `None` = active.
    pub requires: Option<String>,
}

/// A baseline endpoint pack (doc 13 §2 Baseline-pack row / §3 `baseline_pack`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BaselinePack {
    /// `pack_version` — content identity cited in POL-3 provenance (NOT a version
    /// namespace).
    pub pack_version: String,
    /// `families` — family-key -> tier.
    pub families: BTreeMap<String, Tier>,
    /// `entries`.
    pub entries: Vec<PackEntry>,
}

/// An escape-hatch catalog entry (doc 13 §2 Escape-hatches row / §3
/// `escape_hatches.catalog[]`). Entries are `protocol+host+port`; a bare CIDR /
/// address-literal `host` is REJECTED (§7 (d), D45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscapeHatch {
    /// `id`.
    pub id: String,
    /// `protocol` (e.g. "postgres").
    pub protocol: String,
    /// `host` — a hostname, NEVER a bare CIDR / address literal (§7 (d)).
    pub host: String,
    /// `port`.
    pub port: u32,
    /// `scope` — org | repo | session (free string in v0).
    pub scope: String,
    /// `approval` — allow-once | allow-always (free string in v0).
    pub approval: String,
}

/// A credential-swap service-registry entry (doc 13 §2 Credential-swap row / §3
/// `services[]`). CONTENT is Identity-supplied; this schema owns the shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEntry {
    /// `service` — the service_id registry key a credential rule matches.
    pub service: String,
    /// `hosts`.
    pub hosts: Vec<String>,
    /// `credential.location` (e.g. "header").
    pub credential_location: String,
    /// `credential.name` (e.g. "Authorization").
    pub credential_name: String,
}

/// A typed guardrail rule (doc 13 §2 Guardrail-rules row / §3 `guardrails[]`).
/// One typed schema across D52's five classes; `rung` is MANDATORY (§7 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardrailRule {
    /// `id`.
    pub id: String,
    /// `class` — one of D52's five classes.
    pub class: GuardrailClass,
    /// `match` — opaque key/value selector (no expression language in v0; CEL is
    /// the M4 escape hatch). Stored as ordered key→value pairs.
    pub match_: BTreeMap<String, String>,
    /// `limit` — opaque key/value limit (count/per, tokens/window, deny_window…).
    pub limit: BTreeMap<String, String>,
    /// `rung` — MANDATORY (§7 (a), D53). Absent ⇒ rejected at parse.
    pub rung: Rung,
    /// `ttl` — optional (null = no TTL).
    pub ttl: Option<u32>,
}

/// A generic content (secret-scanning) rule (doc 13 §2 Content-class row / §3
/// `content.generic.rules[]`). Generic rules are capped at `block+log` (§7 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericContentRule {
    /// `id`.
    pub id: String,
    /// `regex`.
    pub regex: String,
    /// `keywords`.
    pub keywords: Vec<String>,
    /// `secret_group`.
    pub secret_group: u32,
    /// `entropy` — present, UNUSED in v0 (field exists for forward-compat).
    pub entropy: Option<u32>,
    /// `rung` — capped at `block+log` for generic rules (§7 (b)).
    pub rung: Rung,
}

/// The keyed-plane rung defaults (doc 13 §2 / §3 `content.keyed`). Digests
/// themselves are NOT policy fields (§5 classification); only the rung defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedContent {
    /// `forbidden_default_rung` (keyed-forbidden default; doc 16 §7).
    pub forbidden_default_rung: Rung,
    /// `issued_wrong_destination_rung` (keyed-issued-to-wrong-destination).
    pub issued_wrong_destination_rung: Rung,
}

/// The two-plane content-rules block (doc 13 §2 Content-class row / §3 `content`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentConfig {
    /// `generic.fail_open` — explicit bit; legal only when every generic rule is
    /// `allow+log` AND no keyed plane is loaded (§7 (c)).
    pub fail_open: bool,
    /// `generic.ruleset_version`.
    pub ruleset_version: String,
    /// `generic.rules`.
    pub generic_rules: Vec<GenericContentRule>,
    /// `keyed` — rung defaults; `Some` ⇒ the keyed plane is loaded (forces
    /// fail-closed, §7 (c)).
    pub keyed: Option<KeyedContent>,
}

/// Attendedness defaults (doc 13 §2 Ask-defaults row / §3 `ask.attendedness`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attendedness {
    /// `activity_window_minutes` — T (~10 min); org-tunable (D78).
    pub activity_window_minutes: u32,
}

impl Default for Attendedness {
    fn default() -> Attendedness {
        Attendedness {
            activity_window_minutes: DEFAULT_ACTIVITY_WINDOW_MINUTES,
        }
    }
}

/// Ask-user defaults (doc 13 §2 Ask-defaults row / §3 `ask`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AskConfig {
    /// `unknown_domain` (free string verdict token, e.g. "ask").
    pub unknown_domain: String,
    /// `unattended_downgrade` (e.g. "block").
    pub unattended_downgrade: String,
    /// `attendedness` block.
    pub attendedness: Attendedness,
}

/// IPv6 phasing (doc 13 §2 IPv6 row / §3 `ipv6`). HYBRID (D75): the parser accepts
/// v6 literals NOW; enforcement is phase-gated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ipv6Phase {
    /// `a` — v4-only.
    A,
    /// `b` — proxy-egress dual-stack (guest-invariant; ON at golden MVP).
    B,
    /// `c` — guest dual-stack (dormant, trigger-gated).
    C,
}

impl Ipv6Phase {
    /// Parse an IPv6 phase token.
    pub fn parse(s: &str) -> Result<Ipv6Phase, PolicyError> {
        match s {
            "a" => Ok(Ipv6Phase::A),
            "b" => Ok(Ipv6Phase::B),
            "c" => Ok(Ipv6Phase::C),
            other => Err(PolicyError::new(
                PolicyErrorCode::BadValue,
                "ipv6.phase",
                format!("unknown ipv6 phase {other:?} (a|b|c)"),
            )),
        }
    }
}

/// IPv6 config (doc 13 §2 IPv6 row / §3 `ipv6`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Config {
    /// `phase`.
    pub phase: Ipv6Phase,
    /// `synthetic_a_pool` — phase-B synthetic-A admission pool (strawman string).
    pub synthetic_a_pool: Option<String>,
}

impl Default for Ipv6Config {
    fn default() -> Ipv6Config {
        Ipv6Config {
            phase: Ipv6Phase::B,
            synthetic_a_pool: None,
        }
    }
}

/// One POL-1 v0 layer document (doc 13 §3). A single layer of the
/// `system-baseline -> org -> repo/session` composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLayer {
    /// `schema_version` (frozen `pol1/v0`).
    pub schema_version: String,
    /// `layer`.
    pub layer: Layer,
    /// `posture`.
    pub posture: Posture,
    /// `admission` timers.
    pub admission: AdmissionTimers,
    /// `dns`.
    pub dns: DnsConfig,
    /// `quic`.
    pub quic: QuicConfig,
    /// `baseline_pack`.
    pub baseline_pack: BaselinePack,
    /// `allowlist`.
    pub allowlist: Vec<AllowEntry>,
    /// `blocklist` — always wins (deny-overrides).
    pub blocklist: Vec<BlockEntry>,
    /// `passthrough` — ships EMPTY (§2 Pass-through row).
    pub passthrough: Vec<String>,
    /// `escape_hatches.catalog`.
    pub escape_hatches: Vec<EscapeHatch>,
    /// `services` — the credential-swap registry.
    pub services: Vec<ServiceEntry>,
    /// `guardrails` — typed rules.
    pub guardrails: Vec<GuardrailRule>,
    /// `content` — the two-plane content rules.
    pub content: ContentConfig,
    /// `ask` — ask-user defaults.
    pub ask: AskConfig,
    /// `ipv6`.
    pub ipv6: Ipv6Config,
}

// ─────────────────────────────────────────────────────────────────────────────
// Address parsing (§2 IPv6 row, D75) — v6 literals accepted in every
// address-shaped field. Reuses AdmittedAddr / AddressFamily (no parallel type).
// ─────────────────────────────────────────────────────────────────────────────

/// Whether `s` parses as a bare IP address LITERAL — used both to ACCEPT v6
/// literals in address-shaped fields (D75) and to REJECT a bare address literal
/// where a hostname is required (escape-hatch `host`, §7 (d), D45).
///
/// Accepts dotted-quad IPv4 and (a pragmatic subset of) RFC 4291 IPv6 literals.
/// CIDR (`addr/len`) is detected too so the escape-hatch validator catches a
/// `host: 10.0.0.0/8`.
pub fn parse_ip_literal(s: &str) -> Option<AdmittedAddr> {
    let s = s.trim();
    if let Some(addr) = parse_ipv4_literal(s) {
        return Some(addr);
    }
    parse_ipv6_literal(s)
}

/// Whether `s` looks like a CIDR (`<addr>/<prefix-len>`) — a bare network range,
/// always illegal as an escape-hatch `host` (§7 (d), D45).
pub fn is_cidr(s: &str) -> bool {
    let s = s.trim();
    match s.split_once('/') {
        Some((addr, len)) => {
            // numeric prefix length AND an address literal on the left.
            len.parse::<u32>().is_ok()
                && (parse_ipv4_literal(addr).is_some() || parse_ipv6_literal(addr).is_some())
        }
        None => false,
    }
}

/// Whether `host` is a bare address literal or CIDR — the §7 (d) / §8.1
/// rejection predicate for escape-hatch `host` fields (D45). A hostname (even a
/// dotted one like `db.staging.example.internal`) returns `false`.
pub fn is_bare_address_or_cidr(host: &str) -> bool {
    is_cidr(host) || parse_ip_literal(host).is_some()
}

fn parse_ipv4_literal(s: &str) -> Option<AdmittedAddr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = Vec::with_capacity(4);
    for p in parts {
        // reject empty / non-numeric / leading-`+` etc. and out-of-range.
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        octets.push(v as u8);
    }
    Some(AdmittedAddr {
        family: AddressFamily::V4,
        octets,
    })
}

/// A pragmatic RFC 4291 IPv6 literal parser (supports `::` compression and a
/// trailing embedded IPv4). Enough to ACCEPT v6 literals (D75) and to RECOGNISE
/// a v6 `host` so the escape-hatch validator rejects it.
fn parse_ipv6_literal(s: &str) -> Option<AdmittedAddr> {
    // Must contain a colon to be a v6 literal; reject obvious non-v6.
    if !s.contains(':') {
        return None;
    }
    // Split on the "::" zero-compression marker (at most one allowed).
    let double_colon_count = s.matches("::").count();
    if double_colon_count > 1 {
        return None;
    }

    // Helper: parse a colon-separated run of hextets, expanding a trailing
    // embedded IPv4 (e.g. "::ffff:192.0.2.1") into two hextets.
    fn parse_run(run: &str) -> Option<Vec<u16>> {
        if run.is_empty() {
            return Some(Vec::new());
        }
        let mut out: Vec<u16> = Vec::new();
        let groups: Vec<&str> = run.split(':').collect();
        for (i, g) in groups.iter().enumerate() {
            // A trailing group containing a dot is an embedded IPv4 tail.
            if g.contains('.') {
                if i != groups.len() - 1 {
                    return None; // embedded v4 must be last
                }
                let v4 = parse_ipv4_literal(g)?;
                out.push(((v4.octets[0] as u16) << 8) | v4.octets[1] as u16);
                out.push(((v4.octets[2] as u16) << 8) | v4.octets[3] as u16);
            } else {
                if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(u16::from_str_radix(g, 16).ok()?);
            }
        }
        Some(out)
    }

    let hextets: Vec<u16> = if double_colon_count == 1 {
        let (head, tail) = s.split_once("::")?;
        let head_h = parse_run(head)?;
        let tail_h = parse_run(tail)?;
        let total = head_h.len() + tail_h.len();
        if total > 7 {
            // "::" must stand for at least one zero group.
            return None;
        }
        let mut v = head_h;
        v.extend(std::iter::repeat_n(0u16, 8 - total));
        v.extend(tail_h);
        v
    } else {
        let v = parse_run(s)?;
        if v.len() != 8 {
            return None;
        }
        v
    };

    if hextets.len() != 8 {
        return None;
    }
    let mut octets = Vec::with_capacity(16);
    for h in hextets {
        octets.push((h >> 8) as u8);
        octets.push((h & 0xff) as u8);
    }
    Some(AdmittedAddr {
        family: AddressFamily::V6,
        octets,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation (§7 / §8.1 parse-time structural rejections, collect-all).
// ─────────────────────────────────────────────────────────────────────────────

/// Run the §7 / §8.1 structural validators over a parsed layer, COLLECTING all
/// rejections (§8.1 recommendation). Returns `Ok(())` for a clean document.
///
/// The frozen rejection set (a single rejection test per rule lives in this
/// module's tests):
/// - (a) every guardrail rule carries a rung — enforced by the type
///   ([`GuardrailRule::rung`] is non-optional; the reader rejects an absent
///   `rung` with [`PolicyErrorCode::MissingRung`] before this runs);
/// - (b) generic content rules ≤ `block+log` (§8.1 rung-cap);
/// - (c) `fail_open: true` legal only when every generic rule is `allow+log` and
///   no keyed plane is loaded (§8.1; mirrors `fail_mode_is_legal`);
/// - (d) escape-hatch `host` is not a bare CIDR / address literal (§8.1);
/// - (e) every baseline-pack entry carries `provenance_source_url` + `evidence`
///   (§8.1 mandatory provenance).
pub fn validate_layer(layer: &PolicyLayer) -> Result<(), PolicyErrors> {
    let mut errs: Vec<PolicyError> = Vec::new();

    // (b) Generic content rung cap — block+log is the structural cap (§8.1, D73).
    for rule in &layer.content.generic_rules {
        if rule.rung > Rung::BlockLog {
            errs.push(PolicyError::new(
                PolicyErrorCode::GenericRungCap,
                format!("content.generic.rules[{}].rung", rule.id),
                format!(
                    "generic content rule (rule_id={:?}, declared_rung={}) exceeds the \
                     block+log cap; suspend+ask/kill+snapshot are forbidden on generic rules",
                    rule.id,
                    rule.rung.token()
                ),
            ));
        }
    }

    // (c) fail_open legality (§8.1, D73). Mirror fail_mode_is_legal: fail_open is
    // legal ONLY when no keyed plane is loaded AND every generic rule is allow+log.
    if layer.content.fail_open {
        let keyed_loaded = layer.content.keyed.is_some();
        let all_generic_allow_log = layer
            .content
            .generic_rules
            .iter()
            .all(|r| r.rung == Rung::AllowLog);
        if keyed_loaded {
            errs.push(PolicyError::new(
                PolicyErrorCode::FailOpenIllegal,
                "content.generic.fail_open",
                "fail_open: true is illegal while the keyed plane is loaded \
                 (fail-closed is mandatory whenever content.keyed is present)",
            ));
        }
        if !all_generic_allow_log {
            // Name the first offending generic rule.
            let offending = layer
                .content
                .generic_rules
                .iter()
                .find(|r| r.rung != Rung::AllowLog);
            let named = offending
                .map(|r| format!(" (e.g. rule_id={:?} declared {})", r.id, r.rung.token()))
                .unwrap_or_default();
            errs.push(PolicyError::new(
                PolicyErrorCode::FailOpenIllegal,
                "content.generic.fail_open",
                format!(
                    "fail_open: true is legal only when every generic rule is allow+log{named}"
                ),
            ));
        }
    }

    // (d) Escape-hatch host must not be a bare CIDR / address literal (§8.1, D45).
    for hatch in &layer.escape_hatches {
        if is_bare_address_or_cidr(&hatch.host) {
            errs.push(PolicyError::new(
                PolicyErrorCode::EscapeHatchBareAddress,
                format!("escape_hatches.catalog[{}].host", hatch.id),
                format!(
                    "escape-hatch host {:?} is a bare address/CIDR; entries are \
                     protocol+host+port and host must be a hostname (never a bare IP range)",
                    hatch.host
                ),
            ));
        }
    }

    // (e) Mandatory baseline-pack provenance (§8.1, D74).
    for entry in &layer.baseline_pack.entries {
        if entry.provenance_source_url.is_none() {
            errs.push(PolicyError::new(
                PolicyErrorCode::MissingProvenance,
                format!(
                    "baseline_pack.entries[{}].provenance_source_url",
                    entry.fqdn
                ),
                format!(
                    "baseline-pack entry {:?} is missing provenance_source_url (mandatory, D74)",
                    entry.fqdn
                ),
            ));
        }
        if entry.evidence.is_none() {
            errs.push(PolicyError::new(
                PolicyErrorCode::MissingProvenance,
                format!("baseline_pack.entries[{}].evidence", entry.fqdn),
                format!(
                    "baseline-pack entry {:?} is missing evidence (mandatory, D74)",
                    entry.fqdn
                ),
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(PolicyErrors(errs))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The stdlib-only POL-1 document reader (§3 subset). No serde / serde_yaml.
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a POL-1 v0 layer document from its YAML-subset text, running the §7 /
/// §8.1 structural validators (parse-time, collect-all). Returns the parsed
/// [`PolicyLayer`] on success, or the bundle of rejections.
///
/// Stdlib only — no serde / serde_yaml (the `[dependencies]`-empty fence). The
/// reader understands exactly the POL-1 block structure (two-space indented
/// mappings, `- ` list items, scalars, inline `[a, b]` flow sequences, `#`
/// comments) and rejects anything it does not recognise as a [`PolicyError`]
/// with `code = Syntax`.
pub fn parse_layer(text: &str) -> Result<PolicyLayer, PolicyErrors> {
    let doc = match YamlNode::parse_document(text) {
        Ok(d) => d,
        Err(e) => return Err(PolicyErrors(vec![e])),
    };
    let mut errs: Vec<PolicyError> = Vec::new();
    let layer = build_layer(&doc, &mut errs);
    // Structural validators run regardless, so a single CI pass surfaces both
    // shape errors and §7 violations (collect-all, §8.1).
    let layer = match layer {
        Some(l) => l,
        None => return Err(PolicyErrors(errs)),
    };
    match validate_layer(&layer) {
        Ok(()) => {
            if errs.is_empty() {
                Ok(layer)
            } else {
                Err(PolicyErrors(errs))
            }
        }
        Err(mut v) => {
            errs.append(&mut v.0);
            Err(PolicyErrors(errs))
        }
    }
}

// ---- The YAML-subset reader ------------------------------------------------
//
// A minimal block-structure reader. NOT a general YAML parser. It recognises the
// POL-1 document subset: indentation-scoped mappings (`key: value` / `key:`),
// `- ` block-sequence items (scalars or nested mappings), inline flow sequences
// `[a, b, c]`, scalars, and `#` comments. Anything outside this shape is a
// `Syntax` error.

#[derive(Clone, Debug, PartialEq, Eq)]
enum YamlNode {
    /// A scalar leaf (string form; consumers coerce to int/bool/null).
    Scalar(String),
    /// A block (or inline-flow) sequence of nodes.
    Sequence(Vec<YamlNode>),
    /// A mapping of key → node, insertion-ordered.
    Mapping(Vec<(String, YamlNode)>),
}

impl YamlNode {
    fn parse_document(text: &str) -> Result<YamlNode, PolicyError> {
        let lines = Self::logical_lines(text)?;
        let mut idx = 0usize;
        let node = Self::parse_block(&lines, &mut idx, 0)?;
        if idx != lines.len() {
            return Err(PolicyError::new(
                PolicyErrorCode::Syntax,
                "<document>",
                format!("unexpected trailing content at line {}", lines[idx].line_no),
            ));
        }
        Ok(node)
    }

    /// Strip comments / blank lines, compute indentation, reject tabs.
    fn logical_lines(text: &str) -> Result<Vec<LogicalLine>, PolicyError> {
        let mut out = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line_no = i + 1;
            if raw.contains('\t') {
                return Err(PolicyError::new(
                    PolicyErrorCode::Syntax,
                    "<document>",
                    format!("tab character in indentation at line {line_no} (use spaces)"),
                ));
            }
            // Strip a trailing comment that is not inside a quoted string. The
            // POL-1 subset never embeds an unquoted '#' in a scalar value, so a
            // simple split is sufficient and well-defined for this grammar.
            let no_comment = Self::strip_comment(raw);
            if no_comment.trim().is_empty() {
                continue;
            }
            let indent = no_comment.len() - no_comment.trim_start().len();
            out.push(LogicalLine {
                indent,
                content: no_comment.trim_end().to_string(),
                line_no,
            });
        }
        Ok(out)
    }

    fn strip_comment(raw: &str) -> &str {
        // Find a '#' that is preceded by whitespace or starts the (trimmed) line;
        // do not strip inside a quoted scalar. The POL-1 subset has no '#' inside
        // values, so we only need to avoid splitting a URL fragment. Require the
        // '#' to be at column 0 (after indent) or preceded by a space.
        let bytes = raw.as_bytes();
        let mut i = 0;
        let mut in_single = false;
        let mut in_double = false;
        while i < bytes.len() {
            let c = bytes[i] as char;
            match c {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '#' if !in_single && !in_double => {
                    let prev_is_space = i == 0 || bytes[i - 1] == b' ';
                    let at_line_start = raw[..i].trim().is_empty();
                    if prev_is_space || at_line_start {
                        return &raw[..i];
                    }
                }
                _ => {}
            }
            i += 1;
        }
        raw
    }

    /// Parse the block at indentation `>= min_indent` starting at `*idx`.
    fn parse_block(
        lines: &[LogicalLine],
        idx: &mut usize,
        min_indent: usize,
    ) -> Result<YamlNode, PolicyError> {
        if *idx >= lines.len() {
            return Ok(YamlNode::Mapping(Vec::new()));
        }
        let base = lines[*idx].indent;
        if base < min_indent {
            return Ok(YamlNode::Mapping(Vec::new()));
        }
        if lines[*idx].content.trim_start().starts_with("- ")
            || lines[*idx].content.trim_start() == "-"
        {
            Self::parse_sequence(lines, idx, base)
        } else {
            Self::parse_mapping(lines, idx, base)
        }
    }

    fn parse_mapping(
        lines: &[LogicalLine],
        idx: &mut usize,
        base: usize,
    ) -> Result<YamlNode, PolicyError> {
        let mut entries: Vec<(String, YamlNode)> = Vec::new();
        while *idx < lines.len() && lines[*idx].indent == base {
            let line = &lines[*idx];
            let content = line.content.trim_start();
            if content.starts_with("- ") || content == "-" {
                break; // a sequence at this level belongs to the parent key
            }
            let colon = Self::split_key(content, line.line_no)?;
            let (key, rest) = colon;
            *idx += 1;
            if rest.is_empty() {
                // Nested block under this key (mapping or sequence), or empty.
                let child = if *idx < lines.len() && lines[*idx].indent > base {
                    Self::parse_block(lines, idx, base + 1)?
                } else {
                    YamlNode::Mapping(Vec::new())
                };
                entries.push((key, child));
            } else {
                entries.push((key, Self::parse_scalar_or_flow(&rest, line.line_no)?));
            }
        }
        Ok(YamlNode::Mapping(entries))
    }

    fn parse_sequence(
        lines: &[LogicalLine],
        idx: &mut usize,
        base: usize,
    ) -> Result<YamlNode, PolicyError> {
        let mut items: Vec<YamlNode> = Vec::new();
        while *idx < lines.len() && lines[*idx].indent == base {
            let line = &lines[*idx];
            let content = line.content.trim_start();
            if !(content.starts_with("- ") || content == "-") {
                break;
            }
            let after_dash = content[1..].trim_start();
            *idx += 1;
            if after_dash.is_empty() {
                // `-` then a nested block.
                let child = if *idx < lines.len() && lines[*idx].indent > base {
                    Self::parse_block(lines, idx, base + 1)?
                } else {
                    YamlNode::Mapping(Vec::new())
                };
                items.push(child);
            } else if let Some(colon_pos) = Self::find_mapping_colon(after_dash) {
                // `- key: value` — a mapping item whose first key is inline. The
                // continuation lines are indented to the column after "- ".
                let inline_key = after_dash[..colon_pos].trim().to_string();
                let inline_rest = after_dash[colon_pos + 1..].trim();
                let mut map_entries: Vec<(String, YamlNode)> = Vec::new();
                if inline_rest.is_empty() {
                    let child = if *idx < lines.len() && lines[*idx].indent > base {
                        Self::parse_block(lines, idx, base + 1)?
                    } else {
                        YamlNode::Mapping(Vec::new())
                    };
                    map_entries.push((inline_key, child));
                } else {
                    map_entries.push((
                        inline_key,
                        Self::parse_scalar_or_flow(inline_rest, line.line_no)?,
                    ));
                }
                // Remaining keys of this mapping item are indented past base.
                let cont_indent = base + 2;
                while *idx < lines.len() && lines[*idx].indent >= cont_indent {
                    if lines[*idx].indent != cont_indent {
                        // deeper indentation is handled by the recursive parse of
                        // the value; only same-level continuation keys here.
                        break;
                    }
                    let cline = &lines[*idx];
                    let ccontent = cline.content.trim_start();
                    if ccontent.starts_with("- ") || ccontent == "-" {
                        break;
                    }
                    let (ckey, crest) = Self::split_key(ccontent, cline.line_no)?;
                    *idx += 1;
                    if crest.is_empty() {
                        let child = if *idx < lines.len() && lines[*idx].indent > cont_indent {
                            Self::parse_block(lines, idx, cont_indent + 1)?
                        } else {
                            YamlNode::Mapping(Vec::new())
                        };
                        map_entries.push((ckey, child));
                    } else {
                        map_entries
                            .push((ckey, Self::parse_scalar_or_flow(&crest, cline.line_no)?));
                    }
                }
                items.push(YamlNode::Mapping(map_entries));
            } else {
                // `- scalar` (or `- [flow]`).
                items.push(Self::parse_scalar_or_flow(after_dash, line.line_no)?);
            }
        }
        Ok(YamlNode::Sequence(items))
    }

    /// Split `key: rest`, returning `(key, rest)`. `rest` may be empty.
    fn split_key(content: &str, line_no: usize) -> Result<(String, String), PolicyError> {
        match Self::find_mapping_colon(content) {
            Some(pos) => {
                let key = content[..pos].trim().to_string();
                let rest = content[pos + 1..].trim().to_string();
                if key.is_empty() {
                    return Err(PolicyError::new(
                        PolicyErrorCode::Syntax,
                        "<document>",
                        format!("empty mapping key at line {line_no}"),
                    ));
                }
                Ok((Self::unquote(&key), rest))
            }
            None => Err(PolicyError::new(
                PolicyErrorCode::Syntax,
                "<document>",
                format!("expected `key: value` at line {line_no}, got {content:?}"),
            )),
        }
    }

    /// Find the colon that terminates a mapping key: a `:` followed by end-of-line
    /// or a space, not inside a `[...]` flow sequence or a quoted string.
    fn find_mapping_colon(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        let mut depth = 0i32;
        let mut in_single = false;
        let mut in_double = false;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'\'' if !in_double => in_single = !in_single,
                b'"' if !in_single => in_double = !in_double,
                b'[' | b'{' if !in_single && !in_double => depth += 1,
                b']' | b'}' if !in_single && !in_double => depth -= 1,
                b':' if !in_single && !in_double && depth == 0 => {
                    let next_is_space_or_end = i + 1 >= bytes.len() || bytes[i + 1] == b' ';
                    if next_is_space_or_end {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn parse_scalar_or_flow(s: &str, line_no: usize) -> Result<YamlNode, PolicyError> {
        let t = s.trim();
        if t.starts_with('[') {
            if !t.ends_with(']') {
                return Err(PolicyError::new(
                    PolicyErrorCode::Syntax,
                    "<document>",
                    format!("unterminated flow sequence at line {line_no}: {t:?}"),
                ));
            }
            let inner = &t[1..t.len() - 1];
            let mut items = Vec::new();
            if !inner.trim().is_empty() {
                for part in Self::split_flow(inner) {
                    items.push(YamlNode::Scalar(Self::unquote(part.trim())));
                }
            }
            Ok(YamlNode::Sequence(items))
        } else if t.starts_with('{') {
            // Inline flow mapping `{ key: value, key2: value2 }` (§3 strawman:
            // `core: { tier: enabled }`, `credential: { location: header, ... }`).
            if !t.ends_with('}') {
                return Err(PolicyError::new(
                    PolicyErrorCode::Syntax,
                    "<document>",
                    format!("unterminated flow mapping at line {line_no}: {t:?}"),
                ));
            }
            let inner = &t[1..t.len() - 1];
            let mut entries: Vec<(String, YamlNode)> = Vec::new();
            if !inner.trim().is_empty() {
                for part in Self::split_flow(inner) {
                    let part = part.trim();
                    match part.split_once(':') {
                        Some((k, v)) => entries.push((
                            Self::unquote(k.trim()),
                            // a nested flow value may itself be `[...]`.
                            Self::parse_scalar_or_flow(v.trim(), line_no)?,
                        )),
                        None => {
                            return Err(PolicyError::new(
                                PolicyErrorCode::Syntax,
                                "<document>",
                                format!("flow-mapping entry without `key: value` at line {line_no}: {part:?}"),
                            ))
                        }
                    }
                }
            }
            Ok(YamlNode::Mapping(entries))
        } else {
            Ok(YamlNode::Scalar(Self::unquote(t)))
        }
    }

    /// Split a flow-sequence body on top-level commas (no nested flow in POL-1,
    /// but quotes are respected).
    fn split_flow(inner: &str) -> Vec<&str> {
        let bytes = inner.as_bytes();
        let mut parts = Vec::new();
        let mut start = 0;
        let mut depth = 0i32;
        let mut in_single = false;
        let mut in_double = false;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'\'' if !in_double => in_single = !in_single,
                b'"' if !in_single => in_double = !in_double,
                b'[' | b'{' if !in_single && !in_double => depth += 1,
                b']' | b'}' if !in_single && !in_double => depth -= 1,
                b',' if !in_single && !in_double && depth == 0 => {
                    parts.push(&inner[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        parts.push(&inner[start..]);
        parts
    }

    fn unquote(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\'')))
        {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }

    // ---- typed accessors used by the layer builder ----

    fn as_mapping(&self) -> Option<&[(String, YamlNode)]> {
        match self {
            YamlNode::Mapping(m) => Some(m),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&YamlNode> {
        match self {
            YamlNode::Mapping(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_scalar(&self) -> Option<&str> {
        match self {
            YamlNode::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_sequence(&self) -> Option<&[YamlNode]> {
        match self {
            YamlNode::Sequence(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalLine {
    indent: usize,
    content: String,
    line_no: usize,
}

// ---- The layer builder: YamlNode tree → PolicyLayer, collecting errors -------

fn build_layer(doc: &YamlNode, errs: &mut Vec<PolicyError>) -> Option<PolicyLayer> {
    let root = match doc.as_mapping() {
        Some(_) => doc,
        None => {
            errs.push(PolicyError::new(
                PolicyErrorCode::Syntax,
                "<document>",
                "top-level POL-1 document must be a mapping",
            ));
            return None;
        }
    };

    let schema_version = scalar_or(root, "schema_version", SCHEMA_VERSION_V0);

    let layer = match root.get("layer").and_then(|n| n.as_scalar()) {
        Some(s) => match Layer::parse(s) {
            Ok(l) => l,
            Err(e) => {
                errs.push(e);
                Layer::SystemBaseline
            }
        },
        None => {
            errs.push(PolicyError::new(
                PolicyErrorCode::BadLayer,
                "layer",
                "missing required `layer`",
            ));
            Layer::SystemBaseline
        }
    };

    let posture = match root.get("posture").and_then(|n| n.as_scalar()) {
        Some(s) => match Posture::parse(s) {
            Ok(p) => p,
            Err(e) => {
                errs.push(e);
                Posture::Standard
            }
        },
        None => {
            errs.push(PolicyError::new(
                PolicyErrorCode::BadPosture,
                "posture",
                "missing required `posture`",
            ));
            Posture::Standard
        }
    };

    let admission = build_admission(root.get("admission"), errs);
    let dns = build_dns(root.get("dns"), errs);
    let quic = build_quic(root.get("quic"), errs);
    let baseline_pack = build_pack(root.get("baseline_pack"), errs);
    let allowlist = build_allowlist(root.get("allowlist"));
    let blocklist = build_blocklist(root.get("blocklist"), errs);
    let passthrough = build_string_seq(root.get("passthrough"));
    let escape_hatches = build_escape_hatches(root.get("escape_hatches"), errs);
    let services = build_services(root.get("services"));
    let guardrails = build_guardrails(root.get("guardrails"), errs);
    let content = build_content(root.get("content"), errs);
    let ask = build_ask(root.get("ask"), errs);
    let ipv6 = build_ipv6(root.get("ipv6"), errs);

    Some(PolicyLayer {
        schema_version,
        layer,
        posture,
        admission,
        dns,
        quic,
        baseline_pack,
        allowlist,
        blocklist,
        passthrough,
        escape_hatches,
        services,
        guardrails,
        content,
        ask,
        ipv6,
    })
}

fn scalar_or(node: &YamlNode, key: &str, default: &str) -> String {
    node.get(key)
        .and_then(|n| n.as_scalar())
        .map(|s| s.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn parse_u32_field(
    node: &YamlNode,
    key: &str,
    path: &str,
    errs: &mut Vec<PolicyError>,
) -> Option<u32> {
    let s = node.get(key)?.as_scalar()?;
    match s.parse::<u32>() {
        Ok(v) => Some(v),
        Err(_) => {
            errs.push(PolicyError::new(
                PolicyErrorCode::BadValue,
                path,
                format!("expected an unsigned integer, got {s:?}"),
            ));
            None
        }
    }
}

fn parse_bool_field(node: &YamlNode, key: &str) -> Option<bool> {
    match node.get(key)?.as_scalar()? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn build_admission(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> AdmissionTimers {
    let mut t = AdmissionTimers::default();
    let Some(n) = node else { return t };
    if let Some(v) = parse_u32_field(n, "ttl_floor", "admission.ttl_floor", errs) {
        t.ttl_floor = v;
    }
    if let Some(v) = parse_u32_field(n, "ttl_ceil", "admission.ttl_ceil", errs) {
        t.ttl_ceil = v;
    }
    if let Some(v) = parse_u32_field(n, "grace", "admission.grace", errs) {
        t.grace = v;
    }
    if let Some(v) = parse_u32_field(
        n,
        "max_ips_per_domain",
        "admission.max_ips_per_domain",
        errs,
    ) {
        t.max_ips_per_domain = v;
    }
    if let Some(seq) = n.get("per_domain_overrides").and_then(|x| x.as_sequence()) {
        for item in seq {
            let domain = item.get("domain").and_then(|x| x.as_scalar()).unwrap_or("");
            if domain.is_empty() {
                continue;
            }
            let ttl_ceil = item
                .get("ttl_ceil")
                .and_then(|x| x.as_scalar())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(t.ttl_ceil);
            t.per_domain_overrides.push(PerDomainOverride {
                domain: domain.to_string(),
                ttl_ceil,
            });
        }
    }
    t
}

fn build_dns(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> DnsConfig {
    let mut d = DnsConfig::default();
    let Some(n) = node else { return d };
    if let Some(v) = parse_u32_field(n, "negative_ttl", "dns.negative_ttl", errs) {
        d.negative_ttl = v;
    }
    if let Some(seq) = n.get("upstream_resolvers").and_then(|x| x.as_sequence()) {
        for (i, item) in seq.iter().enumerate() {
            if let Some(s) = item.as_scalar() {
                match parse_ip_literal(s) {
                    Some(addr) => d.upstream_resolvers.push(addr),
                    None => errs.push(PolicyError::new(
                        PolicyErrorCode::BadAddress,
                        format!("dns.upstream_resolvers[{i}]"),
                        format!("not an IP literal: {s:?}"),
                    )),
                }
            }
        }
    }
    // ADDITIVE (D71): the authored-SOA boundary-zone suffix. Absent => the
    // DEFAULT_BOUNDARY_ZONE working name carried by `DnsConfig::default()`, so a
    // layer that never names it composes exactly as before.
    if let Some(s) = n.get("boundary_zone").and_then(|x| x.as_scalar()) {
        if !s.is_empty() {
            d.boundary_zone = s.to_string();
        }
    }
    d
}

fn build_quic(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> QuicConfig {
    let mut q = QuicConfig::default();
    let Some(n) = node else { return q };
    if let Some(b) = parse_bool_field(n, "reject_counter") {
        q.reject_counter = b;
    }
    if let Some(v) = parse_u32_field(
        n,
        "canary_latency_budget_ms",
        "quic.canary_latency_budget_ms",
        errs,
    ) {
        q.canary_latency_budget_ms = v;
    }
    if let Some(s) = n.get("trigger_eval").and_then(|x| x.as_scalar()) {
        q.trigger_eval = s.to_string();
    }
    q
}

fn build_pack(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> BaselinePack {
    let mut pack = BaselinePack::default();
    let Some(n) = node else { return pack };
    pack.pack_version = scalar_or(n, "pack_version", "");
    if let Some(YamlNode::Mapping(fams)) = n.get("families") {
        for (fam, val) in fams {
            let tier_str = val.get("tier").and_then(|x| x.as_scalar()).unwrap_or("");
            match Tier::parse(tier_str) {
                Ok(t) => {
                    pack.families.insert(fam.clone(), t);
                }
                Err(mut e) => {
                    e.path = format!("baseline_pack.families.{fam}.tier");
                    errs.push(e);
                }
            }
        }
    }
    if let Some(seq) = n.get("entries").and_then(|x| x.as_sequence()) {
        for item in seq {
            let fqdn = item
                .get("fqdn")
                .and_then(|x| x.as_scalar())
                .unwrap_or("")
                .to_string();
            let family = item
                .get("family")
                .and_then(|x| x.as_scalar())
                .unwrap_or("")
                .to_string();
            let ports = item
                .get("ports")
                .and_then(|x| x.as_sequence())
                .map(|s| {
                    s.iter()
                        .filter_map(|p| p.as_scalar().and_then(|t| t.parse::<u32>().ok()))
                        .collect()
                })
                .unwrap_or_default();
            let provenance_source_url = nonnull_scalar(item.get("provenance_source_url"));
            let machine_source = nonnull_scalar(item.get("machine_source"));
            let passthrough = item
                .get("passthrough")
                .and_then(|x| x.as_scalar())
                .map(|s| s == "true")
                .unwrap_or(false);
            let evidence = nonnull_scalar(item.get("evidence"));
            let path_scope = build_string_seq(item.get("path_scope"));
            let requires = nonnull_scalar(item.get("requires"));
            pack.entries.push(PackEntry {
                fqdn,
                family,
                ports,
                provenance_source_url,
                machine_source,
                passthrough,
                evidence,
                path_scope,
                requires,
            });
        }
    }
    pack
}

/// Scalar that treats the YAML `null` token (and the empty string) as `None`.
fn nonnull_scalar(node: Option<&YamlNode>) -> Option<String> {
    let s = node?.as_scalar()?;
    if s.is_empty() || s == "null" || s == "~" {
        None
    } else {
        Some(s.to_string())
    }
}

fn build_allowlist(node: Option<&YamlNode>) -> Vec<AllowEntry> {
    let mut out = Vec::new();
    let Some(seq) = node.and_then(|n| n.as_sequence()) else {
        return out;
    };
    for item in seq {
        // Accept either `- domain` (scalar) or `- domain: x` (mapping).
        let domain = item.as_scalar().map(|s| s.to_string()).or_else(|| {
            item.get("domain")
                .and_then(|x| x.as_scalar())
                .map(|s| s.to_string())
        });
        if let Some(d) = domain {
            if !d.is_empty() {
                out.push(AllowEntry { domain: d });
            }
        }
    }
    out
}

fn build_blocklist(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> Vec<BlockEntry> {
    let mut out = Vec::new();
    let Some(seq) = node.and_then(|n| n.as_sequence()) else {
        return out;
    };
    for (i, item) in seq.iter().enumerate() {
        let domain = item
            .get("domain")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        if domain.is_empty() {
            continue;
        }
        let reason = nonnull_scalar(item.get("reason"));
        let rung = match item.get("rung").and_then(|x| x.as_scalar()) {
            Some(s) => match Rung::parse(s) {
                Ok(r) => Some(r),
                Err(mut e) => {
                    e.path = format!("blocklist[{i}].rung");
                    errs.push(e);
                    None
                }
            },
            None => None,
        };
        out.push(BlockEntry {
            domain,
            reason,
            rung,
        });
    }
    out
}

fn build_string_seq(node: Option<&YamlNode>) -> Vec<String> {
    node.and_then(|n| n.as_sequence())
        .map(|s| {
            s.iter()
                .filter_map(|x| x.as_scalar().map(|t| t.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn build_escape_hatches(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> Vec<EscapeHatch> {
    let mut out = Vec::new();
    let Some(n) = node else { return out };
    let Some(seq) = n.get("catalog").and_then(|x| x.as_sequence()) else {
        return out;
    };
    for (i, item) in seq.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        let protocol = item
            .get("protocol")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        let host = item
            .get("host")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        let port = match item.get("port").and_then(|x| x.as_scalar()) {
            Some(s) => match s.parse::<u32>() {
                Ok(p) => p,
                Err(_) => {
                    errs.push(PolicyError::new(
                        PolicyErrorCode::BadValue,
                        format!("escape_hatches.catalog[{i}].port"),
                        format!("expected a port number, got {s:?}"),
                    ));
                    0
                }
            },
            None => 0,
        };
        let scope = item
            .get("scope")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        let approval = item
            .get("approval")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        out.push(EscapeHatch {
            id,
            protocol,
            host,
            port,
            scope,
            approval,
        });
    }
    out
}

fn build_services(node: Option<&YamlNode>) -> Vec<ServiceEntry> {
    let mut out = Vec::new();
    let Some(seq) = node.and_then(|n| n.as_sequence()) else {
        return out;
    };
    for item in seq {
        let service = item
            .get("service")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        if service.is_empty() {
            continue;
        }
        let hosts = build_string_seq(item.get("hosts"));
        let (credential_location, credential_name) = match item.get("credential") {
            Some(cred) => (
                cred.get("location")
                    .and_then(|x| x.as_scalar())
                    .unwrap_or("")
                    .to_string(),
                cred.get("name")
                    .and_then(|x| x.as_scalar())
                    .unwrap_or("")
                    .to_string(),
            ),
            None => (String::new(), String::new()),
        };
        out.push(ServiceEntry {
            service,
            hosts,
            credential_location,
            credential_name,
        });
    }
    out
}

fn build_kv(node: Option<&YamlNode>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(YamlNode::Mapping(entries)) = node {
        for (k, v) in entries {
            if let Some(s) = v.as_scalar() {
                m.insert(k.clone(), s.to_string());
            } else if let YamlNode::Mapping(inner) = v {
                // Flatten one nesting level (e.g. limit.deny_window.cron) into a
                // dotted key so the opaque selector captures structured limits.
                for (ik, iv) in inner {
                    if let Some(s) = iv.as_scalar() {
                        m.insert(format!("{k}.{ik}"), s.to_string());
                    }
                }
            }
        }
    }
    m
}

fn build_guardrails(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> Vec<GuardrailRule> {
    let mut out = Vec::new();
    let Some(seq) = node.and_then(|n| n.as_sequence()) else {
        return out;
    };
    for (i, item) in seq.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        let class = match item.get("class").and_then(|x| x.as_scalar()) {
            Some(s) => match GuardrailClass::parse(s) {
                Ok(c) => c,
                Err(mut e) => {
                    e.path = format!("guardrails[{i}].class");
                    errs.push(e);
                    continue;
                }
            },
            None => {
                errs.push(PolicyError::new(
                    PolicyErrorCode::BadGuardrailClass,
                    format!("guardrails[{i}].class"),
                    "missing required `class`",
                ));
                continue;
            }
        };
        // (a) MANDATORY rung on every guardrail rule (§7 (a), D53). Absence is a
        // parse-time rejection — the rung field is non-optional in the type.
        let rung = match item.get("rung").and_then(|x| x.as_scalar()) {
            Some(s) => match Rung::parse(s) {
                Ok(r) => r,
                Err(mut e) => {
                    e.path = format!(
                        "guardrails[{}].rung",
                        if id.is_empty() {
                            i.to_string()
                        } else {
                            id.clone()
                        }
                    );
                    errs.push(e);
                    continue;
                }
            },
            None => {
                errs.push(PolicyError::new(
                    PolicyErrorCode::MissingRung,
                    format!(
                        "guardrails[{}].rung",
                        if id.is_empty() {
                            i.to_string()
                        } else {
                            id.clone()
                        }
                    ),
                    format!(
                        "guardrail rule (rule_id={:?}) is missing its mandatory rung (D53: every \
                         guardrail rule declares a rung)",
                        id
                    ),
                ));
                continue;
            }
        };
        let match_ = build_kv(item.get("match"));
        let limit = build_kv(item.get("limit"));
        let ttl = item.get("ttl").and_then(|x| x.as_scalar()).and_then(|s| {
            if s == "null" || s.is_empty() {
                None
            } else {
                s.parse::<u32>().ok()
            }
        });
        out.push(GuardrailRule {
            id,
            class,
            match_,
            limit,
            rung,
            ttl,
        });
    }
    out
}

fn build_content(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> ContentConfig {
    let mut c = ContentConfig::default();
    let Some(n) = node else { return c };
    if let Some(generic) = n.get("generic") {
        c.fail_open = generic
            .get("fail_open")
            .and_then(|x| x.as_scalar())
            .map(|s| s == "true")
            .unwrap_or(false);
        c.ruleset_version = generic
            .get("ruleset_version")
            .and_then(|x| x.as_scalar())
            .unwrap_or("")
            .to_string();
        if let Some(rules) = generic.get("rules").and_then(|x| x.as_sequence()) {
            for (i, rule) in rules.iter().enumerate() {
                let id = rule
                    .get("id")
                    .and_then(|x| x.as_scalar())
                    .unwrap_or("")
                    .to_string();
                let regex = rule
                    .get("regex")
                    .and_then(|x| x.as_scalar())
                    .unwrap_or("")
                    .to_string();
                let keywords = build_string_seq(rule.get("keywords"));
                let secret_group = rule
                    .get("secret_group")
                    .and_then(|x| x.as_scalar())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let entropy = rule
                    .get("entropy")
                    .and_then(|x| x.as_scalar())
                    .and_then(|s| {
                        if s == "null" || s.is_empty() {
                            None
                        } else {
                            s.parse::<u32>().ok()
                        }
                    });
                let rung = match rule.get("rung").and_then(|x| x.as_scalar()) {
                    Some(s) => match Rung::parse(s) {
                        Ok(r) => r,
                        Err(mut e) => {
                            e.path = format!(
                                "content.generic.rules[{}].rung",
                                if id.is_empty() {
                                    i.to_string()
                                } else {
                                    id.clone()
                                }
                            );
                            errs.push(e);
                            // default to the cap so validate_layer still runs cleanly on this field.
                            Rung::BlockLog
                        }
                    },
                    None => {
                        errs.push(PolicyError::new(
                            PolicyErrorCode::MissingRung,
                            format!(
                                "content.generic.rules[{}].rung",
                                if id.is_empty() {
                                    i.to_string()
                                } else {
                                    id.clone()
                                }
                            ),
                            "generic content rule is missing its rung",
                        ));
                        Rung::BlockLog
                    }
                };
                c.generic_rules.push(GenericContentRule {
                    id,
                    regex,
                    keywords,
                    secret_group,
                    entropy,
                    rung,
                });
            }
        }
    }
    if let Some(keyed) = n.get("keyed") {
        let forbidden = keyed
            .get("forbidden_default_rung")
            .and_then(|x| x.as_scalar())
            .and_then(|s| Rung::parse(s).ok())
            .unwrap_or(Rung::SuspendAsk);
        let issued = keyed
            .get("issued_wrong_destination_rung")
            .and_then(|x| x.as_scalar())
            .and_then(|s| Rung::parse(s).ok())
            .unwrap_or(Rung::BlockLog);
        c.keyed = Some(KeyedContent {
            forbidden_default_rung: forbidden,
            issued_wrong_destination_rung: issued,
        });
    }
    c
}

fn build_ask(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> AskConfig {
    let mut a = AskConfig::default();
    let Some(n) = node else { return a };
    a.unknown_domain = n
        .get("unknown_domain")
        .and_then(|x| x.as_scalar())
        .unwrap_or("ask")
        .to_string();
    a.unattended_downgrade = n
        .get("unattended_downgrade")
        .and_then(|x| x.as_scalar())
        .unwrap_or("block")
        .to_string();
    if let Some(att) = n.get("attendedness") {
        if let Some(v) = parse_u32_field(
            att,
            "activity_window_minutes",
            "ask.attendedness.activity_window_minutes",
            errs,
        ) {
            a.attendedness.activity_window_minutes = v;
        }
    }
    a
}

fn build_ipv6(node: Option<&YamlNode>, errs: &mut Vec<PolicyError>) -> Ipv6Config {
    let mut c = Ipv6Config::default();
    let Some(n) = node else { return c };
    if let Some(s) = n.get("phase").and_then(|x| x.as_scalar()) {
        match Ipv6Phase::parse(s) {
            Ok(p) => c.phase = p,
            Err(e) => errs.push(e),
        }
    }
    c.synthetic_a_pool = nonnull_scalar(n.get("synthetic_a_pool"));
    c
}

#[cfg(test)]
mod tests;

// ─────────────────────────────────────────────────────────────────────────────
// Additive coverage for the D71 authored-SOA boundary-zone (a new optional POL-1
// `dns.boundary_zone` field). Lives in this file (not the §7 `tests` module) so the
// pre-existing POL-1 suite stays byte-identical: this is a NEW, additive field, so
// its proof is additive too. The default-preservation case is what makes the field
// frozen-additive — every fixture that never names `boundary_zone` composes exactly
// as before.
#[cfg(test)]
mod boundary_zone_tests {
    use super::*;

    /// The smallest valid POL-1 layer (required `layer` + `posture` only), with an
    /// optional `dns:` block whose body is `extra`.
    fn layer_with_dns(extra: &str) -> String {
        format!("schema_version: pol1/v0\nlayer: system-baseline\nposture: standard\ndns:\n{extra}")
    }

    #[test]
    fn boundary_zone_default_is_the_working_name() {
        // The constant pins the D71 working name.
        assert_eq!(DEFAULT_BOUNDARY_ZONE, "boundary.");
        // And `DnsConfig::default()` materializes it.
        assert_eq!(DnsConfig::default().boundary_zone, "boundary.");
    }

    #[test]
    fn absent_boundary_zone_falls_back_to_the_default() {
        // A layer whose dns block names ONLY negative_ttl (the pre-existing shape)
        // must materialize the working-name boundary zone — proving every existing
        // fixture is unchanged in behaviour.
        let doc = layer_with_dns("  negative_ttl: 5\n");
        let layer = parse_layer(&doc).expect("clean layer parses");
        assert_eq!(layer.dns.negative_ttl, 5);
        assert_eq!(
            layer.dns.boundary_zone, DEFAULT_BOUNDARY_ZONE,
            "an omitted dns.boundary_zone falls back to the default working name"
        );
    }

    #[test]
    fn no_dns_block_at_all_still_defaults_the_boundary_zone() {
        let doc = "schema_version: pol1/v0\nlayer: org\nposture: standard\n";
        let layer = parse_layer(doc).expect("clean layer parses");
        assert_eq!(layer.dns.boundary_zone, DEFAULT_BOUNDARY_ZONE);
    }

    #[test]
    fn explicit_boundary_zone_overrides_the_default() {
        let doc = layer_with_dns("  negative_ttl: 5\n  boundary_zone: example.test.\n");
        let layer = parse_layer(&doc).expect("clean layer parses");
        assert_eq!(
            layer.dns.boundary_zone, "example.test.",
            "an explicit dns.boundary_zone is the policy-pushed authored-SOA suffix"
        );
        // The rest of the dns block is untouched by the additive field.
        assert_eq!(layer.dns.negative_ttl, 5);
    }

    #[test]
    fn empty_boundary_zone_scalar_keeps_the_default() {
        // A blank value is not a meaningful override (mirrors the reader's empty-string
        // skip), so it falls back rather than authoring an empty SOA suffix.
        let doc = layer_with_dns("  boundary_zone: \"\"\n");
        let layer = parse_layer(&doc).expect("clean layer parses");
        assert_eq!(layer.dns.boundary_zone, DEFAULT_BOUNDARY_ZONE);
    }
}
