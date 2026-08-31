//! role/v0 machine validator — parse-time rejection rules + `role_content_hash`
//! (doc 18 §5, §7, §11; ratified D89–D96).
//!
//! **Home (doc 18 §5).** The role *document* home is `roles/SCHEMA.md` + the four
//! built-in YAMLs. The machine-validated schema and its validation code path live
//! HERE in `policy-core`, by the one rule doc 18 §5 names: "if role validation ever
//! needs `policy-core` (it does, for axis (c)'s projection), the validation code
//! path lives where POL-1 validation lives." Axis (c) — the role's `policy` block —
//! compiles to a POL-1 *session-layer* document, so the rung-cap checks DELEGATE to
//! the doc 13 §7 suite in [`ds_contracts::pol1`] rather than re-deriving a parallel
//! ladder ([`validate_role`] projects the role's guardrails into a
//! [`ds_contracts::pol1::PolicyLayer`] and calls
//! [`ds_contracts::pol1::validate_layer`] — ONE rung-cap machinery, not two).
//!
//! **Stdlib-only (the workspace dep-free fence; same posture as `pol1.rs`'s
//! hand-rolled reader and `snapshot_verify.rs`'s hand-rolled SHA-256).** There is
//! NO serde / serde_yaml here. The reader below ([`parse_role`]) is a minimal,
//! purpose-built reader for the `role/v0` document subset the SCHEMA.md shapes —
//! two-space-indented mappings, `- ` block-sequence items, inline `[a, b]` and
//! `{k: v}` flow collections, scalars, and `#` comments — and rejects everything
//! else as a [`RoleErrorCode::Syntax`].
//!
//! **The parse-time rejection set (doc 18 §11 schema-validation suite):**
//!
//! - (a) all four built-ins round-trip parse→validate (`tests/role_validation.rs`);
//! - (b) a role embedding **raw credential material** is rejected AT PARSE TIME
//!   ([`RoleErrorCode::CredentialMaterial`], doc 18 §5/§8: axis (d) is a TEMPLATE
//!   only, never material — D39);
//! - (b') a role declaring a **pass-through entry** is rejected at parse time
//!   ([`RoleErrorCode::PassThrough`], doc 18 §9 point 3: the pass-through list stays
//!   empty-by-default — a role cannot add pass-through entries at all, D74);
//! - (c) a guardrail rule **violating the rung caps** is rejected by DELEGATING to
//!   the doc 13 §7 suite (the generic-content-rule `block+log` cap, D73) — the
//!   error rides through as [`RoleErrorCode::RungCap`] carrying the underlying
//!   [`ds_contracts::pol1::PolicyError`] detail.
//!
//! **`role_content_hash` (doc 18 §7; doc 15 OQ3 / doc 13 OQ2 — ONE canonicalization
//! spec, not two).** [`role_content_hash`] serializes the role document to the
//! produce-once RFC 8785 (JCS) canonical-JSON payload under the pinned mapping (keys
//! sorted lexicographically by UTF-8 bytes, no insignificant whitespace, no floats,
//! integers bare, strings JCS-escaped) and hashes those exact bytes with the SAME
//! hand-rolled [`ds_contracts::snapshot_verify::sha256`] the PolicySnapshot
//! `content_hash` uses. The role document hashes on the IDENTICAL path the orch8
//! `role_document` golden fixture pins (doc 13 §5.1 "One spec, two documents"); the
//! cross-check lives in `tests/role_validation.rs`.

use ds_contracts::pol1::{
    self, ContentConfig, GenericContentRule, GuardrailClass, GuardrailRule, PolicyLayer,
    Rung as PolRung,
};
use ds_contracts::snapshot_verify::{content_hash_hex, sha256, ContentHash};
use std::collections::BTreeMap;

/// The frozen `role/v0` schema-version tag (doc 18 §5 `schema_version: role/v0`).
pub const SCHEMA_VERSION_V0: &str = "role/v0";

/// The four built-in role catalog keys (doc 18 §5). A `name` outside this set is
/// NOT rejected (orgs add custom roles via the catalog), but the round-trip suite
/// pins exactly these four.
pub const BUILTIN_ROLE_NAMES: [&str; 4] =
    ["default", "developer", "researcher", "security-engineer"];

// ─────────────────────────────────────────────────────────────────────────────
// Errors — structured `{code, path, detail}` (mirrors the doc 13 §8.1 shape the
// POL-1 validator uses). The error-message SHAPE is free latitude; the SET of
// conditions that must reject is frozen by doc 18 §11. Collect-all.
// ─────────────────────────────────────────────────────────────────────────────

/// The class of a role parse / validation rejection (doc 18 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoleErrorCode {
    /// The reader could not interpret the document structure.
    Syntax,
    /// `schema_version` is absent or not `role/v0`.
    BadSchemaVersion,
    /// A required field (`name`, `version`) is absent or malformed.
    MissingField,
    /// A `posture` token outside `locked|standard|open`.
    BadPosture,
    /// A `credentials.scope_template.mode` outside `read-only|read-write`.
    BadCredentialMode,
    /// The role embeds **raw credential material** — a key/secret/token/header
    /// value where only a scope TEMPLATE is permitted (doc 18 §5/§8, D39).
    CredentialMaterial,
    /// The role declares a **pass-through entry** — forbidden outright; the
    /// pass-through list stays empty-by-default (doc 18 §9 point 3, D74).
    PassThrough,
    /// A guardrail rule violates the rung caps (delegated to the doc 13 §7 suite,
    /// D73). The `detail` carries the underlying POL-1 rejection text.
    RungCap,
    /// An `image.layers[]` / `skills.install[]` entry is inline content rather
    /// than an artifact reference (doc 18 §5 validation rule 1).
    InlineArtifact,
}

/// A single structured role rejection (doc 18 §11; `{code, path, detail}` triple).
/// `detail` is human-readable and, where the rule requires it, NAMES the offending
/// value (e.g. the credential field key, or the underlying POL-1 rung-cap text).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleError {
    /// The rejection class.
    pub code: RoleErrorCode,
    /// Dotted path into the offending field.
    pub path: String,
    /// Human-readable detail.
    pub detail: String,
}

impl RoleError {
    fn new(code: RoleErrorCode, path: impl Into<String>, detail: impl Into<String>) -> RoleError {
        RoleError {
            code,
            path: path.into(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for RoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?} @ {}] {}", self.code, self.path, self.detail)
    }
}

impl std::error::Error for RoleError {}

/// A collect-all bundle of role rejections (the doc 13 §8.1 collect-all posture: a
/// role author sees every violation in one pass). A non-empty bundle means the
/// document is rejected; an empty bundle is never constructed (parse returns `Ok`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleErrors(pub Vec<RoleError>);

impl std::fmt::Display for RoleErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} role/v0 validation error(s):", self.0.len())?;
        for e in &self.0 {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RoleErrors {}

impl RoleErrors {
    /// Whether any rejection of the given code is present (test/consumer helper).
    #[must_use]
    pub fn has(&self, code: RoleErrorCode) -> bool {
        self.0.iter().any(|e| e.code == code)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema enums (doc 18 §5). Field names FREE; the token sets / shapes are FROZEN.
// ─────────────────────────────────────────────────────────────────────────────

/// The role's axis (c) network posture (doc 18 §5 `policy.posture`). The token set
/// is the doc 13 §2 posture ladder; a role posture may be NARROWER than the org
/// default, never effectively wider (doc 18 §9). Reuses the same three tokens
/// [`ds_contracts::pol1::Posture`] freezes — one posture vocabulary, not two.
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
    fn parse(s: &str) -> Result<Posture, RoleError> {
        match s {
            "locked" => Ok(Posture::Locked),
            "standard" => Ok(Posture::Standard),
            "open" => Ok(Posture::Open),
            other => Err(RoleError::new(
                RoleErrorCode::BadPosture,
                "policy.posture",
                format!("unknown posture {other:?} (locked|standard|open)"),
            )),
        }
    }
}

/// The credential-scope template mode (doc 18 §5 `credentials.scope_template.mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialMode {
    /// `read-only`.
    ReadOnly,
    /// `read-write`.
    ReadWrite,
}

impl CredentialMode {
    fn parse(s: &str) -> Result<CredentialMode, RoleError> {
        match s {
            "read-only" => Ok(CredentialMode::ReadOnly),
            "read-write" => Ok(CredentialMode::ReadWrite),
            other => Err(RoleError::new(
                RoleErrorCode::BadCredentialMode,
                "credentials.scope_template.mode",
                format!("unknown credential mode {other:?} (read-only|read-write)"),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema types (doc 18 §5 field inventory). This tree holds COMPOSITIONS, never
// CONTENTS — every axis references artifacts other workstreams own.
// ─────────────────────────────────────────────────────────────────────────────

/// One axis (c) guardrail rule, in the doc 13 §3 reference match shape (the
/// security-engineer role's `se-no-write-egress` is the worked example). These
/// project into a POL-1 session-layer document so the rung-cap delegation
/// ([`validate_role`]) is the doc 13 §7 suite, not a re-implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleGuardrail {
    /// `id`.
    pub id: String,
    /// `class` — one of D52's five classes (doc 13 §2).
    pub class: GuardrailClass,
    /// `match` — opaque selector key→value pairs.
    pub match_: BTreeMap<String, String>,
    /// `limit` — opaque limit key→value pairs.
    pub limit: BTreeMap<String, String>,
    /// `rung` — the D53 rung; mandatory on every guardrail rule (doc 13 §7 (a)).
    pub rung: PolRung,
}

/// A widening-request allowlist entry (doc 18 §9 / `researcher.yaml`). INERT until
/// catalog ratification; the validator records the shape, it does not admit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowlistRequest {
    /// `fqdn` — exact FQDN (stricter than D74's vendor-wildcard exception).
    pub fqdn: String,
    /// `ports`.
    pub ports: Vec<u32>,
    /// `evidence` — provenance for the ratification review (doc 13 §1 rule 4).
    pub evidence: Option<String>,
}

/// The axis (c) policy block (doc 18 §5 `policy`). Compiles to a POL-1 session-layer
/// document; the role may NARROW but never effectively widen (doc 18 §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePolicy {
    /// `posture`.
    pub posture: Posture,
    /// `pack_families` — tier-flip requests; widening => inert until ratification.
    pub pack_families: BTreeMap<String, String>,
    /// `allowlist` — widening requests; inert until ratification (doc 18 §9).
    pub allowlist: Vec<AllowlistRequest>,
    /// `guardrails` — D52-class rules; rung caps apply (doc 13 §7).
    pub guardrails: Vec<RoleGuardrail>,
}

/// The credential-scope TEMPLATE (doc 18 §5 `credentials.scope_template`). NULLABLE:
/// `None` = no narrowing (full envelope, the `default` role); `Some` with an empty
/// `services` = empty intersection, mint nothing (the `researcher` role). NEVER
/// credential material (D39) — that is rejected at parse before this is built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeTemplate {
    /// `services` — subset of the org `services[]` registry keys.
    pub services: Vec<String>,
    /// `mode`.
    pub mode: CredentialMode,
}

/// A parsed, validated `role/v0` document (doc 18 §5). Holds compositions, never
/// contents; every axis is a reference or a template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleDocument {
    /// `schema_version` (frozen `role/v0`).
    pub schema_version: String,
    /// `name` — catalog key.
    pub name: String,
    /// `version` — content identifier (doc 13 §1 rule 3 analog), never a second
    /// version namespace (doc 18 §7).
    pub version: String,
    /// `description`.
    pub description: String,
    /// `image.layers[]` — artifact refs (axis (a)); never inline content.
    pub image_layers: Vec<String>,
    /// `skills.install[]` — artifact refs (axis (b)); never inline content.
    pub skills_install: Vec<String>,
    /// `policy` — axis (c).
    pub policy: RolePolicy,
    /// `credentials.scope_template` — axis (d); `None` = no narrowing.
    pub scope_template: Option<ScopeTemplate>,
    /// `runtime.entrypoint_config_overlay_ref` — axis (e); opaque, `None` = absent.
    pub runtime_overlay_ref: Option<String>,
}

impl RoleDocument {
    /// The `(name, version, role_content_hash-hex)` triple pinned into the
    /// never-recycled session record at create (doc 18 §6 step 1–2, §7).
    #[must_use]
    pub fn identity_triple(&self) -> (String, String, String) {
        (
            self.name.clone(),
            self.version.clone(),
            content_hash_hex(&self.role_content_hash()),
        )
    }

    /// `role_content_hash` (doc 18 §7): SHA-256 over the produce-once RFC 8785 (JCS)
    /// canonical-JSON serialization of the role document — the SAME canonicalization
    /// machinery the PolicySnapshot `content_hash` uses (doc 15 OQ3 / doc 13 OQ2,
    /// "one canonicalization spec, not two"). The bytes are formed ONCE here and
    /// hashed with the shared [`ds_contracts::snapshot_verify::sha256`]; a consumer
    /// VERIFIES these bytes, never re-canonicalizes (doc 13 §5.1).
    #[must_use]
    pub fn role_content_hash(&self) -> ContentHash {
        sha256(self.canonical_payload().as_bytes())
    }

    /// The produce-once RFC 8785 (JCS) canonical-JSON payload for this role
    /// document (doc 13 §5.1 pinned mapping). `pub` so the catalog resolver and the
    /// determinism test can pin the exact bytes (the orch8 `role_document` golden
    /// fixture hashes on this same path).
    #[must_use]
    pub fn canonical_payload(&self) -> String {
        self.to_canonical_json().to_jcs()
    }

    /// Project the role document into a [`JcsValue`] tree with the canonical field
    /// shape. Absent/null axes are OMITTED (absent ≡ default ≡ omitted, doc 13
    /// §5.1 F6) so an unset optional field never churns the hash; `scope_template:
    /// null` is therefore distinct from `scope_template: {services: [], ...}` only
    /// when the latter is materialized.
    fn to_canonical_json(&self) -> JcsValue {
        let mut obj: Vec<(String, JcsValue)> = Vec::new();
        obj.push((
            "schema_version".into(),
            JcsValue::Str(self.schema_version.clone()),
        ));
        obj.push(("name".into(), JcsValue::Str(self.name.clone())));
        obj.push(("version".into(), JcsValue::Str(self.version.clone())));
        if !self.description.is_empty() {
            obj.push((
                "description".into(),
                JcsValue::Str(self.description.clone()),
            ));
        }
        if !self.image_layers.is_empty() {
            obj.push((
                "image_layers".into(),
                JcsValue::Arr(
                    self.image_layers
                        .iter()
                        .cloned()
                        .map(JcsValue::Str)
                        .collect(),
                ),
            ));
        }
        if !self.skills_install.is_empty() {
            obj.push((
                "skills_install".into(),
                JcsValue::Arr(
                    self.skills_install
                        .iter()
                        .cloned()
                        .map(JcsValue::Str)
                        .collect(),
                ),
            ));
        }
        obj.push(("policy".into(), self.policy.to_canonical_json()));
        if let Some(t) = &self.scope_template {
            obj.push(("scope_template".into(), t.to_canonical_json()));
        }
        if let Some(r) = &self.runtime_overlay_ref {
            obj.push(("runtime_overlay_ref".into(), JcsValue::Str(r.clone())));
        }
        JcsValue::Obj(obj)
    }
}

impl RolePolicy {
    fn to_canonical_json(&self) -> JcsValue {
        let mut obj: Vec<(String, JcsValue)> = Vec::new();
        obj.push((
            "posture".into(),
            JcsValue::Str(
                match self.posture {
                    Posture::Locked => "locked",
                    Posture::Standard => "standard",
                    Posture::Open => "open",
                }
                .into(),
            ),
        ));
        if !self.pack_families.is_empty() {
            // No map<> in the canonical form — emit as a sorted repeated
            // {key,value} list (doc 13 §5.1 F6). BTreeMap already yields keys in
            // sorted order, but build the list explicitly to pin the shape.
            let entries: Vec<JcsValue> = self
                .pack_families
                .iter()
                .map(|(k, v)| {
                    JcsValue::Obj(vec![
                        ("key".into(), JcsValue::Str(k.clone())),
                        ("value".into(), JcsValue::Str(v.clone())),
                    ])
                })
                .collect();
            obj.push(("pack_families".into(), JcsValue::Arr(entries)));
        }
        if !self.allowlist.is_empty() {
            let entries: Vec<JcsValue> = self
                .allowlist
                .iter()
                .map(|a| {
                    let mut m: Vec<(String, JcsValue)> = vec![
                        ("fqdn".into(), JcsValue::Str(a.fqdn.clone())),
                        (
                            "ports".into(),
                            JcsValue::Arr(
                                a.ports.iter().map(|p| JcsValue::Int(*p as i64)).collect(),
                            ),
                        ),
                    ];
                    if let Some(e) = &a.evidence {
                        m.push(("evidence".into(), JcsValue::Str(e.clone())));
                    }
                    JcsValue::Obj(m)
                })
                .collect();
            obj.push(("allowlist".into(), JcsValue::Arr(entries)));
        }
        if !self.guardrails.is_empty() {
            let entries: Vec<JcsValue> = self
                .guardrails
                .iter()
                .map(|g| {
                    let mut m: Vec<(String, JcsValue)> = vec![
                        ("id".into(), JcsValue::Str(g.id.clone())),
                        (
                            "class".into(),
                            JcsValue::Str(guardrail_class_token(g.class).into()),
                        ),
                    ];
                    if !g.match_.is_empty() {
                        m.push(("match".into(), kv_list(&g.match_)));
                    }
                    if !g.limit.is_empty() {
                        m.push(("limit".into(), kv_list(&g.limit)));
                    }
                    m.push(("rung".into(), JcsValue::Str(g.rung.token().into())));
                    JcsValue::Obj(m)
                })
                .collect();
            obj.push(("guardrails".into(), JcsValue::Arr(entries)));
        }
        JcsValue::Obj(obj)
    }
}

impl ScopeTemplate {
    fn to_canonical_json(&self) -> JcsValue {
        JcsValue::Obj(vec![
            (
                "services".into(),
                JcsValue::Arr(self.services.iter().cloned().map(JcsValue::Str).collect()),
            ),
            (
                "mode".into(),
                JcsValue::Str(
                    match self.mode {
                        CredentialMode::ReadOnly => "read-only",
                        CredentialMode::ReadWrite => "read-write",
                    }
                    .into(),
                ),
            ),
        ])
    }
}

fn guardrail_class_token(c: GuardrailClass) -> &'static str {
    match c {
        GuardrailClass::Egress => "egress",
        GuardrailClass::Rate => "rate",
        GuardrailClass::Quota => "quota",
        GuardrailClass::Content => "content",
        GuardrailClass::Credential => "credential",
    }
}

fn kv_list(m: &BTreeMap<String, String>) -> JcsValue {
    // No map<> in the canonical form: a sorted repeated {key,value} list.
    JcsValue::Arr(
        m.iter()
            .map(|(k, v)| {
                JcsValue::Obj(vec![
                    ("key".into(), JcsValue::Str(k.clone())),
                    ("value".into(), JcsValue::Str(v.clone())),
                ])
            })
            .collect(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation — the parse-time rejection set (doc 18 §11), collect-all. The rung-cap
// dimension DELEGATES to the doc 13 §7 suite (no parallel ladder).
// ─────────────────────────────────────────────────────────────────────────────

/// Run the doc 18 §11 structural validators over a parsed role, COLLECTING all
/// rejections. Returns `Ok(())` for a clean role.
///
/// The rung-cap check (c) is NOT re-implemented here: the role's `policy.guardrails`
/// project into a [`PolicyLayer`] and [`ds_contracts::pol1::validate_layer`] — the
/// doc 13 §7 suite — runs over the projection. A `content`-class guardrail above
/// `block+log` is therefore rejected by the SAME machinery POL-1 uses (D73), and any
/// future cap the §7 suite gains applies to roles for free.
///
/// Credential-material and pass-through rejections (b)/(b') are STRUCTURAL — the
/// reader [`parse_role`] rejects them at parse time before this runs (they cannot
/// produce a [`RoleDocument`] at all), so they never reach a composed session.
pub fn validate_role(role: &RoleDocument) -> Result<(), RoleErrors> {
    let mut errs: Vec<RoleError> = Vec::new();

    // (c) Rung caps — delegate to the doc 13 §7 suite. Project the role's
    // guardrails into a POL-1 session-layer document and validate it. A
    // `content`-class role guardrail maps to a generic content rule (the plane the
    // block+log cap governs, D73); other classes carry their mandatory rung (the
    // §7 (a) check the type already enforces).
    let projected = project_to_layer(role);
    if let Err(pol_errs) = pol1::validate_layer(&projected) {
        for e in pol_errs.0 {
            errs.push(RoleError::new(
                RoleErrorCode::RungCap,
                format!("policy.guardrails ({})", e.path),
                format!(
                    "role guardrail rejected by the doc 13 §7 rung-cap suite: {}",
                    e.detail
                ),
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(RoleErrors(errs))
    }
}

/// Project a role's axis (c) into a POL-1 session-layer [`PolicyLayer`] so the
/// rung-cap delegation runs the doc 13 §7 suite over it (doc 18 §5: axis (c)
/// compiles to a session-layer document). `content`-class guardrails become generic
/// content rules (the block+log-capped plane); all classes also ride as guardrail
/// rules so their mandatory rung is type-checked. Only the fields the §7 rung-cap
/// suite inspects are populated — this is a validation projection, not the real
/// session-layer compiler (doc 15 owns that).
fn project_to_layer(role: &RoleDocument) -> PolicyLayer {
    let mut generic_rules: Vec<GenericContentRule> = Vec::new();
    let mut guardrails: Vec<GuardrailRule> = Vec::new();
    for g in &role.policy.guardrails {
        guardrails.push(GuardrailRule {
            id: g.id.clone(),
            class: g.class,
            match_: g.match_.clone(),
            limit: g.limit.clone(),
            rung: g.rung,
            ttl: None,
        });
        if g.class == GuardrailClass::Content {
            // A content-class role guardrail is a generic content rule — the plane
            // the §7 block+log cap governs (D73). Carry its rung so an over-cap
            // rung (suspend+ask / kill+snapshot) is rejected by validate_layer.
            generic_rules.push(GenericContentRule {
                id: g.id.clone(),
                regex: String::new(),
                keywords: Vec::new(),
                secret_group: 0,
                entropy: None,
                rung: g.rung,
            });
        }
    }

    PolicyLayer {
        schema_version: pol1::SCHEMA_VERSION_V0.to_string(),
        layer: pol1::Layer::Session,
        posture: match role.policy.posture {
            Posture::Locked => pol1::Posture::Locked,
            Posture::Standard => pol1::Posture::Standard,
            Posture::Open => pol1::Posture::Open,
        },
        admission: pol1::AdmissionTimers::default(),
        dns: pol1::DnsConfig::default(),
        quic: pol1::QuicConfig::default(),
        baseline_pack: pol1::BaselinePack::default(),
        allowlist: Vec::new(),
        blocklist: Vec::new(),
        // The role can NEVER add pass-through entries (doc 18 §9 point 3); the
        // parse-time check rejects any, so the projection is always empty here.
        passthrough: Vec::new(),
        escape_hatches: Vec::new(),
        services: Vec::new(),
        guardrails,
        content: ContentConfig {
            fail_open: false,
            ruleset_version: String::new(),
            generic_rules,
            keyed: None,
        },
        ask: pol1::AskConfig::default(),
        ipv6: pol1::Ipv6Config::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The stdlib-only role/v0 document reader (SCHEMA.md subset). No serde/serde_yaml.
// The parse-time rejections (credential-material, pass-through, schema shape) are
// enforced HERE so a malformed role never produces a RoleDocument at all.
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a `role/v0` document from its YAML-subset text, running the doc 18 §11
/// parse-time rejections (credential-material, pass-through, schema shape) AND the
/// §7 rung-cap delegation. Returns the parsed [`RoleDocument`] on success, or the
/// collect-all bundle of rejections.
///
/// Stdlib only — no serde / serde_yaml (the workspace dep-free fence). The reader
/// understands exactly the `role/v0` block structure and rejects anything else as a
/// [`RoleErrorCode::Syntax`].
pub fn parse_role(text: &str) -> Result<RoleDocument, RoleErrors> {
    let doc = match YamlNode::parse_document(text) {
        Ok(d) => d,
        Err(e) => return Err(RoleErrors(vec![e])),
    };
    let mut errs: Vec<RoleError> = Vec::new();
    let role = build_role(&doc, &mut errs);
    let role = match role {
        Some(r) => r,
        None => return Err(RoleErrors(errs)),
    };
    // The structural validators run regardless so one pass surfaces both shape
    // errors and §7 violations (collect-all).
    match validate_role(&role) {
        Ok(()) => {
            if errs.is_empty() {
                Ok(role)
            } else {
                Err(RoleErrors(errs))
            }
        }
        Err(mut v) => {
            errs.append(&mut v.0);
            Err(RoleErrors(errs))
        }
    }
}

/// The set of credential-material key tokens forbidden anywhere in a role document
/// (doc 18 §5/§8: axis (d) is a TEMPLATE only — never material, D39). A role may
/// carry a `credential.location` / `credential.name` SHAPE in the POL-1 `services`
/// registry, but a role document declaring an actual secret VALUE — a token, key,
/// password, or a populated `Authorization` header — is rejected at parse. The
/// match is on the KEY: any of these keys anywhere in the document is a rejection,
/// because a role document has no legitimate field that carries credential material.
const CREDENTIAL_MATERIAL_KEYS: &[&str] = &[
    "credential",
    "credentials_material",
    "secret",
    "secrets",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "private-key",
    "client_secret",
    "bearer",
    "authorization",
];

fn build_role(doc: &YamlNode, errs: &mut Vec<RoleError>) -> Option<RoleDocument> {
    let map = match doc {
        YamlNode::Mapping(m) => m,
        _ => {
            errs.push(RoleError::new(
                RoleErrorCode::Syntax,
                "",
                "role document root must be a mapping",
            ));
            return None;
        }
    };

    // (b)/(b') The two STRUCTURAL parse-time rejections run FIRST over the whole
    // tree, so a credential-material or pass-through role can never produce a
    // RoleDocument (doc 18 §11). They walk the raw node tree, not the typed
    // projection — the rejection must fire even on a field the typed schema would
    // otherwise ignore.
    scan_forbidden(doc, "", errs);

    let schema_version = scalar(map, "schema_version");
    match &schema_version {
        Some(v) if v == SCHEMA_VERSION_V0 => {}
        other => {
            errs.push(RoleError::new(
                RoleErrorCode::BadSchemaVersion,
                "schema_version",
                format!("schema_version must be {SCHEMA_VERSION_V0:?} (got {other:?})"),
            ));
        }
    }

    let name = match scalar(map, "name") {
        Some(n) if !n.is_empty() => n,
        _ => {
            errs.push(RoleError::new(
                RoleErrorCode::MissingField,
                "name",
                "role name is required (catalog key)",
            ));
            String::new()
        }
    };
    let version = match scalar(map, "version") {
        Some(v) if !v.is_empty() => v,
        _ => {
            errs.push(RoleError::new(
                RoleErrorCode::MissingField,
                "version",
                "role version is required (content identifier)",
            ));
            String::new()
        }
    };
    let description = scalar(map, "description").unwrap_or_default();

    let image_layers = artifact_refs(map, "image", "layers", "images:", errs);
    let skills_install = artifact_refs(map, "skills", "install", "skills:", errs);

    let policy = build_policy(map, errs);
    let scope_template = build_scope_template(map, errs);
    let runtime_overlay_ref = build_runtime_overlay(map);

    // If any blocking shape error fired, do not synthesize a half-built role — the
    // collect-all bundle already carries the reasons. But credential-material /
    // pass-through alone already prevented `Some(..)`? No: those are collected and
    // we still return None so the caller never gets a "valid" role.
    if errs.iter().any(|e| {
        matches!(
            e.code,
            RoleErrorCode::Syntax
                | RoleErrorCode::BadSchemaVersion
                | RoleErrorCode::MissingField
                | RoleErrorCode::BadPosture
                | RoleErrorCode::BadCredentialMode
                | RoleErrorCode::CredentialMaterial
                | RoleErrorCode::PassThrough
                | RoleErrorCode::InlineArtifact
        )
    }) {
        return None;
    }

    Some(RoleDocument {
        schema_version: schema_version.unwrap_or_default(),
        name,
        version,
        description,
        image_layers,
        skills_install,
        policy: policy?,
        scope_template,
        runtime_overlay_ref,
    })
}

/// Walk the whole node tree rejecting (b) credential material and (b') pass-through
/// entries — the two STRUCTURAL parse-time rejections (doc 18 §11). The walk is over
/// the raw YAML node tree by KEY so the rejection fires even on a field the typed
/// schema would discard.
fn scan_forbidden(node: &YamlNode, path: &str, errs: &mut Vec<RoleError>) {
    match node {
        YamlNode::Mapping(members) => {
            for (k, v) in members {
                let key_lc = k.to_ascii_lowercase();
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };

                // (b') Pass-through is forbidden outright (doc 18 §9 point 3, D74).
                if key_lc == "passthrough" || key_lc == "pass_through" || key_lc == "pass-through" {
                    // A `passthrough: []` empty list is STILL a declared pass-through
                    // surface a role may not introduce — the list stays empty by the
                    // POL-1 floor, not by a role re-declaring it. Reject any presence.
                    errs.push(RoleError::new(
                        RoleErrorCode::PassThrough,
                        child_path.clone(),
                        "a role may not declare a pass-through entry — the pass-through list \
                         stays empty-by-default (doc 18 §9 point 3, D74); roles cannot add \
                         pass-through at all",
                    ));
                }

                // (b) Raw credential material is forbidden anywhere (doc 18 §5/§8,
                // D39). The credential-scope TEMPLATE lives under
                // `credentials.scope_template` (services + mode only); a `credential`
                // / `secret` / `token` / `authorization` key anywhere is material.
                if CREDENTIAL_MATERIAL_KEYS.contains(&key_lc.as_str()) {
                    errs.push(RoleError::new(
                        RoleErrorCode::CredentialMaterial,
                        child_path.clone(),
                        format!(
                            "role document embeds credential material at key {k:?} — axis (d) \
                             is a scope TEMPLATE only (services + mode), never material (doc 18 \
                             §5/§8, D39)"
                        ),
                    ));
                }

                scan_forbidden(v, &child_path, errs);
            }
        }
        YamlNode::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                scan_forbidden(item, &format!("{path}[{i}]"), errs);
            }
        }
        YamlNode::Scalar(_) => {}
    }
}

fn build_policy(map: &[(String, YamlNode)], errs: &mut Vec<RoleError>) -> Option<RolePolicy> {
    let policy_node = get(map, "policy");
    let pmap = match policy_node {
        Some(YamlNode::Mapping(m)) => m.as_slice(),
        Some(_) => {
            errs.push(RoleError::new(
                RoleErrorCode::Syntax,
                "policy",
                "policy must be a mapping",
            ));
            return None;
        }
        // Absent policy block => default-no-op posture. (default.yaml always
        // carries one, but be lenient on absence.)
        None => {
            return Some(RolePolicy {
                posture: Posture::Standard,
                pack_families: BTreeMap::new(),
                allowlist: Vec::new(),
                guardrails: Vec::new(),
            })
        }
    };

    let posture = match scalar(pmap, "posture") {
        Some(p) => match Posture::parse(&p) {
            Ok(v) => v,
            Err(e) => {
                errs.push(e);
                Posture::Standard
            }
        },
        None => Posture::Standard,
    };

    let pack_families = flow_or_block_map(pmap, "pack_families");

    let allowlist = build_allowlist(pmap, errs);
    let guardrails = build_guardrails(pmap, errs);

    Some(RolePolicy {
        posture,
        pack_families,
        allowlist,
        guardrails,
    })
}

fn build_allowlist(
    pmap: &[(String, YamlNode)],
    errs: &mut Vec<RoleError>,
) -> Vec<AllowlistRequest> {
    let mut out = Vec::new();
    let node = match get(pmap, "allowlist") {
        Some(YamlNode::Sequence(items)) => items,
        _ => return out,
    };
    for (i, item) in node.iter().enumerate() {
        let m = match item {
            YamlNode::Mapping(m) => m.as_slice(),
            // A bare-string allowlist entry (doc 13 domain-keyed shape) is accepted
            // as `{fqdn: <s>}`.
            YamlNode::Scalar(s) => {
                out.push(AllowlistRequest {
                    fqdn: s.clone(),
                    ports: Vec::new(),
                    evidence: None,
                });
                continue;
            }
            YamlNode::Sequence(_) => {
                errs.push(RoleError::new(
                    RoleErrorCode::Syntax,
                    format!("policy.allowlist[{i}]"),
                    "allowlist entry must be a mapping or a domain string",
                ));
                continue;
            }
        };
        let fqdn = scalar(m, "fqdn").unwrap_or_default();
        let ports = scalar_int_list(m, "ports");
        let evidence = scalar(m, "evidence");
        out.push(AllowlistRequest {
            fqdn,
            ports,
            evidence,
        });
    }
    out
}

fn build_guardrails(pmap: &[(String, YamlNode)], errs: &mut Vec<RoleError>) -> Vec<RoleGuardrail> {
    let mut out = Vec::new();
    let node = match get(pmap, "guardrails") {
        Some(YamlNode::Sequence(items)) => items,
        _ => return out,
    };
    for (i, item) in node.iter().enumerate() {
        let m = match item {
            YamlNode::Mapping(m) => m.as_slice(),
            _ => {
                errs.push(RoleError::new(
                    RoleErrorCode::Syntax,
                    format!("policy.guardrails[{i}]"),
                    "guardrail entry must be a mapping",
                ));
                continue;
            }
        };
        let id = scalar(m, "id").unwrap_or_else(|| format!("guardrail-{i}"));
        let class = match scalar(m, "class") {
            Some(c) => match GuardrailClass::parse(&c) {
                Ok(v) => v,
                Err(e) => {
                    errs.push(RoleError::new(
                        RoleErrorCode::Syntax,
                        format!("policy.guardrails[{i}].class"),
                        e.detail,
                    ));
                    continue;
                }
            },
            None => {
                errs.push(RoleError::new(
                    RoleErrorCode::Syntax,
                    format!("policy.guardrails[{i}].class"),
                    "guardrail rule is missing its class",
                ));
                continue;
            }
        };
        // rung is MANDATORY on a guardrail rule (doc 13 §7 (a)); absence is a parse
        // rejection. We surface it as a Syntax error here (the type below is
        // non-optional), which the §7 suite would also reject.
        let rung = match scalar(m, "rung") {
            Some(r) => match PolRung::parse(&r) {
                Ok(v) => v,
                Err(e) => {
                    errs.push(RoleError::new(
                        RoleErrorCode::RungCap,
                        format!("policy.guardrails[{i}].rung"),
                        e.detail,
                    ));
                    continue;
                }
            },
            None => {
                errs.push(RoleError::new(
                    RoleErrorCode::RungCap,
                    format!("policy.guardrails[{i}].rung"),
                    format!(
                        "guardrail rule (rule_id={id:?}) is missing its mandatory rung \
                         (doc 13 §7 (a), D53)"
                    ),
                ));
                continue;
            }
        };
        let match_ = flow_or_block_map(m, "match");
        let limit = flow_or_block_map(m, "limit");
        out.push(RoleGuardrail {
            id,
            class,
            match_,
            limit,
            rung,
        });
    }
    out
}

fn build_scope_template(
    map: &[(String, YamlNode)],
    errs: &mut Vec<RoleError>,
) -> Option<ScopeTemplate> {
    let creds = match get(map, "credentials") {
        Some(YamlNode::Mapping(m)) => m.as_slice(),
        _ => return None,
    };
    match get(creds, "scope_template") {
        // `scope_template: null` (or absent) = no narrowing, full envelope
        // (doc 18 §5 validation rule 4 — the `default` role).
        None => None,
        Some(YamlNode::Scalar(s)) if s == "null" || s.is_empty() => None,
        Some(YamlNode::Mapping(tm)) => {
            let services = scalar_str_list(tm, "services");
            let mode = match scalar(tm, "mode") {
                Some(m) => match CredentialMode::parse(&m) {
                    Ok(v) => v,
                    Err(e) => {
                        errs.push(e);
                        CredentialMode::ReadOnly
                    }
                },
                None => CredentialMode::ReadOnly,
            };
            Some(ScopeTemplate { services, mode })
        }
        Some(_) => {
            errs.push(RoleError::new(
                RoleErrorCode::Syntax,
                "credentials.scope_template",
                "scope_template must be null or a mapping (services + mode)",
            ));
            None
        }
    }
}

fn build_runtime_overlay(map: &[(String, YamlNode)]) -> Option<String> {
    let rt = match get(map, "runtime") {
        Some(YamlNode::Mapping(m)) => m.as_slice(),
        _ => return None,
    };
    match scalar(rt, "entrypoint_config_overlay_ref") {
        Some(s) if s != "null" && !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Read an axis (a)/(b) artifact-ref list (`image.layers` / `skills.install`),
/// rejecting any entry that is inline content rather than a `prefix`-shaped ref
/// (doc 18 §5 validation rule 1).
fn artifact_refs(
    map: &[(String, YamlNode)],
    outer: &str,
    inner: &str,
    prefix: &str,
    errs: &mut Vec<RoleError>,
) -> Vec<String> {
    let mut out = Vec::new();
    let omap = match get(map, outer) {
        Some(YamlNode::Mapping(m)) => m.as_slice(),
        _ => return out,
    };
    let list = match get(omap, inner) {
        Some(YamlNode::Sequence(items)) => items,
        _ => return out,
    };
    for (i, item) in list.iter().enumerate() {
        match item {
            YamlNode::Scalar(s) => {
                if !s.starts_with(prefix) {
                    errs.push(RoleError::new(
                        RoleErrorCode::InlineArtifact,
                        format!("{outer}.{inner}[{i}]"),
                        format!(
                            "artifact ref {s:?} must be a {prefix}-prefixed reference, never \
                             inline content (doc 18 §5 validation rule 1)"
                        ),
                    ));
                }
                out.push(s.clone());
            }
            _ => {
                errs.push(RoleError::new(
                    RoleErrorCode::InlineArtifact,
                    format!("{outer}.{inner}[{i}]"),
                    "artifact ref must be a reference string, never inline content \
                     (doc 18 §5 validation rule 1)",
                ));
            }
        }
    }
    out
}

// ---- small node accessors --------------------------------------------------

fn get<'a>(map: &'a [(String, YamlNode)], key: &str) -> Option<&'a YamlNode> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn scalar(map: &[(String, YamlNode)], key: &str) -> Option<String> {
    match get(map, key) {
        Some(YamlNode::Scalar(s)) => Some(s.clone()),
        _ => None,
    }
}

fn scalar_str_list(map: &[(String, YamlNode)], key: &str) -> Vec<String> {
    match get(map, key) {
        Some(YamlNode::Sequence(items)) => items
            .iter()
            .filter_map(|n| match n {
                YamlNode::Scalar(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn scalar_int_list(map: &[(String, YamlNode)], key: &str) -> Vec<u32> {
    match get(map, key) {
        Some(YamlNode::Sequence(items)) => items
            .iter()
            .filter_map(|n| match n {
                YamlNode::Scalar(s) => s.parse::<u32>().ok(),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Read a mapping field that may be a `{k: v}` inline flow map OR a block map OR an
/// empty `{}`. Returns an ordered BTreeMap (sorted keys; canonical-form friendly).
fn flow_or_block_map(map: &[(String, YamlNode)], key: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(YamlNode::Mapping(m)) = get(map, key) {
        for (k, v) in m {
            if let YamlNode::Scalar(s) = v {
                out.insert(k.clone(), s.clone());
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// JCS (RFC 8785) canonical-JSON value + serializer. The role canonical payload
// is the SAME byte-format the PolicySnapshot content_hash uses (doc 13 §5.1): keys
// sorted lexicographically by UTF-8 bytes, no insignificant whitespace, integers
// bare, strings JCS-escaped, no floats. Hand-rolled (the dep-free workspace fence).
// ─────────────────────────────────────────────────────────────────────────────

/// A JCS-serializable value. The role canonical form carries only objects, arrays,
/// strings, and integers (no floats — doc 13 §5.1 F3); this enum is total over that
/// subset.
#[derive(Clone, Debug, PartialEq, Eq)]
enum JcsValue {
    Str(String),
    Int(i64),
    Arr(Vec<JcsValue>),
    Obj(Vec<(String, JcsValue)>),
}

impl JcsValue {
    /// Serialize to the RFC 8785 (JCS) canonical byte-form (returned as `String`;
    /// the bytes are UTF-8). Object members are emitted in lexicographic order of
    /// the UTF-16 code units of their keys (RFC 8785 §3.2.3); for our keys (ASCII
    /// field names) that coincides with byte order.
    fn to_jcs(&self) -> String {
        let mut s = String::new();
        self.write_jcs(&mut s);
        s
    }

    fn write_jcs(&self, out: &mut String) {
        match self {
            JcsValue::Str(v) => write_jcs_string(v, out),
            JcsValue::Int(v) => out.push_str(&v.to_string()),
            JcsValue::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_jcs(out);
                }
                out.push(']');
            }
            JcsValue::Obj(members) => {
                // RFC 8785 §3.2.3: sort object members by the UTF-16 code-unit
                // sequence of the (unescaped) member name. Build a sorted view so
                // construction order never leaks into the hash.
                let mut keyed: Vec<&(String, JcsValue)> = members.iter().collect();
                keyed.sort_by(|a, b| utf16_key_cmp(&a.0, &b.0));
                out.push('{');
                for (i, (k, v)) in keyed.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_jcs_string(k, out);
                    out.push(':');
                    v.write_jcs(out);
                }
                out.push('}');
            }
        }
    }
}

/// Compare two object-member keys by their UTF-16 code-unit sequences (RFC 8785
/// §3.2.3). For the ASCII field names the role schema uses this is identical to a
/// byte compare, but the full rule is implemented so a future non-ASCII key would
/// still sort per the RFC.
fn utf16_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Write a JSON string with RFC 8785 (JCS) escaping (§3.2.2.2): the seven two-char
/// escapes for the C0 controls that have them, `\uXXXX` (lowercase hex) for the
/// remaining controls, `\"` and `\\`, and every other character — including raw
/// non-ASCII UTF-8 — emitted literally.
fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ─────────────────────────────────────────────────────────────────────────────
// The YAML-subset reader. Modeled on pol1.rs's reader (which is private to that
// module). NOT a general YAML parser: indentation-scoped mappings (`key: value`
// / `key:`), `- ` block-sequence items, inline flow sequences `[a, b]` and inline
// flow maps `{k: v}`, scalars, and `#` comments. Anything else is a Syntax error.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum YamlNode {
    Scalar(String),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<(String, YamlNode)>),
}

struct LogicalLine {
    indent: usize,
    content: String,
}

impl YamlNode {
    fn parse_document(text: &str) -> Result<YamlNode, RoleError> {
        let lines = Self::logical_lines(text);
        if lines.is_empty() {
            return Ok(YamlNode::Mapping(Vec::new()));
        }
        let mut idx = 0usize;
        let node = Self::parse_block(&lines, &mut idx, lines[0].indent)?;
        if idx != lines.len() {
            return Err(RoleError::new(
                RoleErrorCode::Syntax,
                "",
                format!("unconsumed input at logical line {idx}"),
            ));
        }
        Ok(node)
    }

    /// Strip comments + blank lines, fold multi-line block scalars (`>` / `|`
    /// folded descriptions, common in the built-ins) into their parent value, and
    /// record each remaining line's indent + content.
    fn logical_lines(text: &str) -> Vec<LogicalLine> {
        let mut out: Vec<LogicalLine> = Vec::new();
        let raw: Vec<&str> = text.lines().collect();
        let mut i = 0usize;
        while i < raw.len() {
            let line = raw[i];
            let indent = line.len() - line.trim_start().len();
            let trimmed = strip_comment(line.trim_start());
            if trimmed.is_empty() {
                i += 1;
                continue;
            }
            // Block-scalar folding: `key: >` or `key: |` consumes the more-indented
            // continuation lines as a single folded scalar value. The built-in
            // `description: >` blocks use this.
            if let Some((k, marker)) = block_scalar_header(trimmed) {
                let mut folded = String::new();
                let mut j = i + 1;
                while j < raw.len() {
                    let cont = raw[j];
                    let cont_indent = cont.len() - cont.trim_start().len();
                    if cont.trim().is_empty() {
                        j += 1;
                        continue;
                    }
                    if cont_indent <= indent {
                        break;
                    }
                    if !folded.is_empty() {
                        folded.push(' ');
                    }
                    folded.push_str(cont.trim());
                    j += 1;
                }
                let _ = marker; // both `>` and `|` fold to one logical scalar here
                out.push(LogicalLine {
                    indent,
                    content: format!("{k}: {folded}"),
                });
                i = j;
                continue;
            }
            out.push(LogicalLine {
                indent,
                content: trimmed.to_string(),
            });
            i += 1;
        }
        out
    }

    fn parse_block(
        lines: &[LogicalLine],
        idx: &mut usize,
        indent: usize,
    ) -> Result<YamlNode, RoleError> {
        // Decide: is this block a sequence (`- ...`) or a mapping (`key: ...`)?
        if *idx >= lines.len() {
            return Ok(YamlNode::Mapping(Vec::new()));
        }
        if lines[*idx].content.starts_with("- ") || lines[*idx].content == "-" {
            Self::parse_sequence(lines, idx, indent)
        } else {
            Self::parse_mapping(lines, idx, indent)
        }
    }

    fn parse_mapping(
        lines: &[LogicalLine],
        idx: &mut usize,
        indent: usize,
    ) -> Result<YamlNode, RoleError> {
        let mut members: Vec<(String, YamlNode)> = Vec::new();
        while *idx < lines.len() {
            let line = &lines[*idx];
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(RoleError::new(
                    RoleErrorCode::Syntax,
                    "",
                    format!("unexpected indent at line {idx}: {:?}", line.content),
                ));
            }
            let (key, rest) = split_key(&line.content).ok_or_else(|| {
                RoleError::new(
                    RoleErrorCode::Syntax,
                    "",
                    format!("expected `key:` mapping entry, got {:?}", line.content),
                )
            })?;
            *idx += 1;
            if !rest.is_empty() {
                // Inline value (scalar / flow seq / flow map).
                members.push((key, parse_inline(&rest)?));
            } else {
                // Nested block — must be more-indented, else an empty value.
                if *idx < lines.len() && lines[*idx].indent > indent {
                    let child_indent = lines[*idx].indent;
                    let child = Self::parse_block(lines, idx, child_indent)?;
                    members.push((key, child));
                } else {
                    members.push((key, YamlNode::Scalar(String::new())));
                }
            }
        }
        Ok(YamlNode::Mapping(members))
    }

    fn parse_sequence(
        lines: &[LogicalLine],
        idx: &mut usize,
        indent: usize,
    ) -> Result<YamlNode, RoleError> {
        let mut items: Vec<YamlNode> = Vec::new();
        while *idx < lines.len() {
            let line = &lines[*idx];
            if line.indent != indent || !(line.content.starts_with("- ") || line.content == "-") {
                break;
            }
            let after = line.content[1..].trim_start().to_string();
            if after.is_empty() {
                // `-` then a nested block on the following more-indented lines.
                *idx += 1;
                if *idx < lines.len() && lines[*idx].indent > indent {
                    let child_indent = lines[*idx].indent;
                    items.push(Self::parse_block(lines, idx, child_indent)?);
                } else {
                    items.push(YamlNode::Scalar(String::new()));
                }
                continue;
            }
            // `- key: value...` — an inline mapping start, or `- scalar/flow`.
            if let Some((k, rest)) = split_key(&after) {
                // A mapping item: this line is its first member; following
                // more-indented lines (indent > this `-`'s indent) are siblings.
                let mut members: Vec<(String, YamlNode)> = Vec::new();
                if !rest.is_empty() {
                    members.push((k, parse_inline(&rest)?));
                } else if *idx + 1 < lines.len() && lines[*idx + 1].indent > indent {
                    let mut tmp = *idx + 1;
                    let child_indent = lines[tmp].indent;
                    let child = Self::parse_block(lines, &mut tmp, child_indent)?;
                    members.push((k, child));
                    *idx = tmp - 1; // -1 because the outer += 1 below advances
                } else {
                    members.push((k, YamlNode::Scalar(String::new())));
                }
                *idx += 1;
                // Continuation members of the same map item (deeper indent).
                let item_member_indent = indent + 2;
                while *idx < lines.len() && lines[*idx].indent >= item_member_indent {
                    if lines[*idx].indent != item_member_indent {
                        break;
                    }
                    if let Some((k2, rest2)) = split_key(&lines[*idx].content) {
                        *idx += 1;
                        if !rest2.is_empty() {
                            members.push((k2, parse_inline(&rest2)?));
                        } else if *idx < lines.len() && lines[*idx].indent > item_member_indent {
                            let child_indent = lines[*idx].indent;
                            let child = Self::parse_block(lines, idx, child_indent)?;
                            members.push((k2, child));
                        } else {
                            members.push((k2, YamlNode::Scalar(String::new())));
                        }
                    } else {
                        break;
                    }
                }
                items.push(YamlNode::Mapping(members));
            } else {
                items.push(parse_inline(&after)?);
                *idx += 1;
            }
        }
        Ok(YamlNode::Sequence(items))
    }
}

/// Split `key: rest` -> `(key, rest)`. Handles a quoted-or-bare key followed by a
/// colon. Returns `None` if the line is not a `key:` form.
fn split_key(line: &str) -> Option<(String, String)> {
    // Find the first top-level colon not inside a flow collection / quotes.
    let bytes = line.as_bytes();
    let mut depth = 0i32;
    let mut in_quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match in_quote {
            Some(q) => {
                if b == q {
                    in_quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => in_quote = Some(b),
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                // A colon ends the key only if followed by end-of-line or a space.
                b':' if depth == 0 && (i + 1 >= bytes.len() || bytes[i + 1] == b' ') => {
                    let key = unquote(line[..i].trim());
                    let rest = line[i + 1..].trim().to_string();
                    return Some((key, rest));
                }
                _ => {}
            },
        }
    }
    None
}

/// Parse an inline (flow) value: a flow sequence `[a, b]`, a flow map `{k: v}`, or
/// a bare/quoted scalar.
fn parse_inline(s: &str) -> Result<YamlNode, RoleError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(YamlNode::Scalar(String::new()));
    }
    if t.starts_with('[') {
        return parse_flow_seq(t);
    }
    if t.starts_with('{') {
        return parse_flow_map(t);
    }
    Ok(YamlNode::Scalar(unquote(t)))
}

fn parse_flow_seq(s: &str) -> Result<YamlNode, RoleError> {
    let inner = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .ok_or_else(|| {
            RoleError::new(
                RoleErrorCode::Syntax,
                "",
                format!("malformed inline sequence {s:?}"),
            )
        })?;
    let mut items = Vec::new();
    for part in split_flow(inner) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        items.push(parse_inline(p)?);
    }
    Ok(YamlNode::Sequence(items))
}

fn parse_flow_map(s: &str) -> Result<YamlNode, RoleError> {
    let inner = s
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .ok_or_else(|| {
            RoleError::new(
                RoleErrorCode::Syntax,
                "",
                format!("malformed inline map {s:?}"),
            )
        })?;
    let mut members = Vec::new();
    for part in split_flow(inner) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let (k, rest) = split_key(p).ok_or_else(|| {
            RoleError::new(
                RoleErrorCode::Syntax,
                "",
                format!("expected `key: value` in inline map, got {p:?}"),
            )
        })?;
        members.push((k, parse_inline(&rest)?));
    }
    Ok(YamlNode::Mapping(members))
}

/// Split a flow-collection inner string on top-level commas (commas inside nested
/// `[]` / `{}` / quotes do not split).
fn split_flow(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_quote: Option<u8> = None;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match in_quote {
            Some(q) => {
                if b == q {
                    in_quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => in_quote = Some(b),
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(s[start..i].to_string());
                    start = i + 1;
                }
                _ => {}
            },
        }
    }
    if start <= s.len() {
        out.push(s[start..].to_string());
    }
    out
}

/// Strip a trailing `#` comment from a line (respecting quotes). A `#` inside a
/// quoted scalar is preserved.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match in_quote {
            Some(q) => {
                if b == q {
                    in_quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => in_quote = Some(b),
                // A `#` starts a comment only at line start or after whitespace.
                b'#' if i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t' => {
                    return line[..i].trim_end();
                }
                _ => {}
            },
        }
    }
    line.trim_end()
}

/// Detect a `key: >` / `key: |` block-scalar header; returns `(key, marker)`.
fn block_scalar_header(line: &str) -> Option<(String, char)> {
    let (k, rest) = split_key(line)?;
    let r = rest.trim();
    match r {
        ">" | ">-" | ">+" => Some((k, '>')),
        "|" | "|-" | "|+" => Some((k, '|')),
        _ => None,
    }
}

/// Remove surrounding single/double quotes from a scalar token.
fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 {
        let b = t.as_bytes();
        if (b[0] == b'"' && b[t.len() - 1] == b'"') || (b[0] == b'\'' && b[t.len() - 1] == b'\'') {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}
