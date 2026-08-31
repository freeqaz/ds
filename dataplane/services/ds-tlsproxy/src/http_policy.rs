//! TLS-6 HTTP-level policy evaluator — the framework-agnostic library core for
//! method/host/path rule evaluation + DoH-on-allowed-host detection on the
//! inspected (TLS-3-terminated) path (doc 09 §5 TLS-6; doc 12 §3 / §5.3; D17/D74,
//! D77, D40 pingora confinement).
//!
//! # What this is
//!
//! Once TLS-3 terminates the VM's TLS ([`crate::ca`] mints the leaf the VM sees)
//! the proxy reads the cleartext HTTP exchange — that is what unlocks HTTP-level
//! policy (doc 09 §5 TLS-3 → TLS-6). This module is the HTTP **policy decision**
//! half of TLS-6: given a parsed request line + headers ([`RequestMeta`]) it
//! returns a [`HttpDecision`] carrying the POL-3 provenance triple (rule id /
//! layer / policy version) the boundary executable spec
//! (`boundary/tlsproxy/tlsproxy_httppolicy_test.go`, D26) pins:
//!
//! - **`TestHTTPPolicy_MethodHostPathRules_TableDriven`** — method/host/path
//!   matchers with deny-overrides (a `DELETE /repos/critical/*` deny, a
//!   `/admin` path deny, an org-layer deny that overrides a system allow), each
//!   carrying its rule id; an allowed request reaches upstream, a denied one is a
//!   `403` that NEVER reaches upstream.
//! - **`TestDoH_OnAllowedHost_DetectedAndBlocked`** — DNS-over-HTTP smuggled over
//!   an otherwise-allowed host is detected at the HTTP level and denied with a
//!   **DoH-specific** rule id, by any of the three frozen shapes: a
//!   `Content-Type: application/dns-message` body, a `?dns=<base64url>` query
//!   parameter, or an `Accept: application/dns-json` header (the §9 "DoH endpoint
//!   blocking (HTTP-level half)" row; NFT-4 layering — the named-resolver half
//!   already ships in the D64 baseline blocklist, POL-2).
//!
//! The rate-limit, behavioral-cap, and suspend-on-breach halves of TLS-6 are
//! sibling units; this unit is the request-phase **policy rule** decision +
//! DoH detection that gates a request before any byte goes upstream.
//!
//! # The shared `policy-core` host decision is the floor (POL-3)
//!
//! HTTP-level rules do not re-decide host admission: the host an inspected flow
//! reaches was already admitted by the SAME shared `policy-core` engine the TLS-1
//! SNI gate and the DNS admission both ran ([`policy_core::consumer::tls_connect_decision`],
//! POL-3 "no consumer reimplements a rule"). This module evaluates the
//! *finer-grained* method/host/path rules that only the inspected (cleartext)
//! path can see — and the DoH content-shape detection that catches a resolver
//! tunnelled over an allowed host. A `host`-level deny is still the host engine's
//! job; this layer can only *tighten* (deny a method/path on an allowed host),
//! never loosen — exactly mirroring deny-overrides (§1.2): a deny at any layer
//! wins.
//!
//! # Deny-overrides layering (§1.2, §8.2)
//!
//! [`HttpPolicy::evaluate`] walks the rule set deny-first: the first matching
//! **deny** rule wins over any allow (the org-layer deny that overrides a
//! system-layer allow in the boundary table). DoH detection runs as a built-in
//! deny that fires BEFORE the configured rules so a resolver smuggled over an
//! allowed host can never be allowed by a permissive host rule.
//!
//! # Body examination is opt-in (doc 09 §5 TLS-6, last sentence)
//!
//! > *"Telemetry is request metadata by default; bodies are only examined where a
//! > specific policy requires it."*
//!
//! [`RequestMeta`] carries request METADATA only — method, host, path, and
//! headers; there is no body field. DoH detection over the three frozen shapes is
//! all metadata-level (a `Content-Type` header, a query parameter, an `Accept`
//! header) — it never reads a body byte. A rule that needs the body sets
//! [`HttpRule::examine_body`]; the decision then carries
//! [`HttpDecision::body_examined`] so the caller knows to feed the body-filter
//! chain. Default rules leave it `false`, so the default decision path is
//! metadata-only and the LOG-1 event the caller builds
//! ([`crate::telemetry_http::HttpEvent`], a fingerprint-/body-free shape) never
//! carries a payload byte — never-log-the-secret (D73) holds by construction.
//!
//! # D40 pingora confinement (doc 12 §13.1) + the integration seam
//!
//! No pingora type appears here. `main.rs` extracts the request line + headers off
//! the terminated cleartext stream (the `run_inspected_flow` request phase),
//! builds a [`RequestMeta`], drives [`HttpPolicy::evaluate`], and — on a
//! deny — answers the client an in-band `403` ([`HttpDecision::deny_status`])
//! carrying the structured, machine-readable body D77 requires (the matched rule
//! id + retry-after-approval semantics) WITHOUT opening the upstream leg, then
//! emits the [`crate::telemetry_http::HttpEvent`] /
//! `EventPolicyDecision`-shaped record with this decision's provenance. That
//! wiring is gated behind `DS_TLS3_LIVE` exactly as the TLS-3 inspected path is —
//! the default (`DS_TLS3_LIVE` unset) opaque-tunnel path never constructs a
//! [`RequestMeta`] and is byte-identical, and a TLS-4 pass-through (doc 12 §5.3
//! non-claim, D17/D74) never reaches this evaluator. The live wiring is a deferred
//! unit; this is the lib-side decision core + its unit suite.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// HTTP request metadata the policy evaluator operates on — the lib-side mirror of
/// the boundary `RequestMeta{Method, Host, Path, Headers}` (doc 09 §5 TLS-6). It
/// is METADATA only: there is NO body field (body examination is opt-in and is the
/// body-filter chain's job, §5.3). Header names are matched case-insensitively
/// (RFC 7230 §3.2 — field names are case-insensitive).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMeta {
    /// The HTTP request method (e.g. `GET`, `DELETE`), as read off the request
    /// line. Compared case-sensitively against rule matchers (methods are
    /// upper-case tokens, RFC 7231 §4.1).
    pub method: String,
    /// The origin host the request is bound for — the SNI / `Host` on the
    /// terminated stream (the policy / attribution key). This is the host the
    /// shared engine already admitted; HTTP rules tighten on it, never loosen it.
    pub host: String,
    /// The origin-form request target, INCLUDING any query string
    /// (e.g. `/query?dns=AAAB…`). The query is retained because DoH detection
    /// keys off the `?dns=` parameter (doc 09 §5 TLS-6, NFT-4 layering).
    pub path: String,
    /// The request headers as `(name, value)` pairs. Names are matched
    /// case-insensitively; values are matched as written. DoH detection reads
    /// `Content-Type` and `Accept` from here.
    pub headers: Vec<(String, String)>,
}

impl RequestMeta {
    /// Build a [`RequestMeta`] from its parts. `headers` is any `(name, value)`
    /// iterable (e.g. the parsed inspected request head).
    pub fn new(
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> RequestMeta {
        RequestMeta {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            headers: headers.into_iter().collect(),
        }
    }

    /// The first value of `name` (case-insensitive header-name match, RFC 7230
    /// §3.2), or `None` if absent. The first occurrence wins (HTTP semantics for
    /// the headers DoH detection reads — `Content-Type` / `Accept` are singular).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The path component with any `?query` stripped — the part method/host/path
    /// rules match against (the query string is DoH-detection input, not a path
    /// matcher input).
    pub fn path_only(&self) -> &str {
        match self.path.split_once('?') {
            Some((p, _)) => p,
            None => &self.path,
        }
    }

    /// The raw query string (everything after the first `?`), or `""` if none.
    /// DoH detection scans this for a `dns=` parameter.
    pub fn query(&self) -> &str {
        match self.path.split_once('?') {
            Some((_, q)) => q,
            None => "",
        }
    }
}

/// The POL-3 provenance triple every HTTP-policy verdict carries (rule 4 — a
/// missing-provenance decision is a spec failure). The same shape
/// [`crate::telemetry_http::Provenance`] carries onto the LOG-1 event and the
/// boundary `Provenance{RuleID, PolicyLayer, PolicyVersion}` (doc 09 §5 TLS-6;
/// doc 13 §1.4 POL-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpProvenance {
    /// The matched rule id (e.g. `http:deny-delete-critical`, `doh:content-shape`).
    pub rule_id: String,
    /// The composing policy layer the matched rule came from (e.g. `org`,
    /// `system`).
    pub policy_layer: String,
    /// The policy version in force (the composed document's single version, rule 3).
    pub policy_version: String,
}

impl HttpProvenance {
    /// Build a provenance triple from its three parts.
    pub fn new(
        rule_id: impl Into<String>,
        policy_layer: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> HttpProvenance {
        HttpProvenance {
            rule_id: rule_id.into(),
            policy_layer: policy_layer.into(),
            policy_version: policy_version.into(),
        }
    }

    /// Project onto the [`crate::telemetry_http::Provenance`] the LOG-1
    /// `HttpEvent` / `EventPolicyDecision` record carries (the field set is
    /// identical — this is the mechanical migration the caller performs when it
    /// emits the decision event).
    pub fn to_telemetry(&self) -> crate::telemetry_http::Provenance {
        crate::telemetry_http::Provenance::new(
            self.rule_id.clone(),
            self.policy_layer.clone(),
            self.policy_version.clone(),
        )
    }
}

/// An HTTP-policy verdict: allow or deny, with mandatory POL-3 provenance and the
/// opt-in body-examination flag (doc 09 §5 TLS-6). A deny carries the client-facing
/// status the proxy answers in-band (`403`, distinct from the rate-limit `429` a
/// sibling unit owns) — the request NEVER reaches upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpDecision {
    /// Whether the request is allowed to proceed upstream. `false` ⇒ the proxy
    /// answers the client a `403` in-band and opens NO upstream leg.
    pub allow: bool,
    /// POL-3 provenance (rule 4) — MANDATORY, on both allow and deny.
    pub provenance: HttpProvenance,
    /// Whether the matched rule requires body examination (doc 09 §5 TLS-6 — bodies
    /// are examined only where a specific rule requires it). `false` for every
    /// metadata-only rule (the default), so the default decision path never feeds a
    /// body to telemetry / the scan chain — never-log-the-secret holds (D73).
    pub body_examined: bool,
}

impl HttpDecision {
    /// An allow verdict carrying provenance; not body-examining.
    pub fn allow(provenance: HttpProvenance) -> HttpDecision {
        HttpDecision {
            allow: true,
            provenance,
            body_examined: false,
        }
    }

    /// A deny verdict carrying provenance; not body-examining.
    pub fn deny(provenance: HttpProvenance) -> HttpDecision {
        HttpDecision {
            allow: false,
            provenance,
            body_examined: false,
        }
    }

    /// The client-facing status the proxy answers a denied request in-band: `403`
    /// Forbidden (D77 block+log — the agent sees a `403` with a structured body
    /// naming the matched rule and the retry-after-approval semantics). An allowed
    /// request has no policy status (it proceeds upstream); `None` then.
    ///
    /// This is the HTTP-policy half; the rate-limit `429` is the sibling
    /// rate-limit unit's status (doc 09 §5 TLS-6 — "a 429 (rate) or 403
    /// (quota/content)").
    pub fn deny_status(&self) -> Option<u16> {
        if self.allow {
            None
        } else {
            Some(403)
        }
    }
}

/// Which request facet a [`HttpRule`] matches on. A rule matches a request iff
/// EVERY one of its set matchers matches (AND across facets); an unset facet
/// (`None`) is a wildcard. This is the method/host/path rule shape doc 09 §5
/// TLS-6 names — finer-grained than the host-only `policy-core` domain decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpMatcher {
    /// Match an exact request method (case-sensitive upper-case token). `None`
    /// matches any method.
    pub method: Option<String>,
    /// Match an exact origin host (lowercased compare). `None` matches any host
    /// (the host is already admitted by the shared engine; a host matcher only
    /// narrows a rule to a specific origin).
    pub host: Option<String>,
    /// Match a path PREFIX on the query-stripped path (e.g. `/repos/critical`,
    /// `/admin`). `None` matches any path. Prefix (not exact) because the boundary
    /// rules guard subtrees (`/repos/critical/branch` under `/repos/critical`).
    pub path_prefix: Option<String>,
}

impl HttpMatcher {
    /// Whether this matcher matches `req` (AND across the set facets; an unset
    /// facet is a wildcard).
    pub fn matches(&self, req: &RequestMeta) -> bool {
        if let Some(m) = &self.method {
            if &req.method != m {
                return false;
            }
        }
        if let Some(h) = &self.host {
            if !req.host.eq_ignore_ascii_case(h) {
                return false;
            }
        }
        if let Some(p) = &self.path_prefix {
            if !req.path_only().starts_with(p.as_str()) {
                return false;
            }
        }
        true
    }
}

/// One configured HTTP-level policy rule: a matcher, the verdict effect, the
/// provenance the matched verdict stamps, and the opt-in body-examination bit
/// (doc 09 §5 TLS-6). Rules compose deny-first ([`HttpPolicy::evaluate`]): a deny
/// at any layer wins over an allow (deny-overrides, §1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRule {
    /// What this rule matches on.
    pub matcher: HttpMatcher,
    /// The effect when it matches: `true` = allow, `false` = deny.
    pub allow: bool,
    /// The rule id stamped onto the verdict (e.g. `http:deny-delete-critical`).
    pub rule_id: String,
    /// The composing layer the rule came from (e.g. `org`, `system`).
    pub policy_layer: String,
    /// Whether matching this rule requires body examination (opt-in, §5.3). Default
    /// `false` (metadata-only).
    pub examine_body: bool,
}

impl HttpRule {
    /// A deny rule on a matcher, with its rule id and layer (metadata-only).
    pub fn deny(
        matcher: HttpMatcher,
        rule_id: impl Into<String>,
        layer: impl Into<String>,
    ) -> HttpRule {
        HttpRule {
            matcher,
            allow: false,
            rule_id: rule_id.into(),
            policy_layer: layer.into(),
            examine_body: false,
        }
    }

    /// An allow rule on a matcher, with its rule id and layer (metadata-only).
    pub fn allow(
        matcher: HttpMatcher,
        rule_id: impl Into<String>,
        layer: impl Into<String>,
    ) -> HttpRule {
        HttpRule {
            matcher,
            allow: true,
            rule_id: rule_id.into(),
            policy_layer: layer.into(),
            examine_body: false,
        }
    }

    /// Mark this rule as requiring body examination (the opt-in §5.3 path). A
    /// decision matched by such a rule carries [`HttpDecision::body_examined`] so
    /// the caller feeds the body to the scan / inspection chain.
    pub fn examining_body(mut self) -> HttpRule {
        self.examine_body = true;
        self
    }
}

/// The three frozen DoH-over-HTTP content shapes (doc 09 §5 TLS-6; NFT-4 §86
/// "HTTP-level detection of DoH on otherwise-allowed hosts"). Each maps to a
/// DoH-specific rule id so the block carries DoH-specific provenance (the boundary
/// asserts the rule id contains `doh`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DohShape {
    /// RFC 8484 `Content-Type: application/dns-message` (a wire-format DNS query
    /// POSTed to a resolver endpoint).
    ContentType,
    /// RFC 8484 GET form: a `?dns=<base64url>` query parameter carrying the
    /// wire-format query.
    QueryParam,
    /// JSON DoH (the Google/Cloudflare `application/dns-json` resolver API), via an
    /// `Accept: application/dns-json` header.
    AcceptJson,
}

impl DohShape {
    /// The DoH-specific rule id this shape's block stamps. Every id contains `doh`
    /// so the boundary's "block must carry DoH-specific rule provenance" assertion
    /// holds, and names the shape so telemetry distinguishes the three.
    pub fn rule_id(self) -> &'static str {
        match self {
            DohShape::ContentType => "doh:content-type-dns-message",
            DohShape::QueryParam => "doh:query-param-dns",
            DohShape::AcceptJson => "doh:accept-dns-json",
        }
    }
}

/// The RFC 8484 wire-format DoH media type (POST body content type).
const DOH_WIRE_CONTENT_TYPE: &str = "application/dns-message";
/// The JSON DoH resolver-API media type (the `Accept` header value).
const DOH_JSON_ACCEPT: &str = "application/dns-json";

/// Detect DNS-over-HTTP smuggled in `req` by any of the three frozen shapes,
/// metadata-only (no body byte is read) — doc 09 §5 TLS-6, NFT-4 layering. Returns
/// the matched [`DohShape`] (the first that matches, in `ContentType` →
/// `QueryParam` → `AcceptJson` order), or `None` for an ordinary request.
///
/// This is a CONTENT-shape detection, not a host-wide block: an ordinary JSON POST
/// to the same (allowed) host is NOT DoH (the boundary's control row), so the
/// detector keys strictly on the DoH media types / the `dns=` parameter — never on
/// the host.
pub fn detect_doh(req: &RequestMeta) -> Option<DohShape> {
    // 1. RFC 8484 wire-format POST: Content-Type: application/dns-message. Media
    //    types may carry parameters (`; charset=…`) — match the type/subtype
    //    prefix, case-insensitively (RFC 7231 §3.1.1.1 media types are
    //    case-insensitive).
    if let Some(ct) = req.header("Content-Type") {
        if media_type_is(ct, DOH_WIRE_CONTENT_TYPE) {
            return Some(DohShape::ContentType);
        }
    }
    // 2. RFC 8484 GET form: a `dns=` query parameter. Scan the `&`-separated query
    //    parameters for a `dns` key (an exact key match, so a benign `?dnssec=…`
    //    or `?cdns=…` is not mistaken for DoH).
    if query_has_param(req.query(), "dns") {
        return Some(DohShape::QueryParam);
    }
    // 3. JSON DoH: Accept: application/dns-json (the resolver JSON API). Accept may
    //    list several types — match if the DoH JSON type appears as one of them.
    if let Some(accept) = req.header("Accept") {
        if accept_lists(accept, DOH_JSON_ACCEPT) {
            return Some(DohShape::AcceptJson);
        }
    }
    None
}

/// Whether a media-type header value `value` has type/subtype equal to `want`
/// (case-insensitive), ignoring any `; param=…` suffix (RFC 7231 §3.1.1.1).
fn media_type_is(value: &str, want: &str) -> bool {
    let base = value.split(';').next().unwrap_or(value).trim();
    base.eq_ignore_ascii_case(want)
}

/// Whether an `Accept` header value lists `want` as one of its comma-separated
/// media ranges (each range's type/subtype compared case-insensitively, ignoring
/// q-values / params). RFC 7231 §5.3.2.
fn accept_lists(value: &str, want: &str) -> bool {
    value.split(',').any(|range| media_type_is(range, want))
}

/// Whether a `&`-separated query string has a parameter whose key is EXACTLY `key`
/// (case-sensitive key match — query parameter names are case-sensitive). A bare
/// `key` (no `=`) counts; a `keyextra=…` does NOT.
fn query_has_param(query: &str, key: &str) -> bool {
    query.split('&').any(|pair| {
        let name = pair.split('=').next().unwrap_or(pair);
        name == key
    })
}

/// The HTTP-level policy evaluator (doc 09 §5 TLS-6) — a configured rule set plus
/// the always-on DoH detector, carrying the single policy version every verdict
/// stamps (rule 3). It is the inspected-path request-phase decision point: the
/// caller (`main.rs`, behind `DS_TLS3_LIVE`) builds a [`RequestMeta`] off the
/// terminated stream and asks [`HttpPolicy::evaluate`] before any byte goes
/// upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpPolicy {
    /// The configured method/host/path rules, evaluated deny-first (§1.2).
    rules: Vec<HttpRule>,
    /// The single policy version every verdict stamps (rule 3 — the composed
    /// document's one version).
    policy_version: String,
    /// The default verdict when no configured rule matches and the request is not
    /// DoH: `true` = allow (the host is already engine-admitted; an HTTP rule only
    /// tightens). The provenance carries the default rule id.
    default_allow: bool,
}

/// The rule id stamped onto a default (no-rule-matched) allow verdict.
const DEFAULT_ALLOW_RULE_ID: &str = "http:default-allow";
/// The rule id stamped onto a default (no-rule-matched) deny verdict.
const DEFAULT_DENY_RULE_ID: &str = "http:default-deny";
/// The layer a default verdict's provenance carries.
const DEFAULT_LAYER: &str = "system";

impl HttpPolicy {
    /// Build a policy from its rule set and the single policy version (rule 3), with
    /// a default-ALLOW posture (the host is already engine-admitted; HTTP rules
    /// only tighten). Use [`HttpPolicy::with_default_deny`] for a default-deny
    /// posture.
    pub fn new(rules: Vec<HttpRule>, policy_version: impl Into<String>) -> HttpPolicy {
        HttpPolicy {
            rules,
            policy_version: policy_version.into(),
            default_allow: true,
        }
    }

    /// Flip this policy to a default-DENY posture (an unmatched request is denied
    /// with `http:default-deny` provenance) — for a `locked` posture where only
    /// explicitly-allowed method/host/paths proceed.
    pub fn with_default_deny(mut self) -> HttpPolicy {
        self.default_allow = false;
        self
    }

    /// The single policy version every verdict stamps (rule 3).
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Evaluate `req` against the policy (doc 09 §5 TLS-6). Resolution order:
    ///
    /// 1. **DoH detection first** ([`detect_doh`]): a resolver smuggled over an
    ///    otherwise-allowed host is denied with a DoH-specific rule id, BEFORE any
    ///    configured allow rule can admit it (NFT-4 layering; the §9 HTTP-level
    ///    half). This is a built-in deny that no host allow rule can override.
    /// 2. **Deny rules** (deny-overrides, §1.2): the first matching DENY rule wins
    ///    over any allow — the org-layer deny that overrides a system allow.
    /// 3. **Allow rules**: the first matching ALLOW rule admits, carrying its
    ///    provenance + body-examination flag.
    /// 4. **Default**: the configured default posture (`default_allow`).
    ///
    /// The returned [`HttpDecision`] always carries POL-3 provenance (rule 4) and
    /// the single policy version (rule 3); a deny is answered in-band as a `403`
    /// ([`HttpDecision::deny_status`]) and NEVER reaches upstream.
    pub fn evaluate(&self, req: &RequestMeta) -> HttpDecision {
        // 1. DoH detection — a built-in deny that fires before any allow rule, so a
        //    permissive host allow can never admit a resolver tunnelled over it.
        if let Some(shape) = detect_doh(req) {
            return HttpDecision::deny(HttpProvenance::new(
                shape.rule_id(),
                DEFAULT_LAYER,
                self.policy_version.clone(),
            ));
        }
        // 2. Deny-overrides: the first matching DENY rule wins over any allow.
        for rule in self.rules.iter().filter(|r| !r.allow) {
            if rule.matcher.matches(req) {
                return self.decision_from(rule);
            }
        }
        // 3. The first matching ALLOW rule admits.
        for rule in self.rules.iter().filter(|r| r.allow) {
            if rule.matcher.matches(req) {
                return self.decision_from(rule);
            }
        }
        // 4. Default posture.
        if self.default_allow {
            HttpDecision::allow(HttpProvenance::new(
                DEFAULT_ALLOW_RULE_ID,
                DEFAULT_LAYER,
                self.policy_version.clone(),
            ))
        } else {
            HttpDecision::deny(HttpProvenance::new(
                DEFAULT_DENY_RULE_ID,
                DEFAULT_LAYER,
                self.policy_version.clone(),
            ))
        }
    }

    /// Build the [`HttpDecision`] a matched rule produces (its allow/deny effect,
    /// provenance, and body-examination flag), stamping the single policy version.
    fn decision_from(&self, rule: &HttpRule) -> HttpDecision {
        HttpDecision {
            allow: rule.allow,
            provenance: HttpProvenance::new(
                rule.rule_id.clone(),
                rule.policy_layer.clone(),
                self.policy_version.clone(),
            ),
            body_examined: rule.examine_body,
        }
    }
}

/// A convenience builder for the `(host -> rules)` shape a per-host policy view
/// takes, so a caller can register rules per origin and flatten them into one
/// [`HttpPolicy`] (the matcher's `host` facet narrows each). Kept minimal —
/// the live policy-snapshot binding (off the composed document, §1.2) is a
/// deferred unit; this is the in-memory shape the unit suite drives.
#[derive(Clone, Debug, Default)]
pub struct HttpPolicyBuilder {
    by_host: BTreeMap<String, Vec<HttpRule>>,
    global: Vec<HttpRule>,
}

impl HttpPolicyBuilder {
    /// A fresh builder.
    pub fn new() -> HttpPolicyBuilder {
        HttpPolicyBuilder::default()
    }

    /// Add a rule scoped to `host` (the rule's matcher host facet is set to it).
    pub fn host_rule(mut self, host: impl Into<String>, mut rule: HttpRule) -> HttpPolicyBuilder {
        let host = host.into();
        rule.matcher.host = Some(host.clone());
        self.by_host.entry(host).or_default().push(rule);
        self
    }

    /// Add a host-agnostic rule (matched on every origin).
    pub fn global_rule(mut self, rule: HttpRule) -> HttpPolicyBuilder {
        self.global.push(rule);
        self
    }

    /// Flatten into one [`HttpPolicy`] at `policy_version`: every host rule (sorted
    /// by host for determinism) followed by the global rules. Deny-overrides is
    /// applied at evaluation, so ordering within the flattened set only affects
    /// which same-effect rule's provenance is cited.
    pub fn build(self, policy_version: impl Into<String>) -> HttpPolicy {
        let mut rules: Vec<HttpRule> = Vec::new();
        for (_host, host_rules) in self.by_host {
            rules.extend(host_rules);
        }
        rules.extend(self.global);
        HttpPolicy::new(rules, policy_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "policy-v1";

    fn req(method: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> RequestMeta {
        RequestMeta::new(
            method,
            host,
            path,
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())),
        )
    }

    // ── method/host/path rules + deny-overrides (the boundary table) ────────────

    /// The boundary `TestHTTPPolicy_MethodHostPathRules_TableDriven` rows, modelled
    /// over the lib core: an allowed GET, a denied DELETE on a sensitive path, an
    /// allowed-host denied path, and a deny-overrides layering. Each denied row
    /// carries the expected rule id and is a 403 that never reaches upstream.
    #[test]
    fn method_host_path_rules_table_driven() {
        const HOST: &str = "api.github.com";
        let policy = HttpPolicy::new(
            vec![
                HttpRule::deny(
                    HttpMatcher {
                        method: Some("DELETE".to_string()),
                        host: None,
                        path_prefix: Some("/repos/critical".to_string()),
                    },
                    "http:deny-delete-critical",
                    "org",
                ),
                HttpRule::deny(
                    HttpMatcher {
                        method: None,
                        host: None,
                        path_prefix: Some("/admin".to_string()),
                    },
                    "http:deny-admin-path",
                    "system",
                ),
                // deny-overrides: a system-layer allow exists for /layered, but the
                // org deny wins.
                HttpRule::allow(
                    HttpMatcher {
                        method: None,
                        host: None,
                        path_prefix: Some("/layered".to_string()),
                    },
                    "http:system-allow-layered",
                    "system",
                ),
                HttpRule::deny(
                    HttpMatcher {
                        method: None,
                        host: None,
                        path_prefix: Some("/layered".to_string()),
                    },
                    "http:org-deny-overrides",
                    "org",
                ),
            ],
            V,
        );

        struct Row {
            method: &'static str,
            path: &'static str,
            allow: bool,
            want_rule: &'static str,
        }
        let rows = [
            Row {
                method: "GET",
                path: "/repos/critical/info",
                allow: true,
                want_rule: DEFAULT_ALLOW_RULE_ID,
            },
            Row {
                method: "DELETE",
                path: "/repos/critical/branch",
                allow: false,
                want_rule: "http:deny-delete-critical",
            },
            Row {
                method: "GET",
                path: "/admin/settings",
                allow: false,
                want_rule: "http:deny-admin-path",
            },
            Row {
                method: "GET",
                path: "/layered/resource",
                allow: false,
                want_rule: "http:org-deny-overrides",
            },
        ];
        for row in rows {
            let d = policy.evaluate(&req(row.method, HOST, row.path, &[]));
            assert_eq!(d.allow, row.allow, "row {} allow", row.path);
            assert_eq!(d.provenance.rule_id, row.want_rule, "row {} rule", row.path);
            assert_eq!(d.provenance.policy_version, V);
            if row.allow {
                assert_eq!(d.deny_status(), None);
            } else {
                // denied ⇒ 403, never reaches upstream (the caller opens no leg).
                assert_eq!(d.deny_status(), Some(403));
            }
            // body examination is opt-in: no rule here sets it.
            assert!(!d.body_examined);
        }
    }

    /// A GET that is denied still carries org-layer provenance when the org deny
    /// matched (the layer field is the matched rule's, not a default).
    #[test]
    fn deny_carries_matched_rule_layer() {
        let policy = HttpPolicy::new(
            vec![HttpRule::deny(
                HttpMatcher {
                    method: None,
                    host: None,
                    path_prefix: Some("/layered".to_string()),
                },
                "http:org-deny-overrides",
                "org",
            )],
            V,
        );
        let d = policy.evaluate(&req("GET", "api.github.com", "/layered/x", &[]));
        assert!(!d.allow);
        assert_eq!(d.provenance.policy_layer, "org");
        assert_eq!(d.provenance.rule_id, "http:org-deny-overrides");
    }

    /// The method facet narrows: the same path under a non-matching method is
    /// allowed (a GET to `/repos/critical` is fine; only DELETE is denied).
    #[test]
    fn method_facet_narrows_the_deny() {
        let policy = HttpPolicy::new(
            vec![HttpRule::deny(
                HttpMatcher {
                    method: Some("DELETE".to_string()),
                    host: None,
                    path_prefix: Some("/repos/critical".to_string()),
                },
                "http:deny-delete-critical",
                "org",
            )],
            V,
        );
        assert!(
            policy
                .evaluate(&req("GET", "h", "/repos/critical/x", &[]))
                .allow
        );
        assert!(
            !policy
                .evaluate(&req("DELETE", "h", "/repos/critical/x", &[]))
                .allow
        );
    }

    /// The host facet narrows: a host rule only applies to its origin.
    #[test]
    fn host_facet_narrows_the_rule() {
        let policy = HttpPolicy::new(
            vec![HttpRule::deny(
                HttpMatcher {
                    method: None,
                    host: Some("evil.example".to_string()),
                    path_prefix: None,
                },
                "http:deny-evil-host",
                "org",
            )],
            V,
        );
        assert!(
            !policy
                .evaluate(&req("GET", "evil.example", "/x", &[]))
                .allow
        );
        assert!(
            policy
                .evaluate(&req("GET", "good.example", "/x", &[]))
                .allow
        );
        // host match is case-insensitive.
        assert!(
            !policy
                .evaluate(&req("GET", "EVIL.example", "/x", &[]))
                .allow
        );
    }

    // ── DoH-on-allowed-host detection (the adversarial boundary row) ────────────

    /// The boundary `TestDoH_OnAllowedHost_DetectedAndBlocked` rows: three DoH
    /// shapes blocked with DoH-specific provenance, and a control JSON POST to the
    /// same host allowed (detection is content-shaped, not host-wide).
    #[test]
    fn doh_on_allowed_host_detected_and_blocked() {
        const HOST: &str = "cdn.allowed.example";
        // Default-allow policy (the host is engine-admitted; only DoH content is
        // denied at the HTTP level).
        let policy = HttpPolicy::new(vec![], V);

        // 1. POST application/dns-message → blocked, doh provenance.
        let d = policy.evaluate(&req(
            "POST",
            HOST,
            "/resolve",
            &[("Content-Type", "application/dns-message")],
        ));
        assert!(!d.allow);
        assert_eq!(d.deny_status(), Some(403));
        assert!(
            d.provenance.rule_id.contains("doh"),
            "rule id {:?}",
            d.provenance.rule_id
        );

        // 2. GET ?dns=<base64url> → blocked.
        let d = policy.evaluate(&req("GET", HOST, "/query?dns=AAABAAABAAAAAAAA", &[]));
        assert!(!d.allow);
        assert!(d.provenance.rule_id.contains("doh"));

        // 3. Accept: application/dns-json → blocked.
        let d = policy.evaluate(&req(
            "GET",
            HOST,
            "/lookup?name=example.com",
            &[("Accept", "application/dns-json")],
        ));
        assert!(!d.allow);
        assert!(d.provenance.rule_id.contains("doh"));

        // 4. Control: ordinary JSON POST to the SAME host → allowed (200), reaches
        //    upstream. Detection is content-shaped, not host-wide.
        let d = policy.evaluate(&req(
            "POST",
            HOST,
            "/api",
            &[("Content-Type", "application/json")],
        ));
        assert!(d.allow);
        assert_eq!(d.deny_status(), None);
        assert!(!d.provenance.rule_id.contains("doh"));
    }

    /// DoH detection beats a permissive host allow rule: even with an explicit
    /// allow for the host/path, a DoH content shape is still denied (the built-in
    /// deny fires before any configured allow).
    #[test]
    fn doh_overrides_a_permissive_host_allow() {
        let policy = HttpPolicy::new(
            vec![HttpRule::allow(
                HttpMatcher {
                    method: None,
                    host: Some("cdn.allowed.example".to_string()),
                    path_prefix: None,
                },
                "http:allow-cdn",
                "org",
            )],
            V,
        );
        let d = policy.evaluate(&req(
            "POST",
            "cdn.allowed.example",
            "/resolve",
            &[("Content-Type", "application/dns-message")],
        ));
        assert!(!d.allow, "a permissive allow must not admit DoH content");
        assert!(d.provenance.rule_id.contains("doh"));
    }

    /// The three shapes map to distinct DoH-specific rule ids (so telemetry can
    /// tell them apart while all three carry `doh`).
    #[test]
    fn doh_shapes_map_to_distinct_doh_rule_ids() {
        assert!(DohShape::ContentType.rule_id().contains("doh"));
        assert!(DohShape::QueryParam.rule_id().contains("doh"));
        assert!(DohShape::AcceptJson.rule_id().contains("doh"));
        assert_ne!(
            DohShape::ContentType.rule_id(),
            DohShape::QueryParam.rule_id()
        );
        assert_ne!(
            DohShape::QueryParam.rule_id(),
            DohShape::AcceptJson.rule_id()
        );
    }

    /// Content-Type with a media-type parameter (`; charset=…`) still detects, and
    /// the match is case-insensitive (RFC 7231 §3.1.1.1).
    #[test]
    fn doh_content_type_tolerates_params_and_case() {
        assert_eq!(
            detect_doh(&req(
                "POST",
                "h",
                "/r",
                &[("content-type", "Application/DNS-Message; charset=binary")]
            )),
            Some(DohShape::ContentType)
        );
    }

    /// The `dns=` query detector matches the exact parameter key only — a benign
    /// `?dnssec=…` or `?cdns=…` is NOT mistaken for DoH (no false positive).
    #[test]
    fn doh_query_param_is_an_exact_key_match() {
        assert_eq!(
            detect_doh(&req("GET", "h", "/q?dns=AAAB", &[])),
            Some(DohShape::QueryParam)
        );
        assert_eq!(
            detect_doh(&req("GET", "h", "/q?a=1&dns=AAAB&b=2", &[])),
            Some(DohShape::QueryParam)
        );
        // bare `dns` (no value) still counts.
        assert_eq!(
            detect_doh(&req("GET", "h", "/q?dns", &[])),
            Some(DohShape::QueryParam)
        );
        // benign look-alikes do NOT match.
        assert_eq!(detect_doh(&req("GET", "h", "/q?dnssec=on", &[])), None);
        assert_eq!(detect_doh(&req("GET", "h", "/q?cdns=1", &[])), None);
        assert_eq!(detect_doh(&req("GET", "h", "/q?notdns=1", &[])), None);
    }

    /// Accept detection matches the DoH JSON type even when it appears in a list
    /// alongside other media ranges (RFC 7231 §5.3.2), and ignores an unrelated
    /// Accept.
    #[test]
    fn doh_accept_matches_in_a_list_only() {
        assert_eq!(
            detect_doh(&req(
                "GET",
                "h",
                "/l",
                &[("Accept", "text/html, application/dns-json;q=0.9")]
            )),
            Some(DohShape::AcceptJson)
        );
        assert_eq!(
            detect_doh(&req("GET", "h", "/l", &[("Accept", "application/json")])),
            None
        );
    }

    /// An ordinary request is NOT DoH on any shape (the control case in the large).
    #[test]
    fn ordinary_request_is_not_doh() {
        assert_eq!(detect_doh(&req("GET", "h", "/data", &[])), None);
        assert_eq!(
            detect_doh(&req(
                "POST",
                "h",
                "/api",
                &[("Content-Type", "application/json")]
            )),
            None
        );
    }

    // ── body examination is opt-in (§5.3) ───────────────────────────────────────

    /// Body examination only fires when a specific rule requires it; the default
    /// decision path is metadata-only.
    #[test]
    fn body_examination_is_opt_in() {
        // Default allow: metadata-only.
        let metadata_only = HttpPolicy::new(vec![], V);
        let d = metadata_only.evaluate(&req("POST", "h", "/upload", &[]));
        assert!(d.allow);
        assert!(!d.body_examined, "default path must be metadata-only (D73)");

        // A rule that opts into body examination carries the flag on its decision.
        let examining = HttpPolicy::new(
            vec![HttpRule::allow(
                HttpMatcher {
                    method: None,
                    host: None,
                    path_prefix: Some("/upload".to_string()),
                },
                "body-exam:flagged-content",
                "org",
            )
            .examining_body()],
            V,
        );
        let d = examining.evaluate(&req("POST", "h", "/upload", &[]));
        assert!(d.allow);
        assert!(d.body_examined, "an opt-in rule must flag body examination");
        assert_eq!(d.provenance.rule_id, "body-exam:flagged-content");

        // A different path under the same examining policy stays metadata-only.
        let d = examining.evaluate(&req("GET", "h", "/other", &[]));
        assert!(!d.body_examined);
    }

    // ── default posture ─────────────────────────────────────────────────────────

    /// Default-allow vs default-deny posture for an unmatched request.
    #[test]
    fn default_posture_allow_vs_deny() {
        let allow = HttpPolicy::new(vec![], V);
        let d = allow.evaluate(&req("GET", "h", "/x", &[]));
        assert!(d.allow);
        assert_eq!(d.provenance.rule_id, DEFAULT_ALLOW_RULE_ID);

        let deny = HttpPolicy::new(vec![], V).with_default_deny();
        let d = deny.evaluate(&req("GET", "h", "/x", &[]));
        assert!(!d.allow);
        assert_eq!(d.provenance.rule_id, DEFAULT_DENY_RULE_ID);
        assert_eq!(d.deny_status(), Some(403));
    }

    // ── provenance projects onto the telemetry shape ────────────────────────────

    /// The HTTP-policy provenance projects losslessly onto the
    /// `telemetry_http::Provenance` the LOG-1 event carries (the mechanical
    /// migration the caller performs when it emits the decision event).
    #[test]
    fn provenance_projects_onto_telemetry() {
        let p = HttpProvenance::new("http:deny-admin-path", "system", V);
        let t = p.to_telemetry();
        assert_eq!(t.rule_id, "http:deny-admin-path");
        assert_eq!(t.policy_layer, "system");
        assert_eq!(t.policy_version, V);
    }

    // ── never-log-the-secret: RequestMeta carries no body (§5.3, D73) ────────────

    /// A type-level canary: [`RequestMeta`] has only method/host/path/headers — no
    /// body field — so a decision built off it can never carry a payload byte. The
    /// boundary `TestTelemetry_MetadataOnlyByDefault_NoBodies` structural guarantee
    /// holds by the shape. We assert by exhaustively destructuring the struct: a
    /// new field would break this and force a review.
    #[test]
    fn request_meta_carries_no_body_field() {
        let RequestMeta {
            method: _,
            host: _,
            path: _,
            headers: _,
        } = RequestMeta::default();
    }

    // ── the per-host builder ────────────────────────────────────────────────────

    #[test]
    fn builder_scopes_rules_per_host() {
        let policy = HttpPolicyBuilder::new()
            .host_rule(
                "evil.example",
                HttpRule::deny(HttpMatcher::default(), "http:deny-evil", "org"),
            )
            .global_rule(HttpRule::deny(
                HttpMatcher {
                    method: None,
                    host: None,
                    path_prefix: Some("/admin".to_string()),
                },
                "http:deny-admin",
                "system",
            ))
            .build(V);

        assert!(
            !policy
                .evaluate(&req("GET", "evil.example", "/x", &[]))
                .allow
        );
        assert!(
            policy
                .evaluate(&req("GET", "good.example", "/x", &[]))
                .allow
        );
        assert!(
            !policy
                .evaluate(&req("GET", "good.example", "/admin/s", &[]))
                .allow
        );
    }
}
