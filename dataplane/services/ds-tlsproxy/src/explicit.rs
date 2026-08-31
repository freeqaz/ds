//! TLS-2 explicit-proxy modes — the HTTP `CONNECT` endpoint and the plain-HTTP
//! (port 80) forward proxy (doc 09 §5 TLS-2; doc 12 §13.1 `connect/`).
//!
//! # What this is
//!
//! The golden image sets `HTTP_PROXY`/`HTTPS_PROXY` so well-behaved clients
//! (npm, git, most SDKs) declare their destination explicitly instead of relying
//! on the NFT-2 transparent redirect (doc 09 §5 TLS-2). This module is the
//! framework-agnostic core of the two explicit modes:
//!
//! - **`CONNECT host:port`** — the HTTPS tunnel-establishment verb. The client
//!   asks the proxy to open an opaque TCP tunnel to `host:port`; once the proxy
//!   answers `200`, the client does its own end-to-end TLS over the tunnel (no
//!   inspection at this layer — TLS-3 inspection is a separate, later step that
//!   rides the transparent/inspected path). The destination is named **in the
//!   request line**, so — unlike the transparent path's SNI peek (TLS-1) — the
//!   policy key is the client-declared authority, not a recovered `original_dst`.
//! - **plain-HTTP forward (port 80)** — an absolute-form request line
//!   (`GET http://host/path HTTP/1.1`, RFC 7230 §5.3.2) that names the upstream
//!   origin in the request target. The proxy forwards the request to that origin.
//!
//! Both modes **evaluate the identical `policy-core` rules** as the transparent
//! path (doc 09 §5 TLS-2; doc 12 §13.1 `connect/`): the host the client declares
//! is routed through [`policy_core::consumer::tls_connect_decision`] — the SAME
//! engine verdict the TLS-1 SNI check and the DNS admission both reach (POL-3, "no
//! consumer reimplements a rule"). An explicit-proxy request can therefore never
//! admit a host the transparent path would refuse, and vice-versa.
//!
//! # The pingora wiring seam (doc 12 §13.1)
//!
//! This module is the `connect/` layer's POLICY + PARSE + MARK core, kept
//! framework-agnostic exactly as the [`crate`] severing registry keeps the
//! `Severable` trait framework-agnostic. What lands here:
//!
//! - request-line parsing into a [`ProxyRequest`] (`CONNECT host:port` and the
//!   plain-HTTP absolute-form forward target);
//! - the policy evaluation ([`evaluate_request`]) over the SHARED `policy-core`
//!   verdict, producing an [`ExplicitVerdict`];
//! - the [`UpstreamConnect`] descriptor a connect must satisfy, carrying the
//!   `0x2` upstream-leg DS mark every upstream socket carries **before connect**
//!   (§4.2 frozen — "every upstream socket type (TLS-1 tunnel, TLS-2 CONNECT,
//!   TLS-3 re-originated, TLS-5 swap) carries a DS mark before connect");
//! - the per-request telemetry record ([`RequestTelemetry`]) the LOG-1 emitter
//!   serializes (doc 09 §5 TLS-2 done-when — "per-request telemetry").
//!
//! What does NOT land here, and is M0-host integration work (doc 12 §13.1 — the
//! Pingora dependency stays inside the listener/connect layer):
//!
//! - the real pingora listener that accepts the proxy connection, reads the
//!   request bytes, and (for `CONNECT`) splices the two sockets after a `200`;
//! - the real upstream `TcpStream`/`SO_MARK` syscall (this module produces the
//!   [`UpstreamConnect`] descriptor — including the mark VALUE — that the connect
//!   layer applies via `tweak_new_upstream_tcp_connection` or the custom
//!   l4-connect path, doc 12 §13.5);
//! - the LOG-1 spool/scrub plumbing (`ds-telemetry`) — this module builds the
//!   event SHAPE; the emitter owns the wire/spool.
//!
//! # Frozen non-edge (doc 12 §4.2, D76)
//!
//! Like the rest of this service, the explicit path NEVER depends on `ds-nft` and
//! issues no conntrack/netlink syscall. The upstream DS mark is computed from the
//! `ds-contracts` [`ds_contracts::mark`] constants (never re-declared here, §4.2)
//! and applied with explicit-mask discipline by the connect layer — `ds-tlsproxy`
//! runs `CAP_NET_RAW` only (SO_MARK), never `CAP_NET_ADMIN`.

use crate::SessionUpstreamPools;
use ds_contracts::flush::DstKey;
use ds_contracts::mark::{self, Leg};
use ds_contracts::session::SessionRef;
use policy_core::consumer::{tls_connect_decision, Decision, DecisionKind};
use policy_core::pol1_eval::ComposedPolicy;
use std::future::Future;

/// Which explicit-proxy mode a request arrived on (doc 09 §5 TLS-2).
///
/// Both modes evaluate the identical `policy-core` rules; the mode is carried for
/// the per-request telemetry surface and so the connect layer knows whether to
/// splice an opaque tunnel (`Connect`) or forward an HTTP request (`PlainHttp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    /// `CONNECT host:port` — the HTTPS tunnel-establishment verb. The proxy opens
    /// an opaque TCP tunnel; the client runs its own end-to-end TLS over it.
    Connect,
    /// Plain-HTTP (port 80) forward proxying — an absolute-form request line
    /// (`GET http://host/path HTTP/1.1`) the proxy forwards to the origin.
    PlainHttp,
}

/// The default upstream port for each mode when the client omits one. `CONNECT`
/// requires an explicit port (RFC 7231 §4.3.6 `host:port`), so its parse rejects a
/// missing port; plain-HTTP defaults to 80 (the absolute-form `http://` scheme).
const DEFAULT_HTTP_PORT: u16 = 80;

/// A parsed explicit-proxy request: the mode plus the **client-declared** upstream
/// authority (host + port). This is the policy/telemetry key — the destination the
/// client named in the request line, which for the explicit path is authoritative
/// (the client asked us to reach exactly this host), in contrast to the
/// transparent path where the destination is a kernel-recovered `original_dst`
/// that the SNI is checked *against* (TLS-1, doc 12 §2.1 invariant 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRequest {
    /// Which explicit mode this arrived on.
    pub mode: ProxyMode,
    /// The upstream host the client declared (lowercased; an IP literal stays as
    /// written). This is the `policy-core` evaluation key — the SAME shape the
    /// transparent path's SNI / the DNS admission evaluate (POL-3).
    pub host: String,
    /// The upstream port the client declared (or the mode default).
    pub port: u16,
}

/// Why parsing an explicit-proxy request line failed. The connect layer maps each
/// to the appropriate client-facing status (a malformed `CONNECT` → `400`; these
/// are wire-shape errors, distinct from a policy *refusal*, which is a `403` on a
/// well-formed-but-denied request — see [`ExplicitVerdict`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The request line was empty or had no recognizable target.
    Empty,
    /// A `CONNECT` target was not `host:port` (the verb requires an explicit
    /// port, RFC 7231 §4.3.6) — a missing/empty/non-numeric port, or no host.
    MalformedConnectTarget,
    /// A plain-HTTP forward target was not an absolute-form `http://host[:port]/…`
    /// URI (RFC 7230 §5.3.2): a forward proxy only accepts absolute-form, never
    /// origin-form (which names no host and so cannot be policy-keyed).
    NotAbsoluteForm,
    /// The declared port was out of the `1..=65535` range or did not parse.
    BadPort,
    /// The host component was empty after stripping the scheme/port.
    EmptyHost,
}

impl ProxyRequest {
    /// Parse a `CONNECT` request target (`host:port`, RFC 7231 §4.3.6) into a
    /// [`ProxyRequest`]. The verb names the authority in the request line and
    /// requires an explicit port — a missing port is a malformed target, never a
    /// silent default (a `CONNECT host` with no port is a client bug, and
    /// defaulting it would mask it). The host is lowercased so the policy key is
    /// canonical (DNS is case-insensitive); an IP literal is left as written.
    pub fn parse_connect(target: &str) -> Result<ProxyRequest, ParseError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(ParseError::Empty);
        }
        // `host:port` — split on the LAST colon so an IPv6 literal authority
        // `[::1]:443` keeps its brackets intact (the bracketed form is the only
        // legal way to write a v6 authority; a bare `::1:443` is ambiguous and
        // rejected as a malformed target below).
        let (host, port_str) = target
            .rsplit_once(':')
            .ok_or(ParseError::MalformedConnectTarget)?;
        let host = strip_v6_brackets(host);
        if host.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        let port = parse_port(port_str)?;
        Ok(ProxyRequest {
            mode: ProxyMode::Connect,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Parse a plain-HTTP forward-proxy absolute-form request target
    /// (`http://host[:port]/path`, RFC 7230 §5.3.2) into a [`ProxyRequest`]. A
    /// forward proxy accepts ONLY absolute-form (it must learn the upstream host
    /// from the request line — origin-form names no host); the port defaults to
    /// 80 when the authority omits it. `https://` is NOT accepted here: an
    /// explicit HTTPS destination arrives as `CONNECT`, not a plain-HTTP forward
    /// (the proxy never originates TLS for the client on this path).
    pub fn parse_plain_http(target: &str) -> Result<ProxyRequest, ParseError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(ParseError::Empty);
        }
        // Absolute-form must carry the http scheme; anything else (origin-form
        // `/path`, an `https://` URI, an authority-form) is rejected — the
        // forward-proxy contract is "name the http origin in the request line".
        let rest = target
            .strip_prefix("http://")
            .ok_or(ParseError::NotAbsoluteForm)?;
        // The authority runs up to the first `/`, `?`, or `#` (the path/query/
        // fragment start); everything after is the origin-form the proxy forwards.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        let (host, port) = split_authority(authority, DEFAULT_HTTP_PORT)?;
        if host.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        Ok(ProxyRequest {
            mode: ProxyMode::PlainHttp,
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Strip the `[...]` brackets from an IPv6-literal authority host, leaving any
/// other host untouched. `[::1]` → `::1`; `example.com` → `example.com`.
fn strip_v6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Split an `host[:port]` authority into its host and port, defaulting the port to
/// `default_port` when absent. Handles a bracketed IPv6 authority (`[::1]:80`).
fn split_authority(authority: &str, default_port: u16) -> Result<(&str, u16), ParseError> {
    // Bracketed IPv6 authority: `[v6]` or `[v6]:port`.
    if let Some(after_open) = authority.strip_prefix('[') {
        let (host, rest) = after_open
            .split_once(']')
            .ok_or(ParseError::NotAbsoluteForm)?;
        let port = match rest.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if rest.is_empty() => default_port,
            None => return Err(ParseError::NotAbsoluteForm),
        };
        return Ok((host, port));
    }
    // Unbracketed authority: a single colon separates host:port; more than one
    // colon is a bare (unbracketed) v6 authority, which is illegal in a URI.
    match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            if host.contains(':') {
                // multiple colons, no brackets → illegal bare v6 authority.
                return Err(ParseError::NotAbsoluteForm);
            }
            Ok((host, parse_port(port_str)?))
        }
        None => Ok((authority, default_port)),
    }
}

/// Parse a decimal port string into a `1..=65535` value. An empty, non-numeric, or
/// out-of-range port is a [`ParseError::BadPort`] (`0` is not a connectable port).
fn parse_port(s: &str) -> Result<u16, ParseError> {
    let n: u16 = s.parse().map_err(|_| ParseError::BadPort)?;
    if n == 0 {
        return Err(ParseError::BadPort);
    }
    Ok(n)
}

/// The verdict the explicit path reaches for a parsed request — the policy
/// decision plus, on an admit, the [`UpstreamConnect`] the connect layer must
/// satisfy. Carries the per-request [`RequestTelemetry`] either way (doc 09 §5
/// TLS-2 done-when: per-request telemetry on every request, allowed or refused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitVerdict {
    /// Whether the proxy opens the upstream connection. `Some` iff the shared
    /// `policy-core` verdict [`Decision::admits`]; `None` on a refusal (deny,
    /// ask, or inert-capability-gated — none of which admits, §1.7).
    pub upstream: Option<UpstreamConnect>,
    /// The per-request telemetry record (LOG-1), emitted on EVERY request — an
    /// allow and a refusal both produce one (doc 09 §5 TLS-2; doc 12 §5.5).
    pub telemetry: RequestTelemetry,
}

impl ExplicitVerdict {
    /// Whether the proxy opens the upstream connection (the request was admitted).
    pub fn admits(&self) -> bool {
        self.upstream.is_some()
    }
}

/// What an admitted explicit request requires of the connect layer: the upstream
/// host/port to dial and the `0x2` upstream-leg DS mark to set on the socket
/// **before connect** (§4.2 frozen). The connect layer turns this into a real
/// `TcpStream` + `SO_MARK`; this descriptor is the framework-agnostic seam (doc 12
/// §13.1 — a `pingora-core` type is named only in the connect layer, everything
/// inward speaks this shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConnect {
    /// The upstream host to dial (the client-declared, lowercased authority host).
    pub host: String,
    /// The upstream port to dial.
    pub port: u16,
    /// The composed `0x2` (`Leg::TlsproxyUpstream`) DS mark VALUE the connect layer
    /// sets under [`mark::DS_MARK_MASK`] before connect (`meta mark set (mark &
    /// ~DS_MARK_MASK) | upstream_mark`, the frozen explicit-mask discipline §4.2).
    /// Computed from the `ds-contracts` constants ([`mark::compose`]); never a
    /// re-declared literal (§4.2 — "constants come from `ds-contracts`").
    ///
    /// `Some(value)` when the connection's [`SessionRef`] resolved (the interface-
    /// anchored post-NAT local address, §2.1 invariant 2). `None` when it did NOT
    /// resolve — the **mark-only-adds honest degrade** (§4.2; doc 12 §2.1): the
    /// upstream still opens, UNMARKED best-effort, and the request is NEVER refused
    /// on a derivation failure (the fail-closed boundary is the policy verdict, not
    /// the mark). This mirrors [`mark::compose`] being keyed on a resolved session's
    /// `host_session_index`, and the connect layer's own
    /// `connect_marked_upstream(None)` unmarked path — one `None` flows both places.
    pub upstream_mark: Option<u32>,
}

/// A per-request telemetry record (LOG-1, doc 12 §5.5 / doc 09 §5 TLS-2). The
/// framework-agnostic SHAPE the `ds-telemetry` emitter serializes/spools; built on
/// every request (allow and refusal alike). POL-3 provenance is mandatory on every
/// emitted event (rule 4) — carried here off the shared `policy-core` decision so
/// the explicit path's telemetry cites the same rule id / layer / version the
/// transparent path and the DNS admission cite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestTelemetry {
    /// The never-recycled session join key (doc 14 §4) — the `dstap-<idx>` tap
    /// name (LOG-2 attribution key).
    pub tap_name: String,
    /// Which explicit mode this request arrived on.
    pub mode: ProxyMode,
    /// The client-declared upstream host (the policy key).
    pub host: String,
    /// The client-declared upstream port.
    pub port: u16,
    /// Whether the request was admitted (the upstream connection opened).
    pub admitted: bool,
    /// The matched rule id (POL-3 provenance, rule 4) off the shared decision.
    pub rule_id: String,
    /// The composing policy layer (POL-3 provenance).
    pub policy_layer: String,
    /// The policy version in force (POL-3 provenance).
    pub policy_version: String,
}

/// Evaluate a parsed explicit-proxy request against the SHARED `policy-core`
/// rules (doc 09 §5 TLS-2 — "both modes evaluate the identical `policy-core`
/// rules") and produce the [`ExplicitVerdict`].
///
/// This is the single policy entry point both explicit modes funnel through: it
/// routes the client-declared host through
/// [`policy_core::consumer::tls_connect_decision`] — the SAME engine verdict the
/// TLS-1 SNI check and the DNS admission reach (POL-3, "no consumer reimplements a
/// rule") — so an explicit-proxy request can never admit a host the transparent
/// path would refuse. On an admit it builds the [`UpstreamConnect`] carrying the
/// `0x2` upstream-leg DS mark (§4.2, mark before connect); on any non-admit (deny,
/// ask, inert-capability-gated) it opens no upstream. Either way it emits a
/// per-request telemetry record carrying the decision's POL-3 provenance.
///
/// `session` is the connection's resolved [`SessionRef`], `Some` when the connect
/// layer recovered it from the interface-anchored attachment (the same `ConnOrigin`
/// session signal the transparent path uses — never a raw source IP, doc 12 §2.1
/// invariant 2); its `host_session_index` is what the `0x2` mark disambiguates on.
/// `None` when the derivation did not resolve (an unexpected post-NAT local, a
/// direct-to-proxy connect that never transited the redirect): the policy VERDICT
/// is session-independent so the admit/refuse is unchanged, but the admitted
/// upstream is UNMARKED best-effort and the telemetry is emitted UNATTRIBUTED —
/// the **mark-only-adds honest degrade** (§4.2), NEVER a refusal. This mirrors
/// [`connect_marked_upstream`]'s own `Option<&SessionRef>` shape (the seam this
/// verdict feeds), so one `None` flows the whole path.
pub fn evaluate_request(
    policy: &ComposedPolicy,
    session: Option<&SessionRef>,
    request: &ProxyRequest,
) -> ExplicitVerdict {
    // The ONE shared verdict — the same projection the transparent path's connect
    // and the NFT allow-set membership reach (POL-3). The explicit path keys on the
    // CLIENT-DECLARED host (it asked us to reach exactly this authority); the
    // transparent path keys on the SNI checked against the kernel original_dst. The
    // verdict is SESSION-INDEPENDENT (it keys on the host only), so an unresolved
    // session never changes admit/refuse — it only degrades the mark + attribution.
    let decision: Decision = tls_connect_decision(policy, &request.host);
    let admitted = decision.admits();

    let upstream = if admitted {
        Some(UpstreamConnect {
            host: request.host.clone(),
            port: request.port,
            // The 0x2 upstream-leg mark, composed from the ds-contracts constants
            // (§4.2 frozen — never a re-declared literal). The connect layer sets
            // it under DS_MARK_MASK before connect for EVERY upstream socket type
            // (TLS-1/TLS-2/TLS-3/TLS-5); here it is the TLS-2 CONNECT/forward leg.
            // `None` on an unresolved session: mark-only-adds — open unmarked, never
            // refuse (the fail-closed boundary is the policy verdict above).
            upstream_mark: session
                .map(|s| mark::compose(Leg::TlsproxyUpstream, s.host_session_index)),
        })
    } else {
        // A non-admit opens no upstream. This covers a policy deny (403), an
        // ask-posture host (the explicit path has no socket-hold — that is TLS-1's
        // attended-session mechanism; an explicit ask is refused, the agent's next
        // attempt succeeds once a grant lands), and an inert capability-gated entry
        // (§1.7 — admits nothing, distinct from a deny). All three: no upstream.
        debug_assert!(!matches!(decision.kind, DecisionKind::Admit));
        None
    };

    let provenance = telemetry_provenance(&decision);
    ExplicitVerdict {
        telemetry: RequestTelemetry {
            // The LOG-2 attribution key is the resolved session's never-recycled tap
            // join key. An UNRESOLVED session has no interface-anchored tap, so the
            // event is emitted UNATTRIBUTED (empty `tap_name`) rather than guessing —
            // and NEVER keyed on a raw source IP (doc 12 §2.1 invariant 2).
            tap_name: session.map(|s| s.tap_name.clone()).unwrap_or_default(),
            mode: request.mode,
            host: request.host.clone(),
            port: request.port,
            admitted,
            rule_id: provenance.0,
            policy_layer: provenance.1,
            policy_version: provenance.2,
        },
        upstream,
    }
}

/// Extract the POL-3 provenance triple (rule id, layer, version) off a shared
/// [`Decision`] for the telemetry record (rule 4 — mandatory provenance). Reads
/// the decision's own provenance so the explicit path's event cites exactly what
/// the shared engine matched, never a re-derived rule id.
fn telemetry_provenance(decision: &Decision) -> (String, String, String) {
    let p = &decision.provenance;
    (
        p.rule_id.clone(),
        p.policy_layer.clone(),
        p.policy_version.clone(),
    )
}

/// Whether an explicit-path upstream was REUSED from the session's warm pool or opened
/// FRESH on this request. Carried out of [`acquire_pooled_upstream`] for LOG-1 telemetry
/// (a reuse never re-runs the mark setsockopt — the pooled socket was already marked when
/// it was first opened) and asserted directly by the pooling tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamReuse {
    /// A warm socket taken from the session's OWN pool partition. It carries the D76
    /// `0x2` mark it was stamped with when it was first opened FOR THIS SESSION — so a
    /// reuse is marked without re-issuing the setsockopt.
    Reused,
    /// No warm socket existed for `(session, dst)`: a fresh socket was opened via
    /// `open_marked`, which set the `0x2` upstream-leg mark before connect (§4.2).
    Fresh,
}

/// Acquire the explicit-path upstream for `(session, dst)`: REUSE a warm socket from the
/// session's OWN warm-pool partition, or — on a miss — open a fresh one via `open_marked`
/// (doc 12 §4.2 D76 pool partitioning; §13.4 session-first compound reuse key).
///
/// This is the single seam that drives [`SessionUpstreamPools`] from the TLS-2
/// CONNECT / TLS-5 swap explicit warm-reuse path. The load-bearing invariant is
/// **structural cross-session isolation**: the pool is keyed session-FIRST (the
/// never-recycled `dstap-<idx>` tap name is the partition, then `dst`), so a
/// [`SessionUpstreamPools::take`] for session B only ever scans B's own partition — a
/// socket session A warmed is UNREACHABLE from a B request (never a hash collision that
/// could leak A's admitted connection past the established-state short-circuit, never a
/// mark/LOG-2 attribution skew). `dst` scopes reuse to the same upstream peer.
///
/// `open_marked` is the fresh-open seam that BOTH opens the socket AND sets the frozen
/// `0x2` (`Leg::TlsproxyUpstream`) DS mark before connect (§4.2 mark-before-connect):
/// production passes `connect_marked_upstream(dst, Some(session))`; tests pass a recording
/// [`crate::MarkSetter`] over a fake socket. So a pool MISS is always freshly marked, and
/// a pool HIT returns a socket that was marked when it was first opened for this session —
/// **every socket the explicit path connects, pooled or fresh, carries the mark**.
///
/// Returns the socket plus whether it was [`UpstreamReuse::Reused`] or
/// [`UpstreamReuse::Fresh`]. An `open_marked` error propagates unchanged (the caller maps
/// it to the `502`/unreachable outcome, exactly as the pre-pool direct dial did).
///
/// Only a caller with a resolved [`SessionRef`] pools: an UNRESOLVED session has no
/// partition identity, so the caller opens fresh UNMARKED and never pools (the §2.1
/// mark-only-adds honest degrade) — cross-session reuse cannot be made safe without a
/// session key, so it is simply not offered.
pub async fn acquire_pooled_upstream<T, F, Fut>(
    pools: &SessionUpstreamPools<T>,
    session: &SessionRef,
    dst: &DstKey,
    open_marked: F,
) -> std::io::Result<(T, UpstreamReuse)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    // Session-first take: scoped to THIS session's partition, so a cross-session reuse is
    // a structural miss (doc 12 §13.4) — never a shared connection.
    if let Some(warm) = pools.take(session, dst) {
        return Ok((warm, UpstreamReuse::Reused));
    }
    // Miss: open + mark a fresh socket (the mark rides `open_marked`, §4.2).
    let fresh = open_marked().await?;
    Ok((fresh, UpstreamReuse::Fresh))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ds_contracts::mark::{DS_MARK_MASK, INDEX_MASK};
    use ds_contracts::pol1::parse_layer;
    use policy_core::pol1_eval::compose;

    // ── Policy fixture: a single layer that allows one host and blocks another,
    //    built via the canonical parse path (the same parse→compose round-trip
    //    the consumer-surface tests use). `registry.npmjs.org` allows;
    //    `evil.example` is a severing block; everything else is unknown → ask. ──

    fn layer_allow_block() -> &'static str {
        r#"
schema_version: pol1/v0
layer: org
posture: standard
allowlist:
  - domain: registry.npmjs.org
blocklist:
  - domain: evil.example
    reason: tls2-test-block
    rung: block+log
"#
    }

    fn composed() -> ComposedPolicy {
        compose(
            &[parse_layer(layer_allow_block()).expect("layer parses clean")],
            &[],
        )
    }

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    // ── CONNECT parsing ─────────────────────────────────────────────────────────

    #[test]
    fn connect_target_parses_host_and_port() {
        let r = ProxyRequest::parse_connect("registry.npmjs.org:443").unwrap();
        assert_eq!(r.mode, ProxyMode::Connect);
        assert_eq!(r.host, "registry.npmjs.org");
        assert_eq!(r.port, 443);
    }

    #[test]
    fn connect_lowercases_the_host_for_a_canonical_policy_key() {
        // DNS is case-insensitive; the policy key must be canonical so a client
        // can't dodge a rule by varying case.
        let r = ProxyRequest::parse_connect("Registry.NPMJS.org:443").unwrap();
        assert_eq!(r.host, "registry.npmjs.org");
    }

    #[test]
    fn connect_requires_an_explicit_port() {
        // CONNECT names host:port; a missing port is malformed, never defaulted.
        assert_eq!(
            ProxyRequest::parse_connect("registry.npmjs.org"),
            Err(ParseError::MalformedConnectTarget)
        );
    }

    #[test]
    fn connect_rejects_bad_and_zero_ports() {
        assert_eq!(ProxyRequest::parse_connect("h:0"), Err(ParseError::BadPort));
        assert_eq!(
            ProxyRequest::parse_connect("h:notaport"),
            Err(ParseError::BadPort)
        );
        assert_eq!(
            ProxyRequest::parse_connect("h:99999"),
            Err(ParseError::BadPort)
        );
    }

    #[test]
    fn connect_empty_target_is_empty_error() {
        assert_eq!(ProxyRequest::parse_connect("   "), Err(ParseError::Empty));
    }

    #[test]
    fn connect_parses_bracketed_v6_literal_authority() {
        // [::1]:443 — split on the LAST colon keeps the bracketed v6 intact.
        let r = ProxyRequest::parse_connect("[::1]:443").unwrap();
        assert_eq!(r.host, "::1");
        assert_eq!(r.port, 443);
    }

    // ── plain-HTTP forward parsing ───────────────────────────────────────────────

    #[test]
    fn plain_http_parses_absolute_form_and_defaults_port_80() {
        let r =
            ProxyRequest::parse_plain_http("http://deb.debian.org/dists/stable/Release").unwrap();
        assert_eq!(r.mode, ProxyMode::PlainHttp);
        assert_eq!(r.host, "deb.debian.org");
        assert_eq!(r.port, DEFAULT_HTTP_PORT);
        assert_eq!(r.port, 80);
    }

    #[test]
    fn plain_http_honours_an_explicit_port() {
        let r = ProxyRequest::parse_plain_http("http://mirror.example:8080/x").unwrap();
        assert_eq!(r.host, "mirror.example");
        assert_eq!(r.port, 8080);
    }

    #[test]
    fn plain_http_authority_with_no_path_parses() {
        let r = ProxyRequest::parse_plain_http("http://example.com").unwrap();
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 80);
    }

    #[test]
    fn plain_http_rejects_origin_form_and_https() {
        // Origin-form (`/path`) names no host — a forward proxy cannot key it.
        assert_eq!(
            ProxyRequest::parse_plain_http("/dists/stable/Release"),
            Err(ParseError::NotAbsoluteForm)
        );
        // An explicit HTTPS destination arrives as CONNECT, never a plain forward.
        assert_eq!(
            ProxyRequest::parse_plain_http("https://example.com/"),
            Err(ParseError::NotAbsoluteForm)
        );
    }

    #[test]
    fn plain_http_parses_bracketed_v6_authority() {
        let r = ProxyRequest::parse_plain_http("http://[2001:db8::1]:80/p").unwrap();
        assert_eq!(r.host, "2001:db8::1");
        assert_eq!(r.port, 80);
    }

    #[test]
    fn plain_http_rejects_bare_unbracketed_v6_authority() {
        // A bare (unbracketed) v6 authority is ambiguous and illegal in a URI.
        assert_eq!(
            ProxyRequest::parse_plain_http("http://2001:db8::1/p"),
            Err(ParseError::NotAbsoluteForm)
        );
    }

    // ── identical-policy evaluation (the TLS-2 headline) ─────────────────────────

    #[test]
    fn connect_to_an_allowed_host_admits_and_opens_an_upstream() {
        let policy = composed();
        let s = session(7);
        let r = ProxyRequest::parse_connect("registry.npmjs.org:443").unwrap();
        let v = evaluate_request(&policy, Some(&s), &r);
        assert!(v.admits());
        let up = v.upstream.expect("admitted → upstream");
        assert_eq!(up.host, "registry.npmjs.org");
        assert_eq!(up.port, 443);
        // telemetry carries the request, the admit, and POL-3 provenance.
        assert!(v.telemetry.admitted);
        assert_eq!(v.telemetry.mode, ProxyMode::Connect);
        assert_eq!(v.telemetry.tap_name, "dstap-7");
        assert!(!v.telemetry.policy_version.is_empty());
    }

    #[test]
    fn plain_http_to_a_blocked_host_refuses_and_opens_no_upstream() {
        let policy = composed();
        let s = session(3);
        let r = ProxyRequest::parse_plain_http("http://evil.example/x").unwrap();
        let v = evaluate_request(&policy, Some(&s), &r);
        assert!(!v.admits());
        assert!(v.upstream.is_none());
        assert!(!v.telemetry.admitted);
        assert_eq!(v.telemetry.mode, ProxyMode::PlainHttp);
        assert_eq!(v.telemetry.host, "evil.example");
    }

    #[test]
    fn both_modes_reach_the_identical_policy_verdict_for_the_same_host() {
        // The TLS-2 headline (doc 09 §5): CONNECT and plain-HTTP forward evaluate
        // the IDENTICAL policy-core rules. Same host → same admit/refuse, same
        // provenance, regardless of mode.
        let policy = composed();
        let s = session(1);

        let connect = evaluate_request(
            &policy,
            Some(&s),
            &ProxyRequest::parse_connect("evil.example:443").unwrap(),
        );
        let forward = evaluate_request(
            &policy,
            Some(&s),
            &ProxyRequest::parse_plain_http("http://evil.example/").unwrap(),
        );
        assert_eq!(connect.admits(), forward.admits());
        assert!(!connect.admits());
        // identical provenance — the SAME engine verdict, not two parallel rules.
        assert_eq!(connect.telemetry.rule_id, forward.telemetry.rule_id);
        assert_eq!(
            connect.telemetry.policy_layer,
            forward.telemetry.policy_layer
        );
        assert_eq!(
            connect.telemetry.policy_version,
            forward.telemetry.policy_version
        );
    }

    #[test]
    fn explicit_verdict_matches_the_shared_tls_connect_decision() {
        // The whole POL-3 point: the explicit path admits exactly what
        // tls_connect_decision (the transparent path's own surface) admits — no
        // reimplemented rule. Drive the shared decision directly and compare.
        let policy = composed();
        let s = session(2);
        for host in ["registry.npmjs.org", "evil.example", "unknown.example"] {
            let shared = tls_connect_decision(&policy, host);
            let r = ProxyRequest {
                mode: ProxyMode::Connect,
                host: host.into(),
                port: 443,
            };
            let v = evaluate_request(&policy, Some(&s), &r);
            assert_eq!(
                v.admits(),
                shared.admits(),
                "explicit path must agree with the shared connect decision for {host}"
            );
        }
    }

    // ── the §4.2 mark-before-connect invariant ───────────────────────────────────

    #[test]
    fn admitted_upstream_carries_the_0x2_leg_mark_under_the_mask() {
        // §4.2 frozen: every upstream socket carries a DS mark before connect.
        // The TLS-2 CONNECT/forward upstream rides the 0x2 (TlsproxyUpstream) leg,
        // composed from the ds-contracts constants (never a re-declared literal),
        // carrying this session's 14-bit index disambiguator under the mask.
        let policy = composed();
        let s = session(9);
        let r = ProxyRequest::parse_connect("registry.npmjs.org:443").unwrap();
        let up = evaluate_request(&policy, Some(&s), &r)
            .upstream
            .expect("admitted");
        // a RESOLVED session marks the upstream (Some); an unresolved one degrades
        // to None (the honest-degrade test below covers that arm).
        let m = up
            .upstream_mark
            .expect("a resolved session marks the explicit upstream");
        // the composed mark equals the ds-contracts compose() for this leg+index.
        assert_eq!(m, mark::compose(Leg::TlsproxyUpstream, 9));
        // it is the 0x2 leg, and the session index rides the low 14 bits.
        assert_eq!(
            (m & DS_MARK_MASK) >> mark::LEG_SHIFT & 0xF,
            Leg::TlsproxyUpstream.nibble()
        );
        assert_eq!(m & INDEX_MASK, 9);
        // mask discipline: no bits outside DS_MARK_MASK are ever set (§4.2).
        assert_eq!(m & !DS_MARK_MASK, 0);
    }

    #[test]
    fn an_unresolved_session_degrades_to_an_unmarked_upstream() {
        // MARK-ONLY-ADDS (§4.2): when the connect layer could not derive a SessionRef
        // (an unexpected post-NAT local / a direct-to-proxy connect that never
        // transited the redirect), the policy verdict is UNCHANGED (session-
        // independent) so an allowed host still ADMITS — but the upstream opens
        // UNMARKED (`upstream_mark == None`), never refused, and the telemetry is
        // emitted UNATTRIBUTED (empty tap_name, never a raw source IP). This is the
        // explicit-path twin of `connect_marked_upstream(None)`.
        let policy = composed();
        let r = ProxyRequest::parse_connect("registry.npmjs.org:443").unwrap();
        let v = evaluate_request(&policy, None, &r);
        assert!(
            v.admits(),
            "the verdict is session-independent — admit unchanged"
        );
        let up = v
            .upstream
            .expect("admitted → upstream (degrade never refuses)");
        assert_eq!(up.host, "registry.npmjs.org");
        assert_eq!(up.port, 443);
        assert!(
            up.upstream_mark.is_none(),
            "an unresolved session opens the upstream UNMARKED (mark-only-adds)"
        );
        // unattributed telemetry: no tap key invented, never a source IP.
        assert!(v.telemetry.tap_name.is_empty());
        assert!(v.telemetry.admitted);
        // provenance is still mandatory even when unattributed (POL-3 rule 4).
        assert!(!v.telemetry.policy_version.is_empty());
    }

    #[test]
    fn an_unresolved_session_still_refuses_a_blocked_host() {
        // The degrade only affects the mark/attribution — a policy DENY is still a
        // refusal with no upstream even when the session did not resolve (the verdict
        // keys on the host, not the session).
        let policy = composed();
        let r = ProxyRequest::parse_plain_http("http://evil.example/x").unwrap();
        let v = evaluate_request(&policy, None, &r);
        assert!(!v.admits());
        assert!(v.upstream.is_none());
        assert!(v.telemetry.tap_name.is_empty());
    }

    #[test]
    fn a_refused_request_computes_no_upstream_mark() {
        // No upstream → no mark to set: a refusal never produces an UpstreamConnect.
        let policy = composed();
        let s = session(4);
        let r = ProxyRequest::parse_plain_http("http://evil.example/").unwrap();
        assert!(evaluate_request(&policy, Some(&s), &r).upstream.is_none());
    }

    #[test]
    fn telemetry_is_emitted_for_both_an_allow_and_a_refusal() {
        // doc 09 §5 TLS-2 done-when: per-request telemetry — on EVERY request.
        let policy = composed();
        let s = session(6);
        let allow = evaluate_request(
            &policy,
            Some(&s),
            &ProxyRequest::parse_connect("registry.npmjs.org:443").unwrap(),
        );
        let refuse = evaluate_request(
            &policy,
            Some(&s),
            &ProxyRequest::parse_connect("evil.example:443").unwrap(),
        );
        assert!(allow.telemetry.admitted);
        assert!(!refuse.telemetry.admitted);
        // both carry mandatory POL-3 provenance (rule 4).
        assert!(!allow.telemetry.policy_version.is_empty());
        assert!(!refuse.telemetry.policy_version.is_empty());
    }

    // ── SessionUpstreamPools driven from the explicit warm-reuse path (D76) ──────
    //
    // `acquire_pooled_upstream` is the seam that drives the per-session warm pool from
    // the TLS-2/TLS-5 explicit upstream open. These prove the load-bearing facts with
    // FAKE sockets + a recording MarkSetter (no live network, no syscall, D50): a fresh
    // open marks the socket; a pool hit returns the previously-marked socket without a
    // re-open; session B can never take session A's pooled socket (structural isolation);
    // and `drop_session` empties only the swept session's partition.

    use crate::{mark_upstream, MarkAttempt, MarkSetter};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fake upstream socket carrying the D76 mark it was stamped with at open. The
    /// explicit-path pool is generic over the socket type, so the tests parametrise it
    /// with this instead of a live `TcpStream` (D40: the real socket type stays in
    /// `main.rs`; the framework-agnostic pooling seam is exercised here).
    #[derive(Debug, PartialEq, Eq)]
    struct FakeUpstream {
        /// The `0x2` upstream-leg mark value the open stamped (best-effort — ALWAYS
        /// computed even when the setsockopt is refused, so a pooled socket is "marked"
        /// by construction).
        mark: Option<u32>,
    }

    /// A `MarkSetter` that RECORDS every mark value it is asked to set and reports the
    /// sandbox `EPERM` outcome (the value is still computed + recorded — the best-effort
    /// contract). Proves the `0x2` mark VALUE and the CALL with no kernel involvement.
    struct RecordingMarkSetter {
        marks: RefCell<Vec<u32>>,
    }
    impl MarkSetter for RecordingMarkSetter {
        fn set_mark(&self, mark: u32) -> MarkAttempt {
            self.marks.borrow_mut().push(mark);
            MarkAttempt::PermissionDenied // tolerated sandbox outcome; value still recorded
        }
    }

    /// Drive an immediately-ready future to completion on a minimal current-thread
    /// runtime (the pooling seam is `async` for the real connect; the test opens are
    /// ready-now, so no live I/O runs — D50).
    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(f)
    }

    fn dst(s: &str) -> DstKey {
        DstKey(s.into())
    }

    /// Open a freshly-MARKED fake upstream for `session` via the recording setter — the
    /// production `connect_marked_upstream` twin (mark-before-connect, §4.2). The mark
    /// VALUE is always stamped onto the fake socket even though the setsockopt EPERMs.
    fn open_marked_fake(setter: &RecordingMarkSetter, session: &SessionRef) -> FakeUpstream {
        let (value, _attempt) = mark_upstream(setter, session);
        FakeUpstream { mark: Some(value) }
    }

    #[test]
    fn a_pool_miss_opens_and_marks_a_fresh_upstream() {
        // MISS: an empty partition opens a fresh socket through `open_marked`, which sets
        // the 0x2 upstream-leg mark before connect (§4.2). The recording setter proves the
        // VALUE composed from ds-contracts; the returned socket carries it.
        let pools: SessionUpstreamPools<FakeUpstream> = SessionUpstreamPools::new();
        let s = session(9);
        let setter = RecordingMarkSetter {
            marks: RefCell::new(Vec::new()),
        };
        let (sock, reuse) = block_on(acquire_pooled_upstream(
            &pools,
            &s,
            &dst("d:443"),
            || async { Ok::<_, std::io::Error>(open_marked_fake(&setter, &s)) },
        ))
        .expect("fresh open succeeds");
        assert_eq!(reuse, UpstreamReuse::Fresh);
        // the fresh socket carries the composed 0x2 (TlsproxyUpstream) mark for session 9.
        let expected = mark::compose(Leg::TlsproxyUpstream, 9);
        assert_eq!(sock.mark, Some(expected));
        // the mark setter was invoked exactly once, with that value (mark-before-connect).
        assert_eq!(*setter.marks.borrow(), vec![expected]);
    }

    #[test]
    fn a_pool_hit_returns_the_previously_marked_socket_without_reopening() {
        // HIT: a socket the session previously warmed (and that carries the 0x2 mark from
        // its own fresh open) is returned by `take` WITHOUT calling `open_marked` again —
        // so a pooled upstream is marked by construction, not re-marked on reuse.
        let pools: SessionUpstreamPools<FakeUpstream> = SessionUpstreamPools::new();
        let s = session(9);
        let expected = mark::compose(Leg::TlsproxyUpstream, 9);
        pools.put(
            &s,
            &dst("d:443"),
            FakeUpstream {
                mark: Some(expected),
            },
        );

        let opens = AtomicUsize::new(0);
        let (sock, reuse) = block_on(acquire_pooled_upstream(
            &pools,
            &s,
            &dst("d:443"),
            || async {
                opens.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(FakeUpstream { mark: None })
            },
        ))
        .expect("pool hit succeeds");
        assert_eq!(reuse, UpstreamReuse::Reused);
        assert_eq!(
            sock.mark,
            Some(expected),
            "the pooled socket carries the 0x2 mark"
        );
        assert_eq!(
            opens.load(Ordering::SeqCst),
            0,
            "a pool hit must NOT reopen (and must not re-run the mark setsockopt)"
        );
    }

    #[test]
    fn session_b_can_never_take_session_a_pooled_socket() {
        // STRUCTURAL cross-session isolation (doc 12 §4.2/§13.4): session A warms a socket
        // to a dst; session B's acquire for the SAME dst is a structural MISS (B's take
        // scans only B's tap-keyed partition), so B opens a FRESH, B-marked socket and A's
        // pooled socket is left untouched — B can never ride A's admitted connection.
        let pools: SessionUpstreamPools<FakeUpstream> = SessionUpstreamPools::new();
        let a = session(1);
        let b = session(2);
        let a_mark = mark::compose(Leg::TlsproxyUpstream, 1);
        pools.put(&a, &dst("origin:443"), FakeUpstream { mark: Some(a_mark) });

        let setter = RecordingMarkSetter {
            marks: RefCell::new(Vec::new()),
        };
        let (sock, reuse) = block_on(acquire_pooled_upstream(
            &pools,
            &b,
            &dst("origin:443"),
            || async { Ok::<_, std::io::Error>(open_marked_fake(&setter, &b)) },
        ))
        .expect("B opens fresh on the structural miss");
        assert_eq!(reuse, UpstreamReuse::Fresh, "B's take is a structural miss");
        assert_eq!(
            sock.mark,
            Some(mark::compose(Leg::TlsproxyUpstream, 2)),
            "B's fresh socket carries B's OWN mark, never A's"
        );
        assert_ne!(
            sock.mark,
            Some(a_mark),
            "B never receives A's marked socket"
        );
        // A's pooled socket is untouched — still exactly one warm socket in A's partition.
        assert_eq!(pools.warm_count(&a), 1);
        assert_eq!(pools.warm_count(&b), 0);
    }

    #[test]
    fn drop_session_empties_only_the_swept_session_partition() {
        // Session sweep (doc 12 §8): `drop_session(A)` drops every socket A warmed and
        // NOTHING else — B's warm partition survives so a concurrent B session keeps its
        // reuse. Proves the swept-partition scoping the explicit path relies on.
        let pools: SessionUpstreamPools<FakeUpstream> = SessionUpstreamPools::new();
        let a = session(1);
        let b = session(2);
        pools.put(&a, &dst("d1:443"), FakeUpstream { mark: Some(1) });
        pools.put(&a, &dst("d2:443"), FakeUpstream { mark: Some(1) });
        pools.put(&b, &dst("d1:443"), FakeUpstream { mark: Some(2) });

        let dropped = pools.drop_session(&a);
        assert_eq!(dropped, 2, "both of A's warm sockets are dropped");
        assert_eq!(
            pools.warm_count(&a),
            0,
            "A's partition is empty after the sweep"
        );
        assert_eq!(
            pools.warm_count(&b),
            1,
            "B's partition is untouched by the A sweep"
        );

        // B can still reuse its surviving socket after A's sweep.
        let opens = AtomicUsize::new(0);
        let (_sock, reuse) = block_on(acquire_pooled_upstream(
            &pools,
            &b,
            &dst("d1:443"),
            || async {
                opens.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(FakeUpstream { mark: None })
            },
        ))
        .expect("B still reuses after A's sweep");
        assert_eq!(reuse, UpstreamReuse::Reused);
        assert_eq!(opens.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn reuse_is_scoped_to_the_same_destination() {
        // The reuse key is `(session, dst)`: a socket warmed to dst1 is NOT handed out for
        // a request to dst2 in the SAME session (a pooled socket is only ever reused for
        // the peer it was opened to).
        let pools: SessionUpstreamPools<FakeUpstream> = SessionUpstreamPools::new();
        let s = session(5);
        pools.put(&s, &dst("dst1:443"), FakeUpstream { mark: Some(7) });

        let opens = AtomicUsize::new(0);
        let (sock, reuse) = block_on(acquire_pooled_upstream(
            &pools,
            &s,
            &dst("dst2:443"),
            || async {
                opens.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(FakeUpstream { mark: Some(8) })
            },
        ))
        .expect("a different dst is a miss");
        assert_eq!(
            reuse,
            UpstreamReuse::Fresh,
            "a different dst does not reuse"
        );
        assert_eq!(sock.mark, Some(8));
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        // the dst1 socket is still warm — untouched by the dst2 miss.
        assert_eq!(pools.warm_count(&s), 1);
    }
}
