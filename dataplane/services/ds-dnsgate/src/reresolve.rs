//! The intra-Boundary DNS-2 **re-resolve** seam (D68 re-admit-not-refuse, doc 12 §3 /
//! §4.1, doc 14 §3).
//!
//! ds-tlsproxy's TLS-1 FORWARD gate refuses a connection whose SNI is policy-allowed but
//! has **no live admission** in the DNS-2b map (the admission expired, or DNS-2 never
//! admitted the domain on this session). D68 says: do not refuse outright — ask DNS-2
//! to **re-admit** the domain (re-evaluate policy, re-resolve, run the W1/W2
//! insert-then-answer transaction that writes a FRESH shm entry + NFT-3 element) and
//! then PROCEED on a freshly admitted address. ds-dnsgate is the sole writer of that
//! map, so it owns the re-resolve; ds-tlsproxy reaches it over this seam.
//!
//! This module is the ds-dnsgate (server) half:
//!
//! * The **hickory-free value types** ([`ReResolveRequest`] / [`ReResolveResponse`])
//!   and a hand-rolled **length-prefixed frame** codec — no gRPC/tonic/tower exist in
//!   the dataplane workspace (D40/D67), so the transport is the lightest thing that
//!   works: a tokio UDS stream with a 4-byte big-endian length prefix per frame,
//!   mirroring the "transport is free" convention the snapshot feed uses.
//! * The [`ReResolveSeam`] trait — one method, sync-shaped over plain `std`/contract
//!   types, so the orchestration is unit-testable independent of the transport.
//! * [`AdmissionReResolver`] — the PRODUCTION seam body: it routes the SAME pieces the
//!   live DNS-2 admission path uses (the [`PolicyHook`] evaluator + the shm-backed
//!   [`AdmissionStores`] W1/W2 transaction), with the resolver abstracted behind the
//!   [`ReResolver`] trait so the hickory `Forwarder` (a `main`-side, handler-private
//!   type) plugs in without dragging hickory into this module.
//! * [`serve_reresolve`] — the server loop that accepts UDS connections and answers each
//!   framed request through a seam.
//!
//! **Fail-closed by construction.** A policy `Deny`/`Ask`, an empty/unresolvable name,
//! a DNS-4-scrubbed (no plumbable address) result, or a W1/W2 transaction failure all
//! map to [`ReResolveResponse::Denied`] / [`ReResolveResponse::Failed`] — never a
//! fabricated admit. The ds-tlsproxy client maps both to `None`, so the gate refuses
//! (the boundary is never weakened by a re-resolve).

use std::sync::Arc;

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionKey, AdmissionMap, AdmissionType, AdmittedAddr, Instant, Provenance,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::policy::{DnsQueryCtx, PolicyHook, Verdict};
use crate::txn::{is_plumbable, AdmissionInputs, AdmissionOutcome, AdmissionStores};

/// The default UDS path the re-resolve seam listens on / a ds-tlsproxy client dials when
/// no explicit endpoint is configured (doc 14 §3). Both sides single-source the name
/// through [`reresolve_endpoint`] (env [`RERESOLVE_ENDPOINT_ENV`]); the default is a
/// host-local socket under `/run`, alongside the policy-feed directory convention.
pub const DEFAULT_RERESOLVE_ENDPOINT: &str = "/run/ds-dnsgate/reresolve.sock";

/// The env var both ds-dnsgate (the listener) and ds-tlsproxy (the client) read to
/// single-source the re-resolve UDS endpoint path. Unset → [`DEFAULT_RERESOLVE_ENDPOINT`].
pub const RERESOLVE_ENDPOINT_ENV: &str = "DS_DNSGATE_RERESOLVE_LISTEN";

/// The endpoint path the re-resolve seam binds / a client dials — the env override
/// ([`RERESOLVE_ENDPOINT_ENV`]) when set non-empty, else [`DEFAULT_RERESOLVE_ENDPOINT`].
/// The ONE place both sides resolve the path, so the listener and the client can never
/// drift (mirrors `admission_shm_name` single-sourcing the segment name).
pub fn reresolve_endpoint() -> String {
    match std::env::var(RERESOLVE_ENDPOINT_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => DEFAULT_RERESOLVE_ENDPOINT.to_string(),
    }
}

/// A re-resolve request: re-admit `sni_domain` for `session_uuid`. Hickory-free; the
/// wire shape is the two strings, length-prefixed (see [`encode_request`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReResolveRequest {
    /// The attributed session the admission keys on (doc 11 §5.1) — the SAME token
    /// ds-tlsproxy holds on the connection's `ConnOrigin`.
    pub session_uuid: String,
    /// The policy-allowed SNI to re-admit (the original query name DNS-2 keys on).
    pub sni_domain: String,
}

/// A re-resolve response. The three outcomes the ds-tlsproxy gate maps onto its D68
/// `ReAdmit` arm: a non-empty [`Admitted`](ReResolveResponse::Admitted) set →
/// `Proceed`; everything else → `None` → `Refuse` (fail-closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReResolveResponse {
    /// Re-admitted: the W1/W2 transaction wrote a fresh shm entry + NFT-3 element and
    /// these are the freshly admitted addresses (non-empty — an empty set is never
    /// `Admitted`, it degrades to `Failed`).
    Admitted(Vec<AdmittedAddr>),
    /// Policy DECLINED the re-admit (a `Deny`/`Ask` verdict for the name). Distinct from
    /// `Failed` so an operator can tell a policy refusal from a transport/resolve fault;
    /// both fail closed at the client.
    Denied,
    /// A genuine ds-dnsgate FAILURE on the re-resolve: the name did not resolve, every
    /// resolved address was DNS-4-scrubbed (no plumbable IP), or the W1/W2 transaction
    /// failed closed. Never a policy verdict.
    Failed,
}

/// The re-resolve seam (doc 14 §3): re-admit one `(session, sni)` through DNS-2 and
/// return the freshly admitted addresses. One sync-shaped method over plain
/// `std`/contract types so the orchestration is unit-testable without the transport.
pub trait ReResolveSeam: Send + Sync + 'static {
    /// Re-run DNS-2 admission for the request and return the outcome.
    fn reresolve(&self, req: &ReResolveRequest) -> ReResolveResponse;
}

/// A resolver for the re-admit path: resolve `sni_domain` to its terminal A/AAAA
/// addresses plus the chain-minimum TTL and the upstream answer's provenance hooks.
/// Abstracted as a trait so the production hickory [`crate::handler`] forwarder plugs in
/// from `main` (it is handler-private and hickory-bound) WITHOUT this module taking a
/// hickory dependency — the seam orchestration stays hickory-free (D67). The tests inject
/// a fixed in-proc resolver.
///
/// `Resolved` → the terminal addresses (post-CNAME-chase, pre-DNS-4-filter) + the
/// chain-minimum TTL the W2 clamp consumes. `Unresolved` → the name had no usable answer
/// (NXDOMAIN / NoData / upstream failure) — the seam fails closed.
pub trait ReResolver: Send + Sync + 'static {
    /// Resolve the original query name to its terminal addresses + chain-min TTL.
    fn resolve(&self, sni_domain: &str) -> ReResolveResolved;
}

/// The result of a [`ReResolver::resolve`]: the terminal addresses + chain-min TTL, or
/// the no-usable-answer sentinel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReResolveResolved {
    /// The name resolved to one or more terminal addresses.
    Resolved {
        /// The terminal A/AAAA addresses (post-CNAME-chase), pre-DNS-4-filter.
        terminal_addrs: Vec<std::net::IpAddr>,
        /// The chain-minimum upstream TTL (seconds) the W2 clamp consumes.
        chain_min_ttl: u32,
    },
    /// No usable answer (NXDOMAIN / NoData / upstream failure / timeout).
    Unresolved,
}

/// The PRODUCTION re-resolve seam body: re-evaluate policy, resolve, DNS-4-filter, and
/// run the SAME W1/W2 insert-then-answer transaction the live admission path runs —
/// against the SAME shm-backed [`AdmissionStores`] a ds-tlsproxy reader reads (doc 11
/// §8.4 / §3.1). Generic over the resolver (`R`), the policy evaluator (`P`), the
/// admission map (`M`), and the NFT-3 set programmer (`S`) so it binds the live pieces in
/// `main` and a fake resolver + a real (shm or in-memory) store in tests.
pub struct AdmissionReResolver<R, P, M, S>
where
    R: ReResolver,
    P: PolicyHook,
    M: AdmissionMap + Send + Sync,
    S: crate::txn::NftSetProgrammer + Send + Sync,
{
    resolver: R,
    policy: Arc<P>,
    admission: AdmissionStores<M, S>,
    /// The POL-1 `admission.grace` (seconds) the W2 shared deadline carries — threaded
    /// off the live snapshot exactly as the handler threads it (never hardcoded).
    grace_secs: u32,
}

impl<R, P, M, S> AdmissionReResolver<R, P, M, S>
where
    R: ReResolver,
    P: PolicyHook,
    M: AdmissionMap + Send + Sync,
    S: crate::txn::NftSetProgrammer + Send + Sync,
{
    /// Build the production re-resolve seam over its resolver, policy evaluator, shared
    /// admission stores, and the live POL-1 grace.
    pub fn new(
        resolver: R,
        policy: Arc<P>,
        admission: AdmissionStores<M, S>,
        grace_secs: u32,
    ) -> Self {
        Self {
            resolver,
            policy,
            admission,
            grace_secs,
        }
    }
}

impl<R, P, M, S> ReResolveSeam for AdmissionReResolver<R, P, M, S>
where
    R: ReResolver,
    P: PolicyHook,
    M: AdmissionMap + Send + Sync + 'static,
    S: crate::txn::NftSetProgrammer + Send + Sync + 'static,
{
    fn reresolve(&self, req: &ReResolveRequest) -> ReResolveResponse {
        // An empty SNI (or session) can never be a valid admission key — refuse before
        // touching policy or the resolver.
        if req.sni_domain.is_empty() || req.session_uuid.is_empty() {
            return ReResolveResponse::Denied;
        }
        // The map key is the ORIGINAL query name in lower-cased trailing-dot form (the
        // §3.1 admission key DNS-2 wrote and the SNI presents) — normalize the SNI the
        // SAME way the handler's `query_ctx` does, so the re-admit lands on the key the
        // tlsproxy reader will look up.
        let qname = normalize_qname(&req.sni_domain);

        // (1) Re-evaluate policy through the SAME engine the live admission used (POL-3 —
        // no rule reimplemented). A non-`Allow` verdict DECLINES the re-admit (D68: a
        // domain DNS-2 declines is never admitted by the proxy).
        let ctx = DnsQueryCtx {
            session: req.session_uuid.clone(),
            qname: qname.clone(),
            // A (1) record query — the re-admit re-resolves the original name's A set
            // (the AAAA leg is the handler's §3.5 settlement; the SNI flow is v4-keyed).
            qtype: 1,
            // The re-resolve has no client source socket; a loopback sentinel keeps the
            // ctx well-formed (the evaluator keys on `session`/`qname`, never the raw
            // source — doc 11 §5.1).
            source: std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
        };
        let (admit, provenance) = match self.policy.evaluate(&ctx) {
            Verdict::Allow { admit, provenance } => (admit, provenance),
            // Deny / Ask: the re-admit is policy-declined (fail-closed at the client).
            _ => return ReResolveResponse::Denied,
        };

        // (2) Resolve the name to its terminal addresses (post-CNAME-chase). No usable
        // answer → a genuine failure (the name resolves to nothing plumbable).
        let (terminal_addrs, chain_min_ttl) = match self.resolver.resolve(&qname) {
            ReResolveResolved::Resolved {
                terminal_addrs,
                chain_min_ttl,
            } => (terminal_addrs, chain_min_ttl),
            ReResolveResolved::Unresolved => return ReResolveResponse::Failed,
        };

        // (3) DNS-4 answer filter (W5): drop every unplumbable/martian address, de-dupe to
        // a distinct set (so a duplicate-stuffed answer never inflates the refcount), and
        // preserve first-occurrence order — the SAME scrub the handler runs before the
        // transaction sees the answer (doc 11 §3.1).
        let mut seen: std::collections::HashSet<std::net::IpAddr> =
            std::collections::HashSet::new();
        let filtered: Vec<std::net::IpAddr> = terminal_addrs
            .into_iter()
            .filter(|addr| is_plumbable(*addr))
            .filter(|addr| seen.insert(*addr))
            .collect();
        if filtered.is_empty() {
            // Every resolved address was scrubbed — no plumbable IP to admit (fail-closed).
            return ReResolveResponse::Failed;
        }

        // (4) Run the SAME W1/W2 insert-then-answer transaction the live admission path
        // runs, against the SAME shm-backed stores a ds-tlsproxy reader reads — so the
        // fresh entry + NFT-3 element are genuinely visible cross-process (doc 11 §8.3 /
        // §8.4). Keyed on the ORIGINAL query name, canonicalized to the DOT-LESS
        // admission-key form (doc 11 §5.1 / D131-rollout) — the IDENTICAL canonicalization
        // the live forward path (`handler::run_admission_for_answer`) runs, so the D68
        // re-admit lands on the SAME dot-less key a co-host ds-tlsproxy reads with.
        let admission_fqdn = crate::handler::admission_key_fqdn(&qname);
        let inputs = AdmissionInputs {
            session_uuid: req.session_uuid.clone(),
            session_index: session_index_from_token(&req.session_uuid),
            original_query_fqdn: admission_fqdn.clone(),
            terminal_addrs: filtered,
            chain_min_ttl,
            ttl_floor: admit.ttl_floor,
            ttl_ceil: admit.ttl_ceil,
            grace: self.grace_secs,
            provenance: to_provenance(&provenance),
            // v0: every admission is NORMAL (the guest connects directly), matching the
            // handler's forward path.
            admission_type: AdmissionType::Normal,
            real_targets: Vec::new(),
        };
        match self
            .admission
            .run_admission(&inputs, reresolve_answer_time())
        {
            AdmissionOutcome::Admitted { .. } => {}
            // A W1 fail-closed (set/map failure) or no-plumbable-address outcome is a
            // genuine failure — fail closed (the transaction left zero residue).
            AdmissionOutcome::FailClosed | AdmissionOutcome::NoPlumbableAddress => {
                return ReResolveResponse::Failed
            }
        }

        // (5) Read the freshly admitted addresses back off the SAME map the transaction
        // just wrote (proving the entry actually landed in the shared store) and return
        // them. A non-empty set → the client proceeds; an empty/absent entry degrades to
        // `Failed` (never a fabricated admit).
        let key = AdmissionKey {
            session_uuid: req.session_uuid.clone(),
            original_query_fqdn: admission_fqdn,
        };
        match self.admission.lookup(&key) {
            Some(entry) if !entry.admitted_ips.is_empty() => {
                ReResolveResponse::Admitted(entry.admitted_ips)
            }
            _ => ReResolveResponse::Failed,
        }
    }
}

/// Normalize an SNI host to the §3.1 admission-key form: lower-cased, trailing-dot
/// (FQDN) — the SAME shape `handler::query_ctx` produces, so the re-admit writes the key
/// the tlsproxy reader looks up. An already-dotted name is unchanged.
fn normalize_qname(sni: &str) -> String {
    let lower = sni.to_ascii_lowercase();
    if lower.ends_with('.') {
        lower
    } else {
        format!("{lower}.")
    }
}

/// Project the evaluator's POL-1 [`Provenance`](crate::policy::SeamProvenance) onto the
/// contract [`Provenance`] the admission entry carries — field-for-field, the SAME
/// projection the handler's `to_admission_provenance` performs.
fn to_provenance(p: &crate::policy::SeamProvenance) -> Provenance {
    Provenance {
        rule_id: p.rule_id.clone(),
        policy_layer: p.policy_layer.clone(),
        policy_version: p.policy_version.clone(),
    }
}

/// Derive the host-local session index that composes the NFT-3 element mark from the
/// session token — the SAME deterministic derivation the handler uses at the pre-stage
/// (the authoritative key is the session UUID on the map; the 14-bit index is a
/// disambiguator only, doc 11 §5.1). FNV-1a over the token, masked to 14 bits.
fn session_index_from_token(token: &str) -> u32 {
    // FNV-1a 32-bit, masked to the 14-bit NFT mark index space (`compose` reduces it
    // mod 2^14 regardless; masking here keeps the value stable/printable).
    let mut hash: u32 = 0x811c_9dc5;
    for b in token.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash & 0x3fff
}

/// The gate's clock at re-admit authorship — the W2 deadline base (the re-resolve twin of
/// the handler's `admission_answer_time`). Wall-clock nanos since the Unix epoch, clamped
/// into the `Instant` width (a clock past the u64-nanos horizon clamps rather than
/// wrapping, so the deadline never silently moves earlier).
fn reresolve_answer_time() -> Instant {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Instant::from_unix_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// Length-prefixed frame codec (hand-rolled — no tonic/tower/hyper in the dataplane).
// ─────────────────────────────────────────────────────────────────────────────

/// The hard cap on a single re-resolve frame body (bytes). A request is two short
/// strings; a response is a small address vector. The cap bounds a malformed/hostile
/// length prefix so a single connection can never make the server allocate unboundedly
/// (a length over the cap is a malformed frame → the connection is dropped).
const MAX_FRAME_BODY: u32 = 64 * 1024;

/// Encode a request body (no length prefix): `session_uuid` then `sni_domain`, each as a
/// 4-byte big-endian length + UTF-8 bytes.
fn encode_request(req: &ReResolveRequest) -> Vec<u8> {
    let mut out = Vec::new();
    encode_str(&mut out, &req.session_uuid);
    encode_str(&mut out, &req.sni_domain);
    out
}

/// Decode a request body (the length-prefixed strings encoded by [`encode_request`]).
fn decode_request(body: &[u8]) -> Option<ReResolveRequest> {
    let mut cur = body;
    let session_uuid = decode_str(&mut cur)?;
    let sni_domain = decode_str(&mut cur)?;
    // Trailing bytes are a malformed frame.
    if !cur.is_empty() {
        return None;
    }
    Some(ReResolveRequest {
        session_uuid,
        sni_domain,
    })
}

/// Response tag bytes (first body byte): the discriminant the wire carries.
const TAG_ADMITTED: u8 = 0;
const TAG_DENIED: u8 = 1;
const TAG_FAILED: u8 = 2;

/// Encode a response body (no length prefix): a 1-byte tag, then for `Admitted` the
/// address vector (a 4-byte count, then per address a 1-byte family + a length-prefixed
/// octet blob).
fn encode_response(resp: &ReResolveResponse) -> Vec<u8> {
    let mut out = Vec::new();
    match resp {
        ReResolveResponse::Admitted(addrs) => {
            out.push(TAG_ADMITTED);
            out.extend_from_slice(&(addrs.len() as u32).to_be_bytes());
            for a in addrs {
                out.push(match a.family {
                    AddressFamily::V4 => 4,
                    AddressFamily::V6 => 6,
                });
                out.extend_from_slice(&(a.octets.len() as u32).to_be_bytes());
                out.extend_from_slice(&a.octets);
            }
        }
        ReResolveResponse::Denied => out.push(TAG_DENIED),
        ReResolveResponse::Failed => out.push(TAG_FAILED),
    }
    out
}

/// Decode a response body (encoded by [`encode_response`]). A malformed frame → `None`,
/// which the client maps to `Failed` (fail-closed).
fn decode_response(body: &[u8]) -> Option<ReResolveResponse> {
    let (&tag, mut cur) = body.split_first()?;
    match tag {
        TAG_ADMITTED => {
            let count = decode_u32(&mut cur)?;
            let mut addrs = Vec::with_capacity(count.min(MAX_FRAME_BODY) as usize);
            for _ in 0..count {
                let (&fam, rest) = cur.split_first()?;
                cur = rest;
                let family = match fam {
                    4 => AddressFamily::V4,
                    6 => AddressFamily::V6,
                    _ => return None,
                };
                let octets = decode_bytes(&mut cur)?;
                // The octet width must match the family (4 for V4, 16 for V6) — a
                // mismatched blob is a malformed frame.
                let want = match family {
                    AddressFamily::V4 => 4,
                    AddressFamily::V6 => 16,
                };
                if octets.len() != want {
                    return None;
                }
                addrs.push(AdmittedAddr { family, octets });
            }
            if !cur.is_empty() {
                return None;
            }
            Some(ReResolveResponse::Admitted(addrs))
        }
        TAG_DENIED if cur.is_empty() => Some(ReResolveResponse::Denied),
        TAG_FAILED if cur.is_empty() => Some(ReResolveResponse::Failed),
        _ => None,
    }
}

fn encode_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn decode_str(cur: &mut &[u8]) -> Option<String> {
    let bytes = decode_bytes(cur)?;
    String::from_utf8(bytes).ok()
}

fn decode_bytes(cur: &mut &[u8]) -> Option<Vec<u8>> {
    let len = decode_u32(cur)? as usize;
    if len > MAX_FRAME_BODY as usize || cur.len() < len {
        return None;
    }
    let (head, tail) = cur.split_at(len);
    *cur = tail;
    Some(head.to_vec())
}

fn decode_u32(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let (head, tail) = cur.split_at(4);
    *cur = tail;
    Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
}

/// Write a length-prefixed frame (a 4-byte big-endian body length + the body) to the
/// stream and flush it.
async fn write_frame(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    if body.len() as u64 > MAX_FRAME_BODY as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "re-resolve frame body over cap",
        ));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Read ONE length-prefixed frame body from the stream (the 4-byte length, then the
/// body). A length over [`MAX_FRAME_BODY`] is a malformed frame.
async fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "re-resolve frame length over cap",
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

// ─────────────────────────────────────────────────────────────────────────────
// The UDS server loop.
// ─────────────────────────────────────────────────────────────────────────────

/// Serve the re-resolve seam over a bound [`UnixListener`]: accept each connection, read
/// ONE framed [`ReResolveRequest`], run the seam, and write the framed
/// [`ReResolveResponse`]. The seam call is offloaded to a blocking task
/// (`spawn_blocking`) because the production body does synchronous resolve + admission
/// work; the listener task itself never blocks. Runs until the listener errors fatally
/// (the caller spawns it on its own tokio task alongside the udp/tcp listeners).
///
/// A malformed request / read error on one connection is isolated to that connection
/// (logged, the connection dropped) — never fatal to the listener, mirroring the §5.5
/// per-query fail-closed discipline.
pub async fn serve_reresolve<S: ReResolveSeam>(listener: UnixListener, seam: Arc<S>) {
    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("ds-dnsgate: re-resolve listener accept error: {e}; stopping");
                return;
            }
        };
        let seam = Arc::clone(&seam);
        tokio::spawn(async move {
            if let Err(e) = serve_one(&mut stream, seam).await {
                // A per-connection fault is isolated — never fatal to the listener.
                eprintln!("ds-dnsgate: re-resolve connection dropped: {e}");
            }
        });
    }
}

/// Handle ONE re-resolve connection: read the framed request, run the seam (offloaded to
/// a blocking task), write the framed response.
async fn serve_one<S: ReResolveSeam>(stream: &mut UnixStream, seam: Arc<S>) -> std::io::Result<()> {
    let body = read_frame(stream).await?;
    let Some(req) = decode_request(&body) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed re-resolve request frame",
        ));
    };
    // The seam body is synchronous (resolve + admission), so run it off the listener task.
    let resp = tokio::task::spawn_blocking(move || seam.reresolve(&req))
        .await
        .map_err(|e| std::io::Error::other(format!("re-resolve seam task panicked: {e}")))?;
    write_frame(stream, &encode_response(&resp)).await
}

/// Send ONE re-resolve request to a server bound at `endpoint` over a fresh UDS
/// connection and return the response. The CLIENT-side transport, used by the ds-tlsproxy
/// production `ReResolve` (it lives here so the codec has exactly one home, shared by both
/// sides). A connect/io/decode failure surfaces as `Err` (the client maps it to `None` →
/// the gate refuses, fail-closed).
pub async fn request_over_uds(
    endpoint: &str,
    req: &ReResolveRequest,
) -> std::io::Result<ReResolveResponse> {
    let mut stream = UnixStream::connect(endpoint).await?;
    write_frame(&mut stream, &encode_request(req)).await?;
    let body = read_frame(&mut stream).await?;
    decode_response(&body).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed re-resolve response frame",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FixedStubPolicy, PolicyHook, RcodePolicy, SeamProvenance};
    use crate::txn::AdmissionStores;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ── frame codec round-trips ─────────────────────────────────────────────

    #[test]
    fn request_frame_round_trips() {
        let req = ReResolveRequest {
            session_uuid: "sess-uuid-9".into(),
            sni_domain: "Example.Test".into(),
        };
        let body = encode_request(&req);
        assert_eq!(decode_request(&body), Some(req));
    }

    #[test]
    fn response_frame_round_trips_admitted_and_terminals() {
        let v4 = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![93, 184, 216, 34],
        };
        let v6 = AdmittedAddr {
            family: AddressFamily::V6,
            octets: Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 0x10)
                .octets()
                .to_vec(),
        };
        for resp in [
            ReResolveResponse::Admitted(vec![v4.clone(), v6]),
            ReResolveResponse::Admitted(vec![v4]),
            ReResolveResponse::Denied,
            ReResolveResponse::Failed,
        ] {
            let body = encode_response(&resp);
            assert_eq!(decode_response(&body), Some(resp));
        }
    }

    #[test]
    fn malformed_response_frames_decode_to_none() {
        // Unknown tag.
        assert_eq!(decode_response(&[9]), None);
        // Admitted with a truncated count.
        assert_eq!(decode_response(&[TAG_ADMITTED, 0, 0]), None);
        // Admitted claiming one addr but no body.
        assert_eq!(decode_response(&[TAG_ADMITTED, 0, 0, 0, 1]), None);
        // A v4 family with a 16-byte (v6-width) blob is a family/width mismatch.
        let mut bad = vec![TAG_ADMITTED, 0, 0, 0, 1, 4, 0, 0, 0, 16];
        bad.extend_from_slice(&[0u8; 16]);
        assert_eq!(decode_response(&bad), None);
        // Trailing bytes after a Denied tag.
        assert_eq!(decode_response(&[TAG_DENIED, 0]), None);
    }

    // ── the production seam orchestration ────────────────────────────────────

    /// A fixed resolver returning a preset answer for any name.
    struct FixedResolver(ReResolveResolved);
    impl ReResolver for FixedResolver {
        fn resolve(&self, _sni_domain: &str) -> ReResolveResolved {
            self.0.clone()
        }
    }

    /// A policy that denies everything (so the seam's policy-decline arm is exercised).
    struct DenyAll;
    impl PolicyHook for DenyAll {
        fn evaluate(&self, _ctx: &DnsQueryCtx) -> Verdict {
            Verdict::Deny {
                rcode_policy: RcodePolicy::NxDomain,
                rung: None,
                provenance: SeamProvenance {
                    rule_id: "deny-1".into(),
                    policy_layer: "org".into(),
                    policy_version: "v0".into(),
                },
            }
        }
    }

    fn pub_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    fn allow_resolver(addrs: Vec<IpAddr>) -> FixedResolver {
        FixedResolver(ReResolveResolved::Resolved {
            terminal_addrs: addrs,
            chain_min_ttl: 300,
        })
    }

    #[test]
    fn allowed_name_re_admits_and_writes_the_shared_map() {
        // The PRODUCTION pieces: the allow-all evaluator, a fixed-answer resolver, the
        // real in-memory admission stores (the SAME store type the gate writes through).
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            allow_resolver(vec![pub_v4()]),
            Arc::new(FixedStubPolicy::new()),
            stores.clone(),
            60,
        );
        let req = ReResolveRequest {
            session_uuid: "sess-1".into(),
            sni_domain: "example.test".into(),
        };
        let resp = seam.reresolve(&req);
        // Admitted on a non-empty fresh address set.
        match &resp {
            ReResolveResponse::Admitted(addrs) => {
                assert!(
                    !addrs.is_empty(),
                    "re-admit returns a non-empty address set"
                );
                assert_eq!(addrs[0].octets, vec![93, 184, 216, 34]);
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
        // WRITE-BACK CORRECTNESS: a subsequent lookup() on the SAME stores finds the
        // fresh entry (the re-admit actually populated the shared map) — exactly what a
        // ds-tlsproxy reader on the same map would see, so the next connection tunnels
        // WITHOUT a second re-resolve.
        let entry = stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-1".into(),
                // DOT-LESS canonical admission-key fqdn (the FIX-2 reconciliation): the
                // re-admit writes the same dot-less form the live forward path writes and
                // the ds-tlsproxy SNI reader looks up.
                original_query_fqdn: "example.test".into(),
            })
            .expect("the re-admit wrote a fresh entry to the shared map");
        assert_eq!(entry.admitted_ips[0].octets, vec![93, 184, 216, 34]);
    }

    #[test]
    fn denied_name_yields_denied_and_writes_nothing() {
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            allow_resolver(vec![pub_v4()]),
            Arc::new(DenyAll),
            stores.clone(),
            60,
        );
        let resp = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-2".into(),
            sni_domain: "blocked.test".into(),
        });
        assert_eq!(resp, ReResolveResponse::Denied);
        // The policy decline left ZERO residue (no map entry).
        assert!(stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-2".into(),
                original_query_fqdn: "blocked.test.".into(),
            })
            .is_none());
    }

    #[test]
    fn unresolvable_name_fails_closed() {
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            FixedResolver(ReResolveResolved::Unresolved),
            Arc::new(FixedStubPolicy::new()),
            stores,
            60,
        );
        let resp = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-3".into(),
            sni_domain: "nxdomain.test".into(),
        });
        assert_eq!(resp, ReResolveResponse::Failed);
    }

    #[test]
    fn all_addresses_scrubbed_fails_closed() {
        // A resolver answering only martian/unplumbable addresses → every address is
        // DNS-4-scrubbed → no plumbable IP → fail-closed.
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            allow_resolver(vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ]),
            Arc::new(FixedStubPolicy::new()),
            stores,
            60,
        );
        let resp = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-4".into(),
            sni_domain: "martian.test".into(),
        });
        assert_eq!(resp, ReResolveResponse::Failed);
    }

    #[test]
    fn empty_sni_is_denied_without_touching_policy() {
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            allow_resolver(vec![pub_v4()]),
            Arc::new(FixedStubPolicy::new()),
            stores,
            60,
        );
        assert_eq!(
            seam.reresolve(&ReResolveRequest {
                session_uuid: "sess-5".into(),
                sni_domain: String::new(),
            }),
            ReResolveResponse::Denied
        );
    }

    #[test]
    fn duplicate_resolved_terminal_collapses_to_one_membership_refcount_one() {
        // Caller-independent distinct-IP: the D68 re-resolve builds its admission
        // input from `terminal_addrs` originating OUTSIDE handler.rs (the injected
        // resolver / production hickory forwarder), so the distinct-IP discipline
        // `txn::admit` enforces on the live forward path must hold HERE too. A
        // duplicate-stuffed resolver answer (the SAME plumbable IP twice) must NOT fan
        // out 1:1 into two memberships: step (3)'s `seen.insert` DNS-4 filter collapses
        // it so the re-admit writes ONE distinct admitted IP and the `(session, ip)`
        // reverse-index refcount is 1 — a later sibling-name revocation frees it
        // EXACTLY once (bias-to-under-delete). This test pins that property so the
        // dedup cannot silently regress into a 1:1 fan-out.
        let dup = pub_v4();
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            // The resolver answers with the SAME plumbable IP twice (a malformed /
            // duplicate-stuffed answer, or a non-canonical resolver).
            allow_resolver(vec![dup, dup]),
            Arc::new(FixedStubPolicy::new()),
            stores.clone(),
            60,
        );
        let resp = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-dup".into(),
            sni_domain: "dup.test".into(),
        });

        // The admitted set collapsed to the DISTINCT count (1), not the raw answer
        // count (2) — distinct-IP regardless of resolver shape.
        match &resp {
            ReResolveResponse::Admitted(addrs) => {
                assert_eq!(
                    addrs.len(),
                    1,
                    "a duplicate-stuffed answer collapses to one distinct admitted IP"
                );
                assert_eq!(addrs[0].octets, vec![93, 184, 216, 34]);
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // The fresh entry written to the shared map holds the IP ONCE (dot-less
        // canonical admission-key fqdn, the same key the live forward path writes).
        let entry = stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-dup".into(),
                original_query_fqdn: "dup.test".into(),
            })
            .expect("the re-admit wrote a fresh entry");
        assert_eq!(
            entry.admitted_ips.len(),
            1,
            "admitted_ips collapses to the distinct count regardless of producer"
        );

        // The `(session, ip)` reverse-index refcount is 1, not 2 — the membership is
        // distinct-IP, so a later revoke frees it EXACTLY once (bias-to-under-delete).
        let dup_addr = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![93, 184, 216, 34],
        };
        assert_eq!(
            stores.reverse_refcount("sess-dup", &dup_addr),
            1,
            "a duplicate-fed re-resolve increfs the distinct IP exactly once"
        );
    }

    #[test]
    fn shared_cdn_ip_across_two_sni_re_admits_ends_at_refcount_two() {
        // The LIVE D68 re-admit twin of the warm-restart shared-CDN refcount
        // invariant (b): two DISTINCT SNI names re-admit the SAME terminal CDN IP in
        // ONE session over two separate `ReResolveRequest` calls (the realistic
        // shared-CDN case — many fronted names resolve to one edge IP). Each re-admit
        // writes its OWN `(session, fqdn)` entry through the frozen DNS-2b API, both
        // referencing the shared IP, so the `(session, ip)` reverse-index refcount
        // ends at 2 — a later revocation of EITHER sibling name frees the element
        // only once, never severing the still-admitted other name (the
        // bias-to-under-delete property the §5.4 sweep depends on). This pins that the
        // live re-resolve path holds the same refcount-N property the warm-restart
        // rebuild does, so a sweep over either path is uniformly safe.
        let cdn = pub_v4(); // ONE terminal CDN IP backing both names
        let stores = AdmissionStores::new();
        let seam = AdmissionReResolver::new(
            allow_resolver(vec![cdn]),
            Arc::new(FixedStubPolicy::new()),
            stores.clone(),
            60,
        );

        // First SNI re-admits the shared CDN IP.
        let resp_a = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-cdn".into(),
            sni_domain: "a.cdn.test".into(),
        });
        assert!(matches!(resp_a, ReResolveResponse::Admitted(_)));

        // Second, DISTINCT SNI re-admits the SAME shared CDN IP in the same session.
        let resp_b = seam.reresolve(&ReResolveRequest {
            session_uuid: "sess-cdn".into(),
            sni_domain: "b.cdn.test".into(),
        });
        assert!(matches!(resp_b, ReResolveResponse::Admitted(_)));

        // Both `(session, fqdn)` entries landed in the shared map, each referencing
        // the shared IP.
        assert!(stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-cdn".into(),
                original_query_fqdn: "a.cdn.test".into(),
            })
            .is_some());
        assert!(stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-cdn".into(),
                original_query_fqdn: "b.cdn.test".into(),
            })
            .is_some());

        // The `(session, ip)` reverse-index refcount is exactly 2 — distinct-name
        // membership, the bias-to-under-delete property (warm-restart invariant (b)'s
        // live re-resolve twin).
        let cdn_addr = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![93, 184, 216, 34],
        };
        assert_eq!(
            stores.reverse_refcount("sess-cdn", &cdn_addr),
            2,
            "two SNI re-admitting one shared CDN IP end at refcount 2 (bias-to-under-delete)"
        );
    }

    // ── the UDS transport end-to-end ─────────────────────────────────────────

    #[tokio::test]
    async fn uds_round_trip_admits_through_the_seam() {
        let dir = std::env::temp_dir().join(format!("ds-reresolve-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("admit.sock");
        let _ = std::fs::remove_file(&sock);

        let stores = AdmissionStores::new();
        let seam = Arc::new(AdmissionReResolver::new(
            allow_resolver(vec![pub_v4()]),
            Arc::new(FixedStubPolicy::new()),
            stores.clone(),
            60,
        ));
        let listener = UnixListener::bind(&sock).expect("bind re-resolve test socket");
        let server = tokio::spawn(serve_reresolve(listener, seam));

        let resp = request_over_uds(
            sock.to_str().unwrap(),
            &ReResolveRequest {
                session_uuid: "sess-uds".into(),
                sni_domain: "example.test".into(),
            },
        )
        .await
        .expect("re-resolve over UDS");
        match resp {
            ReResolveResponse::Admitted(addrs) => {
                assert_eq!(addrs[0].octets, vec![93, 184, 216, 34])
            }
            other => panic!("expected Admitted over UDS, got {other:?}"),
        }
        // The cross-process round-trip wrote the shared map (the e2e the spec asks for),
        // under the DOT-LESS canonical admission-key fqdn (the FIX-2 reconciliation).
        assert!(stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-uds".into(),
                original_query_fqdn: "example.test".into(),
            })
            .is_some());

        server.abort();
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn uds_round_trip_propagates_denied() {
        let dir = std::env::temp_dir().join(format!("ds-reresolve-deny-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("deny.sock");
        let _ = std::fs::remove_file(&sock);

        let seam = Arc::new(AdmissionReResolver::new(
            allow_resolver(vec![pub_v4()]),
            Arc::new(DenyAll),
            AdmissionStores::new(),
            60,
        ));
        let listener = UnixListener::bind(&sock).expect("bind deny socket");
        let server = tokio::spawn(serve_reresolve(listener, seam));

        let resp = request_over_uds(
            sock.to_str().unwrap(),
            &ReResolveRequest {
                session_uuid: "sess-deny".into(),
                sni_domain: "blocked.test".into(),
            },
        )
        .await
        .expect("re-resolve over UDS");
        assert_eq!(resp, ReResolveResponse::Denied);

        server.abort();
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn client_unreachable_endpoint_is_an_error() {
        // A dial against a path with no listener is a connect error (the client maps it
        // to None → the gate refuses, fail-closed).
        let missing = std::env::temp_dir().join("ds-reresolve-nope.sock");
        let _ = std::fs::remove_file(&missing);
        let res = request_over_uds(
            missing.to_str().unwrap(),
            &ReResolveRequest {
                session_uuid: "x".into(),
                sni_domain: "y.test".into(),
            },
        )
        .await;
        assert!(
            res.is_err(),
            "an unreachable endpoint is an error, not a silent admit"
        );
    }
}
