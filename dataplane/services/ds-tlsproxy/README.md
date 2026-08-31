# ds-tlsproxy

**The TLS/HTTP-CONNECT-terminating egress gateway and credential swapper** — the second boundary
service of the D63 split and the L7 policy authority for all HTTP(S) (D42). It owns
every HTTP(S) byte leaving a session: TLS termination via the per-session interception
CA (D17), HTTP-level policy and telemetry, the credential swap that keeps long-lived
secrets out of the agent's world (D8/D39), and opaque pass-through tunnels for
cert-pinned clients (doc 12 §1).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15)
- **Governing decisions:** D40 (pingora-core 0.8.x, pinned + vendored, with a written
  re-evaluation trigger), D69 (REDIRECT v0 behind the frozen `ConnOrigin` recovery
  seam, doc 12 §2),
  D70 (QUIC posture), D73 (SecretMatcher hook,
  doc 12 §5),
  D76 (kernel defense-in-depth + capability posture,
  doc 12 §4.2),
  D17/D74 (inspection CA; pass-through list ships EMPTY)

## The two load-bearing non-edges

| Rule | Why |
|---|---|
| **NEVER depends on `ds-nft`** (doc 12 §4.2). CI asserts the dependency-graph invariant; the `Cargo.toml` comment records it | Capability posture: `ds-tlsproxy` gets **CAP_NET_RAW only** (systemd `AmbientCapabilities`; enough for SO_MARK since Linux 5.17), never CAP_NET_ADMIN — which gates nftables netlink. A compromised proxy must not rewrite the ruleset that contains it. Only `ds-dnsgate` / the host agent write nftables objects (D76) |
| **Read-only consumer of the DNS-2b admission map** — read synchronously on every TLS-1/TLS-4 connection, written only by `ds-dnsgate` | Single-writer discipline (doc 11 §5.2; doc 14 §3) |

## Frozen contract highlights (full text: doc 12)

- **`ConnOrigin` recovery seam (D69):** `original_dst` only from a kernel source
  (never SNI/Host); `session` only from an interface-anchored signal (never raw
  source IP); recovery failure refuses; the admission signature
  `allow = f(session, sni, original_dst)` is mechanism-independent.
- **TLS (D17):** per-session CA TLS termination at the egress gateway, strict upstream WebPKI; ECH / absent-SNI /
  IP-literal refused; **pass-through list ships EMPTY** (D74 — an entry requires
  reproduction evidence of a pinning failure).
- **Re-admit, not refuse (D68):** a policy-allowed SNI with no live admission
  re-resolves through full DNS-2 admission; check-to-connect must complete within
  the grace margin or re-check.
- **D76:** upstream pools partitioned per session; every upstream socket carries a
  DS mark before connect; mark constants only from `ds-contracts`.
- **D72:** never opens a control-plane policy stream; consumes the host snapshot
  (`ds-policy-snapshot`); contributes tunnel-teardown to the revocation sweep.

## Modules this service grows (doc 16 §5.2, doc 12 §5)

- **NFT-2 transparent path** (`src/transparent.rs`, BUILT — spike) — the
  `accept/` redirect listener's framework-agnostic core (doc 03 §3; doc 09 NFT-2;
  doc 12 §2/§2.1/§13.1; D2/D40/D69). Resolves the frozen mechanism-agnostic
  `ConnOrigin { original_dst, session }` at accept time: `original_dst` from a
  **kernel source only** (`SO_ORIGINAL_DST`/`IP6T_SO_ORIGINAL_DST` getsockopt via
  `socket2` — the EXACT mechanism Pingora's stock `SocketDigest::original_dst()`
  performs; the `OriginalDst` trait is the seam a TPROXY/`bpf_sk_assign` backend
  or the real `SocketDigest` slots into), `session` from an **interface-anchored
  signal only** (never raw source IP); **recovery failure REFUSES** (invariant 3,
  the §10 recovery-failure event). The opaque-tunnel `forward` splice carries bytes
  once recovery (+ in production the TLS-1 SNI/admission check) succeed. The real
  `pingora-core` listener that binds `:18080`/`:18443` and attaches the per-tap
  session is the **pingora wiring seam** (doc 12 §13.1). The `iifname`-matched
  REDIRECT ruleset is golden text in `nft/transparent-redirect.nft`; the **live
  iifname-REDIRECT demo is reboot-pending** (kernel `nft_redir`/`nft_nat` modules
  absent) — `SPIKE-NOTES.md` marks validated-now (loopback + the real getsockopt
  syscall + an outbound-HTTP-forwarded e2e) vs deferred honestly.
- **TLS-2 explicit-proxy modes** (`src/explicit.rs`, BUILT) — the HTTP `CONNECT`
  endpoint and the plain-HTTP (port 80) forward proxy (doc 09 §5 TLS-2; doc 12
  §13.1 `connect/`). The golden image sets `HTTP_PROXY`/`HTTPS_PROXY` so
  well-behaved clients (npm, git, most SDKs) declare their destination explicitly;
  the transparent path remains for everything that ignores proxy variables. Both
  modes **evaluate the identical `policy-core` rules** — the client-declared host
  is routed through `policy_core::consumer::tls_connect_decision`, the SAME engine
  verdict the TLS-1 SNI check and the DNS admission reach (POL-3, no consumer
  reimplements a rule). An admit yields an `UpstreamConnect` carrying the `0x2`
  upstream-leg DS mark (`mark::compose`, set before connect per §4.2); every
  request — allow or refuse — emits a per-request telemetry record carrying the
  decision's POL-3 provenance. The real pingora listener that reads the request
  bytes, splices the `CONNECT` tunnel, and applies `SO_MARK` is the **pingora
  wiring seam** (doc 12 §13.1 — `UpstreamConnect`/`ProxyRequest` are the
  framework-agnostic shapes; the socket plumbing is M0-host integration work).
- **Swap executor** — the grant-holding module: registry match → D22 Validate →
  fetch the real credential **outside the boundary** → substitute upstream → scrub
  both creds → `CredentialUseEvent`. Holds fetched credentials in memory ≤ session;
  the key store and digest producer stay off-host in the D39 trust zone (D83,
  doc 16 §5.2).
- **SecretMatcher consumer** — the D73 in-process body-filter hook; the trait and
  verdict semantics live in `policy-core`; the keyed digest feed is Identity's
  (proto frozen at Stage 0 beside the D22 seam).
- **Severing registry + revocation sweep** (`src/lib.rs`, BUILT) — the proxy-side
  half of `flush_session` (doc 12 §8; doc 14 §5; D72/D53/D68). A framework-agnostic
  registry of live tunnels and pooled upstream sockets keyed per `(SessionRef,
  DstKey, leg-set)`, implementing the frozen `ds_contracts::flush::FlushSession`
  contract as the userspace twin of `ds-nft`'s `NftWriter` (it severs sockets, not
  conntrack — **never depends on `ds-nft`**). Hosts the D53 rung-conditional caller
  (`RevocationSweep`): a revoke severs tunnels + pools **only at block-or-higher
  rung**; session-end teardown is unconditional `legs=all`; per **D68** expiry is
  never revocation (severs nothing). The `Severable` trait is the **pingora wiring
  seam** (doc 12 §13.1 — real socket `shutdown()` + pool eviction land in the
  `accept/`/`connect/` layers; the "within seconds" kill latency is M0-host
  integration work). `ds-contracts` is the service's only dependency.
- **Pause/resume hold registry** (`src/hold.rs`, BUILT) — the proxy-side consumer
  of the D46 transparent-suspend coordination marker (doc 12 §12; D46/D110/D53).
  For the **≤5-min fully-transparent** and **5–15-min best-effort** tiers it holds
  and buffers **both legs** of a paused session and resumes forwarding **only after
  the guest clock is resynced** (frozen invariant: *resume invisible ≤5 min*). The
  marker rides the `hostagent.v1` host-ward session-lifecycle channel (the D72-exempt
  class — never a `boundary.v1` message, no control-plane-inbound endpoint); its
  shape (`PauseMarker { session, phase ∈ {HOLD_BEGIN, HOLD_DEGRADE, RESUME_RESYNCED},
  tier, deadline, resume_with_clock_resync, dedup_key }`) is **PROPOSED pending
  round-4 ratification**, so it is a local in-crate type (`ds-contracts` is frozen
  v1) the future proto slot decodes into. The `Holdable` trait is the **pingora
  wiring seam** (the hold/resume twin of `Severable`); the VM-leg socket-option
  tuning (`tcp_retries2` / `TCP_USER_TIMEOUT`), buffer sizing, and the best-effort
  abandon-vs-reconnect split are §9-FREE and land on the real socket at M0-host
  integration. The **>15-min park tier consumes no marker** (`hold::park_teardown`
  reaches the severing registry's `flush_session(legs=all)` — the same body NFT-6
  teardown uses). The proxy owns the socket physics; the orchestrator owns the
  trigger, the tier, and the resume-with-resync edge.

## What must NOT live here

- **`ds-nft` linkage / any nftables write** — see above.
- **Approval surfaces** — socket-hold (D77) holds a connection while the human is
  notified over the D18 seam; the UI lives in `client/tui/`, never the proxy
  (D18/D45/D53).
- **A QUIC/HTTP-3 terminator** — deliberately absent (doc 12 §7): if the D70 trigger
  ever fires, it arrives as a separate sibling listener service behind the same
  logical `ConnOrigin` contract, not inside this binary.

## Neighbors

`ds-dnsgate` (writes the admission map this service reads), `policy-core` /
`ds-contracts` / `ds-policy-snapshot` / `ds-telemetry` (embedded), `identity/` (digest feed +
D22 Validate + D17/D82 CA mint), `assurance/conformance-adapter/` (wire-conformance
clients: curl, npm, git, pinned client, DoH-blocked).
