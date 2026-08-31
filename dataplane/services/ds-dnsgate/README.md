# ds-dnsgate

**The DNS gating proxy** — one of the two boundary services of the D63 split. It serves
DNS to every agent VM, gives every query a `policy-core` verdict before any byte goes
upstream, and converts allowed resolutions into kernel + admission-map state: the
admission half of the default-deny design (D4/D42). It is a *forwarder with a policy
brain*, not a recursor, and it is the fleet's single resolver and therefore a DoS
chokepoint (doc 11 §1).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15)
- **Governing decisions:** D63 (service split), **D67** (stack: hickory, not Pingora —
  doc 11 §2), D68 (admission
  deadlines), D71 (denial semantics), D75 (IPv6 phases / AAAA strip), D44
  (interface-anchored attribution)

## Stack (D67 — frozen)

| Layer | Choice |
|---|---|
| Listener/framing | **hickory-server 0.26.x**, pinned + vendored |
| Query handling | custom `RequestHandler` owning every query end to end |
| Policy | `policy-core` embedded |
| Upstream | **hickory-resolver 0.26.x** forwarder pool (1.1.1.1 / 8.8.8.8 per D64; host-side egress only) |
| Process shell | **plain tokio binary — NOT Pingora** (D67: pingora-core 0.8.1 has no general-purpose UDP listener) |
| Fallback | hickory-proto/hickory-net on raw tokio — documented, not built; **no hickory types in any cross-service interface** keeps the swap a library migration |

Pins are recorded in `Cargo.toml` comments and `vendor/README.md`. As of the
hickory **pre-stage** (below) these dependencies are declared, pinned at
`[workspace.dependencies]` (hickory-server / hickory-resolver `0.26`, tokio `1.48`),
and vendored under `../../vendor/`; `.cargo/config.toml` replaces `crates-io` with
`vendored-sources`, so the workspace still builds and checks **offline** with
`--locked`.

## Pre-stage status — hickory framework validation (NOT DNS-1 complete)

This service is currently a **framework-validation pre-stage**, not the DNS-1 gate.
`main` stands up the **hickory-server 0.26.x** listener engine on a plain tokio
binary behind the **real pack-backed admission evaluator** (`src/policy.rs`:
`PolicyHook` / `PolicyCorePolicy`) on loopback high ports: every query is routed
through `policy-core`'s public `dns_admission_decision` over the SHIPPED read-only
POL-2 baseline pack (`artifacts/policy-packs/pol2-system-baseline.pol1.yaml`), built
network-free at startup (the same construction the seam tests use — fresh install,
capability-gated entries INERT). The always-`Allow` `FixedStubPolicy` is retained as
the policy `src/policy.rs` and the framework / forwarder / suppression test harnesses
run with (they validate the listener and scrub against synthetic names no shipped pack
lists), but it is **no longer the binary default**. The **hickory-resolver 0.26.x upstream
forwarder pool is now wired** (`src/handler.rs`): for the stub `Allow` ceiling the
handler runs **verdict → (scrub) → forward → scrub → respond** — it resolves the
original query name against the D64 host-side upstreams (`1.1.1.1` / `8.8.8.8`,
injectable via `ForwarderConfig`), follows the CNAME chain internally, applies the
§3.3 AAAA/HTTPS/SVCB scrub (below), and authors the scrubbed upstream answer back to
the VM. The previous fixed `198.18.0.53` sentinel answer path is gone.
hickory stays a library: every hickory type — wire types AND the
`hickory_resolver::Resolver` pool — lives only behind `src/handler.rs` (and the
private listener fields of `RunningGate`); the `PolicyHook` seam and the
`ForwarderConfig` knob are hickory-free (D67), so the documented raw-tokio fallback is
a library migration. The TCP path is served by an **accept-loop semaphore cap** in
`src/server.rs` (`GateConfig::max_tcp_connections`, injectable, default 256) — the
concurrency cap hickory itself does not provide.

The installed evaluator authors the frozen
`evaluate(DnsQueryCtx{…}) -> Verdict{Allow/Deny/Ask}` admission interface (doc 11 §4):
`PolicyCorePolicy` projects `policy-core`'s family-agnostic decision into the frozen
verdict shape — Admit → `Allow{admit, ttl_clamp}`, a policy deny → `Deny{NxDomain}`
(the §3.2 NXDOMAIN+authored-SOA shape), and unknown-domain / inert-capability postures
→ `Ask{prompt_ref}` (REFUSED + the Stage-0 ask-user seam). The **§5.3 D72 admitter-LAST
policy-distribution path is now wired end to end** (the dnsgate2 wave; see the
production-publisher status section): the host's single `WatchPolicies(from_seq)`
subscription is driven onto the host-local committed-snapshot feed by the PRODUCTION
publisher `server::run_policy_publisher` (a `PolicyVersionSource`-driven pass-through),
the single-per-host subscriber `server::watch_snapshots` commits each version
admitter-LAST through the gate's sole reload path (`RunningGate::reload_boundary_zone`),
and the §5.4 revocation sweep re-evaluates the live derived state behind that commit. The
publisher's default `PolicyVersionSource` is the `IdlePolicySource` (an exhausted stream —
no control-plane stream is opened on the offline/CI path, §5.3); the live host-agent
binding is selected behind the `DS_DNSGATE_HOST_AGENT_FEED` env gate (the doc 13 §8.4 v0
file+atomic-rename `HostLocalFeedSource`), gated exactly like `DS_NFTGATE_LIVE`. What is
still **not built** is the admission TRANSACTION behind `Allow{admit}` (W1/W2
insert-then-answer, the single shared deadline) and the nft / DNS-2b writes the §5.4 sweep
will revoke (no live nft / DNS-2b kernel writes exist to sweep yet).
**Interface-anchored attribution (D44) is now LIVE-WIRED** into the handler: when an
`AttributionTable` is wired (`StubRequestHandler::with_attribution_local` / `_per_tap`),
`query_ctx` derives the session from the never-recycled per-session tap (`attribute_local`
post-NAT local-address, or `attribute_per_tap` per-tap bind) — NEVER the raw source IP —
and FAILS CLOSED to SERVFAIL (a genuine ds-dnsgate failure, never a policy NXDOMAIN) on an
unknown interface; the recorded-source `src:<addr>` token is now the pre-stage fallback
ONLY, kept where no table is wired (and the production `main` still serves with it until the
orchestrator per-session tap registry is plumbed). The **§3.3 record scrub is now wired** on the forwarded answer path
(`src/handler.rs`): an AAAA query is answered as a fast NOERROR/NODATA with the D71
authored SOA (no upstream round-trip; the AAAA never reaches the VM), HTTPS(65)/SVCB(64)
are suppressed entirely (an explicit type-65/64 query returns NODATA with the authored
SOA, never forwarded), and any AAAA/HTTPS/SVCB RR bundled into a forwarded answer to
another qtype is stripped — identically over UDP and TCP/53 (D75/D70, doc 11 §3.3–3.4).
The **§5.5 LOG-1 `DnsEvent` surface is now wired** (`src/event.rs` + `src/handler.rs`):
every query path emits a service-internal `DnsEvent` carrying `aaaa_stripped` (the AAAA
RRs that path removed), `aaaa_only` (the D75 trigger, settled by the bounded AAAA probe —
see below), and the **live verdict's** POL-3 provenance on **every** path (doc 11 §6.7).
The type stays SERVICE-INTERNAL at this pre-stage (the `ds-contracts`/LOG-1 Stage-0
schema freeze is the separate later seam), the default sink is a no-op
(`NullSink` — there is no telemetry transport yet, only the emission sites), and tests
inject a `CapturingSink` to assert emission on every path. Still **not built** here
(DNS-1+ work): admission /
insert-then-answer (W1/W2), the single shared deadline (W2, D68),
full-admission-on-every-answer (W3), the §3.2 NXDOMAIN/REFUSED *policy-denial* shapes
(an unresolved name is NOERROR/NODATA, an upstream failure/timeout is SERVFAIL — doc 11
§8.5; the §3.3 NODATA+SOA above is a scrub, not a denial),
the orchestrator tap-registry POPULATION in `main` (the attribution table is live-wired
into the handler and fail-closed-tested, but `main` still serves with the pre-stage
recorded-source fallback, D44), and nft / DNS-2b map writes.

### Measured hickory 0.26.1 behaviors (DNS-1 spike, doc 11 §3.4)

Demonstrated and asserted by `tests/framework_validation.rs` via live UDP/TCP
round-trips against the stub gate (not read from docs). Run with
`cargo test -p ds-dnsgate`.

| DNS-1 spike item | Measured behavior (hickory 0.26.1) |
|---|---|
| **UDP truncation cap — no EDNS** | Response encoder is capped at `MAX_RECEIVE_BUFFER_SIZE = 4096`, **not 512** (`zone_handler/message_response.rs::encode`). A `>512 B` answer with no EDNS OPT is **not** truncated until it passes 4096. |
| **EDNS buffer interaction (load-bearing)** | hickory-server does **NOT** auto-echo the request's EDNS OPT. The advertised UDP buffer cap only takes effect if the `RequestHandler` attaches an EDNS OPT to the **response** (`MessageResponseBuilder::edns`). Without it the cap stays 4096 regardless of what the client advertised. The handler therefore echoes request EDNS — mandatory for correct TC behavior. |
| **EDNS floor (RFC 6891)** | An advertised payload `< 512` is clamped **up** to 512 (`Edns::set_max_payload`/`Message::max_payload`). Measured: client advertises 200 → 29 records / 511 B fit, no TC, identical to the 512 case. |
| **EDNS flag-day default** | `DEFAULT_MAX_PAYLOAD_LEN = 1232` (2020 flag day). With an echoed 1232 OPT, a `(512, 1232] B` answer that the 512 case truncated passes untruncated. |
| **TC-bit emission threshold** | Set by `emit_message_parts` when a section overflows the encoder `max_size`; the response is filled to ≤ cap and partial records are kept (measured: EDNS 512 → 29 records / 511 B / TC=1; no-EDNS → 196 records / 4091 B / TC=1). |
| **TCP truncation** | TCP encoder `max_size = u16::MAX`; **TCP answers never truncate** (TC bit never set). UDP/TCP parity: the identical query that UDP must truncate is delivered in full over TCP, with identical rcode and answer set otherwise. |
| **TCP read/idle timeout** | A TCP connection that sends no complete request within `GateConfig::tcp_timeout` (5 s default) is closed. hickory's `register_listener` enforces this via `TimeoutStream`; `src/server.rs` now serves TCP through its own capped accept loop and enforces the same per-connection read timeout around the framed read. |
| **Concurrent-connection cap** | hickory 0.26.1 has **no fixed concurrent-connection cap** — `handle_tcp` spawns one task per accepted connection (only `reap_tasks` cleans finished ones). The gate therefore **imposes its own**: `src/server.rs` runs the TCP accept loop behind an **accept-loop semaphore** (`GateConfig::max_tcp_connections`, injectable, default 256), so at most `cap` connections are served concurrently under a flood; the paired nftables conn-limit is DNS-5 territory (the two layers are complementary). Asserted under a synthetic loopback flood by `tcp_connection_cap_holds_under_flood` / `tcp_cap_serializes_concurrent_connections_to_cap`. |

## Frozen contract highlights (full text: doc 11 §3–§5)

- **Sole allow-set / admission writer.** Only this service (plus the host agent)
  writes nftables objects or the DNS-2b admission map; `ds-tlsproxy` reads the map
  synchronously, read-only.
- Insert-then-answer, synchronous, fail-closed (W1); single shared deadline across
  kernel element and map entry (W2, D68); full admission on every answer — the
  resolver cache may never create a bypass (W3).
- Denials: hard-deny = NXDOMAIN with a ds-dnsgate-authored SOA (TTL == MINIMUM ==
  POL-1 `negative_ttl`; MNAME = `denied.policy.<boundary-zone>.`, the D71 signature
  shape — the `denied.policy.` prefix is frozen, the boundary-zone suffix is a
  policy-push VALUE now carried as the POL-1 `dns.boundary_zone` field and lifted onto
  the host snapshot (`ds-policy-snapshot::PolicySnapshot::boundary_zone`), read through
  the `with_forwarder_and_dns_config` / `with_forwarder_and_boundary_zone` seam; the
  handler-local `DEFAULT_BOUNDARY_ZONE` = `boundary.` is the fallback ONLY, matching the
  snapshot's own default when a layer omits the field); ask = REFUSED, never cacheable;
  SERVFAIL is never a policy verdict (D71).
- AAAA stripped as fast NOERROR/NODATA; HTTPS/SVCB (type 65/64) suppressed entirely;
  every invariant holds identically over TCP/53 incl. TC-bit retries (D75/D70,
  doc 11 §3.3–3.4).
- Session attribution only from interface-anchored signals, never raw source IP
  (D44; three-keys-agree is a frozen NFT-2 clause).

## What must NOT live here

- **An approval surface** — ask flows travel the D18 ask-user seam to the client
  wrapper; the boundary never grows its own approval UI (doc 09 POL-5).
- **A control-plane policy stream** — one `WatchPolicies` subscriber per host, the
  host agent (D72); this service consumes the host snapshot via `ds-policy-snapshot`.
- **hickory types in any interface another crate sees** (D67).

## Neighbors

`ds-tlsproxy` (sibling, reads the DNS-2b map this service writes), `ds-nft` (its write
path), `ds-policy-snapshot`/`ds-telemetry`/`policy-core` (embedded), `artifacts/nft/` (the
bootstrap ruleset its writes layer onto), `boundary/` harness (executable spec).

## Status — wave15b (2026-06-12)

The DNS-1 pre-stage harness (hickory framework validation against a stub policy hook,
taskdb `01KTYJ72J03KD64XW502WG6B69`) was built in wave14b but **pulled at the wave14b
gate**: the vendored `tracing-0.1.44` crate's `.cargo-checksum.json` lists a `bin` file
that the repo gitignore swallows, so a fresh clone fails `cargo build --workspace
--locked`. With that blocker cleared, **wave15b lands the forwarder + hardening pair on
this service**: the upstream forwarder pool and the TCP cap / guardrail-map / RUSTSEC
hardening are now on the branch (the "Pre-stage status" and "Measured behaviors"
sections above describe the live code, not a skeleton). The full dataplane gate
(`cargo build/test/clippy -D warnings/fmt`, `--workspace --locked --offline`) is green
from a fresh clone, with `tests/framework_validation.rs` exercising the forwarder, the
TCP cap, and the two RUSTSEC reproductions network-free.

That breakage is a *class*, not an instance (any future `cargo vendor` can shadow a
crate file behind a root gitignore pattern), so it is now caught at lint time by
`scripts/check-vendor-tracked.sh` (`make check-vendor-tracked`, folded into
`repo-lints`): every path in each `dataplane/vendor/*/.cargo-checksum.json` "files" map
must be `git ls-files`-tracked, and no untracked file may lurk under
`dataplane/vendor/`. The lint loud-skips (exit 0) on pre-vendor branches that carry only
`vendor/README.md`, so it stays green until the first crate is vendored.

Re-land and follow-on work is filed in taskdb, in dispatch order:

- `01KTYNMSNBPCVV9EJAQCBAWYCJ` — the blocker fix: prune the gitignore-swallowed bin
  entry from the checksum map and re-gate the pre-stage from a fresh clone (sole owner
  of `dataplane/vendor/**` in its wave).
- `01KTYNNAX5EJM5XH73S792PX0Z` — **LANDED (wave15b)**: the hickory-resolver upstream
  forwarder pool (1.1.1.1 / 8.8.8.8 per D64) with CNAME-chain following behind the
  handler seam (D67); the sentinel answer path is replaced by verdict → forward →
  respond at the `StubVerdict::Allow` ceiling.
- `01KTYNNAXSVT0EPS7H80CN432M` — **LANDED (wave15b)**: hardening — the accept-loop
  semaphore TCP concurrent-connection cap (`src/server.rs`), the
  `dataplane/services/ds-dnsgate/**` guardrail-map row (D47), and the
  RUSTSEC-2026-0118/0119 wire-driven regressions (back-linked into the two advisory
  YAMLs; `deny.toml [advisories] ignore` stays `[]`).
- `01KTYNNAXF0Z843WSECJHEMZW2` — swap `StubVerdict` for the frozen
  `evaluate(DnsQueryCtx) -> Verdict` admission seam (doc 11 §4); additionally gated on
  the attachment-primitive spike interface freeze.

### Wave15b close-out (finalize, 2026-06-12)

Merged this wave, gate-green from a fresh clone (repo-lints, dispatch unittests,
taskdb Go build/test, full offline dataplane cargo gate): the forwarder unit above
plus five repo-hygiene units — `check-vendor-tracked` (described above,
`01KTYNNAWVBN89Q7TC86AQE501`), the `wave_sandbox.sh` snapshot diagnostics
(`01KTYNNAY4R8ZF3H7BF5BC0BTC`), and the tracked-only enumeration conversions for
`check-spdx.sh` (`01KTYQT9CN81ATT2GQB32A2231`), `check-freeze-riders.sh` CHECK 4
(`01KTYXJBX39TVNQRR0YH61M418`), and `check-doc-links.sh`
(`01KTYXJYCS79WRRV1JRMR8FT60`). The last three close instances of one cross-session
footgun class: a repo-lint that enumerates the working tree (`find`/`rglob`) instead
of `git ls-files` lets an untracked file from a parallel session's worktree
false-fail the shared gate; a guard-the-guard meta-lint to close the class outright
is queued for the next wave.

Deferred to the next loop wave on files-overlap with this wave's units (one re-scope
task each filed under `01KTYTA82DKD6A28Z42SSA1CF3`; all assertion work in this wave
ran against loopback mocks only — no live resolver was queried):

- `01KTYXJYDKVJ8GABEV3HW97B08` — doc 11 §3.3 AAAA fast-NODATA + HTTPS/SVCB
  (type 65/64) suppression on the forwarded answer path. **Landed in wave16b**
  (`src/handler.rs` + `tests/suppression_shapes.rs`); the scrub is now on the wire, as
  the pre-stage section states. The §5.5 LOG-1 `aaaa_stripped` / `aaaa_only` event
  signals were deferred to the event-surface unit then; **that unit landed in wave17b**
  (see the wave17b status section above) — the signals are now recorded on every path.
- `01KTYXJYEC3R9PQBRE1DT232Y8` — the dispatch surface for the admission-seam swap
  `01KTYNNAXF0Z843WSECJHEMZW2` (same `src/handler.rs` overlap; re-scope
  `01KTYYVR743X7C3P9BEEQEAQH4`); still freeze-gated on the attachment-primitive
  spike regardless of sequencing.
- `01KTYXJYGSE72Q8ZR57QQY9RVQ` — extending the malformed-query fuzz corpus beyond
  the RUSTSEC-2026-0119 pointer-cycle shape. **Landed in wave16b**
  (`tests/framework_validation.rs`): a fixed, bounded corpus over overlapping
  compression offsets, deep pointer chains, oversized UDP frames, a TCP
  length-prefix mismatch, and header/QD-boundary truncations, each asserted
  bounded-time with a liveness check, over both UDP and TCP/53.
- `01KTYXJYHKC5NFQB5RYKTT70KZ` — wave15b deferred manual verification of the
  env-gated live-only steps, post-land (collides with the vendor-tracked unit on
  `.github/workflows/repo-lints.yml`; re-scope `01KTYYW9N7KDA8MXHE4H5ZGHSC`).

### Wave16b close-out (finalize, 2026-06-12)

Merged this wave as one consolidated answer-path unit, gate-green from a fresh clone
(repo-lints, dispatch unittests, taskdb Go build/test, full offline dataplane cargo
gate — `build`/`test`/`clippy -D warnings`/`fmt`, `--workspace --locked --offline`):

- `01KTYXJYDKVJ8GABEV3HW97B08` — the doc 11 §3.3 record scrub on `src/handler.rs`
  (AAAA fast-NODATA + HTTPS/SVCB suppression, D70/D75; D71 authored SOA), proven by
  `tests/suppression_shapes.rs` (a network-free loopback mock upstream; 7 wire tests,
  each AAAA/HTTPS/SVCB shape over BOTH UDP and TCP/53, plus a "no upstream round-trip"
  timing assertion and a UDP/TCP parity assertion).
- `01KTYXJYGSE72Q8ZR57QQY9RVQ` — the extended malformed-query fuzz corpus on
  `tests/framework_validation.rs` (the remainder of canonical
  `01KTWJ8CWG81WCW9FA4XDN8ZYX`), a fixed bounded-iteration set over both transports.
  The two units share no file (handler/suppression vs framework_validation), so the
  consolidation carries no cross-file collision.

Still deferred (as of wave16b finalize): the §5.5 LOG-1 `aaaa_stripped` / `aaaa_only`
DnsEvent signals (no event surface in this pre-stage — the scrub BEHAVIOR is on the
wire, the SIGNALS are not yet recordable) and the `StubVerdict` → frozen
`evaluate(DnsQueryCtx) -> Verdict` admission-seam swap (`01KTYNNAXF0Z843WSECJHEMZW2`,
shares `src/handler.rs`; freeze-gated on the attachment-primitive spike). **The event
signals subsequently landed in wave17b** (the §5.5 `DnsEvent` surface — see the wave17b
status section above); the admission-seam swap stays freeze-gated.

Finalize disposition (taskdb): both landed units above are `done`, and canonical
`01KTWJ8CWG81WCW9FA4XDN8ZYX` (RUSTSEC regressions + fuzz corpus + guardrail-map
wiring) is folded `done` per its remainder row's standing instruction — its last
open deliverable was exactly this corpus. The two `src/handler.rs` follow-ups
deferred on files-overlap with this wave's answer-path unit are re-opened for the
next loop wave, each with a re-scope task filed under wave parent
`01KTYTA82DKD6A28Z42SSA1CF3`: the §5.5 event surface
(`01KTZ1ERZNG3PQYCACDVARQX1M`, re-scope `01KTZ3C5DMVWKC88S25C9P5CNN`) and the
authored-SOA MNAME boundary-zone derivation (`01KTZ1F59MGW4FBPBEW621K0T8`,
re-scope `01KTZ3CEJGZA8PDTHMWSSV836Y`). Sequencing rule carried by both re-scope
tasks: never two `src/handler.rs` units in one wave (the admission-seam swap
included).

### Wave16b — the QUIC reject companion proof (the other half of §3.3)

doc 11 §3.3 specifies **two independent controls** for QUIC, and the spec is
explicit that they get two tests and are **never merged into one assertion** (D70):

- the **steering** control for *cooperative* clients — the type-65/64 HTTPS/SVCB +
  AAAA suppression on the forwarded answer path (the deferred `01KTYXJYDKVJ…` unit
  above), which lives on *this* service; and
- the **reject** control for *non-cooperative* clients (raw QUIC libraries, curl
  `--http3-only`, WebTransport, MASQUE) — the NFT-4 udp/443 rule, which by D70 is
  **rejected with ICMP port-unreachable and counted per session, never silently
  dropped** so the off-box flip-to-inspect trigger can see the refusal.

The reject side's proof landed in wave16b (`01KTZ1EBM548JGWWJ1XCA11MKZ`) but
deliberately **not** here: it is a pure-`std` ruleset-text predicate in
**`dataplane/crates/ds-nft/src/quic_reject.rs`** (the `ds-contracts` `nft_lint`
pattern) with a `tests/nft4_quic_reject.rs` companion that imports nothing from
this dnsgate / suppression side — so the independence is a property of the
dependency graph, not just an assertion. It enforces reject-not-drop (icmp(x)
port-unreachable), per-session `counter`, and `RejectReason::QuicBlocked` staying
distinct from `DefaultDeny`, all against synthetic fixtures (no live nft, no live
DNS). The NFT-1 bootstrap artifact stays scope-fenced default-deny; the predicate
is the executable shape the later udp/443 reject rule must satisfy, nothing here is
edited.

## Status — wave17b (2026-06-13)

The two deferred `src/handler.rs` follow-ups consolidated into one unit (no two
`handler.rs` units co-dispatched, per the sequencing rule both re-scope tasks carry):

- `01KTZ1ERZNG3PQYCACDVARQX1M` — **the §5.5 LOG-1 `DnsEvent` surface** (`src/event.rs`,
  new): a SERVICE-INTERNAL `DnsEvent` (the StubVerdict pattern — hickory-free *and*
  `ds-contracts`-free; the LOG-1 Stage-0 schema freeze is the separate later seam)
  carrying `aaaa_stripped` (a count, not a bool — the soft, high-volume §3.3 signal),
  `aaaa_only` (the D75 trigger, see the decision below), an `EventPath` tag, and POL-3
  provenance. The handler emits one event on **every** query path (§6.7:
  FastNodata / ForwardedAnswer / NoData / ServFail / FormErr), behind the doc 11 §6
  `event/` module shape. The default `EventSink` is `NullSink` (no transport at the
  pre-stage); `tests/event_surface.rs` injects a `CapturingSink` and drives the handler
  directly (network-free loopback mock upstream) to assert emission + provenance on
  each path.
- `01KTZ1F59MGW4FBPBEW621K0T8` — **the authored-SOA MNAME boundary-zone derivation**:
  the MNAME the gate authors is now derived from a constructor parameter
  (`StubRequestHandler::with_forwarder_and_boundary_zone`) defaulting to the working
  name `boundary.`, so the derivation point `denied.policy.<boundary-zone>.` exists and
  is tested. A VALUE change, not a SHAPE change (D71): the `denied.policy.` prefix, the
  always-authored SOA, and TTL==MINIMUM==the POL-1 negative-TTL all stay frozen.
  `ds-policy-snapshot` had **no boundary-zone field yet** at that wave, so the value was
  threaded handler-locally — that later seam **landed in wave20b** (see below). The
  default reproduces the frozen working-name MNAME exactly
  (`tests/suppression_shapes.rs` asserts both the default and a configured zone).

## Status — wave25b (2026-06-13)

Two units landed this wave, consolidated here: the live-reload SUBSCRIBER half that
wave24b left as a later seam, and a test-only deepening of the spool integration
evidence. Both ran network-free against host-local synthetic fixtures — ds-dnsgate
never opens a control-plane stream (doc 11 §5.3), and no live host agent, claude,
podman, or cia was driven. This supersedes the "WatchPolicies subscriber is not yet
plumbed" / "subscriber loop is still a later seam" notes in the wave19b and wave24b
status sections above.

- `01KV05D22G53P8K5BA9AEDS6CG` — **the WatchPolicies host-snapshot subscriber loop
  (D72 admitter-LAST).** wave24b built and tested the boundary-zone reload SEAM
  (`RunningGate::reload_boundary_zone` re-sources the authored-SOA boundary zone on
  BOTH transports behind a shared lock, no listener re-bind), but nothing yet
  subscribed to a policy commit and called it. This wave closes the live-reload half:
  `main` now spawns the single-per-host snapshot-subscriber loop (doc 11 §5.3) that
  consumes the host-LOCAL `BoundarySnapshotFeed` (the
  `ds-policy-snapshot::PolicySnapshot::boundary_zone_value` read), and on each commit
  drives `RunningGate::reload_boundary_zone` in **admitter-LAST order** — re-sourcing
  the boundary zone only AFTER the enforcement layers (the NFT path + the
  TLS-termination egress gateway) have applied vN, so ds-dnsgate the admitter commits
  last. The redundant `StubRequestHandler::reload_boundary_zone` pub method in
  `handler.rs` is **folded into** the one `server.rs` reload path so a policy push has a
  single re-source seam. Wired through `main.rs` → `server.rs` → `handler.rs`; driven by
  host-local synthetic snapshot fixtures (a real host agent is not exercised). A policy
  push now actually re-sources the suffix in production. Per-file:
  - **`server.rs`** — `BoundarySnapshot{ seq, boundary_zone }` (the host-LOCAL
    committed-snapshot hand-off shape; the value `PolicySnapshot::boundary_zone_value`
    materializes), `boundary_snapshot_feed()` (a bounded `mpsc` so a fan-out burst
    back-pressures the host agent, never unbounded growth against the single resolver,
    §1), and `watch_policies()` — the subscriber loop. It commits each snapshot
    admitter-LAST via the SOLE reload path, and applies **D72 forward-only seq
    discipline**: a non-advancing seq (re-delivered or out-of-order host-local fan-out)
    is dropped, never re-sourced backwards (one monotonic policy version end to end, no
    per-service namespace). The boundary zone re-sources on BOTH transports in one
    commit (no per-transport skew), so the §5.4 revocation sweep that re-evaluates live
    admissions would run against one consistent authored suffix. `ds-dnsgate` NEVER
    opens a control-plane stream (§5.3): the feed is the host-local hand-off the host
    agent fans out behind its commit barrier. A `BoundaryZoneSink` trait lets the loop
    run against the REAL `RunningGate` in production AND a synthetic recorder in tests
    through the same single path; the detached `GateBoundaryReloader` handle lets `main`
    run the subscriber on its own task while keeping the gate to block on its listeners.
  - **`handler.rs`** — the redundant `StubRequestHandler::reload_boundary_zone` pub
    method is folded into the single `RunningGate` path: the gate reaches each handler's
    signature only through the cloned `BoundaryZoneReload` handle (the UDP handler is
    moved into hickory's `Server`), so a parallel handler method would let the two
    transports skew. **There is now exactly ONE reload path.**
  - **`main.rs`** — spawns the subscriber on the host-local feed driving a detached
    reloader. (**SUPERSEDED by the production-publisher status section below:** wave25b
    drove the subscriber from an env-gated single synthetic commit; the dnsgate2 wave
    replaced that scaffolding with the production publisher `server::run_policy_publisher`
    over a `PolicyVersionSource` — default `IdlePolicySource`, live binding behind
    `DS_DNSGATE_HOST_AGENT_FEED`. The wave25b synthetic-reload env gate is retired —
    there is no longer any env-gated synthetic commit on the publisher path.)

  Proven network-free (loopback / synthetic only): four `src/`-module tests in
  `server::watch_policies_tests` — the synthetic snapshot → subscriber → reload flow,
  the D72 forward-only seq drop of duplicate/stale fan-outs, the empty-value
  working-name fallback, and the **end-to-end drive of the REAL
  `RunningGate::reload_boundary_zone` admitter-LAST** (assert the live gate's authored
  MNAME moves from the startup suffix to the pushed suffix). (At wave25b these `src/`
  module tests rode alongside the integration suites; the merged-tip per-suite counts are
  recorded in the production-publisher status section below.)
- `01KV05DFN4DJDET0HPHAGNAQX8` — **three deepenings of the spool integration tests**
  in `tests/event_surface.rs`, all test-only (no production logic, `src/**` zero diff),
  strengthening the pre-Stage-0-LOG-1-freeze evidence the wave24b `SpoolSink`
  integration test established:
  - **UDP-transport parity** — the overflow test
    (`spool_wired_gate_emits_overflow_marker_under_forced_bound`) previously exercised
    only the TCP listener (`gate.tcp_local_addr()`). A UDP arm now drives a loopback
    datagram to `gate.udp_local_addr()` on the AAAA fast-NODATA path, proving a
    UDP-driven query ALSO lands a `DnsEvent` on the real spool and closing the §3.4
    byte-identical-across-transports parity gap on the telemetry surface. A
    `udp_query()` helper mirrors `tcp_query()` for raw UDP datagrams (no length prefix).
  - **Full §5.5 D75 signal-set decode** — the flush test
    (`spool_wired_gate_flushes_dns_event_to_disk`) previously asserted only `qname=`
    presence in the body. It now decodes the `0x02` `DnsEvent` body and asserts the FULL
    §5.5 D75 trigger signal set for the FastNodata arm — `qname=v6.example.test.`,
    `qtype=28`, `path=FastNodata`, `aaaa_stripped=1`, and
    `aaaa_only=Deferred(FastNodataNoForward)` — the recorded-deferral proving the §3.3
    forward-free AAAA arm fires no parallel A-probe (D75 design decision), not just the
    qname prefix.
  - **Off-tmpfs scratch** — both spool tests used `std::env::temp_dir()` (commonly
    `/tmp`, tmpfs/RAM). Both now call `spool_scratch_root()`, a new test-local helper
    that prefers `DS_WT_ROOT` (btrfs-backed `~/tmp`, same device as the repo) then
    `TMPDIR`, then falls back to `temp_dir()` — per the repo's tmpfs-avoidance
    convention (scratch under `~/tmp`, never `/tmp`).

A later seam at wave25b but **shipped since** (the dnsgate2 wave — see the
production-publisher status section below): the live host-agent PUBLISHER half of the
snapshot feed (`server::run_policy_publisher`) and the §5.4 revocation sweep of derived
state. Still NOT built: the W1/W2 insert-then-answer transaction behind `Allow{admit}`,
the orchestrator tap registry POPULATION in `main` (sibling `01KV05CN1SCEGT9MMQ6M6CANTQ`;
the live `AttributionTable` still serves with the `src:<addr>` pre-stage fallback), and
the nft / DNS-2b kernel writes the sweep will revoke. The LOG-1 Stage-0 schema freeze remains the separate later seam
the §5.5 decode assertions stay below (substring/tag-based, not coupling to the free
pre-freeze payload rendering). Green from a fresh clone (repo-lints, dispatch
unittests, taskdb Go build/test, full offline dataplane cargo build/test/clippy
`-D warnings`/fmt). No proto / docs / §6 edits; no new D-number (cites D72 / D75 /
D116; log ends at D122).

## Status — production policy-distribution publisher (dnsgate2 wave)

This section is the **current live path** and supersedes every "the live host-agent
PUBLISHER half … is a later seam" / env-gated synthetic-reload note in the wave25b and
earlier status sections above. The D72 §5.3 admitter-LAST policy-distribution chain now
runs end to end on the production code path: a PRODUCTION publisher drives the host's one
`WatchPolicies(from_seq)` subscription onto the host-local committed-snapshot feed, the
single-per-host subscriber commits each version admitter-LAST, the §5.4 revocation sweep
re-evaluates the live derived state behind that commit, and an applied-seq heartbeat
surfaces the committed identity AFTER the sweep. All of it runs network-free against
host-local synthetic fixtures — `ds-dnsgate` NEVER opens a control-plane stream (doc 11
§5.3), and no live host agent, claude, podman, or cia is driven.

### The production publisher — `server::run_policy_publisher` over a `PolicyVersionSource`

`main` spawns the PRODUCTION publisher `server::run_policy_publisher`
(`server::run_policy_publisher_with_drop_sink` is the observable variant `main` actually
wires, threading the operator drop sink below) on its own task alongside the gate's
listeners + subscriber. The publisher is a thin pass-through driven by a
`PolicyVersionSource`: for every committed `CommittedPolicyVersion` the host agent fans
out behind its prepare/commit barrier, it lifts the WHOLE committed policy (composed
document + W2 clamp + boundary zone + the `(seq, content_hash)` identity) onto the
`BoundarySnapshotFeed` through `BoundarySnapshot::with_policy_layer` — the SAME shared
`ds-policy-snapshot` accessor `main`'s startup path sources from — and the host agent's
barrier owns version ordering (the subscriber's D72 forward-only-seq discipline drops any
non-advancing fan-out).

The publisher's default `PolicyVersionSource` is `IdlePolicySource`: an EXHAUSTED
`WatchPolicies(from_seq)` stream that delivers no versions, so the production mechanism
runs unconditionally but publishes nothing on the offline/CI path and opens NO
control-plane stream (§5.3). The **live host-agent binding is selected behind the
`DS_DNSGATE_HOST_AGENT_FEED` env gate — gated exactly the way the live `ds-nft` writer is
behind `DS_NFTGATE_LIVE`**: SET → the doc 13 §8.4 v0 file+atomic-rename
`HostLocalFeedSource` over the feed directory (the env value when it names a path, else
`DEFAULT_HOST_AGENT_FEED_DIR` = `/run/ds-dnsgate/policy-feed`), resuming
`WatchPolicies(from_seq)` from the persisted applied-seq cursor (D36); UNSET → the
`IdlePolicySource`. There is no synthetic-reload env gate and no synthetic host-local feed
— the wave25b env-gated single synthetic commit is RETIRED.

### The produce-once / verify-only loader — `ds_policy_snapshot::load_verified_snapshot`

A version carrying its produce-once transported wire form is driven through the
VERIFY-ONLY loader `ds_policy_snapshot::load_verified_snapshot`, which **hash-checks the
TRANSPORTED bytes BEFORE parse** (doc 13 §5.1): it recomputes the `content_hash` over the
transported bytes and compares it to the producer-pinned wire hash, and only on a match
does it parse the POL-1 document. The two NACK verdicts both **reject the apply HOST-WIDE
and leave the host on `vN`** (it never advances), never a silent drop:

- `LoadVerdict::HashNack` — a D120 `content_hash` MISMATCH: the recomputed hash did NOT
  match the wire hash, so the loader NACKed host-wide and **NEVER parsed the bytes** (the
  tampered/corrupt transport is never fed to the POL-1 reader).
- `LoadVerdict::ParseError` — the bytes VERIFIED against the wire hash but FAILED the
  POL-1 schema parse (a §5 "schema failure"): the same integrity-rejection class as a hash
  NACK — the apply is NACKed host-wide and the host stays on `vN`.

A version with no transported wire form (the in-memory loopback hand-off) takes the
existing lift unchanged. The live file-feed path additionally threads the
separately-transported `content_hash` through the FROZEN
`ds_contracts::consumer::Consumer::prepare_verified` seam (the non-vacuous identity gate)
before the publisher's own lift, so a tampered snapshot is dropped fail-closed and the
admission map is NEVER re-sourced.

### The applied-seq heartbeat (`OperatorLogHeartbeat`) and operator drop sink (`OperatorLogDropSink`)

The `SnapshotCommitSink` reports each committed version's `AppliedSeqIdentity` —
the `(seq, content_hash, verified D120 wire-hash)` triple — through the
`AppliedSeqHeartbeat` carrier **ONLY AFTER the §5.4 revocation sweep completes** (doc 13
§5 after-sweep readiness ordering), so the surfaced `applied_seq` always names a version
whose now-denied admissions are already revoked. The loopback/synthetic carrier is
`OperatorLogHeartbeat` (it prints the forward-only `seq`, the per-version local
fingerprint, and the verified wire-hash hex an operator joins the fleet min-over-three
`applied_seq` on; `main` tees it into a `PersistingAppliedSeqHeartbeat` when an applied-seq
store is wired); a production deployment swaps in the host agent's heartbeat carrier.

The publisher's verify-only NACK drops route to `OperatorLogDropSink`, the loopback/
synthetic stand-in for the production spool. It keeps the DISTINCT non-commit reasons
joinable in operator logs: a `SnapshotDropReason::ContentHashMismatch` is the D120
integrity REJECTION (a tampered/corrupt transport) and a `SnapshotDropReason::SchemaFailure`
is the OTHER integrity rejection (verified bytes that failed the POL-1 parse) — both NACK
host-wide and an operator must act on either — while a `SnapshotDropReason::StaleFanOut` is
the benign forward-only-seq dedup (nothing to chase). The greppable `reason=` token leads
the line so the integrity rejection stays **separable from the benign `StaleFanOut`** the
subscriber raises.

### Per-section test counts (merged tip)

Network-free (loopback / synthetic only); run with `cargo test -p ds-dnsgate -p
ds-policy-snapshot`:

| Suite | Tests |
|---|---|
| `ds-dnsgate` lib unittests (`src/lib.rs`) | 188 |
| `ds-dnsgate` main unittests (`src/main.rs`) | 10 |
| `tests/event_surface.rs` | 36 |
| `tests/framework_validation.rs` | 21 |
| `tests/policy_seam.rs` | 4 |
| `tests/policy_verdict.rs` | 22 |
| `tests/querypath_guardrails.rs` | 9 |
| `tests/suppression_shapes.rs` | 9 |
| `tests/sweep.rs` | 4 |
| `ds-policy-snapshot` (`src/lib.rs`) | 27 |

The one residual seam on the publisher path is the CROSS-PROCESS Go D35 host-agent
fan-out half — the host's sole control-plane `WatchPolicies` subscriber that writes
committed versions INTO the host-local feed directory `DS_DNSGATE_HOST_AGENT_FEED` names.
That producer lives OUTSIDE this dataplane workspace (a separate host-agent task); the
dataplane-side CONSUMER+publisher documented here is shipped and reads what it
atomic-renames in.

Still NOT built (a later seam): the W1/W2 insert-then-answer admission TRANSACTION behind
`Allow{admit}`, the orchestrator tap-registry POPULATION in `main` (the live
`AttributionTable` still serves with the `src:<addr>` pre-stage fallback), and the nft /
DNS-2b kernel writes the §5.4 sweep will revoke.

## Status — wave24b (2026-06-13)

The §5.5 sink-collapse (a `DnsEvent` now encodes to an `EventEnvelope` and rides the
real `ds_telemetry::SpoolSink` via the `TelemetrySink` adapter — replace the sink, never
the emission sites, doc 11 §5.5) had so far been covered only by `CapturingSink`
in-process unit tests. This wave adds the first **network-free integration test driving
the gate end-to-end over a real `ds_telemetry::SpoolSink`** (not a null/stub), in its own
fenced unit touching only `tests/event_surface.rs`:

- `01KTZYSM527A7CNYZBQ3PAFB7C` — `tests/event_surface.rs` gains two tests that bind the
  gate on `127.0.0.1:0` (OS-assigned loopback port, no network, no live tooling) and
  wire `spawn_gate_with_sink` to a `TelemetrySink` over a live `ds_telemetry::Spool`:
  - `spool_wired_gate_flushes_dns_event_to_disk` — one AAAA query drives the §3.3
    fast-NODATA path (no upstream contact); the authored `DnsEvent` flows
    `to_envelope` → `SpoolSink` → flush task → segment file, and the test reads the raw
    segment bytes back and asserts a `DnsEvent` record (free-encoding kind tag `0x02`)
    carrying the queried `qname=` payload landed, with **no** overflow marker on the
    normal path.
  - `spool_wired_gate_emits_overflow_marker_under_forced_bound` — a tiny-bound spool
    (`max_records = 1`, `batch_size = 100`, `flush_interval = 60s` so neither auto-drain
    nor the ticker races the test window) is driven with three queries; the drop-oldest
    bound fires, and the test asserts both a `SpoolOverflow` marker (priority-lane `0xFF`
    tag) **and** a surviving `DnsEvent` payload record land on disk — the D116 visible-loss
    invariant proven through the production gate path, the marker riding the surviving
    stream rather than replacing it.

  The on-disk frame walk (1-byte tag, 4-byte big-endian length, body) mirrors
  `ds_telemetry::spool::append_batch`; the assertions are substring/tag-based, so they do
  not couple to the free pre-freeze payload rendering beyond the documented signals. Zero
  diff to `src/**`, `dataplane/crates/ds-telemetry/**`, `ds-contracts`, and proto; no new
  D-number (cites D116 / D67 / D75). The sink-wired constructor `spawn_gate_with_sink` and
  the `TelemetrySink` adapter were already present on the pinned base, so the test asserts
  against the real production wiring — not a fixture stand-in.

## Status — wave20b (2026-06-13)

The wave19b re-scoped follow-up `01KTZGK0SGFMM765HG1K9EFJNT` (carry the D71
boundary-zone suffix as a real POL-1 / snapshot field rather than the handler-local
`DEFAULT_BOUNDARY_ZONE` const, re-scope `01KTZHMVMMP671XVVPQN57CJZA`) landed this wave,
in its own fenced unit with `dataplane/crates/**` unfenced and no concurrent
`src/handler.rs` (dnsgate-provenance lineage) unit:

- **POL-1 carries the field** — `dns.boundary_zone` is now an optional, additive POL-1
  field (`ds-contracts::pol1::DnsConfig::boundary_zone`, default
  `DEFAULT_BOUNDARY_ZONE = "boundary."`). A layer that omits it materializes the working
  name, so every pre-existing POL-1 fixture composes byte-identically (the
  frozen-additive proof).
- **The snapshot lifts it** — `ds-policy-snapshot::PolicySnapshot` carries
  `boundary_zone`, sourced from the composed POL-1 DNS block via
  `PolicySnapshot::from_dns_config`, defaulting to the same working name.
- **The handler reads it** — `StubRequestHandler::with_forwarder_and_dns_config` threads
  `dns.boundary_zone` through the existing `with_forwarder_and_boundary_zone` seam, so a
  snapshot carrying `boundary_zone='example.test.'` drives the authored SOA MNAME
  (`denied.policy.example.test.`) and a snapshot WITHOUT the field falls back to the
  frozen `SOA_SIGNATURE_MNAME` (`denied.policy.boundary.`). The `DEFAULT_BOUNDARY_ZONE`
  const is the fallback ONLY.

A VALUE-source move, not a SHAPE change (D71): the `denied.policy.` prefix, the
always-authored SOA on every deny / NODATA, and TTL==MINIMUM==POL-1 negative-TTL all
stay frozen. No proto / docs / §6 edits; no new D-number. Proven network-free by
`tests/event_surface.rs`, `tests/suppression_shapes.rs`, and the
`handler::boundary_zone_from_snapshot_tests` unit tests.

### wave20b finalize — composition outcome and re-scoped follow-ups

Wave20b composed and landed **two** units green on `wave20b-integration` (repo-lints,
dispatch unittests, taskdb Go build/test, full offline dataplane cargo
build/test/clippy `-D warnings`/fmt — all from a fresh clone):

- `01KTZGK0SGFMM765HG1K9EFJNT` — the boundary-zone POL-1 / snapshot field detailed in
  the Status section above (`ds-contracts::pol1::DnsConfig::boundary_zone`,
  `ds-policy-snapshot::PolicySnapshot::boundary_zone`, threaded through
  `with_forwarder_and_dns_config`); landed in its own fenced unit with
  `dataplane/crates/**` unfenced and no concurrent `src/handler.rs` unit.
- `01KTZGKAW1VB0RGAF8Z2TTXH6F` — the taskdb shared-helper convention lint generalization,
  landed outside this tree (`scripts/taskdb/helper_convention_test.go`).

Three sibling units scoped this wave were **deferred for files-overlap** with the two
landed units (the wave engine never co-dispatches two units touching the same file) and
re-filed as explicit re-scope tasks under wave parent `01KTYTA82DKD6A28Z42SSA1CF3`, left
OPEN for the next loop wave to pick up. All assertion work this wave ran against loopback
mocks only — no live resolver was queried:

- `01KTZQQCYYJNGA77JXD7W7RHM2` — validate POL-1 `dns.boundary_zone` as a well-formed DNS
  name (hickory `Name::from_ascii`) at snapshot load via a new additive
  `PolicyError::BadName` in `ds-contracts` `build_dns`, so a malformed value NACKs at load
  instead of panicking the gate's SOA-authoring `.expect()` at runtime; collided on
  `dataplane/crates/ds-contracts/src/pol1.rs` with the boundary-zone unit (re-scope task
  `01KTZR2B6Z7ES0D7CSETB98WFX`).
- `01KTZQQT812DMT3B5ATM7G31FK` — thread the composed `DnsConfig.boundary_zone` from the
  live host `PolicySnapshot` into `GateConfig` and `spawn_gate`'s handler construction
  (closing the production loop so the policy-pushed suffix is authored, not the
  `DEFAULT_BOUNDARY_ZONE` fallback), then fold into the doc 13 §5.3 admitter-LAST snapshot
  hot-reload (D72); collided on `dataplane/crates/ds-policy-snapshot/src/lib.rs` (re-scope
  task `01KTZR2P3JY1JS640JBPQ36DJB`). Gate-fence: never co-dispatch with another ds-dnsgate
  unit (e.g. the boundary-zone-validation follow-up).
- `01KTZQR4FFPXHTH4TZM0A481WW` — extend the taskdb shared-helper lint's Rule 2 to `t.Run`
  subtest closures and `go`/`defer` `Test*` calls; same-file extension of
  `scripts/taskdb/helper_convention_test.go` (re-scope task `01KTZR30CBN5BEH1M5H3202KB7`).

Sequencing rule every re-scope task carries: ds-dnsgate units sharing `src/handler.rs` /
`src/main.rs` / `src/server.rs`, and units re-touching `pol1.rs` /
`ds-policy-snapshot/src/lib.rs`, are dispatched in separate waves or folded into one
unit — never co-dispatched.

## Status — wave19b (2026-06-13)

The two re-scoped `src/handler.rs` follow-ups, consolidated into one unit (they share
`handler.rs`, so they are never co-dispatched — the sequencing rule both carry):

- `01KTZ6FWNDV23F45MT7DX16AZY` — **real POL-3 provenance at every emission site.** The
  `evaluate(DnsQueryCtx) -> Verdict` swap had already landed at the base, so every
  `DnsEvent` now stamps the LIVE verdict's `SeamProvenance` (matched rule id / composing
  layer / policy version) via `SeamProvenance` → `EventProvenance`. The fixed pre-stage
  stub provenance constructors (the `{rule_id: "stub", ...}` triple) are **retired**;
  `FixedStubPolicy`, the always-`Allow` framework-validation harness default, now stamps
  an honest
  `harness/allow-all` marker instead of pretending to be a real-but-unfinished rule. The
  error paths with no query to evaluate (FormErr / request-info-less ServFail) carry an
  explicit `error-path` marker. `tests/event_surface.rs` proves — through the pack-backed
  `PolicyCorePolicy` over the shipped POL-2 baseline — that an allowed (`api.anthropic.com`)
  and a denied (`dns.google`) name each carry their matched pack rule's real triple, not
  the stub.
- `01KTZ6FA8T8P4M3M5054REZ57Y` — **the bounded explicit AAAA probe** (doc 11 §3.5
  phase-B pre-step). The forwarded-NoData arm now fires a single bounded AAAA probe on the
  *existing single upstream forwarder* (no second resolver, no per-query fan-out — doc 11
  §1), gated by an in-flight budget (`DEFAULT_AAAA_PROBE_BUDGET`), to settle the genuine
  pure-v6-only `aaaa_only` trigger to `Determined(true)` instead of deferring it. The
  deferral remains only where the probe cannot settle the answer (budget exhausted, or the
  AAAA leg itself failed/NoData). `tests/event_surface.rs` proves the v6-only origin is
  settled, an empty origin is `Determined(false)`, and the probe rides the single forwarder
  with at most one AAAA leg per query (no fan-out).

### The `aaaa_only` trigger — bounded explicit AAAA probe on the single forwarder (D75)

`aaaa_only` is the D75 trigger metric: "upstream had AAAA but **zero A** after the CNAME
chase" — a needed domain a v4-only guest can't reach. The §3.3 fast-NODATA AAAA path
**deliberately never forwards AAAA upstream** (an explicit timing freeze the RFC-4074
stall mitigation depends on), so it holds no A-count and stays
`AaaaOnly::Deferred(FastNodataNoForward)`. And — MEASURED in-tree against the vendored
hickory-resolver 0.26.x — a type-filtered `lookup(name, A)` over a genuinely v6-only
origin returns **NoData and does not surface the upstream AAAA RRs**, so the forwarded
A-path alone cannot observe "AAAA but zero A" for a pure v6-only origin.

The doc 11 §3.5 phase-B pre-step settles it: a **bounded explicit AAAA probe** on the
*existing single upstream forwarder*. It fires ONLY on the forwarded-NoData arm (a
policy-allowed name — Deny/Ask never forward), rides `self.forwarder`'s one resolver pool
(no second resolver, no per-query fan-out — doc 11 §1: ds-dnsgate is the fleet single
resolver / DoS chokepoint), and is gated by a small in-flight budget
(`DEFAULT_AAAA_PROBE_BUDGET`) so a flood of v6-only-NoData names cannot multiply upstream
load. The settled arms:

- `AaaaOnly::Determined(true)` — the held answer set bundled AAAA with no surviving A,
  OR the A-lookup was NoData and the bounded AAAA probe found AAAA RRs (the genuine
  pure-v6-only origin). **This is the T-C3 trigger.**
- `AaaaOnly::Determined(false)` — an A survived, or the AAAA probe was also NoData (a
  genuinely empty name, not v6-only).
- `AaaaOnly::Deferred(reason)` — the trigger is real but uncomputable on this path: the
  forward-free fast-NODATA path, a no-answer-set error path, or a forwarded NoData the
  bounded probe could not settle (budget exhausted, or the AAAA leg itself failed). T-C3
  treats deferrals as "unknown", never as `false` (which would mask a real v6-only domain).

POL-3 provenance on every emitted `DnsEvent` is now the **live verdict's** matched rule
id / composing layer / policy version (`SeamProvenance` → `EventProvenance`), not a fixed
stub marker; the no-rule-reached error paths (FormErr / request-info-less ServFail) carry
an explicit `error-path` marker since there is no query to evaluate.

### wave17b finalize — composition outcome and re-scoped follow-ups

Wave17b composed and landed the two units above (`01KTZ1ERZNG3PQYCACDVARQX1M`,
`01KTZ1F59MGW4FBPBEW621K0T8`) green. Three sibling units scoped the same wave were
**deferred for files-overlap** with the event-surface unit (the wave engine never
co-dispatches two units touching the same file) and re-filed as explicit re-scope
tasks, dispatchable now that the files they collide on are landed:

- `01KTZ6FA8T8P4M3M5054REZ57Y` — the phase-B bounded explicit AAAA probe
  (doc 11 §3.5) that would settle the genuine pure-v6-only `aaaa_only` trigger;
  collided on `src/handler.rs` (re-scope task `01KTZ82F23YZK4YW55GE5THRYN`).
  **LANDED wave19b** (consolidated with the provenance unit below — see the wave19b
  status section above).
- `01KTZ6FWNDV23F45MT7DX16AZY` — thread real POL-3 provenance into `DnsEvent` at
  the emission sites once the `evaluate(DnsQueryCtx) -> Verdict` swap lands;
  collided on `src/handler.rs` (re-scope task `01KTZ82VJEYX95A07NZETBAVAZ`).
  **LANDED wave19b** (consolidated with the AAAA-probe unit — both share `handler.rs`).
- `01KTZ6HEN7QS4FR6DP67M096RQ` — a dedicated `DeferralReason` variant for the
  no-answer-set error paths (FormErr / request-info-less ServFail); collided on
  `src/event.rs` (re-scope task `01KTZ8356E7T5HWT5YP5N8B3BJ`). **LANDED**
  (`DeferralReason::ErrorPathNoAnswerSet`).

A fourth deferred unit, the cross-tree README-literal survey for
`scripts/lint-readme-tokens.sh` adoption (`01KTZ6HQJSBAEZRBYB5P2FJAXP`), collides
on this README itself (re-scope task `01KTZ83JEDXJ8RAN6H4P1GDHBW`). The sequencing
rule every re-scope task carries: ds-dnsgate units sharing `src/handler.rs` /
`src/event.rs` are dispatched in separate waves or folded into one unit — never
co-dispatched.

## Status — wave19b (2026-06-13)

`main` now installs the **real pack-backed `PolicyCorePolicy`** as the binary default
(taskdb `01KTZGJM48P008XM18SG1RKCVT`), replacing the always-`Allow` `FixedStubPolicy`
the runner previously ran with. The host's ONE `ComposedPolicy` is built network-free
at startup from the SHIPPED read-only POL-2 baseline pack
(`artifacts/policy-packs/pol2-system-baseline.pol1.yaml`): `ds-contracts::pol1::parse_layer`
parses the pack, `policy_core::pol1_eval::compose(&[layer], &[])` composes it over a
fresh install (no capabilities present, so `requires:`-gated entries stay INERT), and
`PolicyCorePolicy::new(composed)` is installed through the already-generic `spawn_gate`
(no signature change; `src/server.rs` is untouched). The startup preamble no longer
claims always-`Allow`. The seam SHAPE was already landed (the wave17b policy-seam unit);
this wave only makes the real evaluator the startup default — `FixedStubPolicy` is
retained for the test harnesses (it admits the synthetic names the framework/forwarder/
suppression suites probe, which a shipped pack would `Ask`/REFUSE).

Still a later seam, NOT built by this wave: the §5.3 snapshot-subscriber **hot reload**
(admitter-LAST, D72 — the policy is composed ONCE at startup, not yet live-reloaded on a
policy push), the W1/W2 insert-then-answer transaction behind `Allow{admit}`, D44
attribution, and the nft / DNS-2b writes. The gate stays green from a fresh clone
(repo-lints, dispatch unittests, taskdb Go build/test, full offline dataplane cargo
build/test/clippy `-D warnings`/fmt); `tests/policy_seam.rs` exercises the pack-backed
evaluator network-free against the shipped baseline.

## Status — wave24b (2026-06-13)

Two §5.1/§3.4 + D72 closures the prior waves left open, consolidated into the handler /
main / server / `ds-policy-snapshot` (taskdb `01KTZPNG9WWW73R6J53BF17742` +
`01KTZQQT812DMT3B5ATM7G31FK`):

- **Attribution live-wire (§5.1 / W6, D44).** `StubRequestHandler` now threads an
  `AttributionTable` (`with_attribution_local` / `with_attribution_per_tap`); `query_ctx`
  derives `DnsQueryCtx::session` through the never-recycled per-session tap (`attribute_local`
  post-NAT local-address, or `attribute_per_tap` per-tap bind), NEVER the raw source IP,
  REPLACING the `pre_stage_session_token(source)=src:<addr>` join. `AttributionError::UnknownInterface`
  FAILS CLOSED to **SERVFAIL** (a genuine ds-dnsgate failure per W1/§3.2, never a policy
  NXDOMAIN), enforced at runtime and proven on the wire. The frozen `DnsQueryCtx`
  (session/qname/qtype/source) shape is unchanged — only the `session` computation moves;
  the `src:<addr>` token is the pre-stage fallback ONLY (no table wired). `main` still serves
  with the fallback until the orchestrator tap registry is plumbed.
- **TC-bit retry EDE-15 parity (§3.4).** A forced-TC src-module fixture (a long boundary
  zone + long qname overflowing a 512-byte advertised EDNS buffer) sets the UDP TC bit, then
  asserts the TCP retry carries the byte-identical NXDOMAIN + authored-SOA
  (`MNAME=denied.policy.<zone>.`, `TTL==MINIMUM==`POL-1 negative-TTL) + EDE-15(`ds:` provenance)
  — no UDP-only fast path skips admission, and the truncated UDP answer is still a NXDOMAIN
  deny. The fixture lives as a `src/` `#[cfg(test)]` module (`tests/` belongs to the sibling
  inttest unit).
- **boundary_zone from the LIVE snapshot + D72 hot-reload (PART 3).** `GateConfig` gains a
  `boundary_zone` field; `main` sources it from the live host snapshot's POL-1
  `dns.boundary_zone` (the value `ds-policy-snapshot::PolicySnapshot::boundary_zone_value`
  materializes), threaded `GateConfig` → `spawn_gate` → `StubRequestHandler` in place of the
  `with_forwarder`-defaulted `DEFAULT_BOUNDARY_ZONE`. The authored-SOA signature lives behind
  a shared lock so `RunningGate::reload_boundary_zone` re-sources it on the doc 13 §5.3
  admitter-LAST D72 hot-reload (both transports at once, no listener re-bind). The
  WatchPolicies SUBSCRIBER loop is still a later seam; the reload SEAM is built and tested.
  `ds-policy-snapshot/src/lib.rs` exposes `boundary_zone_value()` (the owned live-wire read)
  with hot-reload re-source tests.

Still a later seam, NOT built by this wave: the W1/W2 insert-then-answer transaction, the
WatchPolicies subscriber loop (the boundary-zone reload SEAM exists), the orchestrator tap
registry POPULATION in `main`, and the nft / DNS-2b writes. Green from a fresh clone
(repo-lints, dispatch unittests, taskdb Go build/test, full offline dataplane cargo
build/test/clippy `-D warnings`/fmt).

### wave19b finalize — composition outcome and re-scoped follow-ups

Wave19b composed and landed **four** units green on `wave19b-integration` (gate above):

- `01KTZ6FWNDV23F45MT7DX16AZY` + `01KTZ6FA8T8P4M3M5054REZ57Y` — the live POL-3
  provenance plumbing at every `DnsEvent` site and the bounded explicit AAAA probe
  for the genuine pure-v6-only `aaaa_only` trigger (doc 11 §3.5), consolidated into
  one unit because both edit `src/handler.rs` (folded; both marked done).
- `01KTZGJ6XDHAC2Q7SZEE30R80Z` — the two `clippy::manual_repeat_n` lints in
  `tests/framework_validation.rs` swapped to `std::iter::repeat_n` (these were
  invisible to the canonical `--workspace --locked` gate, which omits
  `--all-targets`).
- `01KTZGJM48P008XM18SG1RKCVT` — the pack-backed `PolicyCorePolicy` main-default
  swap (detailed in the Status section above).
- `01KTZ6JEXPDWY6R3EFZ2HSB36D` — the taskdb static convention check
  (`scripts/taskdb/helper_convention_test.go`), landed outside this tree.

Two further units scoped this wave were **deferred for files-overlap** with wave-1
units (the engine never co-dispatches two units touching the same file) and re-filed
as explicit re-scope tasks, left OPEN for the next loop wave to pick up:

- `01KTZGK0SGFMM765HG1K9EFJNT` — carry the D71 boundary-zone suffix as a real
  ds-policy-snapshot / POL-1 field rather than the handler-local
  `DEFAULT_BOUNDARY_ZONE` const; collided on `src/handler.rs` with the provenance
  unit AND crosses the fenced `dataplane/crates/**` tree, so it needs its own wave
  with crates unfenced (re-scope task `01KTZHMVMMP671XVVPQN57CJZA`).
- `01KTZGKAW1VB0RGAF8Z2TTXH6F` — generalize the taskdb convention check to other
  shared-helper `Test*` misuses (`t.Log` / `t.Error`); extends the
  `helper_convention_test.go` file the wave-1 lint unit creates, so it could not be
  co-owned this wave (re-scope task `01KTZHMVMX43BY2F98SDHE903Y`). Now that the
  base lint has landed, the dependency is satisfied.

Next-wave follow-ups carried forward from the unit exec-reports: add `--all-targets`
to the canonical clippy gate so test-target lints surface at CI; refresh the now-stale
`FixedStubPolicy`/`main` rustdoc in `src/policy.rs` + `src/lib.rs`; decouple startup
from the compile-time pack path via a snapshot-source seam; and wire the §5.3
admitter-LAST snapshot hot-reload (D72) into `main`.

### wave24b finalize — composition outcome and re-scoped follow-ups

Wave24b composed and landed **two** units green on `wave24b-integration` (gate above
— repo-lints, dispatch unittests, taskdb Go build/test, full offline dataplane cargo
build/test/clippy `-D warnings`/fmt from a fresh clone):

- `01KTZPNG9WWW73R6J53BF17742` (+ folded `01KTZQQT812DMT3B5ATM7G31FK`) — the
  attribution live-wire into `query_ctx`, the §3.4 forced-TC TCP-retry EDE-15 parity
  fixture, and the boundary-zone-from-live-snapshot + D72 reload SEAM, consolidated
  into the handler / main / server / `ds-policy-snapshot` files (detailed in the
  Status section above; both folded ids marked done).
- `01KTZYSM527A7CNYZBQ3PAFB7C` — the network-free integration test driving the gate
  over a real `ds_telemetry::SpoolSink` end-to-end (`DnsEvent` → envelope → `SpoolSink`
  → disk segment), with the forced-bound `SpoolOverflow` marker assertion. Loopback /
  synthetic only (`127.0.0.1:0`); no live claude / podman / cia, no network.

Four further units scoped this wave were **deferred for files-overlap** with the two
wave-1 units (the engine never co-dispatches two units touching the same file) and
re-filed as explicit re-scope tasks, left OPEN for the next loop wave to pick up — each
must land on top of the composed wave-1 tree:

- `01KV05CB5KT7PBEX256B7X5P46` — compose handler-livewire + dnsgate-inttest to one
  integration branch and verify the merged tree green; collided on `src/server.rs`
  with handler-livewire (re-scope task `01KV05SDTV51GMVE410ZQ8MRGK`). Note: this wave's
  finalize already performed the equivalent composition green on `wave24b-integration`.
- `01KV05CN1SCEGT9MMQ6M6CANTQ` — plumb the orchestrator per-session tap registry into
  `main` so the live `AttributionTable` is exercised in production (today `main` still
  serves with the `src:<addr>` pre-stage fallback); collided on `src/main.rs` with
  handler-livewire (re-scope task `01KV05SNS5FNWXFZMEM4XVFWWS`).
- `01KV05D22G53P8K5BA9AEDS6CG` — build the WatchPolicies host-snapshot subscriber loop
  that drives `RunningGate::reload_boundary_zone` (D72 admitter-LAST; the reload SEAM
  exists, the subscriber that calls it does not); collided on `src/main.rs` with
  handler-livewire (re-scope task `01KV05SY026D3FH53YKHX228HJ`). Serialize with the
  tap-registry unit — both touch `main.rs`.
- `01KV05DFN4DJDET0HPHAGNAQX8` — strengthen the spool integration tests with
  UDP-transport parity, the full §5.5 signal-set decode, and off-tmpfs scratch;
  extends the same `tests/event_surface.rs` the inttest unit owns (re-scope task
  `01KV05T5WMFT2HS9PF96N4SX9R`).
