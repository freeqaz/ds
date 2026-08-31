# ds-telemetry

**The LOG-1 emitter.** One crate owns how data-plane events are constructed, scrubbed,
and spooled, so the auditable record of "everything every VM did on the network"
(doc 09 §7) has one set of conventions instead of three. Both proxies and `ds-flowlog`
emit through it (doc 14 §6).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15; LOG-1 events are data-plane and open even
  though dashboards over them are paid)
- **Governing decisions:** D73 (fingerprint-only / never-log-the-secret,
  doc 12 §5.1),
  D75 (family-agnostic addresses, doc 14 §2),
  D116 (`SpoolOverflow` visible-loss marker),
  POL-3/D67 (mandatory provenance)

## Frozen invariants

| Invariant | Source |
|---|---|
| **Never-log-the-secret, enforced once, here** (D73): a matched secret or swapped credential value appears in **no** log, event, spool, or error path — fingerprint only (the `CredentialUseEvent` convention). This is a (c)-suite assertion, not a code-review hope | doc 14 §2; doc 12 §5.1 |
| POL-3 provenance (rule id, policy layer, policy version) mandatory on every event; missing provenance fails CI | doc 09 POL-3; doc 11 §5.5 |
| Family-agnostic addresses (bytes/string + family enum, never `fixed32`) — time-locked at the Stage-0 LOG-1 freeze | D75; doc 14 §2 |
| `PolicyDecision.plane = KEYED \| GENERIC` + digest-set version in verdict provenance (a separate, non-policy version namespace) | D73; doc 14 §2 |

## Free (firmed up during build)

The conventions layer is built (`scrub` / `provenance` / `address` / `event` /
`spool`); the LOG-1 schema stays in `ds-contracts` (below). The free items the
build firmed up — bounded by the §2 frozen message set, never the wire schema
(doc 14 §12.4):

- **Spool format (on disk).** A framed append log: per record a 1-byte kind tag
  (`1`=FlowRecord … `5`=CredentialUseEvent, `0xFF`=`SpoolOverflow` marker), a
  4-byte big-endian length, then the body. Payload bodies are the POL-3 triple +
  an optional credential **fingerprint** (keyed digest, never plaintext — the D73
  chokepoint) + the opaque already-scrubbed payload. A `0xFF` overflow-marker body
  leads with a 1-byte **loss-origin discriminator** (`0x01`=disk drop-oldest,
  `0x02`=sync channel-shed) followed by the `session|dropped|timestamp_ms` text, so
  an on-disk reader can attribute WHICH of the two loss points minted the receipt.
  The encoding — including the origin byte — is free implementation; the message
  *set* is what's frozen (the origin discriminator is not part of the frozen wire
  schema).
- **Disk bounds + batching (`SpoolBounds`).** Defaults: `max_records = 4096`
  payload records in the bounded on-disk ring, `batch_size = 64`,
  `channel_depth = 256`, `flush_interval = 50ms`. Drop-oldest under the bound is
  contractual **only because loss is visible**: each eviction mints a
  `SpoolOverflow {session, dropped, timestamp_ms}` marker on a never-evicted
  priority lane, drained markers-first, so the loss receipt always survives even a
  saturated ring (D116). Silent loss is the one disallowed behavior.
- **Two loss points, both marked in-stream (never silent)** (§12.4 visible-loss
  invariant + the D116 channel-shed land). The disk ring's drop-oldest is the
  contractual path: §12.4 requires that overflow loss is visible and never silent, so
  the spool reserves a never-evicted priority lane for the `SpoolOverflow` marker.
  The synchronous fire-and-forget `EventSink::emit` may additionally shed at the
  in-memory channel when it is momentarily full (telemetry never blocks the data
  path); that shed is the *second* loss point, introduced by the D116 channel-shed
  land — not by §12.4 prose. It is now ALSO marked in-stream: it mints a per-session
  `SpoolOverflow` receipt (derived from the shed event's mandatory POL-3 provenance
  namespace, with a monotonic per-session `dropped` count) onto the SAME never-evicted
  priority lane the disk-ring receipt rides, via a small dedicated marker channel so
  the receipt is never itself shed behind the payload back-pressure it reports on. It
  is additionally counted in `SpoolSink::dropped_total` (the fast liveness gauge). The
  durable path (`SpoolSink::emit_async`) awaits channel back-pressure, so the
  disk-ring marker is the only loss there. So D116's "silent loss is the one
  disallowed behavior" is now airtight across BOTH the sync `emit()` channel-shed and
  the durable disk-ring drop-oldest paths. Each `SpoolOverflow` carries a `LossOrigin`
  (`DiskDrop` vs `ChannelShed`) that the free on-disk encoding records as a 1-byte
  discriminator, so the two distinct loss points stay operator-distinguishable in a
  flushed segment — the disk drop-oldest receipt decodes back as disk-origin and the
  channel-shed receipt as channel-shed-origin (both round-tripped through the on-disk
  decoder in tests).
- **Async runtime.** tokio (the one pinned workspace 1.x major) — a background
  flush task over `tokio::fs`; no `net` feature.
- **Emission transport into `ds-flowlog`.** Still a later seam — this client's job
  ends at a durable, bounded, visible-loss on-disk spool; the off-box ship from
  the TLS-terminating egress gateway / resolver into `ds-flowlog` is not wired
  here (doc 14 §12.4).

## What must NOT live here

- **Schema definitions** — LOG-1 message shapes are generated into `ds-contracts`
  from `proto/dreamserpent/boundary/v1` (zero `.proto` bodies until the one-shot
  Stage-0 freeze).
- **The off-box log sink** — v0 sink is files + Postgres inside the orchestrator
  (doc 15 §5.6); only the reserved `proto/dreamserpent/logsink/v1/` seam exists.
- **Reconciliation logic** — LOG-4 lives in `ds-flowlog`.

## Neighbors

`ds-contracts` (generated event types), both services and `ds-flowlog` (emit through
it), the orchestrator log sink (consumes what ships off-box).

## Wave21b composition outcome

This crate's conventions layer landed on `wave21b-integration` (D73 scrub chokepoint,
POL-3 provenance, D75 family-agnostic addresses, the disk-bounded D116 spool). The wave
finalize record, so the next loop wave does not re-derive it:

- **Merged (done):** the `ds-telemetry` unit — the six `src/*.rs` conventions modules
  plus the two `dataplane/Cargo.lock` dep edges (`ds-contracts` path crate + workspace
  `tokio`), no new vendored crate. Gate green at merge (repo-lints, dispatch suite,
  taskdb build/test, dataplane build/test/clippy `-D warnings`/fmt all clean;
  `ds-telemetry` ships 17 lib tests).
- **Blocked (empty branch):** the `readme-survey` unit produced no commits — its wave
  branch was byte-identical to the pinned base, so there was nothing to compose. Not a
  conflict and not a contradiction drop. The prioritized README token-guard backlog it
  was meant to produce is instead captured as the deferred follow-ups below.
- **Deferred → re-scoped (filed open for the next loop wave under the b-stream
  grouping epic).** Each was a disjoint-files deferral: every follow-up's working set
  overlapped a wave-1 unit's whole-tree grant (`ds-telemetry/**` or a `readme-survey`
  README), so they could not co-run this wave:
  - per-session `SpoolOverflow` receipt for the sync `emit()` channel-shed loss point
    (overlaps `ds-telemetry/src/spool.rs`).
  - collapse `ds-dnsgate` `event.rs` onto `ds_telemetry::event` (dual-crate unit;
    overlaps `ds-telemetry/src/event.rs`).
  - post-freeze LOG-1 migration of the convention carriers onto frozen `ds-contracts`
    types (overlaps `ds-telemetry/src/{provenance,address,event,spool}.rs`; also
    Stage-0 boundary.v1 freeze-gated — keep deferred until the freeze generates the
    LOG-1 types).
  - service-README lint home for `dataplane/services/*` token guards (readme-survey P1).
  - mirror env-default token guards in `lint-env-drift.sh --self-test` (readme-survey
    P2+P3).
  - cache endpoint per-row port token guards in `lint-image-drift.sh --self-test`
    (readme-survey P7/P8).

## Wave23b composition outcome

This wave hardened two loss-attribution / fail-closed seams and retired a stale
backlog item. The finalize record, so the next loop wave does not re-derive it:

- **Merged (done):**
  - `spool-loss-origin` — tagged the free spool's on-disk `SpoolOverflow` markers with
    a 1-byte loss-point origin discriminator (disk drop-oldest vs channel-shed) in the
    free pre-freeze encoding (doc 14 §12.4 free-encoding latitude), making the two
    distinct loss points operator-distinguishable from a flushed segment (§12.4
    visible-loss invariant covers the disk overflow path; the channel-shed loss point
    was introduced by the D116 channel-shed land). No proto/wire change, no new
    D-number; touched `src/spool.rs` + this README.
  - `mirror-env-absent` — added a `deploy/ds-mirror.env`-absent rename/restore injection
    to the mirror lint `--self-test`, locking the fail-closed ABORT that was previously
    unexercised. Test-only, `images/mirror/lint-env-drift.sh`.
  - `lint-readme-tokens-regression-home` — **MOOT no-op:** the proposed sourcing-API
    regression home (an internal dispatch-suite test module, 13 tests) and the
    `--check` CLI mode already landed at the pinned base (commits `6fd87aa7`,
    `scripts/lint-readme-tokens.sh:192-205`). Closed already-satisfied; no commits.

  Gate green at merge (repo-lints, dispatch suite, taskdb build/test, dataplane
  build/test/clippy `-D warnings`/fmt all clean).
- **Blocked:** none.
- **Deferred → re-scoped (filed open for the next loop wave under the b-stream
  grouping epic).** Each was a disjoint-files deferral against a wave-1 unit's grant:
  - `spool-doc14-attribution-soften` — reword the LossOrigin comments/README so "two
    distinct loss points" is attributed to "doc 14 §12.4 visible-loss invariant + the
    D116 channel-shed land" rather than quoted as §12.4 verbatim (overlaps
    `src/spool.rs`; now collision-free since `spool-loss-origin` merged).
  - `flowlog-lossorigin-decoder` — promote the test-only `from_byte()` decoder to a
    production off-box `ds-flowlog` path that attributes a flushed marker to its loss
    point (overlaps `src/spool.rs`; also blocked on the `ds-flowlog` seam, still absent
    from `dataplane/crates/`).
  - `gate-wire-lints-makefile` — fold `images/*/lint-*.sh --self-test` into the standing
    `make repo-lints` gate so the env-absent injection + token guards run in CI
    (overlaps `lint-env-drift.sh`; also fence-blocked on the standing `Makefile`
    zero-diff — needs a wave owning the Makefile grant).
