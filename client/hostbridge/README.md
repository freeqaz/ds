# client/hostbridge/ — the host-agent transport bridge (M0)

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D38, D61, D79
(co-cited D18/D45/D53 for the no-approval-state invariant) ·
**Tier 2 of** [`../wrapper/DRIVE-PROTOCOL.md`](../wrapper/DRIVE-PROTOCOL.md)
("The e2e harness, in tiers") · taskdb `01KTXBGTHF`, advancing the two
hand-reconciled wave-2 capabilities `01KTXMASVK25R8J95B5ASP23DP` (framed
UDS/socket transport — [`socket.go`](socket.go)) and
`01KTXMBBZX30JPWZDG7VSMPQ5R` (resume-from-seq slow-reader recovery —
[`bridge.go`](bridge.go) history ring + [`loopback.go`](loopback.go)
`Conn.Resume`/`Gap`), each re-applied onto the merged Subscriber /
`Server.Attach` / typed-`DriveInput` seam (never copied wholesale).

The minimal host-agent-side transport bridge: it runs beside a wrapped Claude
Code process, projects CC's stdout (stream-json wire) through the wrapper adapter
into `attach.v1` deltas served over a `WatchSession`-style event stream, and
accepts writer-seat input + ask-response grants back through the wrapper driver
onto CC's stdin. It exercises the **D79 transport-ambivalent `AttachHandle`** for
real across the container boundary, with the **D61 one-writer/N-reader**
arbitration enforced **server-side** at the `WatchSession` terminator
(docs/15 §5.3-5.4, attach.v1 freeze
checklist row 2).

M0 transport is **direct client→host-agent, no relay** — but the
`EndpointCandidate` list shape is admitted from day one (the relay endpoint joins
at M2, the spectate multiplexer at M4, without a v2 handle; D79).

## Import, don't duplicate

The read half (CC stdout → `attach.Event`) and the write half (`DriveInput` /
`DriveGrant` → CC stdin) **already ship and are reused verbatim** — this package
adds only the transport seam and the server-side arbitration, never a second copy
of the adapter, driver, `attach.Event`, `DriveInput`, or `DriveGrant` shapes:

| Reused (imported) | From | Used as |
|---|---|---|
| `claudecode.Adapter` (`New` / `WithClock` / `Feed` / `ProcessStream` / `Warnings`) | `../wrapper/adapters/claude-code` | CC stdout → `attach.Event` projection (the read half) |
| `attach.Event` &c. | `../wrapper/attach` | the event model served over the stream |
| `claudecode.Driver` (`NewDriver` / `EncodeInput` / `EncodeGrant` / `EncodeGrantPromptTool`) | `../wrapper/adapters/claude-code` | `DriveInput` / `DriveGrant` → CC stdin records (the write half) |
| `claudecode.DriveInput` / `claudecode.DriveGrant` | `../wrapper/adapters/claude-code` | the inbound write shapes (aliased here, one definition) |

What is **net-new** here:

- **`AttachHandle` / `EndpointCandidate` / `AuthMaterial` / `Role` (WRITER \|
  READER)** — declared **locally** in [`handle.go`](handle.go) because `attach.v1`
  is README-only at M0 ([proto/FREEZE.md](../../proto/FREEZE.md): no stub message
  bodies before the freeze). The five fields are the M0-frozen `AttachHandle`
  shape verbatim (`session_uuid`, `endpoints`, `auth`, `role`, `expires_at`); when
  the proto freezes these collapse to the generated view.
- **Server-side WRITER/READER seat arbitration** ([`server.go`](server.go)) — the
  **server half** of the seam whose client half already lives in the TUI
  (`01KTWJ23Q0`). The writer seat lives in the session record, not on the handle:
  a first WRITER takes it, a **second WRITER attach is rejected**
  (`ErrWriterSeatTaken`), N READERs attach and receive events but **any READER
  write is refused** (`ErrReaderCannotWrite`), and the seat frees on detach so a
  later WRITER can take it (driver handoff, docs/15 §5.4).
- **Handle auth + expiry validation** ([`server.go`](server.go)) — `AuthMaterial`
  is compared constant-time against the session's minted token and `ExpiresAt`
  must be in the future; an expired or wrong-token handle is rejected before any
  seat is granted.
- **The stdio pump + fan-out** ([`bridge.go`](bridge.go)) — the goroutine-per-
  stream model (the same model `../goldentrace/e2e` proved deadlock-safe): a
  reader goroutine drains CC stdout and fans projected deltas to subscribers;
  writer input is serialized onto CC stdin under a mutex.
- **The in-process / loopback transport** ([`loopback.go`](loopback.go)) — the M0
  direct transport realized without a socket or a container: `Dial(handle)`
  resolves the handle through the `Server` and returns a `Conn` carrying the
  event stream out and the drive path in. It is the same seam the socket
  transport implements.
- **The framed UDS / socket transport** ([`socket.go`](socket.go),
  `01KTXMASVK25R8J95B5ASP23DP`) — the SECOND
  realization of the same seam, crossing a REAL process/namespace boundary:
  `SocketTransport.Dial(handle)` connects the handle's `unix` endpoint, performs
  a framed attach handshake, and returns a `SocketConn` with the SAME
  client-facing surface as the loopback `Conn` (`Events` / `Role` / `DriveInput`
  / `DriveGrant` / `Resume` / `Close`). `Serve(ln, srv)` / `ServeBridge(ctx, path, srv)` is
  the server half. It reuses `Server.Attach` arbitration verbatim, so an attach
  is accepted/rejected by the SAME sentinels over the wire (mapped to a stable
  reject code and back via `errors.Is`), and it carries the typed
  `DriveInput`/`DriveGrant` shapes — the **Driver stays the only encoder**, so the
  bytes that land on CC stdin are byte-identical to loopback's. The wire is
  type-length-payload framing declared locally (attach/v1 is README-only). The
  server-side per-conn outbox is **bounded** (`socketOutboxDepth`, the socket twin
  of loopback's `eventBuffer`): a slow cross-process reader **drops** the overflow
  for its own conn rather than stalling the shared bridge pump (docs/15 §5.4
  N-reader independence) — the exact loopback slow-reader drop, recovered the same
  way (next bullet).
- **Resume protocol on the wire** ([`socket.go`](socket.go),
  `01KTXRFTW4146JGZ4SP3SX0N76`) — the cross-process twin of the loopback
  `Conn.Resume`, closing the loopback-vs-socket recovery asymmetry. A slow
  `SocketConn` reader that dropped a span detects its Seq hole (`Gap`, tail or
  mid-stream) and calls `SocketConn.Resume(afterSeq)` — **no full re-attach**. The
  request crosses as a `frameResume{afterSeq}` (8-byte BE), and the server answers
  ONLY from `Bridge.ReplayFrom` — the **SAME bounded history ring** the loopback
  `Conn.Resume` reads, never a second ring, never re-derived events — with a
  `frameResumeReply` carrying the recovered span (a 4-byte BE count, then per
  event a 4-byte BE length + the event JSON) or a `frameResumeReject` whose code
  maps back via `errors.Is`. The recovered span is **RETURNED** from `Resume`,
  never re-injected into `Events()` — identical client-facing semantics to
  loopback `Conn.Resume`: exactly-once, ascending-Seq, all-or-nothing.
  A window-exceeded resume (the missing span aged out of the ring) is a **clean
  reply** — `errors.Is(err, ErrResumeWindowExceeded)` holds across the wire, never
  a dropped connection — and so is a malformed/oversized resume request
  (`resumeRejectInternal`, the conn survives so the reader may resume again).
  `Resume(0)` backfills whatever the ring still retains (the late-joiner case).
  The single-ring property is asserted directly:
  [`socket_test.go`](socket_test.go)'s parity test shows the socket-recovered span
  equals loopback `Conn.Resume`'s for the same `afterSeq`.
- **Resume-from-seq slow-reader recovery** ([`bridge.go`](bridge.go) history ring +
  [`loopback.go`](loopback.go) `Conn.Dropped` / `Conn.Resume` / `Gap`,
  `01KTXMBBZX30JPWZDG7VSMPQ5R`) — a READER
  slower than the shared pump drops events past its bounded delivery buffer rather
  than stalling the pump or its peers (docs/15 §5.4 N-reader independence). The
  drop leaves a Seq hole; the reader detects it (`Gap`), resumes from its last-good
  Seq (`Conn.Resume` → `Bridge.ReplayFrom` over the bounded history ring), and the
  missing span is recovered exactly once, in order — or fails LOUD
  (`ErrResumeWindowExceeded`) when it has aged out of the ring. A silently gapped
  stream is never produced. The ring's Seq-sorted invariant — which
  `replayFromLocked`'s binary search depends on — is sourced from the adapter's
  strictly-monotonic-Seq contract (P10, asserted by the goldentrace golden suite),
  not re-asserted at ingest: the sole ingest path is `Bridge.Pump`, which consumes
  adapter-projected events, so there is no caller-facing event-injection seam through
  which a non-monotonic Seq could reach the ring.

The bridge core names **no CC-isms** (D38): every CC fact is reached through the
adapter/driver seam. Stdlib-only ([client/go.mod](../go.mod)).

## Synthetic-verified vs DS_E2E_LIVE-deferred

| | What runs | Gate |
|---|---|---|
| **Synthetic (verified, always-on)** | A fixture-fed synthetic CC stdio fake replays `../fixtures/*.cc-wire.ndjson` (read-only; Unit goldentrace-harness owns `fixtures/`) into the bridge's CC-stdout side and captures the bridge's CC-stdin side, over **BOTH transports**: the **in-process loopback** ([`bridge_test.go`](bridge_test.go)) AND a **real framed UDS / socketpair under a tmpdir** ([`socket_test.go`](socket_test.go), `t.TempDir`). The four ACCEPTANCE clauses are asserted over each. The resume-from-seq recovery battery runs over **BOTH transports** too: the in-process fan-out ([`resume_test.go`](resume_test.go)) AND a **real framed UDS** ([`socket_test.go`](socket_test.go) `TestSocketResume*`) — a forced Seq gap recovered exactly-once-in-order via `SocketConn.Resume`, window-exceeded failing loud across the wire (`errors.Is(_, ErrResumeWindowExceeded)`), a parity check that the socket-recovered span equals loopback `Conn.Resume`'s for the same `afterSeq` (the single-ring property), a malformed/oversized resume frame rejected cleanly without dropping the conn, a `Resume(0)` late-joiner backfill of the retained ring, and a resume-vs-pump race held race-clean (run under `-race`). | none — every `go test` run |
| **Real-container (deferred manual step)** | A CC process inside `scripts/cc_sandbox.sh`, its stdio bridged across the container boundary to a client outside that attaches over the handle and drives in (DRIVE-PROTOCOL.md tier 2). | **`DS_E2E_LIVE=1`** ([`live.go`](live.go) `RunLiveBridge`) |

The framed UDS tests run over a **real** `net.Listen("unix", …)` socket in a
`t.TempDir`, not a mock — no container, no live `claude`/`cia`/`podman`. The
`DS_E2E_LIVE` gate covers only the real-container launch; the socket carrier
itself is fully exercised in-fleet over the socketpair.

There is exactly **one** live gate, shared with `../goldentrace/e2e`:
`DS_E2E_LIVE=1`. Unset — the default and every CI / `go test` run —
`RunLiveBridge` returns `ErrLiveGateUnset` and launches **nothing**: no podman, no
`claude`, no `cia`. The live wiring (the cross-container socket transport + the
gated launcher) is scaffolded in [`live.go`](live.go) as the deferred manual step,
mirroring how the `cc_sandbox` / live-tier work was landed.

## What the tests assert (the ACCEPTANCE clauses)

[`bridge_test.go`](bridge_test.go), all over the loopback transport with a
fixture-driven synthetic CC stream — no live process:

1. A **WRITER** attaches and receives `attach.v1` deltas projected through the
   **existing adapter** from the fixture-driven CC stream (asserted *against the
   adapter's own projection* of the same fixture — not re-derived).
2. A **`DriveInput` and a `DriveGrant`** drive back through the writer seat and
   the bytes landing on CC stdin **byte-match the existing driver's**
   `EncodeInput` / `EncodeGrantPromptTool` / `EncodeGrant` output (asserted
   against the driver, never re-encoded independently).
3. A **second WRITER attach is rejected** server-side (`ErrWriterSeatTaken`)
   while **N READER** attaches receive events but every READER write is refused
   (`ErrReaderCannotWrite`); the seat frees on detach for a later WRITER.
4. An attach with an **expired-at-in-the-past** or **invalid-`AuthMaterial`**
   handle is rejected (`ErrHandleExpired` / `ErrAuthInvalid`), as are
   malformed (no endpoint / relay-only / bad role) and unknown-session handles.

No live podman/claude/cia is invoked — the container path is `DS_E2E_LIVE`-gated
and skipped (`TestRunLiveBridgeGated`).

## The binary

[`../cmd/ds-hostbridge/main.go`](../cmd/ds-hostbridge/main.go) wires a wrapped CC
command's stdin/stdout to a listening transport that issues/honors
`AttachHandle`s:

- `ds-hostbridge --self-check [--drive "<text>"]` — stands the bridge up over a
  static synthetic stream + the loopback transport, attaches a WRITER, prints the
  projected deltas and the bytes the driver wrote to CC stdin. Always safe; no
  live process.
- `ds-hostbridge --socket-self-check [--drive "<text>"]` — the same proof over a
  **real framed UDS** bound in a tmpdir (`ServeBridge` + `SocketTransport.Dial`):
  the cross-process twin of `--self-check`. Always safe; a real socket, a
  synthetic CC stream, no live process.
- `ds-hostbridge --live` — the real-container path; returns `ErrLiveGateUnset`
  unless `DS_E2E_LIVE=1` (the deferred manual step).

**Running it live by hand:** the operator runbook for driving a real Claude Code
through this stack is [`LIVE-VALIDATION.md`](LIVE-VALIDATION.md) — the no-spend
synthetic smoke, the `serpent claude` one-command live drive, and the
`ds-capture`-instead-of-CIA egress recipe.

## Decisions

- **D38** — runtime ignorance: the bridge speaks `attach.Event` out and
  `DriveInput`/`DriveGrant` in; the only runtime-aware import is the claude-code
  adapter/driver, and no CC-ism leaks out of this package.
- **D61** — one-writer/N-reader, enforced **server-side** at the `WatchSession`
  terminator (the server half of the TUI's client-side arbitration).
- **D79** — the transport-ambivalent `AttachHandle`: endpoint candidates (M0
  direct, relay reserved) + short-lived session-scoped `AuthMaterial` (D39) +
  WRITER/READER role + expiry.

## Language verdict (tier-2 byte-bridge)

[`DRIVE-PROTOCOL.md`](../wrapper/DRIVE-PROTOCOL.md) §"Language & performance"
asks the host-agent transport bridge to **default to Go, move only the byte-path
to Rust if tier-2 profiling shows it is the feels-local bottleneck, and record the
verdict here when tier 2 lands.** Tier 2 has now landed: the framed UDS transport
([`socket.go`](socket.go)) carries real bytes across a real socket, and
[`socket_test.go`](socket_test.go) profiles it against the in-process loopback
floor.

**Verdict: stays Go — measured, not assumed.** The benchmark
(`BenchmarkSocket_*` vs `BenchmarkLoopback_*`, `parallel-fanout` fixture, same-host
UDS) shows the framed-socket carrier adds, end to end per attached session
(dial + handshake + fan-out), single-digit-µs **per-event** cost over the
in-process floor — on the order of low tens of microseconds per event including
the one-time connection setup, against a sub-microsecond loopback baseline. That
delta is **JSON marshal/unmarshal + the syscall write/read of small frames over a
local UDS**, not a CPU-bound transform: it is dominated by per-event allocation
(the `encoding/json` round-trip) and kernel socket copies, both of which a Rust
rewrite would shave only at the margin while forcing a cross-language seam onto a
path that today reuses the Go adapter/driver `attach.Event` types directly. For a
sustained driving session the absolute per-event latency is far below the
feels-local threshold (the model round-trip dominates by orders of magnitude), so
**there is no measured bottleneck to move to Rust.** The decision is consistent
with the `dataplane/` split's own rule — perf-critical bytes go to Rust *when
measurement shows it*, and here measurement shows the byte bridge is not the
feels-local bottleneck.

Where Rust would re-enter the conversation, to be re-profiled then, not now:
the **cross-container / cross-VM** carrier (real network namespace crossing,
larger frames, many concurrent spectators) the `live.go` `DS_E2E_LIVE` step and
the M2 relay introduce — a different measurement than this same-host UDS floor. If
that path shows the marshal+copy cost dominating at the feels-local boundary,
moving *only* the frame codec to a small Rust component remains the consistent
move. The same-host tier-2 verdict stands until that profile exists.

## Deferred work

- **Cross-container transport bring-up** — `socket.go`'s `Serve` / `ServeBridge`
  is the in-fleet server half; wiring it to a CC process inside
  `scripts/cc_sandbox.sh` (the client *outside* the container dialing the host
  UDS) is the `live.go` `DS_E2E_LIVE` deferred manual step.
- ~~**Resume protocol on the wire**~~ — **RESOLVED** (`01KTXRFTW4146JGZ4SP3SX0N76`,
  [`socket.go`](socket.go)): the cross-process reader now recovers a dropped span
  over the socket frame via `SocketConn.Resume` → `frameResume{afterSeq}`,
  answered from the SAME `Bridge.ReplayFrom` history ring as loopback — no full
  re-attach. See the "Resume protocol on the wire" capability bullet above. The
  loopback-vs-socket recovery asymmetry this entry named is closed.
