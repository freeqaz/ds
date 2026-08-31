# client/goldentrace/e2e/ — the live drive-conformance harness

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D38, D49, D50 ·
**Tier 1 of** [`../../wrapper/DRIVE-PROTOCOL.md`](../../wrapper/DRIVE-PROTOCOL.md)
("The e2e harness, in tiers"). Findings backlink:
[`../../wrapper/DRIVE-FINDINGS.md`](../../wrapper/DRIVE-FINDINGS.md).

This package drives a **real Claude Code** process — record or replay — through
`scripts/cc_sandbox.sh` and projects its stdout
back to `attach.v1`, closing the wrapper↔CC↔driver loop. Where `../replay/`
replays **static** synthetic cassettes (proving the parser is deterministic),
this tier proves we can actually *drive*: send input, sustain the stream, and
project the output of a live binary — with its model "brain" frozen by
record-replay so the run is reproducible.

It is **runtime-ignorant** (D38): no CC record names, no `toolu_`/`task_id`
vocabulary, no runtime flag strings live here. The one runtime fact it encodes is
the `SandboxArgv` contract — the *script* CLI it shells out to — and the stdout→
`attach.v1` projection is delegated to a `Projector` the live tier supplies
(backed by the claude-code adapter, the one place a runtime is named). Stdlib-only.

## One gate story: `DS_E2E_LIVE=1`

There is exactly **one** documented live gate: `DS_E2E_LIVE=1`. Unset — the
default, and **every CI and `go test` run** — nothing is ever launched:

- `e2e.DriveLive(...)` returns `ErrLiveGateUnset` without spawning a process.
- `scripts/cc_sandbox.sh` runs its gates and prints the launch *plan*, but never
  execs podman.

`CC_SANDBOX_LIVE` is **retired**. It arms nothing by itself; if it is set without
`DS_E2E_LIVE`, the script refuses with a pointer to the new name rather than
silently launching. The harness and the script agree on the single name.

So the tests here, `sh -n scripts/cc_sandbox.sh`, and
`scripts/cc_sandbox.sh --self-check` are all safe to run anywhere — none of them
sets the gate, so none of them can reach a `claude`, `cia`, or `podman`
invocation. The live launch is the **deferred manual step** (below).

## The script CLI contract (`SandboxArgv`)

`scripts/cc_sandbox.sh` is the gated launcher; its drive CLI is the `SandboxArgv`
contract, mirrored field-for-field by `e2e.SandboxArgv` (the structural
argv-contract test ties the two together so they cannot drift):

```
cc_sandbox.sh --captool <bin> --mode record|replay --cassette <path> \
              [--budget-usd <X> | --no-egress]
```

| flag | `SandboxArgv` field | meaning |
|---|---|---|
| `--captool <bin>` | `CapToolBin` | the first-party capture binary (`ds-capture`); its egress-gateway proxy defaults to the free `:18099` |
| `--cia <bin>` *(deprecated)* | `CIABin` | the external CIA recorder/replayer alias — bounded migration overlap only (`--captool` wins); legacy proxy `:18080` |
| `--mode record\|replay` | `Mode` | record (live API via the capture tool) or replay (offline) |
| `--cassette <path>` | `Cassette` | API-response cassette: written in record, read in replay |
| `--budget-usd <X>` | `BudgetUSD` | per-run cost cap (record only; default `0.60`) |
| `--no-egress` | `NoEgress` | force the zero-egress network even in record |

The `--captool` leg is the **carry-side** capture binary: the first-party
`ds-capture` (CAPTURE-TOOL-DESIGN.md §3/§4) that replaces the external
Python/mitmproxy `../cia`, kept off the "discover" side of the language split
([`DRIVE-PROTOCOL.md`](../../wrapper/DRIVE-PROTOCOL.md) §Language & performance).
Its egress gateway defaults to the **free `:18099`**, never the protected
`:18080` monitor.

**Migration overlap (taskdb `01KTXKJYYW`).** The deprecated `--cia` /
`CIABin` leg is retained only for the bounded two-flag overlap — the launcher
accepts both `--captool` and `--cia`, **warns** on `--cia`, and `--captool`
wins when both are given. The terminal retire step deletes `--cia`, `CIABin`,
the `:18080` default, and the `~/.cia` references once every consumer is off
the deprecated leg (CAPTURE-TOOL-DESIGN.md §5 step 4); that step also rewrites
the `capture.sh` `cia record` leg and the `e2e/live_drive.go` proxy default,
which sit outside this unit's file fence.

**Gate-then-launch.** The launcher always runs G1–G7 first; the podman launch is
the *only* thing behind `DS_E2E_LIVE=1`. The control actions are all gate/plan,
never launch unless armed:

- `--self-check` — run the planted-violation suite (proves the gate is not
  vacuous) and exit. Including: a `--mount type=bind,source=/tmp/cc-daemon-…`
  bind **must fail** the gate (the hardened G4); a well-formed
  `--captool X --mode replay --cassette Y --no-egress` invocation **must** parse
  and gate green and launch nothing; the deprecated `--cia` alias still gates
  green (the bounded overlap), `--captool` wins when both are given, the record
  proxy defaults to the free `:18099` (never the protected `:18080`), and an
  invocation with **no** capture binary fails G0.
- `--gate` — run G1–G7 against the argv and exit 0/non-0.
- `--plan` — print the podman argv + env the launch would use.
- `--gate-then-plan` — gate, then plan (the CI dry run; also the default for a
  bare drive invocation).

The gates, in brief: **G0** argv contract · **G1** rootless / fresh userns ·
**G2** `--no-session-persistence` + `--model sonnet` + budget cap ·
**G3** container-local `HOME`/`CLAUDE_CONFIG_DIR` · **G4** no forbidden host bind
mount, in **both** `-v`/`--volume` *and* `--mount type=bind,source=…` spellings
(the hardened scan — `/tmp/cc-daemon-*`, host `/tmp`, host `HOME`, `~/.claude`,
`~/.cia`) · **G5** image pinned to CC `2.1.173` (never `:latest`) · **G6**
mode/network coherence · **G7** the in-container runtime assert is wired.

## The two network paths

The network is **mode-dependent** (replacing an old hard-pinned `--network=none`):

- **record** — wires CC to the capture tool's egress-gateway proxy on the free
  **`:18099`** (never the protected `:18080` monitor) the rootless way
  (`--network=slirp4netns:allow_host_loopback=true`, reaching the host-loopback
  proxy via `host.containers.internal`), exporting
  `HTTPS_PROXY`/`HTTP_PROXY=http://host.containers.internal:18099` **and**
  `NODE_USE_ENV_PROXY=1` (PHASE2 P6: undici honours the proxy env only with that
  flag). The API is reachable **only through** the proxy; cred-bearing,
  budget-capped. This produces the API-response cassette. (`CAPTOOL_PROXY_PORT`
  overrides the port.)
- **replay / `--no-egress`** — `--network=none`, **zero external egress**, no
  proxy env, cred-free. The cassette is mounted read-only; CC regenerates its
  stdout from the frozen responses. This is the hermetic CI tier (D50 satisfied
  by construction). Replay is always zero-egress regardless of `--no-egress`.

## The pinned runtime image (D49)

`scripts/cc-sandbox/Containerfile`
pins the runtime image to **Claude Code 2.1.173** — the version the adapter
targets (`../PROTOCOL-NOTES.md`) and the golden-image pin (D49). The plan
references it as `CC_SANDBOX_IMAGE` (`ds/cc-sandbox:2.1.173`); the script and the
tests only ever **name** the tag. The image is **never pulled, built, or run by
any test**. Its entrypoint is
`cc-sandbox-entry` — the
in-container runtime assert (G7's in-band half): before exec'ing `claude` it
re-checks, from inside the container, that the user namespace is fresh, that
`HOME`/`CLAUDE_CONFIG_DIR` are container-local, and that no host
`/tmp/cc-daemon-*` is visible, aborting hard otherwise (PHASE2 §5 /
DRIVE-PROTOCOL §isolation). Build it by hand:

```sh
podman build -t ds/cc-sandbox:2.1.173 scripts/cc-sandbox/
```

## The deadlock-safe drive pump

`driveStreams` is the core, factored to run against in-memory pipes so it is
tested without spawning anything. It implements DRIVE-PROTOCOL.md's
goroutine-per-stream model: a **writer** goroutine drives each input to stdin and
closes stdin after the final input; a **reader** goroutine projects stdout
**concurrently**. Error aggregation preserves `firstErr` semantics (ctx error
dominates, then the projection error, then the writer error) and `ctx`
cancellation aborts promptly (the streams are closed to unblock a pump stuck on a
pipe read/write).

The regression test (`harness_test.go`) drives this through **bounded** in-memory
pipes (the faithful OS-pipe model — `io.Pipe` is synchronous and cannot reproduce
the bug) with a fake CC that echoes input to output: the **old** sequential
"write all inputs, then read stdout" shape **deadlocks** there (proven), and the
concurrent pump must not — bounded by the `go test` timeout so a regression is a
failure, not a hang.

## The deferred manual live step

The actual live drive is operator-driven and runs only when `DS_E2E_LIVE=1`:

1. Build the pinned image (above).
2. Start the first-party `ds-capture` in the chosen mode on the free `:18099`
   (`ds-capture record --port 18099 …`: creds in the job dir, budget-capped;
   replay: point it at the cassette). Never the protected `:18080` monitor.
3. Run the launcher armed:

   ```sh
   DS_E2E_LIVE=1 scripts/cc_sandbox.sh \
       --captool <ds-capture-bin> --mode replay --cassette <path> --no-egress
   ```

The launcher gates again (G1–G7 + the in-container assert) and prints the exact
podman argv to run. Captures are raw-class — real paths, costs, `Authorization:`
headers — and stay in the job dir; only re-authored **synthetic** cassettes ever
enter git (D50, `../HARDENING-NOTES.md`, `../../fixtures/PROVENANCE.md`).

The step-by-step operator runbook — including `serpent claude`, the one command
that runs this live tier (gateway + container + drive) routed through the
first-party `ds-capture` egress gateway instead of the external CIA monitor — is
[`../../hostbridge/LIVE-VALIDATION.md`](../../hostbridge/LIVE-VALIDATION.md).

## The LIVE-DRIVE tier — the loop, closed (`live_drive.go`)

`DriveLive` above drives CC's stdout/stdin **directly** (tier 1). The
**live-drive tier** (`live_drive.go` / `live_drive_test.go`, taskdb
`01KTXBGTJA`) closes the *full* loop through the D79 transport: a **thin client
speaking only `attach.v1`** drives a **real Claude Code** process across the
**framed UDS** (`hostbridge.SocketTransport`) and the **wrapper** (the
`hostbridge.Bridge`, which imports the existing adapter+driver verbatim):

```
thin client ──attach.v1 over framed UDS──▶ host-agent (Server+Bridge) ──┐
  SocketTransport.Dial; DriveInput/DriveGrant   │ wrapper adapter+driver │
                                CC stdin/stdout (podman -i pipes)         │
                                                ▼                         │
                         REAL claude --input-format stream-json …         │
                         inside a rootless podman container ◀─────────────┘
```

The host-agent **fronts** the container (it owns the CC process lifecycle via
`podman -i` pipes), so CC stdio crosses the **container/namespace boundary** via
podman's pipes while the `attach.v1` transport (the UDS) crosses a real
**process boundary** on the host — the closest realizable D79 crossing for
tier 2 ("CC in the container … the thin client attaches from outside and drives
in"). Putting the UDS *inside* the container would require the host-agent inside
too, defeating the fronting design.

The thin client names **no CC-ism**: `DriveText` is an `attach.v1` input, and an
ask is answered with `GrantAsk` (a TTL'd policy-stream grant, D18/D45/D53) — the
wrapper turns the grant into CC's `control_response` *inside* the boundary. The
ask arrives natively because the container runs `--permission-prompt-tool stdio`
with **no** `--allowedTools` (DRIVE-FINDINGS §1).

### Live run evidence — 2026-06-12 (`01KTXBGTJA`, live-e2e r2)

The gated `TestLiveDriveSocketBridgeReal` was run with `DS_E2E_LIVE=1` against
**real Claude Code `2.1.173`** in a rootless podman container (image
`ds/cc-sandbox:2.1.173`), egress through the `:18080` CIA proxy
(`--network=pasta:-T,18080`, `NODE_EXTRA_CA_CERTS=/ca/mitmproxy.crt`,
`NODE_USE_ENV_PROXY=1`), the host claude binary mounted ro at `/opt/claude-code`
(the in-image npm build is broken under TLS interception). **It passed**, driving
a multi-turn session and projecting **20 `attach.v1` events** the thin client
received over the UDS:

```
session.init · quota.updated · chat.message ×2 · tool.invoked(Agent) ·
session.state · subagent.completed · subagent.accounted · chat.message ×2 ·
session.accounted · session.state · session.init · chat.message ·
tool.invoked(Bash) · ask.requested(source=control) · tool.completed ·
ask.resolved(behavior=allow) · chat.message · session.accounted
```

- **chat** — multi-turn assistant text across two turns (one live CC process,
  sustained; a fresh `session.init` per driven input, DRIVE-FINDINGS §3).
- **subagent-spawn** — the live model dispatched a real `Agent` subagent
  (`tool.invoked` → `subagent.completed` → `subagent.accounted`, id-correlated by
  node_id; spawn happens-before its terminals).
- **ask-grant round-trip** — a Bash tool escalated to the **native**
  `can_use_tool` control_request (`ask.requested` source `control`, carrying
  `permission_suggestions[]`); the thin client answered `allow` on the grant
  path; the wrapper drove the `control_response` into CC, the tool **executed
  live** (`tool.completed` `is_error=false`, "Done. `/work/scratch/seed.txt` now
  contains 'seeded'"), and `ask.resolved` correlated back id-relative
  (`ask_id`/`node_id`, request precedes resolution).

Assertions are **structural / id-relative**, never literal ids or wall-clock
(DRIVE-PROTOCOL.md): `validateEvents` (seq monotonic-from-1, constant session,
one payload per event) plus the spawn-tree node_id correlation and the
ask request→resolve happens-before — the same checklist machinery the goldentrace
suite uses. **3 live sessions, ~$0.18 total spend**, all under `--model sonnet`,
`--max-budget-usd`, the ≤$5/session and ≤4-session rails. The raw CC stdout
capture is **raw-class** (under `~/tmp/…`, env `DS_LIVE_SCRATCH`) and is **never
committed**; no token, cost, or real path enters git (D50).

The harness builds the podman argv itself because `cc_sandbox.sh`'s `launch_live`
is a **planner, not a launcher** (DRIVE-FINDINGS §drift 3) — the script remains
the gate/plan oracle; the Go harness is the executor, re-asserting the G-gate
invariants (rootless, sonnet, budget, no forbidden mount, the cc-sandbox-entry
in-container assert) before any container starts. The `cc_sandbox.sh` plan was
reconciled with what ran live: G1 no longer requires the crun-broken
`--userns=auto` (the default rootless userns is fresh and sufficient), the claude
argv carries `--permission-prompt-tool stdio`, and the CA/host-binary/pasta
notes are recorded (DRIVE-FINDINGS §"Code/plan drift").

### Re-pin run evidence — 2026-06-12 (`01KTXXFSA4` / `01KTXRHN8T`, re-pin pass)

The post-keystone re-pin pass re-drove this topology live to consolidate two
residual risks behind the same gated live step (raw-class captures under
`~/tmp/ds-keystone/cap-repin/`, never committed; `--model sonnet`,
`--max-budget-usd` cap, egress only through the read-only `:18080` proxy). **4
live sessions, ~$0.05 total**, all under the rails:

- **`initialize` registry-block re-confirmation** — an initialize-only SDK-host
  probe (no model turn, near-zero spend) re-captured the native `initialize`
  control_response and confirmed its registry block + conditional riders match
  the keystone shape, with one synthetic-completeness correction to the
  `models[]` object (DRIVE-FINDINGS §"Re-pin pass"; the completed-registry
  fixture is deferred to the cassette owner — a new `fixtures/*.cc-wire.ndjson`
  auto-requires goldens under the fenced `replay`/`canary` testdata trees).
- **cross-process resume over the LIVE wire** — the full `live_drive.go` topology
  (`NewBridge`+`NewServer`+`ServeBridge` over a real framed UDS, a WRITER thin
  client + a second READER) drove a live Bash-ask turn (**9 `attach.v1` events**,
  the native ask **executed live** via the grant→`control_response` path), then
  exercised `SocketConn.Resume` over the **live** `frameResume`/`frameResumeReply`
  codec against a bridge fed by **live CC stdout**: `Resume(0)` backfilled the
  retained ring exactly-once-ascending, `Resume(1)` (an aged-out span) returned
  LOUD with `errors.Is(_, ErrResumeWindowExceeded)` across the wire (conn
  surviving), `Resume(maxSeq)` (caught up) returned an empty span. First live
  round-trip of the resume protocol on live-projected events (the gated
  `TestLiveDriveSocketBridgeReal` + `hostbridge/socket_test.go` prove the drive
  and the synthetic resume respectively; the live resume was driven by an
  uncommitted re-pin harness under `~/tmp/`).
- **what stays unverified** (documented limitation, no behavior change): the
  server-side outbox **overflow drop** (`socketOutboxDepth=256`, an unexported var
  only an in-package test shrinks) was not triggered by live event volume — the
  recoverable gap was forced via the history-ring window instead; and a true
  cross-CONTAINER UDS is not realizable without the host-agent inside the
  container. See DRIVE-FINDINGS §"Re-pin pass" for the full residual list.

## Tests

- `TestDriveStreamsBackpressure` — the deadlock regression (bounded pipes).
- `TestDriveStreamsClosesStdin` / `…ProjectorFault` / `…ContextCancel` — the
  pump's close-after-final-input, firstErr fault, and ctx-cancel semantics.
- `TestDriveLiveGated` — `DriveLive` returns `ErrLiveGateUnset` with the gate
  unset (never spawns).
- `TestSandboxArgvMatchesScriptUsage` — the structural argv-contract test: every
  flag `SandboxArgv` emits (now including `--captool`), the single live gate, the
  network tokens (the `:18080` legacy/monitor token survives during the
  deprecation overlap, plus `--network=none`), and the gate/plan actions all
  appear in the script source (read, never executed). The test migrates to assert
  `--captool` and drop the `:18080` expectation in the terminal retire step
  (CAPTURE-TOOL-DESIGN.md §4) — that edit lands in `harness_test.go`, outside this
  unit's file fence.
- `TestSandboxArgvArgsShape` / `…Validate` — the rendered argv shape and the G0
  cross-flag validation.
- `TestLiveDriveSocketBridgeFakeCC` / `…Deny` — **always-on**: the full
  host-agent + framed-UDS + thin-client wiring driven against a **scripted
  fake-CC helper process** (a real separate process with real stdio pipes, the
  exact shape the live podman process presents). Proves chat + subagent-spawn +
  the ask grant round-trip (allow *and* deny) structurally, in CI, with **no**
  live `claude`/`cia`/`podman` — every line the live path runs except the model's
  scripted choice to call the tool.
- `TestLiveDriveSocketBridgeGated` — `DriveLiveSocketBridge` returns
  `ErrLiveDriveGateUnset` (wrapping the shared `ErrLiveGateUnset`) with
  `DS_E2E_LIVE` unset: the real-container entry launches nothing.
- `TestLiveDriveSocketBridgeReal` — **gated `DS_E2E_LIVE=1`**: the real
  live-drive container run (see the live run evidence above). Skips without the
  gate, so it is CI-green by default; the fake-CC twin proves the wiring offline.

