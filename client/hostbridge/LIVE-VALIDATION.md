# LIVE-VALIDATION.md — running real Claude Code against our backend

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D18/D38/D45/D49/D50/D53/D61/D79
· taskdb `01KTXMC3` (operator-run tier-2 validation) · **Single live gate:** `DS_E2E_LIVE=1`

This is the operator runbook for driving a **real Claude Code `2.1.173`** through the
Dream Serpent stack and confirming the round-trip by hand. It collects the recipes the
keystone (`01KTXBG14J`) and the live-drive harness (`01KTXBGTJA`) proved, so a manual
validation is a checklist, not an investigation.

> **Validated live 2026-06-15** against Claude Code `2.1.173`:
> `serpent claude` ran the real `claude` through our gateway (replied `PONG`; the gateway
> captured the turn); `serpent drive` drove a Bash-tool prompt through the backend (6
> `attach.v1` events incl. `tool.invoked → tool.completed`); the gated `TestLiveDriveSocketBridgeReal`
> passed (19 events incl. a live `ask.requested → ask.resolved` round-trip; gateway captured
> all 6 `/v1/messages` turns); **C** ran real CC (Haiku) through the gateway; **A** projected
> its deltas. Raw captures stayed under `~/tmp` (D50).

There are **four things you can run**, in increasing fidelity:

| | What it exercises | Real CC? | API spend |
|---|---|---|---|
| **A — synthetic smoke** | the thin-client transport stack (UDS + bridge + driver + adapter) over a synthetic CC stream | no | none |
| **B — thin-client live drive** | a thin client driving REAL CC through our wrapper/hostbridge backend in a **rootless podman** container, egress via **ds-capture** | yes | ~$0.02–0.12 (Sonnet, capped) |
| **C — Claude Code → our egress gateway** | plain `claude` with its API egress TLS-terminated and recorded by our first-party gateway (the **ds-capture instead of CIA** path) | yes | budget-capped |
| **D — KVM-VM writer-seat drive** | the SAME scripted scenario as B, retargeted by a **transport-target swap** to drive REAL CC running INSIDE a **per-session KVM VM** over `attach.v1`, dialing the writer-seat the live host-agent serving child advertises | yes | budget-capped |

> **`serpent up` — the VM-hosted path (Milestone-1 LIVE CLOSE) lives elsewhere.**
> A/B/C above all drive Claude Code in a **rootless podman** backend on the host.
> The M1 live close drives a real Claude Code running INSIDE a **per-session KVM
> VM**, writer-seat over `attach.v1`, with `serpent up`. That arc — bake the M0
> image → the nft4 host↔guest `:4242` allow → the host-agent daemon
> (`DS_HOSTAGENT_LIVE=1`) → the orchestrator (`DS_ORCH_LIVE=1`) → `serpent up
> --orchestrator/--repo/--env-config-ref` → drive — is the consolidated operator
> runbook at
> [`../../orchestrator/cmd/host-agent/LIVE-SMOKE.md`](../../orchestrator/cmd/host-agent/LIVE-SMOKE.md)
> **§A**. `serpent up` itself EXECs the `serpent-tui` sibling (resolved exactly
> like `ds-capture`), keeping grpc/bubbletea out of this stdlib-only client (D80).

> **Two independent gates.** B is behind `DS_E2E_LIVE=1` (it launches a podman
> container running real CC); **D** is behind its own `DS_KVM_LIVE=1` (it dials a
> writer-seat a *separate* live VM already serves — it launches no podman/claude/cia
> of its own, so arming it is the independent "there is a live VM serving this
> session" step). A and C are always safe to run. With both gates unset — every
> `go test` / CI / sandbox run — the harness launches **no** podman, claude, capture
> daemon, **and dials no socket**; the gated tests skip cleanly (exit 0).

> **D50 wall.** Anything a live run records — real paths, costs, `Authorization: Bearer …` —
> is **raw-class**: it stays under `~/tmp`/the job dir and is **never committed**. Only
> re-authored **synthetic** cassettes enter git (`../goldentrace/HARDENING-NOTES.md`,
> `../fixtures/PROVENANCE.md`). Run `ds-capture scrub` before any promotion.

---

## Prerequisites (verify once)

```sh
podman image ls | grep ds/cc-sandbox     # localhost/ds/cc-sandbox:2.1.173 present (D49 pin)
ls -l /opt/claude-code/bin/claude        # host claude mounted ro into the image (drift 1)
ls -l ~/.claude/.credentials.json        # OAuth token source (.claudeAiOauth.accessToken)
id -u                                    # must NOT be 0 — rootless podman only
```

Build the binaries (or `go run` them straight from source via `go.work`):

```sh
( cd client && go build -o ../.bin/serpent      ./cmd/serpent )
( cd client && go build -o ../.bin/ds-capture   ./cmd/ds-capture )
( cd client && go build -o ../.bin/ds-hostbridge ./cmd/ds-hostbridge )
export PATH="$PWD/.bin:$PATH"   # so `serpent` finds `ds-capture` as a sibling
```

---

## The everyday command: `serpent claude` (the real TUI, through our backend)

`serpent claude` **wraps the real Claude Code TUI**. It stands up the ds-capture
egress gateway (auto-picking a free port), runs the real `claude` binary with its
stdio inherited — so the full terminal UI works exactly as normal — routes its API
egress through the gateway, and tears the gateway down on exit. It is just `claude`
+ a local egress gateway, so it needs **no container and no gate**.

```sh
serpent claude                          # the real interactive Claude Code TUI
serpent claude -- -p "summarize x.go"   # anything after `--` is passed to claude
#   --keep     keep the raw-class gateway cassette for inspection (D50)
#   --port N   pin the gateway port (default: auto-pick a free one; never :18080)
#   --claude PATH / --capture-bin PATH   override the resolved binaries
```

The session runs through our gateway; every `/v1/messages` turn lands in the
gateway cassette (raw-class — see the D50 wall). Use this for "drive Claude Code
normally, against our backend."

> **Tier B — `serpent drive` (headless, gated).** The other process form: launch a
> real CC in the podman backend fronted by the host-agent bridge and drive ONE
> prompt over `attach.v1`, printing the projected event stream. This is the
> attach-plane POC (chat / tool / ask round-trip as `attach.v1` events), not an
> interactive TUI:
>
> ```sh
> DS_E2E_LIVE=1 serpent drive --prompt "Run 'echo hi' with the Bash tool." [--deny]
> ```
>
> It prints e.g. `session.init → quota.updated → tool.invoked → tool.completed →
> chat.message → session.accounted`. **The longhand it replaces** (start the gateway
> in one terminal, run the gated harness pointed at it in another):
>
> ```sh
> go run ./client/cmd/ds-capture record --port 18099 --cassette ~/tmp/cap.json --ca-dir ~/tmp/ds-ca
> DS_E2E_LIVE=1 DS_LIVE_PROXY_PORT=18099 DS_LIVE_CA=~/tmp/ds-ca/ds-capture-ca.pem \
>     go test ./client/goldentrace/e2e -run TestLiveDriveSocketBridgeReal -v
> ```

---

## A — synthetic smoke (no spend, runs anywhere)

Proves the thin-client surface end to end — a synthetic CC stream projected to `attach.v1`
deltas over a **real framed UDS**, and a writer-seat `DriveInput` encoded back onto CC stdin
by the real driver — with no live process:

```sh
go run ./client/cmd/ds-hostbridge --socket-self-check --drive "hello from the thin client"
```

You should see the projected `attach.v1` deltas (`seq=… type=session.init / chat.message / …`)
and the bytes the driver wrote to CC stdin. This is the fast pre-flight before any live run.

---

## B — thin-client live drive (real CC → our backend, egress via ds-capture)

A thin client speaking only `attach.v1` drives a **real** Claude Code in a rootless podman
container, across the framed UDS, through the wrapper (adapter+driver) — a multi-turn chat,
a subagent spawn, and a native tool **ask** answered on the grant path. The harness lives in
`../goldentrace/e2e/live_drive.go`; you arm it with the gate.

> **Prefer `serpent drive`** (above) — it is this tier in one command. The two-terminal
> form below is the underlying harness, useful when you want to pin the gateway port, keep
> the cassette, or run the fixed conformance scenario (`TestLiveDriveSocketBridgeReal`).

**The longhand (routed through our first-party ds-capture egress gateway on `:18099`):**

```sh
# 1) stand up the first-party egress gateway in one terminal:
go run ./client/cmd/ds-capture record --port 18099 \
    --cassette ~/tmp/live-drive.json --ca-dir ~/tmp/ds-ca

# 2) in another, drive real CC through the thin-client stack, pointed at it:
DS_E2E_LIVE=1 DS_LIVE_PROXY_PORT=18099 DS_LIVE_CA=~/tmp/ds-ca/ds-capture-ca.pem \
DS_LIVE_SCRATCH=~/tmp/ds-live \
    go test ./client/goldentrace/e2e -run TestLiveDriveSocketBridgeReal -v
```

The test prints the projected `attach.v1` event stream and the raw-capture path, and asserts
the chat + spawn + ask round-trip against the conformance checklist — now against **live**
output. `ds-capture` writes the parallel API-plane cassette to `~/tmp/live-drive.json` (raw-class).

**Routing knobs** (`live_drive_test.go`, all additive — unset ⇒ the default `:18080` read-only
CIA monitor + mitmproxy CA, the legacy path):

| env | effect |
|---|---|
| `DS_LIVE_PROXY_PORT` | egress-gateway port; re-derives the pasta forward (`pasta:-T,<port>`) |
| `DS_LIVE_CA` | the CA the gateway terminates TLS with (the ds-capture CA when routing through ds-capture) |
| `DS_LIVE_NET` | override the podman egress-network spelling (e.g. a portable slirp4netns form) |
| `DS_LIVE_SCRATCH` | persist the raw CC-stdout capture for inspection (under `~/tmp`, never committed) |

The fake-CC twin proves the exact same wiring offline (no gate, no spend):
`go test ./client/goldentrace/e2e -run TestLiveDriveSocketBridgeFakeCC -v`.

### Scripted headless drive (multi-turn, data-driven, VM-side-effect-proven)

The conformance run above pins one fixed conversation. The **scripted headless
drive** generalizes it: a real CC session driven **headlessly** (no human),
**multi-turn**, from a committed **JSONL script** — one `Turn`
(`{"prompt":…,"allow":…,"assert":{…}}`) per line — stepped over the **same**
`DriveLiveSocketBridge` engine and the **same** thin-client surface
(`DriveScriptScenario`, `client/goldentrace/e2e/script.go`). Each turn's tool-use
ask is answered on the **proven `attach.v1` grant path** (`GrantAsk` → the
wrapper's native `control_response`) — **never** `--dangerously-skip-permissions`
on the host.

The deterministic proof goes one step past the projected events: the committed
fixture [`../goldentrace/e2e/testdata/proof.jsonl`](../goldentrace/e2e/testdata/proof.jsonl)
instructs CC to write a token to a proof file under its `/work` cwd, and the gated
test asserts **both halves** — the projected `attach.v1` ask round-trip closed
allow, **and** the proof file actually exists on the host side of the `/work`
bind mount carrying the token. That second half proves CC **executed** the
instruction in the container, not merely streamed text about it.

**Operator invocation** (the smoke harness arms the gate and runs the gated test
against the committed fixture, recording GREEN):

```sh
# offline first (no gate, no spend) — proves the parser + multi-turn stepping:
scripts/ds-headless-drive-smoke.sh --offline

# the armed live run (real CC in rootless podman, egress via the operator's
# ds-capture gateway on :18099 — prerequisites as in §B above):
scripts/ds-headless-drive-smoke.sh --proxy-port 18099 \
    --ca ~/tmp/ds-ca/ds-capture-ca.pem --scratch ~/tmp/ds-headless
```

The longhand it wraps (the gated test directly):

```sh
DS_E2E_LIVE=1 DS_LIVE_PROXY_PORT=18099 DS_LIVE_CA=~/tmp/ds-ca/ds-capture-ca.pem \
    go test ./client/goldentrace/e2e -run TestScriptedDriveVMSideEffectReal -v
```

The offline fake-CC twins (`TestDriveScriptScenarioFakeCC` / `…Deny` /
`…MultiTurn`, plus `TestParseScript*`) prove the JSONL parse and the multi-turn
stepping — the grant round-trip and per-turn result advance — with **no**
podman/claude/cia, so they run in the wave gate and the gated test skips cleanly
when `DS_E2E_LIVE` is unset.

> **Retargets to the KVM tier by a transport-target swap (tier D below).**
> `DriveScriptScenario` speaks only `attach.v1` and names no transport, so the
> **same scenario code** — the same fixture, the same stepping, the same assertion
> helpers — drives the per-session **KVM VM** tier (taskdb `01KV8YSY8N`). Tier D is
> that retarget: it dials the writer-seat the live host-agent serving child
> advertises instead of launching a local podman container. No change to the
> script, the stepping, or the `validateEventsLive` / `assertAskRoundTripLive` +
> VM-side-effect assertions.

---

## D — KVM-VM writer-seat drive (the scripted scenario, retargeted to a per-session VM)

Tier D drives the **exact same** scripted headless scenario as tier B's scripted
drive (the committed [`../goldentrace/e2e/testdata/proof.jsonl`](../goldentrace/e2e/testdata/proof.jsonl)
fixture, `DriveScriptScenario`, the same ask-grant round-trip and VM-side-effect
proof), but against **real Claude Code running inside a per-session KVM VM** rather
than a rootless podman container. It is a **transport-target swap, not a scenario
change**: where tier B launches a local container + host-agent and dials its local
UDS, tier D dials the **writer-seat the live `ds-hostbridge` serving child already
advertises** — the host side of the per-session framed UDS the in-guest forwarder
splices to `GuestIP:4242` (the §A topology in
[`../../orchestrator/cmd/host-agent/LIVE-SMOKE.md`](../../orchestrator/cmd/host-agent/LIVE-SMOKE.md)).
The thin client uses the **same `hostbridge.SocketTransport`**; only the dial target
differs.

**Prerequisite: a live VM is already serving the session.** Tier D launches no
podman/claude/cia of its own — it is a pure `attach.v1` client. Stand up the M1
create→boot path first (bake → nft4 `:4242` allow → host-agent daemon →
orchestrator → `serpent up`), so the serving child is up and has minted a
session-scoped writer-seat token. That whole arc is the consolidated runbook in
[`../../orchestrator/cmd/host-agent/LIVE-SMOKE.md`](../../orchestrator/cmd/host-agent/LIVE-SMOKE.md) §A.

**The writer-seat is resolved at runtime from `DS_KVM_LIVE_*` — nothing is
box-specific or hardcoded** (mirroring how tier B reads `DS_LIVE_PROXY_PORT` /
`DS_LIVE_CA`):

| env | effect |
|---|---|
| `DS_KVM_LIVE` | the gate: `=1` arms the tier (else `TestScriptedDriveKVMVMSideEffectReal` skips clean) |
| `DS_KVM_LIVE_ATTACH_UDS` | the host-local writer-seat the serving child advertises (e.g. `/run/ds/attach/<uuid>.sock`, `hostagent.DefaultAttachSocketDir`-rooted) |
| `DS_KVM_LIVE_SESSION` | the live session UUID the `AttachHandle` joins (the writer seat lives in the session record) |
| `DS_KVM_LIVE_TOKEN` *or* `DS_KVM_LIVE_TOKEN_FILE` | the short-lived session-scoped attach token (inline, or a file read from the per-session token store the libvirt attach minter wrote — raw-class, never committed) |
| `DS_KVM_LIVE_TRANSPORT` | optional carrier override (default `unix`; a future vsock-direct carrier slots in here unchanged) |
| `DS_KVM_LIVE_WORK` | optional: the host dir mounted at the guest `/work`, for the VM-side-effect proof readback (unset ⇒ the round-trip is still proven and the file readback is a manual operator check) |

**The longhand (the gated test directly):**

```sh
DS_KVM_LIVE=1 \
DS_KVM_LIVE_ATTACH_UDS=/run/ds/attach/<session-uuid>.sock \
DS_KVM_LIVE_SESSION=<session-uuid> \
DS_KVM_LIVE_TOKEN_FILE=<OverlayDir>/.ds-attach-tokens/<session-uuid>.json \
DS_KVM_LIVE_WORK=~/tmp/ds-kvm-work \
    go test ./client/goldentrace/e2e -run TestScriptedDriveKVMVMSideEffectReal -v
```

The test asserts **both halves** exactly as tier B does — the projected `attach.v1`
ask round-trip closed allow (`validateEventsLive` + `assertAskRoundTripLive`), **and**
the proof file CC wrote under the guest `/work` carrying the token (when
`DS_KVM_LIVE_WORK` points at the host side of that share). The offline fake-CC twins
(`TestDriveScriptScenarioFakeCC` / `…Deny` / `…MultiTurn`, `TestParseScript*`) prove
the same stepping + parser with **no** VM, and `TestDriveKVMScriptedGateUnset` proves
the tier dials **nothing** when `DS_KVM_LIVE` is unset — all run in the wave gate.

> **Validated live: `____-__-__` (operator to fill).** Run on the M0/M1 box against
> real CC `2.1.173` inside a per-session KVM VM. Fill in: the session UUID, the
> `attach.v1` event count, that the `ask.requested → ask.resolved` round-trip closed
> allow, and that the proof file landed on the guest `/work` with the token. Raw
> captures (the token, real paths) stay under `~/tmp`/the per-session store and are
> **never committed** (D50 wall).

---

## C — Claude Code → our egress gateway (ds-capture instead of CIA)

The direct replacement for the external `cia run --proxy-port 18080 -- claude …` recipe:
stand up `ds-capture record` on the free `:18099`, point a real `claude` at it, run, then
tear down and report the cassette. Egress is TLS-terminated and re-originated by **our**
gateway — the API turn lands in the cassette, everything else passes through.

**The one-liner** (`scripts/ds-capture-run.sh` does the start → env → run → teardown dance):

```sh
# default throwaway smoke (Sonnet, $0.10 cap):
scripts/ds-capture-run.sh

# drive a real command, capture it:
scripts/ds-capture-run.sh --cassette ~/tmp/cap.json -- \
    claude -p "List the files in this directory." --model sonnet --max-budget-usd 0.20

# interactive Claude Code through our gateway:
scripts/ds-capture-run.sh -- claude
```

**If you'd rather wire it by hand** (what the script automates):

```sh
go run ./client/cmd/ds-capture record --port 18099 \
    --cassette ~/tmp/cap.json --ca-dir ~/tmp/ds-ca &        # prints NODE_EXTRA_CA_CERTS=…
HTTPS_PROXY=http://127.0.0.1:18099 HTTP_PROXY=http://127.0.0.1:18099 \
NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS=~/tmp/ds-ca/ds-capture-ca.pem \
    claude -p "hello" --model sonnet --max-budget-usd 0.10
kill -INT %1                                                # gateway writes the cassette on exit
```

`NODE_USE_ENV_PROXY=1` is **mandatory** — this CC build (undici/Node 26) ignores the proxy env
for inference without it (the PHASE2 P6 confound).

**Replay (hermetic, zero-egress, cred-free):** serve a recorded cassette back instead of
reaching the API —

```sh
go run ./client/cmd/ds-capture replay --port 18099 --cassette ~/tmp/cap.json &
HTTPS_PROXY=http://127.0.0.1:18099 NODE_USE_ENV_PROXY=1 \
NODE_EXTRA_CA_CERTS=~/tmp/ds-ca/ds-capture-ca.pem \
    claude -p "hello" --model sonnet   # served from the cassette; never dials upstream
```

> `ds-capture` **refuses** to bind `:18080` — the protected shared monitor. Always `:18099`-class.

---

## Known drift & workarounds (from the keystone, `DRIVE-FINDINGS.md §"Code/plan drift"`)

1. **The in-image `claude` build is broken under TLS interception.** The `Containerfile`'s
   `npm install` fails `UNABLE_TO_VERIFY_LEAF_SIGNATURE` and the native package arrives
   corrupted. → The harness mounts the **host** `/opt/claude-code/bin/claude` read-only into
   the image (already wired). Keep the host binary at the pinned `2.1.173`.
2. **`--userns=auto` is broken with crun on kernel 7.0.x** (`openat /proc/self/cwd: Permission
   denied`). → The harness uses the **default rootless userns** + `--cap-drop=ALL
   --security-opt=no-new-privileges` (already wired); the in-container assert re-verifies the
   fresh namespace.
3. **`scripts/cc_sandbox.sh` is a PLANNER, not a launcher.** Even with `DS_E2E_LIVE=1` it
   prints the exact podman argv and stops. The live run is operator-driven — either run the
   printed argv yourself, or use harness B above (which builds an equivalent argv and execs it).
4. **The external `cia` record/replay can't coexist with the `:18080` monitor** (socket
   singleton). → This is exactly why we run the first-party **`ds-capture` on `:18099`** for
   both record and replay; the protected monitor is never touched.

---

## Cross-references

- **M1 live close (VM-hosted CC over attach.v1, `serpent up`):** [`../../orchestrator/cmd/host-agent/LIVE-SMOKE.md`](../../orchestrator/cmd/host-agent/LIVE-SMOKE.md) §A — bake → nft4 `:4242` allow → host-agent daemon → orchestrator → `serpent up` → drive → destroy reap — the create→boot path tier **D** above drives the scripted scenario over once it is up
- **Tier D engine (the KVM-tier transport-target swap):** `DriveKVMScripted` + `KVMAttachConfig` in [`../goldentrace/e2e/live_drive.go`](../goldentrace/e2e/live_drive.go); the gated test + the gate-unset guard in [`../goldentrace/e2e/script_test.go`](../goldentrace/e2e/script_test.go)
- Thin-client live tier (the harness B drives): [`../goldentrace/e2e/README.md`](../goldentrace/e2e/README.md) §"The deferred manual live step"
- Capture/replay tool charter: [`../goldentrace/CAPTURE-TOOL-DESIGN.md`](../goldentrace/CAPTURE-TOOL-DESIGN.md), [`../cmd/ds-capture/`](../cmd/ds-capture/)
- Drive-direction design & live findings: [`../wrapper/DRIVE-PROTOCOL.md`](../wrapper/DRIVE-PROTOCOL.md), [`../wrapper/DRIVE-FINDINGS.md`](../wrapper/DRIVE-FINDINGS.md)
- The gated launcher (planner): `../../scripts/cc_sandbox.sh`
- Raw-class hygiene (D50): [`../goldentrace/HARDENING-NOTES.md`](../goldentrace/HARDENING-NOTES.md), [`../fixtures/PROVENANCE.md`](../fixtures/PROVENANCE.md)
</content>
</invoke>
