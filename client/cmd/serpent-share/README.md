# serpent-share — DEMO: a tmux-style 2-person shared Claude Code session (D141)

**Charter:** a small, demo-grade tool that lets **N browsers share ONE Claude
Code stdin** (the shared keyboard) and **broadcasts CC's output to every
browser**. Two people drive the same Claude session at once, tmux-style.

**Owner:** Client workstream (CODEOWNERS `client/`). OSS (D15/D25), stdlib-only
(client/go.mod, D80).

**Mark:** OSS · demo · not a contract surface.

**D-numbers:** D141 (shared stdin; imperfect interleaving accepted, rigorous
turn-serializer DEFERRED), D61 (the one-writer/N-reader seat this demo
deliberately bypasses — see below), D50 (raw-class capture cleanup), D38/D79
(the runtime-ignorant attach.v1 / AttachHandle seam the Bridge realizes).

## This BYPASSES the Server seat ON PURPOSE — it is not the productized path

`hostbridge.Server.Attach` enforces the **D61 one-writer / N-reader** seat: a
second writer is REFUSED. That is the correct contract for arbitrated drive, and
it is the **exact opposite** of what a shared keyboard needs. So this demo does
**not** use the Server. It uses `hostbridge.Bridge` **directly**, which already
is the shared-stdio engine:

- **fan-out** — `Bridge.Pump(ctx, ccStdout)` projects CC stdout to attach.v1
  events and fans every event to **every** `Subscribe()`r. Each browser registers
  its own Subscriber, so each gets the full broadcast.
- **fan-in** — `Bridge.DriveInput(DriveInput{Text})` serializes **any** caller's
  write onto CC stdin under `stdinMu`, **byte-atomically** (a whole record at a
  time, never torn mid-record). Every browser's keystroke calls `DriveInput`, so
  all of them write to the **same** stdin.

The Server / WriterRelay seat-arbitration invariants are **untouched**: this
command imports the **Bridge, not the Server**. It is a D141 demo, not the
productized arbitrated-writer path.

### Imperfect interleaving is ACCEPTED (D141)

Two authors' lines can interleave into one CC *turn* and produce a garbled turn.
That is the **accepted-imperfect** part of D141 — the rigorous turn-serializer is
**DEFERRED**. We mitigate only cosmetically:

- every input is **tagged per author** (`[A] …`, `[B] …`) so it is visible who
  typed what, both on the shared stdin and in the broadcast output;
- input is flushed on a **line/submit boundary** (one `DriveInput` per line) — CC
  in `--print` stream-json mode is line/turn-granular, not raw-keystroke, so we
  never feed it a partial line.

`stdinMu` guarantees **byte-atomic** records (no two authors' records ever
interleave *on the wire*); turn-level coherence is the part we knowingly do not
guarantee. Do not mistake this for the productized WriterRelay seat.

## How it runs

One **local real Claude Code** launched as a plain child (no podman, no KVM —
none are needed for the lean path):

```
claude --print --input-format stream-json --output-format stream-json --verbose
```

with stdin/stdout pipes wired to a single `hostbridge.NewBridge`, and **API
egress routed through the first-party ds-capture gateway** (the same `setupGateway`
/ `proxyEnv` lifecycle as `serpent claude`, on a free local port — never the
protected `:18080` monitor). A tiny stdlib HTTP/WS server (`ws.go`) accepts N
browser WebSocket connections; every connection is **both** a writer (its
keystrokes call `DriveInput`, tagged) **and** a Subscriber (a per-connection
relay broadcasts every attach.Event back). A late/2nd joiner backfills the
session-so-far from the Bridge's resume ring (`ReplayFrom`).

The `--fake` mode swaps the real CC for an in-process **echo CC** (`fakecc.go`):
zero network, zero API spend — the always-green offline stand-in.

**D50:** the gateway cassette and any raw CC stdout are **raw-class** — they stay
under the `~/tmp` job dir and are reaped on exit (reuse `serpent`'s `keep=false`
cleanup posture). Never commit captures.

## Run recipe

Build the binaries (ds-capture must be resolvable for the real-CC run):

```sh
cd "$REPO_ROOT"   # the repository root
go build -o .bin/serpent-share ./client/cmd/serpent-share
go build -o .bin/ds-capture   ./client/cmd/ds-capture
export PATH="$PWD/.bin:$PATH"
```

### Offline demo (no API spend) — drive the echo CC

```sh
serpent-share --fake --addr 127.0.0.1:8099
```

Open `http://127.0.0.1:8099/` in **two** browser tabs/windows. Each tab shows its
author label (`A`, `B`, …). Type a line in either tab and press Enter — it appears
in **both** tabs (shared broadcast), tagged with the author. The echo CC replies
`echo: [<author>] <your line>`.

### Real shared Claude Code session (spends API budget, ~cents/turn)

```sh
serpent-share --addr 127.0.0.1:8099          # real local claude via ds-capture
```

Open `http://127.0.0.1:8099/` in **two** browsers. Both keyboards now drive the
**same real Claude Code session**: type in tab A *and* tab B; both prompts land
on the one shared stdin and CC's replies are broadcast to both tabs. Ctrl-C the
server (or the last browser leaving + CC exit) reaps the gateway and the
raw-class job dir.

Useful flags: `--port N` (pin the gateway port; never `:18080`), `--claude PATH`,
`--capture-bin PATH`, `--scratch DIR`, `--keep` (keep the raw-class job dir — D50
scrub-before-promotion), `--append "system text"`.

## Smoke test

```sh
scripts/ds-share-smoke.sh --offline   # TIER 1: fake/echo CC — always-green, no spend
scripts/ds-share-smoke.sh             # ARMED:  TIER 2 (DS_E2E_LIVE=1) real CC via ds-capture
```

- **Tier 1** (`TestSharedFanInFanOut`, `TestServerTwoClientsSharedSession`):
  proves **byte-atomic shared fan-in** (two concurrent keyboards → whole records
  on one stdin, never torn) and **shared fan-out** (two subscribers / two real WS
  clients see the same broadcast) against the echo CC. No network, no API spend.
- **Tier 2** (`TestSharedSessionRealCC`, `DS_E2E_LIVE=1`): drives a **real** local
  claude through ds-capture with two WS clients sending distinct prompts; asserts
  both reach CC and both clients observe both replies. Off by default (budget).

## Does anything need the operator's live infra (KVM / orchestrator)?

**No.** This demo runs **entirely on the local box**: a local real Claude Code as
a plain child + the ds-capture gateway + two browsers on a local WS port. There
is **no** dependency on KVM/qemu, podman, the orchestrator, or the host-agent.
(The productized arbitrated path — `orchestrator/internal/controlplane/writerrelay.go`
fronted by a host-agent and a KVM VM running CC — is a different, single-seat,
fail-closed surface and is explicitly NOT what this demo exercises.)
