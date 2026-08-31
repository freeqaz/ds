# serpent-tui

The real human-in-the-loop Claude Code experience over `attach.v1`: it dials the
orchestrator's `SessionService.WatchSession` as a subscriber and takes the writer
seat to drive a VM-hosted Claude Code session interactively (taskdb node N6).

- **Charter:** the interactive writer-seat attach client. It folds the
  `attach.v1.SessionEvent` stream a session emits into the OSS `client/tui`
  structured render model, renders it, turns operator keystrokes into writer-seat
  input, and surfaces approvals client-side as TTL'd grants. It is where the D18
  structured-delta surface becomes a live, drivable terminal.
- **Owner:** Client workstream (CODEOWNERS `client/` owner; this module sits beside
  `client/` as its interactive front end). See repo `CODEOWNERS` / `guardrail-map.yaml`.
- **Mark:** OSS. It imports only OSS trees (`client/**`) and the public contract
  module (`proto/gen/go`); it never reaches `paid/**`, `vm/**`, or `dataplane/**`.
- **Decisions:** D18, D45, D53, D61, D79 (resolve to `docs/04-architecture-overview.md` §6).

## Option C: a separate module, deliberately OUT of `go.work`

This is the ratified split (the same shape taskdb's TUI uses):

- `serpent-tui/` is its **own Go module** at the repo root with **its own
  `go.mod`**, and it is **NOT a member of the root `go.work`** (build it with
  `GOWORK=off`). The root workspace is the stdlib-only OSS/contract workspace; this
  module carries a heavy interactive-TUI dependency that the workspace must not.
- **`client/` stays stdlib-only.** `client/go.mod` gains no dependencies. `client/`
  owns the *pure* pieces: the `Model`/`Render` fold (`client/tui`), the `attach.v1`
  Go working model (`client/wrapper/attach`), and the writer-seat transport
  (`client/hostbridge`). serpent-tui **imports** those and is the **only** place
  `github.com/charmbracelet/bubbletea` enters the tree.
- The `proto/gen/go` and `client` modules are wired by repo-relative `replace`
  directives so the module builds offline against the frozen stubs; bubbletea /
  lipgloss come from the upstream module proxy.

## What it wires (three legs)

1. **READ — WatchSession subscriber** (`internal/watch`). A gRPC client of the
   FROZEN `orchestrator.v1 SessionService.WatchSession` server-streaming RPC (the N5
   handlers). Sends one `WatchSessionRequest{session_uuid, from_seq}` and Recv()s;
   on a transport drop it reconnects with capped-exponential-with-full-jitter backoff
   and **resumes from the last applied seq** (D79), exactly-once and in order. The
   dial/backoff/resume shape mirrors the existing reader-only subscriber
   `paid/webclient/attach/live.go` (serpent-tui re-derives it — it cannot import the
   paid tree, D80 — but the semantics are identical).
2. **MAP — `attach.v1` → `client/tui` Event** (`internal/eventmap`). Each frozen
   proto `SessionEvent` is mapped field-for-field onto the `client/wrapper/attach.Event`
   working model the `client/tui.Model` folds. The full §3 state vocabulary (incl.
   PARKED and the D77-narrowed SUSPENDED reason) is projected; the §6.1 plan-delta /
   input-activity classes (no working-model payload) reach the Model's forward-compat
   branch and render one honest line — never a crash, never a fabricated shape. The
   mapping lives **only here** (the N6 scope fence: `client/`'s attach types are not
   migrated onto the frozen proto).
3. **WRITE — writer-seat drive** (`internal/driver`). The writer seat's input path is
   NOT WatchSession (the frozen `orchestrator.v1` has no write RPC); it is the direct
   client→host-agent endpoint the `AttachHandle` carries (D79, doc 15 §5.4), realized
   by `client/hostbridge`'s framed-UDS `SocketConn`. Operator input is `DriveInput`;
   an ask answer is a `DriveGrant` (the proven prompt-tool route by default). The
   client stores **no** standing grant: allow-always is a PROPOSAL forwarded once
   (D45), and an accepted grant arrives later as a TTL'd policy-stream entry — never a
   second proxy channel (D45/D53).

The bubbletea interactive loop (`internal/loop`) is split testability-first: a **pure,
bubbletea-free state machine** (`state.go`) does the fold + keystroke + ask transitions,
and a **thin bubbletea adapter** (`model.go`) routes keystrokes and triggers re-renders.
Events are folded **synchronously in the subscriber goroutine** (under the State lock)
so the resume token (`LastSeq`) is accurate at reconnect time; the bubbletea `Update`
never mutates the seq-ordered Model.

## Live attach is N7-gated

Live e2e against a real orchestrator + VM is the N7 step and is **not** wired here. The
`cmd/serpent-tui` binary refuses a live dial and prints the gate. Everything is
unit-testable **offline**: the WatchSession subscriber (resume/reconnect), the
`attach.v1`→`client/tui` mapping, the keystroke→drive loop, and the ask→grant path run
against an **in-process fake WatchSession gRPC server** (bufconn) and an in-process
writer seat — no orchestrator, no VM, no Claude. When N7 opens, the live wiring is
`orchestratorv1.NewSessionServiceClient` over the dialed SessionService for the Starter
and `driver.SeatFromSocket` over a `hostbridge.SocketTransport.Dial` of the handle's
direct endpoint for the Seat — both already accepted by `serpenttui.Config`.

## Build & test

```sh
cd serpent-tui
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./...      # add -race; the app test runs concurrent goroutines
gofmt -l .                    # clean
```

`GOWORK=off` is required because this module is deliberately absent from the root
`go.work`. Do not add `serpent-tui/` to `go.work`, and do not add dependencies to
`client/go.mod`.
