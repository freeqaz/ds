# client/tui/ — the Dream Serpent TUI

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D18, D45, D53 (+ D61 reader shape)

Our own TUI over the `dreamserpent.attach.v1` event stream (D18): structured
deltas beat tmux/frame-forwarding, and rendering our own surface is what lets
any session attach to any session ("local feel, remote reality",
doc 02 §5).
Reads come via `WatchSession` under the D61 one-writer/N-reader shape; this
surface is the writer-seat client.

**This is the approval surface** (see `../README.md` for the full rule). What
that means concretely here:

- Unknown-domain asks render as near-real-time prompts: allow once / allow
  always / deny (doc 02 §6).
- D45 semantics: allow-once dies with the session; allow-always is a
  *proposal* requiring org-admin acceptance (delegable by posture).
- D53 semantics: asks arrive only on the suspend+ask rung; unanswered asks
  park the session (never timing out into allow or kill) and resume when the
  human answers; attendedness state changes what the boundary even asks.

Framework choice is owner-landed (see `../go.mod`). The paid web console is a
`paid/webclient/` surface over the same stream — no shared widget code, shared
protos only.

## Framework decision (revisitable workstream decision — NOT a D-number)

**Chosen: a stdlib ANSI renderer, no TUI framework dependency.** The go.mod
"TUI framework choice is owner-landed with the first TUI PR" slot is filled by
this PR, and the call is to stay stdlib-only for now. Rationale:

- The core deliverable is **structured-delta rendering driven from cassettes**
  (D18: our own surface over `attach.v1`, never frame-forwarding). A pure
  `Model` fold + a pure `Render(model)` function is the cleanest way to make
  that **golden-testable byte-for-byte** — the render test diffs against
  committed goldens the same insta-style way `../goldentrace` does. An
  interactive event-loop framework (bubbletea et al.) optimizes the part we are
  *not* the bottleneck on (the live TTY loop) and complicates the part we are
  (deterministic replay).
- It keeps the module's **STANDARD-LIBRARY-ONLY skeleton posture** (`../go.mod`)
  intact: no new dependency tree, no pin/vendor obligation, the workspace still
  builds offline. (Module download *does* work in CI, so this is a deliberate
  minimalism call, not a sandbox limitation.)
- The render is split `RenderPlain` (the golden surface) / `Render` (ANSI SGR
  styling) so styling is never load-bearing for correctness.

**Revisit trigger:** adopt a framework (bubbletea is the leading candidate) when
the live interactive loop grows real layout/viewport/scrollback needs the
`App` loop in `app.go` can no longer carry cleanly — e.g. split panes for the
subagent tree, or mouse/resize handling. The `Model`/`Render` split is designed
to survive that swap: a framework would replace `app.go`'s loop and reuse the
same `Model` and line glyphs.

## Status (M0 skeleton)

Built against `client/wrapper/attach` (the working model until `attach.v1`
freezes, D38) — **no `.proto`, no `proto/gen/go` import**. The
`AttachHandle`/`Transport` seam (`transport.go`) is transport-ambivalent per
D79: the M0 local wrapper-process leg is implemented (`transport_local.go`); the
remote `WatchSession` leg (M2, becoming the D61 spectate multiplexer at M4)
plugs in behind the same interface. **Live attach to a real remote CC session is
the integration step that waits on the orchestrator** — the client side is
built and replay-tested; the remote transport is not wired here. Replay mode
(`ds-tui replay <file.attach.ndjson>`) renders any committed attach golden.
