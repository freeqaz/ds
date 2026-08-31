// serpent-tui — the real human-in-the-loop Claude Code experience over
// attach.v1, dialing the orchestrator's SessionService.WatchSession as a
// subscriber and taking the writer seat to drive a VM-hosted session (N6).
//
// MAINTAINER-RATIFIED OPTION C (the taskdb-TUI split). This is a SEPARATE Go module
// at the repo root, deliberately OUT of the root go.work (go.work is the
// stdlib-only OSS/contract workspace; this module takes a heavy interactive-TUI
// dependency that client/ must never carry). It is the ONLY place bubbletea
// enters the tree:
//
//   - client/ stays stdlib-only by charter (client/go.mod gains NO deps): it owns
//     the PURE Model/Render fold (client/tui), the attach.v1 Go working model
//     (client/wrapper/attach), and the writer-seat transport (client/hostbridge).
//   - serpent-tui imports those OSS packages AND proto/gen/go (the FROZEN
//     attach.v1 + orchestrator.v1 stubs + the grpc transport) and adds bubbletea
//     for the interactive keystroke loop.
//
// The proto + client modules are wired by repo-relative replaces so the module
// builds offline against the frozen stubs; bubbletea/lipgloss come from the
// upstream module proxy (authorized). google.golang.org/grpc is pinned to the
// same version the proto module's generated gRPC stubs were built against so the
// in-process fake WatchSession server and a future live dial share one runtime.
//
// D-NUMBERS: D18 (structured-delta attach stream, never frames), D45/D53
// (approvals are TTL'd grants client-side, never a second proxy channel),
// D61 (one-writer/N-reader; the writer seat lives in the session record,
// arbitrated server-side), D79 (transport-ambivalent AttachHandle + per-event
// resume seqs).
module github.com/dream-serpent/dream-serpent/serpent-tui

go 1.26

require (
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/dream-serpent/dream-serpent/client v0.0.0
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	google.golang.org/grpc v1.81.1
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.10.1 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../proto/gen/go

replace github.com/dream-serpent/dream-serpent/client => ../client
