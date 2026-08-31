// Package tui is the writer-seat attach client (D18): it consumes the
// dreamserpent.attach.v1 event stream the smart wrapper emits and renders
// structured deltas — chat, tool invocations, the subagent tree, session
// state, and the approval surface — never forwarded frames.
//
// Contract surface: this package is built against the Go shape in
// client/wrapper/attach (the working model until dreamserpent.attach.v1
// freezes at M0, D38). It imports NO proto/gen/go and authors no .proto: the
// attach proto is README-reserved in proto/dreamserpent/attach/v1/ and the
// generated Go arrives only at the freeze. Gaps found here are inputs to the
// doc 15 §6.1 freeze checklist, recorded as taskdb notes, never invented.
//
// Transport ambivalence (D79, doc 15 §5.4): the AttachHandle admits both
// transports from day one. M0 implements only the direct local leg — the
// wrapper-process EventSource below; the remote WatchSession leg (the
// relay/fan-out that lands at M2 and becomes the D61 spectate multiplexer at
// M4) plugs in behind the same Transport interface without touching the model
// or the renderer.
package tui

import (
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Role is the D61 one-writer/N-reader subscriber class carried on the attach
// handle. The TUI is the writer seat; readers (console, canvas, spectators)
// attach with RoleReader and never forward input. Arbitration of the single
// writer seat is SERVER-side at the WatchSession terminator (doc 15 §5.3) —
// the client carries the role it was issued and forwards input only when it
// holds RoleWriter; it never arbitrates.
type Role string

const (
	RoleWriter Role = "WRITER"
	RoleReader Role = "READER"
)

// EndpointCandidate is one place a Transport can dial. It mirrors the D79
// AttachHandle.endpoints field shape (doc 15 §5.4) without importing the
// (unfrozen) proto: M0 carries the direct client->host-agent endpoint; the
// relay endpoint joins at M2. Kind is "local" for the in-process wrapper leg,
// "host-agent" for the direct remote leg, "relay" for the M2+ fan-out leg.
type EndpointCandidate struct {
	Kind    string
	Address string
}

// AttachHandle is the transport-ambivalent attach descriptor (D79, doc 15
// §5.4). It is the client-side mirror of the M0-frozen handle: endpoint
// candidates + short-lived session-scoped auth material + WRITER/READER role +
// expiry. Until attach.v1 freezes this is a working model; AuthMaterial is an
// opaque token blob here (never a long-lived credential, D39) because the
// boundary's auth shape is owned elsewhere and not on this seam yet.
type AttachHandle struct {
	SessionUUID  string
	Endpoints    []EndpointCandidate
	AuthMaterial []byte
	Role         Role
	ExpiresAt    int64 // unix seconds; 0 ⇒ no expiry expressed (local leg)
}

// Transport is the seam the TUI consumes the event stream over. One concrete
// transport exists at M0 — the local wrapper-process leg (transport_local.go).
// The remote WatchSession leg is a second Transport added without touching the
// model or renderer: the whole point of D79's transport ambivalence.
//
// Open returns an EventStream positioned at FromSeq+1 (0 ⇒ from the start).
// Per-event Seq is the ordering and resume token (adapter-synthesized, see
// attach.go); a re-attach resumes by passing the last Seq the client durably
// rendered. The Writer is non-nil only when the handle carries RoleWriter.
type Transport interface {
	Open(h AttachHandle, fromSeq uint64) (EventStream, Writer, error)
}

// EventStream yields ordered attach events. Next blocks until the next event,
// io.EOF at end of stream, or another error. Events arrive in Seq order; the
// stream is responsible for in-order delivery (the local leg replays a
// pre-ordered slice; the remote leg orders at the WatchSession terminator).
type EventStream interface {
	Next() (attach.Event, error)
	Close() error
}

// Writer is the writer-seat input leg: the TUI forwards human input to the
// runtime's stdin THROUGH the wrapper (D18), never to a frame buffer. It is
// available only to a RoleWriter handle. The one-writer/N-reader guarantee is
// enforced SERVER-side (doc 15 §5.3) — this interface carries input, it does
// not arbitrate the seat.
//
// Two legs:
//   - SendInput forwards a line of operator input to the agent's stdin.
//   - AnswerAsk forwards an approval decision (Decision) for an open ask back
//     through the wrapper to the control protocol. The wrapper holds NO
//     approval state and the client stores NO grants: allow-always is a
//     PROPOSAL requiring org-admin acceptance (D45), so the client forwards
//     the decision and never persists it locally.
type Writer interface {
	SendInput(line string) error
	AnswerAsk(askID string, d Decision) error
}
