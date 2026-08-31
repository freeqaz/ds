// SPDX-License-Identifier: Apache-2.0

package canvas

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ── Single-sourced guardrail tags (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// The five doc 06 §3c / doc 17 §13(c) canvas tags this package's rows carry, in
// doc.go REGISTRATION order. Tags is the SINGLE SOURCE for the row names: the
// repo-root guardrail-map.yaml's canvas glob row and this slice must name the
// SAME rows, and TestTagsStable pins the slice so a silent drift fails HERE
// rather than against a differently-named map row (the orchctl multi-row
// discipline — an honest map row names a real, single-sourced tag value, never a
// placeholder string).
const (
	// TagCanvasEditsNeverReachVM — row 1: a board edit never reaches a session VM
	// (doc 17 §13(c)(1)).
	TagCanvasEditsNeverReachVM = "canvas-edits-never-reach-vm"
	// TagCanvasNotInputChannel — row 2: canvas is not an input channel; the
	// projection pipeline is provably read-only (doc 17 §3.1/§13(c)(2)).
	TagCanvasNotInputChannel = "canvas-not-an-input-channel"
	// TagCanvasControlAttribution — row 3: canvas control actions carry D8
	// attribution and respect single-driver arbitration (doc 17 §7/§13(c)(3)).
	TagCanvasControlAttribution = "canvas-control-rpc-attribution"
	// TagCanvasDirectoryRights — row 4: boards respect directory rights, including
	// the existence-disclosure posture (doc 17 §8/§13(c)(4); §3.3(c)).
	TagCanvasDirectoryRights = "canvas-respects-directory-rights"
	// TagSpectatorNoInject — row 5: a read-only spectator provably cannot inject
	// input into a session (doc 06 §3c re-file; D61).
	TagSpectatorNoInject = "spectator-cannot-inject"
)

// Tags is the ordered set of single-sourced guardrail tags this package owns,
// for the guardrail-map.yaml canvas row to name the SAME rows.
var Tags = []string{
	TagCanvasEditsNeverReachVM,
	TagCanvasNotInputChannel,
	TagCanvasControlAttribution,
	TagCanvasDirectoryRights,
	TagSpectatorNoInject,
}

// ── Runnability (README.md "OSS-runnable vs paid-dependent"; doc 17 §13) ─────
//
// D51 ships the complete table, but canvas rows must be runnable without
// paid-layer scale machinery OR be split. A paid-dependent row still SHIPS (its
// claim text + assertion are public) but an OSS run reports it NOT-APPLICABLE
// rather than FAILED. CheckRunnable short-circuits a paid-dependent row on OSS.

// Runnability marks where a row can execute.
type Runnability string

const (
	// RunnabilityOSS — executes against any OSS checkout: a static data-shape diff
	// with no web-client / paid-layer dependency.
	RunnabilityOSS Runnability = "oss-runnable"
	// RunnabilityPaidDependent — needs paid-layer / web-client machinery; on an OSS
	// run the row is reported not-applicable, never failed (doc 17 §13).
	RunnabilityPaidDependent Runnability = "paid-dependent"
)

// ── Shared violation type ────────────────────────────────────────────────────

// ViolationClass names a single failure mode one of the five rows enumerates, so
// every violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// constants are grouped per row below.
type ViolationClass string

// Violation is a single guardrail breach: which rule, which subject (the
// op/edge/RPC/reference/viewer the check ran against), and a human-readable
// reason citing the governing anchor.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// sortViolations orders a slice by (class, subject) so failure messages and
// class-set comparisons are stable across runs.
func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 1 — canvas edits never reach a session VM (doc 17 §13(c)(1)).
//
// THE CLAIM: a board edit never reaches a session VM — no canvas operation
// produces any observable effect inside any session. Canvas-truth objects
// (§3.2) live in the Yjs document and are not a channel into a guest.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationCanvasOpReachedVM — a canvas operation produced an effect observable
	// inside a session VM; a board edit must never reach a guest.
	ViolationCanvasOpReachedVM ViolationClass = "canvas-edit-reached-session-vm"
)

// CanvasOp is one synthetic canvas operation and whether it produced an effect
// observable inside a session VM (a guest-visible filesystem/env/stdin/socket
// write). For a conforming op this is false.
type CanvasOp struct {
	// Name labels the op for violation messages (e.g. "move-shape").
	Name string `json:"name"`
	// ReachedSessionVM records whether this op produced any effect observable
	// inside a session VM. It MUST be false; true is a breach.
	ReachedSessionVM bool `json:"reached_session_vm"`
}

// CanvasOpSet is a synthetic fixture's full canvas-operation picture.
type CanvasOpSet struct {
	Name string     `json:"-"`
	Ops  []CanvasOp `json:"ops"`
}

// CheckCanvasEditsNeverReachVM scans a synthetic canvas-op set and returns every
// op that produced a VM-observable effect. An empty result means the set
// conforms: no board edit reached any session VM.
func CheckCanvasEditsNeverReachVM(s CanvasOpSet) []Violation {
	var vs []Violation
	for _, op := range s.Ops {
		if op.ReachedSessionVM {
			vs = append(vs, Violation{
				Class:   ViolationCanvasOpReachedVM,
				Subject: opLabel(op.Name),
				Reason: fmt.Sprintf("canvas operation %s produced an effect observable inside a session "+
					"VM; a board edit must never reach a session VM — canvas-truth objects live in the Yjs "+
					"document, not as a channel into a guest (doc 17 §13(c)(1))", opLabel(op.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 2 — canvas is not an input channel (doc 17 §3.1/§13(c)(2)).
//
// THE CLAIM: canvas state cannot become an input channel into any session — the
// projection pipeline is provably READ-ONLY. Every projection edge runs
// platform→board (D61); no canvas.v1 message is input-bearing into a session.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationProjectionEdgeIntoSession — a projection edge runs board→session
	// (or any direction other than platform→board); the projection pipeline must
	// be read-only.
	ViolationProjectionEdgeIntoSession ViolationClass = "projection-edge-into-session"
	// ViolationCanvasMessageInputBearing — a canvas.v1 message is declared
	// input-bearing into a session; canvas.v1's documented posture carries no such
	// message (it is FROZEN, doc 17 §3.1/§13(c)(2)).
	ViolationCanvasMessageInputBearing ViolationClass = "canvas-message-input-bearing-into-session"
)

// EdgeDirection names the direction of a projection-graph edge.
type EdgeDirection string

const (
	// DirPlatformToBoard — the ONLY conforming direction: the platform pushes a
	// read-only projection onto a board tile (doc 17 §3.1, read-only by
	// construction, D61).
	DirPlatformToBoard EdgeDirection = "platform_to_board"
	// DirBoardToSession — a board-state edge pointing INTO a session; this is the
	// regression the row catches.
	DirBoardToSession EdgeDirection = "board_to_session"
)

// ProjectionEdge is one edge of the synthetic projection graph and its
// direction. For a conforming graph every edge is DirPlatformToBoard.
type ProjectionEdge struct {
	// Name labels the edge for violation messages (e.g. "session-tile->guest").
	Name string `json:"name"`
	// Direction is the edge's data-flow direction. It MUST be DirPlatformToBoard.
	Direction EdgeDirection `json:"direction"`
}

// CanvasMessage is one canvas.v1 message in the synthetic posture picture and
// whether it is declared input-bearing INTO a session. canvas.v1 (FROZEN)
// carries no such message; InputBearingIntoSession MUST be false.
type CanvasMessage struct {
	// Name labels the message for violation messages (e.g. "BoardUpdate").
	Name string `json:"name"`
	// InputBearingIntoSession records whether this message delivers canvas/board
	// state back INTO a session as input. It MUST be false; true is a breach.
	InputBearingIntoSession bool `json:"input_bearing_into_session"`
}

// ProjectionGraph is a synthetic fixture's projection-pipeline picture: the
// directed edges plus the canvas.v1 message posture.
type ProjectionGraph struct {
	Name     string           `json:"-"`
	Edges    []ProjectionEdge `json:"edges"`
	Messages []CanvasMessage  `json:"messages"`
}

// CheckCanvasNotInputChannel scans a synthetic projection graph and returns
// every edge that runs into a session and every input-bearing canvas message. An
// empty result means the pipeline conforms: every edge is platform→board and no
// canvas.v1 message is input-bearing into a session.
func CheckCanvasNotInputChannel(g ProjectionGraph) []Violation {
	var vs []Violation
	for _, e := range g.Edges {
		if e.Direction != DirPlatformToBoard {
			vs = append(vs, Violation{
				Class:   ViolationProjectionEdgeIntoSession,
				Subject: edgeLabel(e.Name),
				Reason: fmt.Sprintf("projection edge %s runs %q; the projection pipeline must be read-only "+
					"— every edge runs platform→board, never board→session (doc 17 §3.1/§13(c)(2), "+
					"read-only by construction, D61)", edgeLabel(e.Name), e.Direction),
			})
		}
	}
	for _, m := range g.Messages {
		if m.InputBearingIntoSession {
			vs = append(vs, Violation{
				Class:   ViolationCanvasMessageInputBearing,
				Subject: msgLabel(m.Name),
				Reason: fmt.Sprintf("canvas.v1 message %s is declared input-bearing into a session; "+
					"canvas.v1's documented (FROZEN) posture carries NO message that delivers board state "+
					"back into a session as input (doc 17 §3.1/§13(c)(2))", msgLabel(m.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 3 — canvas control actions carry attribution (doc 17 §7/§13(c)(3); D8/D61).
//
// THE CLAIM: a canvas-originated control-plane RPC carries D8 attribution and
// respects single-driver arbitration — a board is never a second writer.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationControlRPCNoAttribution — a canvas-originated control-plane RPC
	// carried no D8 actor identity.
	ViolationControlRPCNoAttribution ViolationClass = "control-rpc-missing-d8-attribution"
	// ViolationControlRPCSecondWriter — a canvas-originated control-plane RPC was
	// admitted while another principal holds the single writer seat; a board must
	// never be a second writer (doc 17 §7).
	ViolationControlRPCSecondWriter ViolationClass = "control-rpc-second-writer"
)

// ControlRPC is one synthetic canvas-originated control-plane RPC: whether it
// carried a D8 actor identity, whether it was admitted, and whether another
// principal held the single writer seat at admission time.
type ControlRPC struct {
	// Name labels the RPC for violation messages (e.g. "Pause").
	Name string `json:"name"`
	// Actor is the D8 actor identity the RPC carried. It MUST be non-empty.
	Actor string `json:"actor"`
	// Admitted records whether the control plane admitted the RPC.
	Admitted bool `json:"admitted"`
	// WriterSeatHeldByOther records whether a DIFFERENT principal held the single
	// writer seat at admission time. An admitted RPC while this is true is a
	// second-writer breach (doc 17 §7 single-driver arbitration).
	WriterSeatHeldByOther bool `json:"writer_seat_held_by_other"`
}

// ControlRPCSet is a synthetic fixture's canvas-originated control-RPC picture.
type ControlRPCSet struct {
	Name string       `json:"-"`
	RPCs []ControlRPC `json:"rpcs"`
}

// CheckCanvasControlAttribution scans a synthetic control-RPC set and returns
// every RPC missing D8 attribution and every second-writer admission. An empty
// result means the set conforms: every RPC carries an actor identity and no RPC
// was admitted as a second writer.
func CheckCanvasControlAttribution(s ControlRPCSet) []Violation {
	var vs []Violation
	for _, r := range s.RPCs {
		if r.Actor == "" {
			vs = append(vs, Violation{
				Class:   ViolationControlRPCNoAttribution,
				Subject: rpcLabel(r.Name),
				Reason: fmt.Sprintf("canvas-originated control-plane RPC %s carried no D8 actor identity; "+
					"every canvas control action must carry attribution (doc 17 §13(c)(3); D8)",
					rpcLabel(r.Name)),
			})
		}
		if r.Admitted && r.WriterSeatHeldByOther {
			vs = append(vs, Violation{
				Class:   ViolationControlRPCSecondWriter,
				Subject: rpcLabel(r.Name),
				Reason: fmt.Sprintf("canvas-originated control-plane RPC %s was admitted while another "+
					"principal holds the single writer seat; a board must never be a second writer — "+
					"canvas control respects single-driver arbitration (doc 17 §7/§13(c)(3); D61)",
					rpcLabel(r.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 4 — boards respect directory rights (doc 17 §8/§13(c)(4); §3.3(c)).
//
// THE CLAIM: a board never leaks the content or platform metadata of a session
// the viewer lacks directory rights to — including the existence-disclosure
// posture: a dangling reference resolves to a TOMBSTONE, an access-denied viewer
// to an ACCESS PLACEHOLDER, both non-load-blocking and neither leaking the
// underlying session's content or platform metadata.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationDirectoryRightContentLeak — a rendered tile leaked the content or
	// platform metadata of a session the viewer lacks directory rights to.
	ViolationDirectoryRightContentLeak ViolationClass = "board-leaked-unauthorized-session-content"
	// ViolationDirectoryRightLiveRenderUnauthorized — a reference the viewer has no
	// directory right to resolved to a LIVE render instead of a tombstone/access
	// placeholder.
	ViolationDirectoryRightLiveRenderUnauthorized ViolationClass = "board-live-render-without-directory-right"
	// ViolationDirectoryRightUnknownState — a projected reference resolved to a
	// render state outside the enumerated {live, tombstone, access_placeholder}
	// set; the existence-disclosure posture must be one of these.
	ViolationDirectoryRightUnknownState ViolationClass = "board-render-state-outside-taxonomy"
)

// RenderState names how a projected reference resolved on a board tile.
type RenderState string

const (
	// RenderLive — a live, hydrated projection of a session the viewer is
	// authorized to see.
	RenderLive RenderState = "live"
	// RenderTombstone — a dangling reference resolved to an explicit tombstone
	// (non-load-blocking, doc 17 §3.3(c)).
	RenderTombstone RenderState = "tombstone"
	// RenderAccessPlaceholder — an access-denied viewer resolved to an access
	// placeholder (non-load-blocking, doc 17 §3.3(c)).
	RenderAccessPlaceholder RenderState = "access_placeholder"
)

// ProjectedRef is one synthetic projected reference on a board: the viewer's
// directory right to the underlying session, the resolved render state, and
// whether the rendered tile carried the session's content or platform metadata.
type ProjectedRef struct {
	// Name labels the reference for violation messages (e.g. "peer-session-tile").
	Name string `json:"name"`
	// ViewerHasDirectoryRight records whether the viewer holds directory rights to
	// the underlying session.
	ViewerHasDirectoryRight bool `json:"viewer_has_directory_right"`
	// RenderState is how the reference resolved on the tile.
	RenderState RenderState `json:"render_state"`
	// LeakedContentOrMetadata records whether the rendered tile carried the
	// underlying session's content or platform metadata. For an unauthorized
	// viewer this MUST be false.
	LeakedContentOrMetadata bool `json:"leaked_content_or_metadata"`
}

// BoardView is a synthetic fixture's board projection for one viewer.
type BoardView struct {
	Name string         `json:"-"`
	Refs []ProjectedRef `json:"refs"`
}

// CheckCanvasDirectoryRights scans a synthetic board view and returns every
// directory-rights breach. An empty result means the board conforms: every
// reference the viewer lacks rights to renders as a tombstone/placeholder with
// no leaked content/metadata, and every render state is in the enumerated set.
func CheckCanvasDirectoryRights(b BoardView) []Violation {
	var vs []Violation
	for _, r := range b.Refs {
		switch r.RenderState {
		case RenderLive, RenderTombstone, RenderAccessPlaceholder:
		default:
			vs = append(vs, Violation{
				Class:   ViolationDirectoryRightUnknownState,
				Subject: refLabel(r.Name),
				Reason: fmt.Sprintf("projected reference %s resolved to render state %q outside the "+
					"enumerated {live, tombstone, access_placeholder} set; the existence-disclosure "+
					"posture must be one of these (doc 17 §3.3(c)/§13(c)(4))", refLabel(r.Name), r.RenderState),
			})
			continue
		}
		if r.ViewerHasDirectoryRight {
			continue // an authorized viewer may see a live render with content
		}
		// Unauthorized viewer: must NOT leak content/metadata and must NOT live-render.
		if r.LeakedContentOrMetadata {
			vs = append(vs, Violation{
				Class:   ViolationDirectoryRightContentLeak,
				Subject: refLabel(r.Name),
				Reason: fmt.Sprintf("board rendered reference %s with the underlying session's content or "+
					"platform metadata to a viewer who lacks directory rights; a board must never leak "+
					"either (doc 17 §8/§13(c)(4))", refLabel(r.Name)),
			})
		}
		if r.RenderState == RenderLive {
			vs = append(vs, Violation{
				Class:   ViolationDirectoryRightLiveRenderUnauthorized,
				Subject: refLabel(r.Name),
				Reason: fmt.Sprintf("reference %s resolved to a LIVE render for a viewer who lacks "+
					"directory rights; an unauthorized reference must resolve to a tombstone or access "+
					"placeholder, never a live render (doc 17 §3.3(c)/§8/§13(c)(4))", refLabel(r.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 5 — read-only spectate cannot inject (doc 06 §3c, re-filed; D61).
//
// THE CLAIM (quoted exactly from sessions/06 via doc 06 §3c): "a read-only
// spectator provably cannot inject input into a session." Canvas live-views
// inherit this console/attach claim.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationSpectatorInjected — an input event emitted by a spectator-role
	// viewer was accepted into the session; only a driver-role seat may inject.
	ViolationSpectatorInjected ViolationClass = "spectator-input-accepted-into-session"
)

// ViewerRole names a live-view participant's seat role.
type ViewerRole string

const (
	// RoleSpectator — a read-only spectator; may NOT inject input.
	RoleSpectator ViewerRole = "spectator"
	// RoleDriver — the single driver seat; the only role whose input is accepted.
	RoleDriver ViewerRole = "driver"
)

// Viewer is one synthetic live-view participant: their held role and whether an
// input event they emitted was accepted into the session.
type Viewer struct {
	// Name labels the viewer for violation messages (e.g. "alice").
	Name string `json:"name"`
	// Role is the seat role the viewer holds.
	Role ViewerRole `json:"role"`
	// InputAccepted records whether an input event this viewer emitted was
	// accepted into the session. For a spectator this MUST be false.
	InputAccepted bool `json:"input_accepted"`
}

// ViewerSet is a synthetic fixture's live-view participant picture.
type ViewerSet struct {
	Name    string   `json:"-"`
	Viewers []Viewer `json:"viewers"`
}

// CheckSpectatorNoInject scans a synthetic viewer set and returns every
// spectator whose input was accepted into the session. An empty result means the
// picture conforms: input was accepted only from a driver-role seat.
func CheckSpectatorNoInject(s ViewerSet) []Violation {
	var vs []Violation
	for _, v := range s.Viewers {
		if v.Role == RoleSpectator && v.InputAccepted {
			vs = append(vs, Violation{
				Class:   ViolationSpectatorInjected,
				Subject: viewerLabel(v.Name),
				Reason: fmt.Sprintf("an input event from spectator-role viewer %s was accepted into the "+
					"session; a read-only spectator provably cannot inject input into a session — only a "+
					"driver-role seat may inject (doc 06 §3c, re-filed from sessions/06; D61)",
					viewerLabel(v.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ── Runnability short-circuit ────────────────────────────────────────────────

// CheckRunnable runs check only when the row is OSS-runnable on this checkout.
// For a RunnabilityPaidDependent row on an OSS run, it returns (nil, false):
// the row is NOT-APPLICABLE, never FAILED (doc 17 §13 split). The bool reports
// whether the check actually ran.
func CheckRunnable(r Runnability, check func() []Violation) ([]Violation, bool) {
	if r == RunnabilityPaidDependent {
		return nil, false
	}
	return check(), true
}

// ── Labels (blank-safe subject names for violation messages) ─────────────────

func opLabel(s string) string     { return labelOr(s, "(unnamed canvas op)") }
func edgeLabel(s string) string   { return labelOr(s, "(unnamed projection edge)") }
func msgLabel(s string) string    { return labelOr(s, "(unnamed canvas message)") }
func rpcLabel(s string) string    { return labelOr(s, "(unnamed control RPC)") }
func refLabel(s string) string    { return labelOr(s, "(unnamed projected ref)") }
func viewerLabel(s string) string { return labelOr(s, "(unnamed viewer)") }

func labelOr(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

// ── Loading fixtures (cwd-independent) ───────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// LoadJSON reads a synthetic fixture of type T from a JSON file under fixtures/.
// It is the cwd-independent loader the JSON-backed rows use; in-code Go-literal
// fixtures need no loader.
func LoadJSON[T any](path string) (T, error) {
	var v T
	data, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("reading canvas fixture %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("parsing canvas fixture %s: %w", path, err)
	}
	return v, nil
}
