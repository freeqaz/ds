package loop

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

// errReaderOnly is returned by the write paths (SubmitInput / AnswerPending /
// AnswerAsk) when the loop holds no writer seat: the loop NEVER fabricates a
// writer (the seat is arbitrated server-side, D61), so a reader-only loop refuses
// to drive rather than silently dropping the input.
var errReaderOnly = errors.New("serpent-tui/loop: no writer seat (reader-only attach)")

// View renders the full interactive surface for the current State: the folded
// client/tui transcript + status footer (the reference renderer), then the
// serpent-tui composer line and any pending-ask prompt + last error. color
// selects the styled renderer; false is the byte-stable plain golden surface.
// opts gates the Phase-2 enrichments (Layer-2 diffs / Layer-3 highlight / Layer-5
// panels, doc 06): a zero opts keeps the surface byte-identical to the bare
// Render. It is a pure function of (State, color, opts), taken under the loop
// lock, so a snapshot renders deterministically.
func (s *State) View(color bool, opts tui.RenderOpts) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	// Reuse the OSS reference renderer for the transcript + session footer.
	// --no-color (color=false) ALWAYS routes to the byte-stable plain surface —
	// it never highlights/diffs/groups (doc 06 §4.2), so the render enrichments
	// are suppressed there even if a toggle was set. With color on, RenderRich
	// applies the selected enrichments; a zero opts makes it byte-identical to
	// Render (the default-off baseline).
	switch {
	case !color:
		_ = tui.RenderPlain(&b, s.model)
	case opts.IsZero():
		// opts.IsZero() single-sources the zero-routing (client/tui/render.go): a
		// non-nil empty *FoldMap is comparable but not the zero struct, so the raw
		// `opts == tui.RenderOpts{}` would have mis-routed it through RenderRich; the
		// accessor routes it to the byte-identical Render baseline.
		_ = tui.Render(&b, s.model)
	default:
		_ = tui.RenderRich(&b, s.model, opts)
	}

	// serpent-tui's own interactive affordances below the reference surface: the
	// pending-ask prompt (when parked), the composer, and the last forward error.
	if pending := s.model.PendingAsks(); len(pending) > 0 {
		ask := pending[0]
		b.WriteString(fmt.Sprintf("\nASK %s — %s (parked; awaiting a human, never times out)\n", ask.AskID, ask.ToolName))
		b.WriteString("  [a] allow once   [A] allow always (PROPOSAL)   [d] deny\n")
	}
	b.WriteString("\ninput> ")
	b.WriteString(string(s.compose))
	if s.lastErr != nil {
		b.WriteString(fmt.Sprintf("\n[!] %v", s.lastErr))
	}
	b.WriteString("\n")
	return b.String()
}
