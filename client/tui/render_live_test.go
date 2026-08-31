// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// chatDeltaEv builds a render-only ChatDelta event (D145/§Layer 1) for the
// live-tail tests: the typing animation a partials-on adapter emits.
func chatDeltaEv(seq uint64, msgID string, idx int32, kind, text string, final bool) attach.Event {
	return attach.Event{
		Seq:       seq,
		SessionID: "test-session",
		Type:      attach.TypeChatDelta,
		ChatDelta: &attach.ChatDelta{
			MessageID:  msgID,
			BlockIndex: idx,
			Kind:       kind,
			Text:       text,
			Final:      final,
		},
	}
}

// chatMessageEv builds the authoritative non-partial ChatMessage that finalizes
// msgID (the canonical content, P11).
func chatMessageEv(seq uint64, msgID, text string) attach.Event {
	return attach.Event{
		Seq:       seq,
		SessionID: "test-session",
		Type:      attach.TypeChatMessage,
		ChatMessage: &attach.ChatMessage{
			MessageID: msgID,
			Role:      "assistant",
			Blocks:    []attach.ChatBlock{{Kind: "text", Text: text}},
		},
	}
}

func renderString(t *testing.T, m *Model) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

func renderPlainString(t *testing.T, m *Model) string {
	t.Helper()
	var b bytes.Buffer
	if err := RenderPlain(&b, m); err != nil {
		t.Fatalf("render plain: %v", err)
	}
	return b.String()
}

// stripANSI removes SGR escape sequences so a styled Render can be compared by
// its visible text (the live tail is rendered with the same styling as committed
// chat, so the comparison is content-level).
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			// skip "\x1b[ ... m"
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++ // consume the 'm'
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// A4 (doc 06 §7): the interactive Render shows the partial text as a live tail,
// and the committed ChatMessage REPLACES it (the tail clears, the canonical
// LineChat appears). RenderPlain never shows the tail (the golden surface).
func TestLiveTailShownThenReplacedOnFinalize(t *testing.T) {
	m := NewModel()

	// Stream three coalesced deltas + a final delta — the typing animation.
	mustApply(t, m, chatDeltaEv(1, "msg_lt", 0, "text", "Hel", false))
	mustApply(t, m, chatDeltaEv(2, "msg_lt", 0, "text", "lo, ", false))
	mustApply(t, m, chatDeltaEv(3, "msg_lt", 0, "text", "world", false))

	// While streaming: the live tail carries the coalesced text, and NO committed
	// chat line exists yet (the transcript is empty of chat).
	if tail := m.LiveTail(); len(tail) != 1 || tail[0].text != "Hello, world" {
		t.Fatalf("live tail = %+v, want one block carrying the coalesced text", tail)
	}
	for _, ln := range m.Lines {
		if ln.Kind == LineChat {
			t.Fatalf("a committed LineChat appeared during streaming: %q (deltas must not commit)", ln.Text)
		}
	}
	streaming := stripANSI(renderString(t, m))
	if !strings.Contains(streaming, "Hello, world") {
		t.Errorf("interactive Render during streaming = %q, want the live typing text", streaming)
	}
	// The plain golden surface NEVER shows the live tail.
	if plain := renderPlainString(t, m); strings.Contains(plain, "Hello, world") {
		t.Errorf("RenderPlain showed the live tail %q — the golden surface must be tail-free", plain)
	}

	// The final delta marks the block done but keeps it visible until commit.
	mustApply(t, m, chatDeltaEv(4, "msg_lt", 0, "text", "", true))
	if tail := m.LiveTail(); len(tail) != 1 || !tail[0].done {
		t.Fatalf("after final delta the tail block should be present and done: %+v", tail)
	}

	// The authoritative ChatMessage commits: the live tail is REPLACED by the
	// committed LineChat. The tail clears; the canonical line carries the text.
	mustApply(t, m, chatMessageEv(5, "msg_lt", "Hello, world"))
	if tail := m.LiveTail(); len(tail) != 0 {
		t.Fatalf("after the committed ChatMessage the live tail must clear, got %+v", tail)
	}
	sawChat := false
	for _, ln := range m.Lines {
		if ln.Kind == LineChat {
			sawChat = true
			if !strings.Contains(ln.Text, "Hello, world") {
				t.Errorf("committed chat line = %q, want the canonical text", ln.Text)
			}
		}
	}
	if !sawChat {
		t.Fatal("no committed LineChat after the ChatMessage — the canonical content is missing")
	}
}

// The render-only invariant at the RENDER level: a transcript folded WITH the
// ChatDelta events renders identically (RenderPlain) AND, once finalized, the
// interactive Render is identical to one folded WITHOUT any ChatDelta. The
// typing animation is the only difference, and only while streaming.
func TestChatDeltasDoNotChangeCommittedRender(t *testing.T) {
	// With deltas, then the committed ChatMessage.
	withDeltas := NewModel()
	mustApply(t, withDeltas, chatDeltaEv(1, "msg_x", 0, "text", "abc", false))
	mustApply(t, withDeltas, chatDeltaEv(2, "msg_x", 0, "text", "def", false))
	mustApply(t, withDeltas, chatDeltaEv(3, "msg_x", 0, "text", "", true))
	mustApply(t, withDeltas, chatMessageEv(4, "msg_x", "abcdef"))

	// Without any deltas: only the committed ChatMessage (seq aligned so the
	// committed line seq matches; the model only requires monotonicity).
	noDeltas := NewModel()
	mustApply(t, noDeltas, chatMessageEv(4, "msg_x", "abcdef"))

	// RenderPlain (the golden surface) must be byte-identical: deltas never feed
	// Lines, so the committed transcript is the same.
	if a, b := renderPlainString(t, withDeltas), renderPlainString(t, noDeltas); a != b {
		t.Errorf("RenderPlain differs after deltas committed:\n with=%q\n without=%q", a, b)
	}
	// The interactive Render is identical once finalized (the tail has cleared).
	if a, b := renderString(t, withDeltas), renderString(t, noDeltas); a != b {
		t.Errorf("Render differs after deltas committed (tail should have cleared):\n with=%q\n without=%q", a, b)
	}
}

// A thinking delta renders into the live tail as a thinking line (the typing
// view for an in-flight thinking block), distinct from a text block.
func TestLiveTailThinkingKind(t *testing.T) {
	m := NewModel()
	mustApply(t, m, chatDeltaEv(1, "msg_th", 0, "thinking", "weighing", false))
	tail := m.LiveTail()
	if len(tail) != 1 || tail[0].kind != "thinking" || tail[0].text != "weighing" {
		t.Fatalf("live tail = %+v, want one thinking block", tail)
	}
	out := stripANSI(renderString(t, m))
	if !strings.Contains(out, "weighing") {
		t.Errorf("interactive Render = %q, want the thinking typing text", out)
	}
}

// RenderRich with zero opts stays byte-identical to Render including the live
// tail (the byte-identical-baseline invariant, doc 06 §4.2): both draw the tail.
func TestLiveTailRenderRichZeroOptsMatchesRender(t *testing.T) {
	m := NewModel()
	mustApply(t, m, chatDeltaEv(1, "msg_r", 0, "text", "typing", false))

	var rich, plain bytes.Buffer
	if err := RenderRich(&rich, m, RenderOpts{}); err != nil {
		t.Fatalf("render rich: %v", err)
	}
	if err := Render(&plain, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if rich.String() != plain.String() {
		t.Errorf("RenderRich(zero opts) != Render with a live tail:\n rich=%q\n render=%q", rich.String(), plain.String())
	}
}
