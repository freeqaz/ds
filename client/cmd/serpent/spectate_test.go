// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// chatFrame / toolInvokedFrame / … build the synthetic attach.v1.SessionEvent
// CONTENT frames a WatchSession stream fans out. These are the exact frozen
// shapes the orchestrator's real WatchSession handler serves (the D18/§6.1 event
// vocabulary); rendering them here proves the spectator projection without a
// gRPC dial in this stdlib-only module (D80 — the live subscribe is the
// serpent-tui sibling's job).
func chatFrame(seq uint64, role, text string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Seq:  seq,
		Type: attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE,
		Payload: &attachv1.SessionEvent_ChatMessage{ChatMessage: &attachv1.ChatMessage{
			Role:   role,
			Blocks: []*attachv1.ChatBlock{{Kind: "text", Text: text}},
		}},
	}
}

func toolInvokedFrame(seq uint64, name string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Seq:     seq,
		Type:    attachv1.EventType_EVENT_TYPE_TOOL_INVOKED,
		Payload: &attachv1.SessionEvent_ToolInvoked{ToolInvoked: &attachv1.ToolInvoked{Name: name}},
	}
}

func toolCompletedFrame(seq uint64, isErr bool, excerpt string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Seq:  seq,
		Type: attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED,
		Payload: &attachv1.SessionEvent_ToolCompleted{ToolCompleted: &attachv1.ToolCompleted{
			IsError:       isErr,
			OutputExcerpt: excerpt,
		}},
	}
}

// TestRenderContentFramesFromStream encodes a synthetic CHAT + TOOL frame stream
// with the length-delimited codec (the same framing a WatchSession capture / the
// serpent-tui live pipe uses) and renders it through the SPECTATE reader,
// asserting the exact read-only projection. This is the offline stand-in for the
// bufconn-against-the-real-handler fixture: identical frozen frames, identical
// renderer, no gRPC.
func TestRenderContentFramesFromStream(t *testing.T) {
	var wire bytes.Buffer
	frames := []*attachv1.SessionEvent{
		chatFrame(1, "user", "please run the tests"),
		chatFrame(2, "assistant", "on it"),
		toolInvokedFrame(3, "Bash"),
		toolCompletedFrame(4, false, "ok\nall green"),
	}
	for _, f := range frames {
		if err := writeDelimitedFrame(&wire, f); err != nil {
			t.Fatalf("encode frame seq=%d: %v", f.GetSeq(), err)
		}
	}

	var out bytes.Buffer
	rendered, err := renderSpectateStream(&out, &wire)
	if err != nil {
		t.Fatalf("renderSpectateStream: %v", err)
	}
	if rendered != 4 {
		t.Errorf("rendered = %d, want 4 content frames", rendered)
	}
	want := "#1 chat user: please run the tests\n" +
		"#2 chat assistant: on it\n" +
		"#3 tool Bash invoked\n" +
		"#4 tool completed [ok] ok all green\n"
	if out.String() != want {
		t.Errorf("spectate render mismatch\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}

// TestRenderSkipsStateAndSeatFrames proves the spectate surface renders ONLY
// content frames: SESSION_STATE / WRITER_SEAT_CHANGED / SESSION_INIT (the
// state/seat edges the webclient owns) are skipped, never double-rendered, while
// the CHAT frame interleaved with them still renders. This is the surface-split
// invariant the README documents.
func TestRenderSkipsStateAndSeatFrames(t *testing.T) {
	frames := []*attachv1.SessionEvent{
		{Seq: 1, Type: attachv1.EventType_EVENT_TYPE_SESSION_INIT},
		{Seq: 2, Type: attachv1.EventType_EVENT_TYPE_SESSION_STATE},
		chatFrame(3, "assistant", "hi"),
		{Seq: 4, Type: attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED},
	}
	var wire bytes.Buffer
	for _, f := range frames {
		if err := writeDelimitedFrame(&wire, f); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	rendered, err := renderSpectateStream(&out, &wire)
	if err != nil {
		t.Fatalf("renderSpectateStream: %v", err)
	}
	if rendered != 1 {
		t.Errorf("rendered = %d, want only the 1 content (chat) frame", rendered)
	}
	if got := out.String(); got != "#3 chat assistant: hi\n" {
		t.Errorf("render = %q, want only the chat line", got)
	}
}

// TestRenderAllContentClasses covers ASK/PLAN/QUOTA (plus tool-error) so every
// class the task enumerates has a rendered line, and the tool-error outcome is
// distinguished from ok.
func TestRenderAllContentClasses(t *testing.T) {
	frames := []*attachv1.SessionEvent{
		toolCompletedFrame(1, true, "boom"),
		{Seq: 2, Type: attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
			Payload: &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{ToolName: "Bash", RequestId: "req-9"}}},
		{Seq: 3, Type: attachv1.EventType_EVENT_TYPE_ASK_RESOLVED,
			Payload: &attachv1.SessionEvent_AskResolved{AskResolved: &attachv1.AskResolved{Behavior: "allow", RequestId: "req-9"}}},
		{Seq: 4, Type: attachv1.EventType_EVENT_TYPE_PLAN_DELTA,
			Payload: &attachv1.SessionEvent_PlanDelta{PlanDelta: &attachv1.PlanDelta{Plan: "step one\nstep two"}}},
		{Seq: 5, Type: attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED,
			Payload: &attachv1.SessionEvent_QuotaUpdated{QuotaUpdated: &attachv1.QuotaUpdated{RateLimitType: "five_hour", Status: "ok"}}},
	}
	var wire bytes.Buffer
	for _, f := range frames {
		if err := writeDelimitedFrame(&wire, f); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if _, err := renderSpectateStream(&out, &wire); err != nil {
		t.Fatalf("renderSpectateStream: %v", err)
	}
	for _, want := range []string{
		"#1 tool completed [ERROR] boom",
		"#2 ask Bash requested (req=req-9)",
		"#3 ask resolved allow (req=req-9)",
		"#4 plan [unspecified] step one step two",
		"#5 quota five_hour ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("render missing %q\n--- got ---\n%s", want, out.String())
		}
	}
}

// TestDelimitedFrameRoundTrip proves the codec is symmetric and that a clean
// end-of-stream returns io.EOF at a frame boundary (renderSpectateStream relies
// on this to terminate without error).
func TestDelimitedFrameRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	in := chatFrame(7, "assistant", "round trip")
	if err := writeDelimitedFrame(&wire, in); err != nil {
		t.Fatalf("writeDelimitedFrame: %v", err)
	}
	var out bytes.Buffer
	n, err := renderSpectateStream(&out, &wire)
	if err != nil {
		t.Fatalf("renderSpectateStream: %v", err)
	}
	if n != 1 || out.String() != "#7 chat assistant: round trip\n" {
		t.Errorf("round-trip render = %q (n=%d)", out.String(), n)
	}
}

// TestSpectateReplayEndToEnd drives the FULL `serpent spectate --replay` command
// path (flag parse → file open → shared renderer) against a captured frame dump
// on disk, capturing the process stdout — the command-level proof on top of the
// renderer-level tests above.
func TestSpectateReplayEndToEnd(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "watchsession.dump")
	f, err := os.Create(dump)
	if err != nil {
		t.Fatal(err)
	}
	for _, fr := range []*attachv1.SessionEvent{
		chatFrame(1, "assistant", "spectating"),
		toolInvokedFrame(2, "Read"),
	} {
		if err := writeDelimitedFrame(f, fr); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	code := cmdSpectate([]string{"--replay", dump})
	os.Stdout = oldStdout
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("cmdSpectate(--replay) = %d, want 0", code)
	}
	want := "#1 chat assistant: spectating\n#2 tool Read invoked\n"
	if string(out) != want {
		t.Errorf("replay output = %q, want %q", out, want)
	}
}

// TestSpectateGoldenFixtureReplay replays the CHECKED-IN golden frame dump —
// produced by the REAL orchestrator WatchSession handler (orchestrator
// internal/controlplane/contentrelay_test.go writes it as the one artifact
// crossing the D80 seam) — through spectate.go's reader + renderer, asserting the
// exact read-only projection. This closes the "backed by the real handler"
// acceptance in this stdlib-only module with no gRPC: the frozen frames the
// handler serves decode with spectate.go's codec and render to the expected
// spectator lines. Byte-mutating any frame in the fixture flips the decoded
// content (or fails the decode) and REDs this assertion — the golden is pinned.
func TestSpectateGoldenFixtureReplay(t *testing.T) {
	const goldenPath = "testdata/spectate_golden.frames"
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("open golden fixture %s: %v (regenerate via the orchestrator test with DS_REGEN_SPECTATE_FIXTURE=1)", goldenPath, err)
	}
	defer f.Close()

	var out bytes.Buffer
	rendered, err := renderSpectateStream(&out, f)
	if err != nil {
		t.Fatalf("renderSpectateStream(golden): %v", err)
	}
	if rendered != 4 {
		t.Errorf("rendered = %d content frames, want 4", rendered)
	}
	want := "#1 chat assistant: Reading the failing test now.\n" +
		"#2 tool Bash invoked\n" +
		"#3 tool completed [ok] PASS ok ./... all tests pass\n" +
		"#4 chat assistant: All green — the fix holds.\n"
	if out.String() != want {
		t.Errorf("golden replay render mismatch\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}

// TestSpectateNoSourceUsage: no frame source (no --replay/--stdin/--session) is a
// usage error (exit 2), so the read-only contract stays legible — there is always
// exactly one source.
func TestSpectateNoSourceUsage(t *testing.T) {
	if got := cmdSpectate(nil); got != 2 {
		t.Errorf("cmdSpectate() with no source = %d, want 2", got)
	}
}

// TestSpectateAmbiguousSource: two sources is rejected (exit 2).
func TestSpectateAmbiguousSource(t *testing.T) {
	if got := cmdSpectate([]string{"--stdin", "--session", "s1"}); got != 2 {
		t.Errorf("cmdSpectate(--stdin --session) = %d, want 2", got)
	}
}

// TestSpectateLiveGateDisarmed: `--session` without DS_ORCH_LIVE=1 fails closed
// (exit 1) and dials NOTHING — the offline, no-orchestrator guarantee for CI.
func TestSpectateLiveGateDisarmed(t *testing.T) {
	t.Setenv(orchLiveGateEnv, "")
	if got := cmdSpectate([]string{"--session", "sess-1"}); got != 1 {
		t.Errorf("disarmed live spectate = %d, want 1 (fail-closed)", got)
	}
}
