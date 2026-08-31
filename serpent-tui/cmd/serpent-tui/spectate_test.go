// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"

	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/watch"
)

// chatResp / toolInvokedResp build the WatchSession responses a real orchestrator
// fan-out serves — the frozen CONTENT frames a spectator watches. The emit-frames
// verb must relay them verbatim as length-delimited frames.
func chatResp(seq uint64, role, text string) *orchestratorv1.WatchSessionResponse {
	return &orchestratorv1.WatchSessionResponse{Event: &attachv1.SessionEvent{
		Seq:  seq,
		Type: attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE,
		Payload: &attachv1.SessionEvent_ChatMessage{ChatMessage: &attachv1.ChatMessage{
			Role:   role,
			Blocks: []*attachv1.ChatBlock{{Kind: "text", Text: text}},
		}},
	}}
}

func toolInvokedResp(seq uint64, name string) *orchestratorv1.WatchSessionResponse {
	return &orchestratorv1.WatchSessionResponse{Event: &attachv1.SessionEvent{
		Seq:     seq,
		Type:    attachv1.EventType_EVENT_TYPE_TOOL_INVOKED,
		Payload: &attachv1.SessionEvent_ToolInvoked{ToolInvoked: &attachv1.ToolInvoked{Name: name}},
	}}
}

// readDelimitedFrameForTest is the DECODE half of the length-delimited codec —
// byte-for-byte the algorithm client/cmd/serpent/spectate.go's readDelimitedFrame
// uses (uvarint length prefix + proto.Unmarshal). Decoding the emitter's stdout
// with it proves codec parity: the frames serpent-tui writes are exactly the
// frames `serpent spectate`'s reader consumes.
func readDelimitedFrameForTest(t *testing.T, br *bufio.Reader) (*attachv1.SessionEvent, error) {
	t.Helper()
	n, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	ev := &attachv1.SessionEvent{}
	if err := proto.Unmarshal(buf, ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// decodeFrames reads every length-delimited frame off r until a clean EOF.
func decodeFrames(t *testing.T, r io.Reader) []*attachv1.SessionEvent {
	t.Helper()
	br := bufio.NewReader(r)
	var out []*attachv1.SessionEvent
	for {
		ev, err := readDelimitedFrameForTest(t, br)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		out = append(out, ev)
	}
}

// emitFake serves a WatchSession fan-out on an in-process bufconn (honoring
// from_seq so the resume path is faithful) and returns a watch.Starter dialing
// it — the offline stand-in for a live orchestrator.
func emitFake(t *testing.T, log []*orchestratorv1.WatchSessionResponse) watch.Starter {
	t.Helper()
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(log, req.GetFromSeq()), nil
	}
	dialFake(t, fake)
	c, _, err := dialer("bufnet")
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	return c
}

// TestEmitFramesRelaysContentStream drives the emit path against a fake
// WatchSession fan-out and proves the verb writes the delivered content frames as
// length-delimited records that DECODE (with the spectate.go codec) back to the
// exact input events, in order — codec parity between the serpent-tui emitter and
// the `serpent spectate` reader, pinned by a round trip through the real verb.
func TestEmitFramesRelaysContentStream(t *testing.T) {
	log := []*orchestratorv1.WatchSessionResponse{
		chatResp(1, "assistant", "let me run the tests"),
		toolInvokedResp(2, "Bash"),
		chatResp(3, "assistant", "all green"),
	}
	c := emitFake(t, log)

	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code := emitFrames(ctx, c, "sess-emit", 0, &out, io.Discard, watch.Options{Sleep: noSleepOpt, Deterministic: true})
	if code != 0 {
		t.Fatalf("emitFrames exit = %d, want 0", code)
	}

	got := decodeFrames(t, &out)
	if len(got) != 3 {
		t.Fatalf("emitted %d frames, want 3", len(got))
	}
	wantSeq := []uint64{1, 2, 3}
	for i, ev := range got {
		if ev.GetSeq() != wantSeq[i] {
			t.Errorf("frame[%d] seq = %d, want %d", i, ev.GetSeq(), wantSeq[i])
		}
	}
	if got[0].GetType() != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE ||
		got[0].GetChatMessage().GetBlocks()[0].GetText() != "let me run the tests" {
		t.Errorf("frame[0] = %v / %q", got[0].GetType(), got[0].GetChatMessage().GetBlocks()[0].GetText())
	}
	if got[1].GetType() != attachv1.EventType_EVENT_TYPE_TOOL_INVOKED ||
		got[1].GetToolInvoked().GetName() != "Bash" {
		t.Errorf("frame[1] = %v / %q", got[1].GetType(), got[1].GetToolInvoked().GetName())
	}
	if got[2].GetChatMessage().GetBlocks()[0].GetText() != "all green" {
		t.Errorf("frame[2] text = %q", got[2].GetChatMessage().GetBlocks()[0].GetText())
	}
}

// TestEmitFramesResumesFromSeq proves --from-seq threads through to the subscribe
// request: with from-seq=1 only the events strictly after seq 1 are emitted (the
// D61 slow-reader recovery / resume contract).
func TestEmitFramesResumesFromSeq(t *testing.T) {
	log := []*orchestratorv1.WatchSessionResponse{
		chatResp(1, "assistant", "before"),
		chatResp(2, "assistant", "after"),
	}
	c := emitFake(t, log)

	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code := emitFrames(ctx, c, "sess-resume", 1, &out, io.Discard, watch.Options{Sleep: noSleepOpt, Deterministic: true})
	if code != 0 {
		t.Fatalf("emitFrames exit = %d, want 0", code)
	}
	got := decodeFrames(t, &out)
	if len(got) != 1 || got[0].GetSeq() != 2 {
		t.Fatalf("resumed frames = %d (want 1 at seq 2)", len(got))
	}
}

// outOfRangeFake returns a watch.Starter whose WatchSession fan-out refuses the
// subscription with codes.OutOfRange — the control-plane terminal for a from_seq
// that aged out of the bounded resume ring (sessionservice.go's
// ErrResumeWindowExceeded path). watch.Run treats OutOfRange as terminal (no
// reconnect), so emitFrames must surface the operator remedy, not the raw status.
func outOfRangeFake(t *testing.T) watch.Starter {
	t.Helper()
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return nil, status.Errorf(codes.OutOfRange, "controlplane: WatchSession from_seq %d aged out of the resume window", req.GetFromSeq())
	}
	dialFake(t, fake)
	c, _, err := dialer("bufnet")
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	return c
}

// TestEmitFramesOutOfRangeHint proves that when the subscription's resume seq has
// aged out of the session's resume ring (watch.Run returns a terminal OutOfRange),
// emitFrames exits 1 AND surfaces the documented operator remedy on the error
// stream — re-run with --from-seq 0 to re-attach from the frontier — instead of a
// raw gRPC status dump. No content frames are emitted on stdout. The seq in the
// hint is the REFUSED resume token (here the initial --from-seq, 42; on a mid-run
// reconnect it would be the last emitted seq), so the operator sees the number the
// server actually rejected.
func TestEmitFramesOutOfRangeHint(t *testing.T) {
	c := outOfRangeFake(t)

	var out, errOut bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code := emitFrames(ctx, c, "sess-aged-out", 42, &out, &errOut, watch.Options{Sleep: noSleepOpt, Deterministic: true})
	if code != 1 {
		t.Fatalf("emitFrames exit = %d, want 1 (terminal OutOfRange)", code)
	}
	if out.Len() != 0 {
		t.Errorf("emitFrames wrote %d stdout bytes on an aged-out subscription, want 0", out.Len())
	}
	msg := errOut.String()
	if !strings.Contains(msg, "--from-seq 0") {
		t.Errorf("OutOfRange stderr missing the --from-seq 0 remedy\n--- got ---\n%s", msg)
	}
	if !strings.Contains(msg, "resume from seq 42") || !strings.Contains(msg, "frontier") {
		t.Errorf("OutOfRange stderr missing the refused resume seq / frontier remedy\n--- got ---\n%s", msg)
	}
	// The raw gRPC status prefix (`rpc error: code = OutOfRange`) must NOT leak —
	// the operator sees the remedy, not the transport dump.
	if strings.Contains(msg, "rpc error") || strings.Contains(msg, "code = OutOfRange") {
		t.Errorf("OutOfRange stderr leaked the raw gRPC status instead of the remedy\n--- got ---\n%s", msg)
	}
}

// TestSpectateVerbRequiresEmitFrames: a bare `spectate` (no --emit-frames) is a
// usage error (exit 2) and dials nothing — the only supported mode is the raw
// emitter behind `serpent spectate --session`.
func TestSpectateVerbRequiresEmitFrames(t *testing.T) {
	t.Setenv(orchestratorEnv, "")
	if got := cmdSpectate([]string{"--session", "s", "--orchestrator", "x:1"}); got != 2 {
		t.Errorf("spectate without --emit-frames = %d, want 2", got)
	}
}

// TestSpectateVerbRequiresFlags: --emit-frames still needs a session and an
// orchestrator endpoint; missing either refuses cleanly (exit 2) before any dial.
func TestSpectateVerbRequiresFlags(t *testing.T) {
	t.Setenv(orchestratorEnv, "")
	if got := cmdSpectate([]string{"--emit-frames", "--orchestrator", "x:1"}); got != 2 {
		t.Errorf("spectate --emit-frames without --session = %d, want 2", got)
	}
	if got := cmdSpectate([]string{"--emit-frames", "--session", "s"}); got != 2 {
		t.Errorf("spectate --emit-frames without --orchestrator = %d, want 2", got)
	}
}

// TestSpectateVerbEndToEnd drives the FULL `serpent-tui spectate --emit-frames`
// command (flag parse → dial the fake → subscribe → emit) capturing the process
// stdout, the command-level proof on top of emitFrames: the client execs exactly
// this.
func TestSpectateVerbEndToEnd(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter([]*orchestratorv1.WatchSessionResponse{
			chatResp(1, "assistant", "hi from the verb"),
			toolInvokedResp(2, "Read"),
		}, req.GetFromSeq()), nil
	}
	dialFake(t, fake)

	var out bytes.Buffer
	prev := stdout
	t.Cleanup(func() { stdout = prev })
	stdout = &out

	code := runCmd(t, func() int {
		return cmdSpectate([]string{"--emit-frames", "--session", "sess-e2e", "--orchestrator", "bufnet"})
	})
	if code != 0 {
		t.Fatalf("cmdSpectate exit = %d, want 0", code)
	}
	got := decodeFrames(t, &out)
	if len(got) != 2 || got[0].GetChatMessage().GetBlocks()[0].GetText() != "hi from the verb" || got[1].GetToolInvoked().GetName() != "Read" {
		t.Fatalf("verb emitted %d frames, unexpected content", len(got))
	}
}

// noSleepOpt advances backoff instantly while honoring ctx cancellation — the
// deterministic, fast reconnect seam for the emit tests.
func noSleepOpt(ctx context.Context, _ time.Duration) error { return ctx.Err() }
