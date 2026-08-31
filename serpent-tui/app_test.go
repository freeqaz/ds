package serpenttui

import (
	"context"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"net"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"

	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/loop"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/watch"
)

// scriptedServer is the in-process fake orchestrator.v1 WatchSession server: it
// streams a scripted event log then HOLDS the stream open (blocking on ctx) so
// the test can inject keystrokes before the program quits, then is released by
// ctx cancel. NO live orchestrator/VM.
type scriptedServer struct {
	orchestratorv1.UnimplementedSessionServiceServer
	log   []*attachv1.SessionEvent
	hold  bool // if true, block after sending the log (so keystrokes can be driven)
	ready chan struct{}
	once  sync.Once
}

func (s *scriptedServer) WatchSession(req *orchestratorv1.WatchSessionRequest, stream orchestratorv1.SessionService_WatchSessionServer) error {
	for _, ev := range s.log {
		if ev.GetSeq() <= req.GetFromSeq() {
			continue
		}
		if err := stream.Send(&orchestratorv1.WatchSessionResponse{Event: ev}); err != nil {
			return err
		}
	}
	if s.ready != nil {
		s.once.Do(func() { close(s.ready) })
	}
	if s.hold {
		<-stream.Context().Done()
		return status.Error(codes.Canceled, "fake: held stream cancelled")
	}
	return nil
}

func dialScripted(t *testing.T, srv *scriptedServer) watch.Starter {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	orchestratorv1.RegisterSessionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial scripted: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return orchestratorv1.NewSessionServiceClient(conn)
}

// recordingSeat is the in-process writer seat the loop drives — the offline twin
// of a live host-agent SocketConn.
type recordingSeat struct {
	mu     sync.Mutex
	inputs []string
	grants []hostbridge.DriveGrant
}

func (r *recordingSeat) DriveInput(in hostbridge.DriveInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inputs = append(r.inputs, in.Text)
	return nil
}
func (r *recordingSeat) DriveGrant(g hostbridge.DriveGrant, _ hostbridge.GrantRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grants = append(r.grants, g)
	return nil
}
func (r *recordingSeat) snapInputs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.inputs...)
}
func (r *recordingSeat) snapGrants() []hostbridge.DriveGrant {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hostbridge.DriveGrant(nil), r.grants...)
}

func stateEvent(seq uint64, name attachv1.SessionStateName) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{Seq: seq, Type: attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: name}}}
}

// TestRunCleanStreamTerminates proves the full wiring (WatchSession subscriber ->
// eventmap -> loop fold -> bubbletea program) runs headless and terminates
// cleanly when the WatchSession stream ends, with no writer seat needed.
func TestRunCleanStreamTerminates(t *testing.T) {
	srv := &scriptedServer{log: []*attachv1.SessionEvent{
		stateEvent(1, attachv1.SessionStateName_SESSION_STATE_NAME_READY),
		stateEvent(2, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING),
		stateEvent(3, attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED),
	}}
	c := dialScripted(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, Config{
		SessionUUID:    "sess",
		Starter:        c,
		WatchOptions:   watch.Options{Sleep: instantSleep, Deterministic: true},
		programOptions: []tea.ProgramOption{tea.WithoutRenderer(), tea.WithInput(nil)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestRunDrivesWriterSeat proves the END-TO-END human-in-the-loop path: events
// stream in (one is an ask that PARKS the session), an injected keystroke answers
// the ask (driving a grant — the TTL'd-grant path, D45/D53), and injected input
// keystrokes drive a line to the writer seat (the runtime stdin via the wrapper,
// D18). The stream is held open until the test cancels, so the keystrokes land
// before the program quits.
func TestRunDrivesWriterSeat(t *testing.T) {
	srv := &scriptedServer{
		hold:  true,
		ready: make(chan struct{}),
		log: []*attachv1.SessionEvent{
			stateEvent(1, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING),
			{Seq: 2, Type: attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
				Payload: &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{ToolUseId: "tu-1", ToolName: "Bash"}}},
		},
	}
	c := dialScripted(t, srv)
	seat := &recordingSeat{}

	progCh := make(chan *tea.Program, 1)
	stateCh := make(chan *loop.State, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			SessionUUID:    "sess",
			Starter:        c,
			Seat:           seat,
			WatchOptions:   watch.Options{Sleep: instantSleep, Deterministic: true},
			programOptions: []tea.ProgramOption{tea.WithoutRenderer(), tea.WithInput(nil)},
			onProgram:      func(p *tea.Program) { progCh <- p },
			onState:        func(s *loop.State) { stateCh <- s },
		})
	}()

	prog := <-progCh
	st := <-stateCh
	// Wait until the scripted log (incl. the ask) has been sent.
	select {
	case <-srv.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("scripted log never fully sent")
	}
	// Gate deterministically on the FOLD: the ask must have parked the session
	// before we inject the answering keystroke (otherwise 'a' would compose).
	waitUntil(t, 3*time.Second, func() bool { return st.Parked() })
	if !st.Parked() {
		t.Fatal("session never parked on the ask")
	}

	// Answer the parked ask with allow-once ('a'): drives a grant.
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'a'}}))
	// Type and submit an input line: 'h','i', Enter.
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'h'}}))
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'i'}}))
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyEnter}))

	// Assert the seat received the grant and the input.
	waitUntil(t, 3*time.Second, func() bool { return len(seat.snapGrants()) == 1 && len(seat.snapInputs()) == 1 })
	grants := seat.snapGrants()
	if len(grants) != 1 || !grants[0].Allow || grants[0].ToolUseID != "tu-1" {
		t.Fatalf("grants = %+v, want one allow on tu-1", grants)
	}
	if inputs := seat.snapInputs(); len(inputs) != 1 || inputs[0] != "hi" {
		t.Fatalf("inputs = %v, want [hi]", inputs)
	}

	// Quit via Ctrl+C. The program returns; Run's deferred cancel then releases the
	// held subscriber stream. Confirm Run returns clean (a clean operator quit is
	// not an error).
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyCtrlC}))
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after clean quit", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after quit")
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(d)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			return // caller asserts; let the assertion produce the failure message
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func instantSleep(ctx context.Context, _ time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// TestRunEventStreamReadPath pins the direct writer-seat read path: when Config.EventStream
// is set, Run folds attach.Event values straight from the channel (NOT WatchSession), so the
// rendered seq advances as CC's projected events arrive. This is the single-box MVP read path —
// the orchestrator's WatchSession carries only §3 state edges, so CC's response reaches the
// client over this direct stream (the same one the proven goldentrace drive harness reads).
func TestRunEventStreamReadPath(t *testing.T) {
	// A no-op WatchSession server: with EventStream set, Run must NOT subscribe to it.
	srv := &scriptedServer{hold: true, ready: make(chan struct{})}
	c := dialScripted(t, srv)

	events := make(chan attach.Event, 4)
	stateCh := make(chan *loop.State, 1)
	progCh := make(chan *tea.Program, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			SessionUUID:    "sess",
			Starter:        c,
			EventStream:    events,
			programOptions: []tea.ProgramOption{tea.WithoutRenderer(), tea.WithInput(nil)},
			onProgram:      func(p *tea.Program) { progCh <- p },
			onState:        func(s *loop.State) { stateCh <- s },
		})
	}()
	prog := <-progCh
	st := <-stateCh

	// Feed two attach.Events directly down the channel; the loop must fold them and advance seq.
	events <- attach.Event{Seq: 1, Type: attach.TypeSessionState, SessionState: &attach.SessionState{State: "WORKING"}}
	events <- attach.Event{Seq: 2, Type: attach.TypeChatMessage, ChatMessage: &attach.ChatMessage{
		Role: "assistant", Blocks: []attach.ChatBlock{{Text: "PONG"}},
	}}
	waitUntil(t, 3*time.Second, func() bool { return st.LastSeq() >= 2 })
	if got := st.LastSeq(); got < 2 {
		t.Fatalf("EventStream fold did not advance seq: LastSeq=%d, want >=2", got)
	}

	// Closing the channel is a clean session end → Run returns nil.
	close(events)
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on a clean EventStream close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after the EventStream closed")
	}
	_ = prog
}

// TestRunScriptedPromptDrivesSeat pins the scripted-prompt verification leg: setting
// Config.ScriptedPrompt makes the loop submit that ONE prompt through the writer seat
// the moment it is running — via the robust keystroke→SubmitInput→DriveInput path, NOT
// a piped-stdin EOF that can race the program teardown. This is the deterministic,
// non-TTY submit the `serpent claude --vm` verification path relies on (the seq-0 fix's
// submit half). The prompt (with a space) must reach the seat verbatim as one input line.
func TestRunScriptedPromptDrivesSeat(t *testing.T) {
	// Shorten the settle so the test is fast; restore after.
	orig := scriptedPromptSettle
	scriptedPromptSettle = 10 * time.Millisecond
	defer func() { scriptedPromptSettle = orig }()

	srv := &scriptedServer{
		hold:  true,
		ready: make(chan struct{}),
		log:   []*attachv1.SessionEvent{stateEvent(1, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)},
	}
	c := dialScripted(t, srv)
	seat := &recordingSeat{}

	progCh := make(chan *tea.Program, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const prompt = "Reply with exactly: PONG"
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			SessionUUID:    "sess",
			Starter:        c,
			Seat:           seat,
			ScriptedPrompt: prompt,
			WatchOptions:   watch.Options{Sleep: instantSleep, Deterministic: true},
			programOptions: []tea.ProgramOption{tea.WithoutRenderer(), tea.WithInput(nil)},
			onProgram:      func(p *tea.Program) { progCh <- p },
		})
	}()
	prog := <-progCh

	// The scripted leg must drive the prompt to the seat WITHOUT any manual keystroke —
	// proving the non-TTY submit path works on its own.
	waitUntil(t, 3*time.Second, func() bool { return len(seat.snapInputs()) == 1 })
	if inputs := seat.snapInputs(); len(inputs) != 1 || inputs[0] != prompt {
		t.Fatalf("scripted prompt: seat inputs = %v, want [%q]", inputs, prompt)
	}

	// Clean quit; Run returns nil (the loop kept running for the response, as intended).
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyCtrlC}))
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after clean quit", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after quit")
	}
}
