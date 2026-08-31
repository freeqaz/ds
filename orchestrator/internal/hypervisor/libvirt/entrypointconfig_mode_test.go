// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// recordingModeStore is an in-memory SessionModeStore for the producer tests: it
// records each PutMode so the test asserts the producer persisted the SAME resolved
// mode the LaunchSpec was built from (the doc 04 §5 drift guard, in-process). It also
// records each RemoveMode (the §4.2 teardown purge) with the file store's idempotency —
// removing a session that was never put is a clean no-op success — so a service-level
// destroy test can drive the seam without a temp dir.
type recordingModeStore struct {
	put     map[string]SessionMode
	removed []string
	// removeErr, when non-nil, faults every RemoveMode so a test can assert the §4.2
	// marker purge is BEST-EFFORT (a fault never fails the Destroy).
	removeErr error
}

func newRecordingModeStore() *recordingModeStore {
	return &recordingModeStore{put: map[string]SessionMode{}}
}

func (s *recordingModeStore) PutMode(_ context.Context, sessionUUID string, mode SessionMode) error {
	s.put[sessionUUID] = mode
	return nil
}

func (s *recordingModeStore) ModeFor(_ context.Context, sessionUUID string) (SessionMode, bool, error) {
	m, ok := s.put[sessionUUID]
	return m, ok, nil
}

func (s *recordingModeStore) RemoveMode(_ context.Context, sessionUUID string) error {
	s.removed = append(s.removed, sessionUUID)
	if s.removeErr != nil {
		return s.removeErr
	}
	delete(s.put, sessionUUID)
	return nil
}

var _ SessionModeStore = (*recordingModeStore)(nil)

// modeTestFacts is a minimal valid EntrypointFacts carrying the headless launch argv
// (so the terminal path has stream-json flags to strip) at the given default mode.
func modeTestFacts(mode SessionMode) EntrypointFacts {
	return EntrypointFacts{
		HostID: "host-aaa",
		Launch: LaunchSpecInput{
			Command: "/usr/bin/claude",
			Args:    headlessArgv(),
		},
		Posture:         runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,
		EventSocketPath: "/run/ds/attach.sock",
		DefaultMode:     mode,
	}
}

// decodeDeliveredConfig decodes the single delivered config.pb the recordingDeliverer
// captured back to an EntrypointConfig (the producer's drop the guest would read).
func decodeDeliveredConfig(t *testing.T, d *recordingDeliverer) *runtimev1.EntrypointConfig {
	t.Helper()
	if len(d.calls) != 1 {
		t.Fatalf("expected one delivery, got %d", len(d.calls))
	}
	var cfg runtimev1.EntrypointConfig
	if err := proto.Unmarshal(d.calls[0].configPB, &cfg); err != nil {
		t.Fatalf("decode delivered config.pb: %v", err)
	}
	return &cfg
}

// produceWithMode runs the producer over a fake source + recording deliverer + mode
// store at the given default mode, returning the captured config + the store. The
// overlay fixture carries no hint (so the default mode resolves).
func produceWithMode(t *testing.T, defaultMode SessionMode, sessionUUID string) (*runtimev1.EntrypointConfig, *recordingModeStore) {
	t.Helper()
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-overlay")})
	deliver := &recordingDeliverer{}
	modes := newRecordingModeStore()
	p, err := NewEntrypointProducer(src, deliver, modeTestFacts(defaultMode))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	p.WithModeStore(modes)
	if _, err := p.Produce(context.Background(), sessionUUID, produceTestBinding(5), ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	return decodeDeliveredConfig(t, deliver), modes
}

// TestProduce_StructuredDefaultByteIdentical asserts the DEFAULT (structured) producer
// path emits a config whose LaunchSpec carries the FULL headless argv, NO stdio
// (UNSPECIFIED — absent on the wire), and NO initial window — byte-identical to a
// build that never knew about the mode rider (the historical config.pb).
func TestProduce_StructuredDefaultByteIdentical(t *testing.T) {
	cfg, modes := produceWithMode(t, SessionModeStructured, "sess-structured")

	if got := cfg.GetLaunch().GetArgs(); !equalStrings(got, headlessArgv()) {
		t.Errorf("structured args = %v, want full headless argv %v", got, headlessArgv())
	}
	if got := cfg.GetLaunch().GetStdio(); got != runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED {
		t.Errorf("structured stdio = %v, want UNSPECIFIED", got)
	}
	if cfg.GetLaunch().GetInitialWindow() != nil {
		t.Errorf("structured initial_window = %v, want nil", cfg.GetLaunch().GetInitialWindow())
	}
	if modes.put["sess-structured"] != SessionModeStructured {
		t.Errorf("persisted mode = %v, want structured", modes.put["sess-structured"])
	}

	// The literal byte-identity guard: the produced config.pb must equal a build with
	// NO stdio/window set and the unmodified launch (what the pre-rider producer emitted).
	wantCfg, err := BuildEntrypointConfig(EntrypointBuildInput{
		SessionUUID:     "sess-structured",
		HostID:          "host-aaa",
		Binding:         produceTestBinding(5),
		Launch:          LaunchSpecInput{Command: "/usr/bin/claude", Args: headlessArgv()},
		Posture:         runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,
		EventSocketPath: "/run/ds/attach.sock",
		RoleOverlayRef:  []byte("opaque-overlay"),
	})
	if err != nil {
		t.Fatalf("reference build: %v", err)
	}
	if !proto.Equal(cfg, wantCfg) {
		t.Fatalf("structured config NOT byte-identical to the pre-rider build:\n got  = %v\n want = %v", cfg, wantCfg)
	}
}

// TestProduce_TerminalSetsPTYStripsArgvSeedsWindow asserts the TERMINAL producer path
// strips the stream-json argv, sets LaunchSpec.stdio = PTY, seeds the 80x24 default
// initial_window, and persists the terminal mode (the drift guard: one resolution
// feeds the marker AND the LaunchSpec).
func TestProduce_TerminalSetsPTYStripsArgvSeedsWindow(t *testing.T) {
	cfg, modes := produceWithMode(t, SessionModeTerminal, "sess-terminal")

	if got := cfg.GetLaunch().GetArgs(); !equalStrings(got, []string{"--model", "sonnet"}) {
		t.Errorf("terminal args = %v, want stripped [--model sonnet]", got)
	}
	if got := cfg.GetLaunch().GetStdio(); got != runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY {
		t.Errorf("terminal stdio = %v, want PTY", got)
	}
	w := cfg.GetLaunch().GetInitialWindow()
	if w.GetRows() != 24 || w.GetCols() != 80 {
		t.Errorf("terminal initial_window = %dx%d, want 24x80", w.GetRows(), w.GetCols())
	}
	if modes.put["sess-terminal"] != SessionModeTerminal {
		t.Errorf("persisted mode = %v, want terminal", modes.put["sess-terminal"])
	}
}

// TestProduce_PerSessionHintOverridesHostDefault asserts a DS_SESSION_MODE=terminal
// hint in the opaque overlay overrides a STRUCTURED host default (carrier (A) over
// carrier (C), doc 04 §2.3) — the produced config goes PTY though the host default is
// structured, and the persisted mode is terminal.
func TestProduce_PerSessionHintOverridesHostDefault(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{
		ref: []byte("a=b\nDS_SESSION_MODE=terminal\n"),
	})
	deliver := &recordingDeliverer{}
	modes := newRecordingModeStore()
	p, err := NewEntrypointProducer(src, deliver, modeTestFacts(SessionModeStructured))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	p.WithModeStore(modes)
	if _, err := p.Produce(context.Background(), "sess-hint", produceTestBinding(6), ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	cfg := decodeDeliveredConfig(t, deliver)
	if got := cfg.GetLaunch().GetStdio(); got != runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY {
		t.Errorf("hinted stdio = %v, want PTY (hint overrides structured default)", got)
	}
	if modes.put["sess-hint"] != SessionModeTerminal {
		t.Errorf("persisted mode = %v, want terminal (from hint)", modes.put["sess-hint"])
	}
}

// TestProduce_MalformedHintFailsClosed asserts a present-but-garbage mode hint fails
// the produce (no delivery, no persist) — an explicit mistyped hint must not silently
// fall through to the host default.
func TestProduce_MalformedHintFailsClosed(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{
		ref: []byte("DS_SESSION_MODE=termnial\n"),
	})
	deliver := &recordingDeliverer{}
	modes := newRecordingModeStore()
	p, err := NewEntrypointProducer(src, deliver, modeTestFacts(SessionModeStructured))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	p.WithModeStore(modes)
	if _, err := p.Produce(context.Background(), "sess-bad", produceTestBinding(7), ref); err == nil {
		t.Fatal("Produce must fail closed on a malformed mode hint")
	}
	if len(deliver.calls) != 0 {
		t.Error("a malformed-hint produce must NOT deliver a config-drive")
	}
	if _, ok := modes.put["sess-bad"]; ok {
		t.Error("a malformed-hint produce must NOT persist a mode")
	}
}

// TestProduce_NoModeStoreStillProducesStructured asserts a producer with NO mode store
// (the offline default / a caller that does not opt in) still produces the historical
// structured config — the persistence is optional and never gates the build.
func TestProduce_NoModeStoreStillProducesStructured(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-overlay")})
	deliver := &recordingDeliverer{}
	p, err := NewEntrypointProducer(src, deliver, modeTestFacts(SessionModeStructured))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	// No WithModeStore — modes stays nil.
	if _, err := p.Produce(context.Background(), "sess-nostore", produceTestBinding(8), ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	cfg := decodeDeliveredConfig(t, deliver)
	if got := cfg.GetLaunch().GetStdio(); got != runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED {
		t.Errorf("no-store structured stdio = %v, want UNSPECIFIED", got)
	}
}

// equalStrings is a small order-sensitive string-slice equality (nil == empty), to
// avoid an extra import in the table assertions.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
