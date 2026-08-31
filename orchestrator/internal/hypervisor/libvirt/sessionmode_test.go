// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"reflect"
	"testing"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// TestParseSessionMode covers the flag/marker → SessionMode resolution: the empty and
// "structured" strings (and case/whitespace variants) resolve structured; "terminal"
// resolves terminal; a mistyped value fails loud (never a silent structured default).
func TestParseSessionMode(t *testing.T) {
	cases := []struct {
		in      string
		want    SessionMode
		wantErr bool
	}{
		{"", SessionModeStructured, false},
		{"structured", SessionModeStructured, false},
		{"STRUCTURED", SessionModeStructured, false},
		{"  terminal  ", SessionModeTerminal, false},
		{"Terminal", SessionModeTerminal, false},
		{"termnial", SessionModeStructured, true}, // a typo must NOT silently downgrade
		{"headless", SessionModeStructured, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSessionMode(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSessionMode(%q) = nil err, want a fail-loud rejection", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSessionMode(%q): unexpected err %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseSessionMode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSessionModeStringRoundTrip asserts String() is the inverse of ParseSessionMode
// for both modes — the persisted marker the store writes round-trips back to the same
// mode (the drift guard's read-back must agree with the write).
func TestSessionModeStringRoundTrip(t *testing.T) {
	for _, m := range []SessionMode{SessionModeStructured, SessionModeTerminal} {
		got, err := ParseSessionMode(m.String())
		if err != nil {
			t.Fatalf("ParseSessionMode(%q): %v", m.String(), err)
		}
		if got != m {
			t.Errorf("round-trip %v -> %q -> %v", m, m.String(), got)
		}
	}
}

// headlessArgv is the real-CC headless launch argv the live MVP feeds today (the
// ds-serve-stack.sh / -launch-arg surface). The terminal strip must drop the
// stream-json flags + their values + --verbose, leaving any other token in place.
func headlessArgv() []string {
	return []string{
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-prompt-tool", "stdio",
		"--model", "sonnet", // a NON-stream-json flag: must be preserved
	}
}

// TestStripStreamJSONArgs_DropsHeadlessFlags asserts the terminal argv transform drops
// exactly the headless stream-json surface (flags AND their value tokens) and keeps
// every other token in order — leaving the bare interactive argv.
func TestStripStreamJSONArgs_DropsHeadlessFlags(t *testing.T) {
	got := stripStreamJSONArgs(headlessArgv())
	want := []string{"--model", "sonnet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stripStreamJSONArgs(headless) = %v, want %v", got, want)
	}
}

// TestStripStreamJSONArgs_JoinedEqualsForm asserts the `--flag=value` joined token form
// is matched on its flag head and dropped whole (no following-token skip needed).
func TestStripStreamJSONArgs_JoinedEqualsForm(t *testing.T) {
	got := stripStreamJSONArgs([]string{
		"--output-format=stream-json",
		"--input-format=stream-json",
		"--keep-me",
		"value-of-keep",
	})
	want := []string{"--keep-me", "value-of-keep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stripStreamJSONArgs(joined) = %v, want %v", got, want)
	}
}

// TestStripStreamJSONArgs_NoHeadlessFlagsUnchanged asserts a structured argv with NO
// stream-json flags passes through UNCHANGED — the byte-identical guarantee on the
// argv (a terminal session whose operator argv had nothing to strip is untouched).
func TestStripStreamJSONArgs_NoHeadlessFlagsUnchanged(t *testing.T) {
	in := []string{"--model", "opus", "--add-dir", "/work", "positional"}
	got := stripStreamJSONArgs(append([]string(nil), in...))
	if !reflect.DeepEqual(got, in) {
		t.Errorf("stripStreamJSONArgs(no-headless) = %v, want unchanged %v", got, in)
	}
}

// TestStripStreamJSONArgs_DoesNotMutateInput asserts the transform never mutates the
// caller's slice (the producer reuses the facts' Args across sessions).
func TestStripStreamJSONArgs_DoesNotMutateInput(t *testing.T) {
	in := headlessArgv()
	snapshot := append([]string(nil), in...)
	_ = stripStreamJSONArgs(in)
	if !reflect.DeepEqual(in, snapshot) {
		t.Errorf("stripStreamJSONArgs mutated its input: %v, want %v", in, snapshot)
	}
}

// TestApplyLaunchMode_StructuredByteIdentical asserts the structured mode returns the
// launch UNCHANGED (args preserved), stdio UNSPECIFIED, and NO initial window — the
// byte-identical default path (LaunchSpec.stdio absent on the wire == today).
func TestApplyLaunchMode_StructuredByteIdentical(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude", Args: headlessArgv(), WorkingDir: "/work"}
	out, stdio, window := applyLaunchMode(in, SessionModeStructured, TerminalWindow{})

	if !reflect.DeepEqual(out.Args, in.Args) {
		t.Errorf("structured args = %v, want unchanged %v", out.Args, in.Args)
	}
	if out.Command != in.Command || out.WorkingDir != in.WorkingDir {
		t.Errorf("structured launch mutated command/workdir: %+v", out)
	}
	if stdio != runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED {
		t.Errorf("structured stdio = %v, want UNSPECIFIED (byte-identical)", stdio)
	}
	if window != nil {
		t.Errorf("structured initial window = %v, want nil", window)
	}
}

// TestApplyLaunchMode_TerminalStripsAndSetsPTY asserts terminal mode strips the
// stream-json argv, sets stdio PTY, and seeds the DEFAULT 80x24 window when the facts
// carry none (§A7 / G9).
func TestApplyLaunchMode_TerminalStripsAndSetsPTY(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude", Args: headlessArgv()}
	out, stdio, window := applyLaunchMode(in, SessionModeTerminal, TerminalWindow{})

	wantArgs := []string{"--model", "sonnet"}
	if !reflect.DeepEqual(out.Args, wantArgs) {
		t.Errorf("terminal args = %v, want stripped %v", out.Args, wantArgs)
	}
	if stdio != runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY {
		t.Errorf("terminal stdio = %v, want PTY", stdio)
	}
	if window.GetRows() != 24 || window.GetCols() != 80 {
		t.Errorf("terminal default window = %dx%d, want 24x80", window.GetRows(), window.GetCols())
	}
}

// TestApplyLaunchMode_TerminalHonorsFactsWindow asserts a host-provided window
// overrides the 80x24 default for a terminal session.
func TestApplyLaunchMode_TerminalHonorsFactsWindow(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude"}
	_, _, window := applyLaunchMode(in, SessionModeTerminal, TerminalWindow{Rows: 50, Cols: 200})
	if window.GetRows() != 50 || window.GetCols() != 200 {
		t.Errorf("terminal facts window = %dx%d, want 50x200", window.GetRows(), window.GetCols())
	}
}

// envValue returns the VALUE of the first KEY=VALUE entry in env whose key matches, and
// the count of entries with that key (so a test can assert presence, value, AND no
// duplication in one read).
func envValue(env []string, key string) (value string, count int) {
	for _, e := range env {
		if envKey(e) == key {
			if count == 0 {
				if i := indexByte(e, '='); i >= 0 {
					value = e[i+1:]
				}
			}
			count++
		}
	}
	return value, count
}

// indexByte is a tiny local helper so the test file stays import-light (mirrors
// strings.IndexByte for a single byte).
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestApplyLaunchMode_TerminalInjectsTERM asserts terminal mode injects a color-capable
// TERM (and COLORTERM) into out.Env when the facts carry none — the U-COLOR fix: without
// TERM the in-VM CC resolves supports-color level 0 (MONOCHROME). The injected TERM MUST
// equal DefaultTerminalTERM (single-sourced to the M0_PTY_TERM image pin) so it matches
// the terminfo entry the baked image carries.
func TestApplyLaunchMode_TerminalInjectsTERM(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude", Args: headlessArgv(), Env: []string{"HOME=/home/ds"}}
	out, _, _ := applyLaunchMode(in, SessionModeTerminal, TerminalWindow{})

	term, termCount := envValue(out.Env, "TERM")
	if termCount != 1 {
		t.Fatalf("terminal out.Env TERM count = %d, want exactly 1 (env=%v)", termCount, out.Env)
	}
	if term != DefaultTerminalTERM {
		t.Errorf("terminal TERM = %q, want %q (DefaultTerminalTERM)", term, DefaultTerminalTERM)
	}
	if DefaultTerminalTERM != "xterm-256color" {
		t.Errorf("DefaultTerminalTERM = %q, want xterm-256color (single-sourced to M0_PTY_TERM)", DefaultTerminalTERM)
	}
	if colorterm, c := envValue(out.Env, "COLORTERM"); c != 1 || colorterm != DefaultTerminalCOLORTERM {
		t.Errorf("terminal COLORTERM = %q (count %d), want %q x1", colorterm, c, DefaultTerminalCOLORTERM)
	}
	// The pre-existing facts entry is preserved alongside the injected ones.
	if home, c := envValue(out.Env, "HOME"); c != 1 || home != "/home/ds" {
		t.Errorf("terminal out.Env dropped/garbled HOME = %q (count %d), want /home/ds x1", home, c)
	}
}

// TestApplyLaunchMode_TerminalHonorsFactsTERM asserts a host-resolved TERM (and
// COLORTERM) in the facts env WINS — the terminal mode appends a default ONLY when the
// key is absent, never duplicating or clobbering an operator-supplied value.
func TestApplyLaunchMode_TerminalHonorsFactsTERM(t *testing.T) {
	in := LaunchSpecInput{
		Command: "/usr/bin/claude",
		Env:     []string{"TERM=screen-256color", "COLORTERM=24bit"},
	}
	out, _, _ := applyLaunchMode(in, SessionModeTerminal, TerminalWindow{})

	if term, c := envValue(out.Env, "TERM"); c != 1 || term != "screen-256color" {
		t.Errorf("terminal TERM = %q (count %d), want host-supplied screen-256color x1 (no clobber/dup)", term, c)
	}
	if colorterm, c := envValue(out.Env, "COLORTERM"); c != 1 || colorterm != "24bit" {
		t.Errorf("terminal COLORTERM = %q (count %d), want host-supplied 24bit x1", colorterm, c)
	}
}

// TestApplyLaunchMode_StructuredEnvByteIdentical asserts the structured mode returns
// out.Env byte-identical to the input — NO TERM/COLORTERM injected. This is the
// structured byte-identical guard: only the terminal mode shapes the env (mirrors the
// argv byte-identical guard in TestApplyLaunchMode_StructuredByteIdentical).
func TestApplyLaunchMode_StructuredEnvByteIdentical(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude", Env: []string{"HOME=/home/ds", "CLAUDE_CONFIG_DIR=/home/ds/.claude"}}
	out, _, _ := applyLaunchMode(in, SessionModeStructured, TerminalWindow{})

	if !reflect.DeepEqual(out.Env, in.Env) {
		t.Errorf("structured out.Env = %v, want byte-identical to input %v (no TERM injected)", out.Env, in.Env)
	}
	if _, c := envValue(out.Env, "TERM"); c != 0 {
		t.Errorf("structured out.Env carries TERM (%d entries) — the structured path must NOT inject one", c)
	}
}

// TestApplyLaunchMode_TerminalDoesNotMutateFactsEnv asserts the terminal env injection
// does not mutate the caller's facts Env slice (the producer reuses the facts across
// sessions — an append that aliased spare capacity would corrupt later launches).
func TestApplyLaunchMode_TerminalDoesNotMutateFactsEnv(t *testing.T) {
	in := LaunchSpecInput{Command: "/usr/bin/claude", Env: []string{"HOME=/home/ds"}}
	snapshot := append([]string(nil), in.Env...)
	_, _, _ = applyLaunchMode(in, SessionModeTerminal, TerminalWindow{})
	if !reflect.DeepEqual(in.Env, snapshot) {
		t.Errorf("applyLaunchMode mutated facts Env: %v, want unchanged %v", in.Env, snapshot)
	}
}

// TestSessionModeHintFromOverlay covers the per-session hint extraction from the
// opaque overlay body: a present DS_SESSION_MODE= sentinel yields its value; an
// absent one yields found=false; the value runs to the first delimiter.
func TestSessionModeHintFromOverlay(t *testing.T) {
	cases := []struct {
		name      string
		overlay   []byte
		wantVal   string
		wantFound bool
	}{
		{"absent", []byte("some=overlay\nother=value"), "", false},
		{"empty overlay", nil, "", false},
		{"terminal newline-delimited", []byte("a=b\nDS_SESSION_MODE=terminal\nc=d"), "terminal", true},
		{"terminal eof", []byte("DS_SESSION_MODE=terminal"), "terminal", true},
		{"structured space-delimited", []byte("DS_SESSION_MODE=structured x=y"), "structured", true},
		{"bare empty value", []byte("DS_SESSION_MODE=\nx=y"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val, found := sessionModeHintFromOverlay(tc.overlay)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if val != tc.wantVal {
				t.Errorf("val = %q, want %q", val, tc.wantVal)
			}
		})
	}
}

// --- live-text arming: ArmStructuredLiveText (the U-PARTIALS-ARM runtime-arming
// half; doc serpent-cli-mvp/06 Layer 1, D145) ---------------------------------
//
// These pin the host-side arm/strip composition that turns CC's typing-delta
// stream on for a STRUCTURED session and OFF for a TERMINAL (PTY) one: ArmStructured
// LiveText appends --include-partial-messages once (and idempotently), never mutating
// the caller's slice; the structured launch mode keeps the armed flag; the terminal
// launch mode strips EVERY occurrence (a PTY has the real terminal, so the headless
// live-text flag would garble it).

// countIncludePartial returns how many times includePartialMessagesFlag appears in
// args — so a single read asserts the flag is present exactly once (armed /
// idempotent) or not at all (off / stripped).
func countIncludePartial(args []string) int {
	n := 0
	for _, a := range args {
		if a == includePartialMessagesFlag {
			n++
		}
	}
	return n
}

// TestArmStructuredLiveText_OffReturnsVerbatimNonAliasingCopy pins the DEFAULT
// (liveText=false) contract: the returned argv is byte-identical to the input (NO
// flag added — the live-text-off byte-identical invariant) AND is a NON-ALIASING
// copy. The non-aliasing half matters because the EntrypointProducer reuses the
// facts' Args across sessions: an arm that returned the caller's backing array would
// let a later mutation corrupt a previously-produced config.
func TestArmStructuredLiveText_OffReturnsVerbatimNonAliasingCopy(t *testing.T) {
	in := []string{"--input-format", "stream-json", "--output-format", "stream-json"}
	snapshot := append([]string(nil), in...)

	out := ArmStructuredLiveText(in, false)
	if !reflect.DeepEqual(out, in) {
		t.Errorf("off path out = %v, want byte-identical to input %v (no flag added)", out, in)
	}
	if c := countIncludePartial(out); c != 0 {
		t.Errorf("off path armed the live-text flag (%d occurrences), want 0", c)
	}
	// NON-ALIASING: mutate every element of the returned slice and assert the input
	// is untouched (a fresh backing array).
	for i := range out {
		out[i] = "MUTATED"
	}
	if !reflect.DeepEqual(in, snapshot) {
		t.Errorf("off path aliased the caller's slice: in = %v after mutating out, want unchanged %v", in, snapshot)
	}
}

// TestArmStructuredLiveText_OffEmptyAndNilCopy pins the off path on the degenerate
// nil/empty inputs: it returns an empty argv (the defensive-copy posture even when
// there is nothing to copy), never panicking and never adding a flag.
func TestArmStructuredLiveText_OffEmptyAndNilCopy(t *testing.T) {
	if got := ArmStructuredLiveText(nil, false); len(got) != 0 {
		t.Errorf("ArmStructuredLiveText(nil,false) = %v, want empty", got)
	}
	if got := ArmStructuredLiveText([]string{}, false); len(got) != 0 {
		t.Errorf("ArmStructuredLiveText([],false) = %v, want empty", got)
	}
}

// TestArmStructuredLiveText_OnAppendsOnce pins liveText=true: it appends
// --include-partial-messages EXACTLY ONCE as the last token, leaving the prior argv
// in order, and never aliases the caller's slice.
func TestArmStructuredLiveText_OnAppendsOnce(t *testing.T) {
	in := []string{"--input-format", "stream-json", "--output-format", "stream-json"}
	snapshot := append([]string(nil), in...)

	out := ArmStructuredLiveText(in, true)
	if c := countIncludePartial(out); c != 1 {
		t.Fatalf("on path flag count = %d, want exactly 1 (out=%v)", c, out)
	}
	if out[len(out)-1] != includePartialMessagesFlag {
		t.Errorf("on path last token = %q, want %q (appended last)", out[len(out)-1], includePartialMessagesFlag)
	}
	if !reflect.DeepEqual(out[:len(in)], in) {
		t.Errorf("on path prefix = %v, want the original argv %v in order", out[:len(in)], in)
	}
	// The arm must not have mutated the caller's slice.
	if !reflect.DeepEqual(in, snapshot) {
		t.Errorf("on path mutated the caller's slice: %v, want %v", in, snapshot)
	}
}

// TestArmStructuredLiveText_OnIdempotent pins that arming an argv that ALREADY
// carries --include-partial-messages is a no-op (never duplicated): a re-derive of
// EntrypointFacts.Launch leaves exactly one flag.
func TestArmStructuredLiveText_OnIdempotent(t *testing.T) {
	// Already-armed argv (the flag mid-argv, to prove the scan is position-agnostic).
	armed := []string{"--output-format", "stream-json", includePartialMessagesFlag, "--model", "sonnet"}
	out := ArmStructuredLiveText(armed, true)
	if c := countIncludePartial(out); c != 1 {
		t.Errorf("idempotent arm flag count = %d, want exactly 1 (no duplicate); out=%v", c, out)
	}
	if !reflect.DeepEqual(out, armed) {
		t.Errorf("idempotent arm out = %v, want unchanged %v", out, armed)
	}

	// Re-arming the OUTPUT of a first arm is also a no-op (double-arm idempotency).
	once := ArmStructuredLiveText([]string{"--output-format", "stream-json"}, true)
	twice := ArmStructuredLiveText(once, true)
	if c := countIncludePartial(twice); c != 1 {
		t.Errorf("double-arm flag count = %d, want exactly 1; twice=%v", c, twice)
	}
}

// TestArmedStructuredArgvSurvivesStructuredLaunchMode pins the end-to-end
// resolved-mode contract on the STRUCTURED path: an armed argv keeps
// --include-partial-messages through applyLaunchMode(SessionModeStructured) (the
// default branch returns the argv UNCHANGED), so a structured session actually
// carries the flag to the in-guest CC.
func TestArmedStructuredArgvSurvivesStructuredLaunchMode(t *testing.T) {
	armed := ArmStructuredLiveText(headlessArgv(), true)
	in := LaunchSpecInput{Command: "/usr/bin/claude", Args: armed}

	out, stdio, window := applyLaunchMode(in, SessionModeStructured, TerminalWindow{})
	if c := countIncludePartial(out.Args); c != 1 {
		t.Errorf("structured-mode armed argv flag count = %d, want 1 (survives the structured launch mode); out.Args=%v", c, out.Args)
	}
	if !reflect.DeepEqual(out.Args, armed) {
		t.Errorf("structured-mode armed argv = %v, want unchanged %v (byte-identical structured path)", out.Args, armed)
	}
	if stdio != runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED || window != nil {
		t.Errorf("structured-mode stdio/window = %v/%v, want UNSPECIFIED/nil", stdio, window)
	}
}

// TestArmedArgvStrippedForTerminalLaunchMode pins the resolved-mode contract on the
// TERMINAL path: a session a per-session overlay hint flips to terminal has the
// live-text flag STRIPPED — both via stripStreamJSONArgs directly and via the full
// applyLaunchMode(SessionModeTerminal) transform — so the PTY (native TUI) argv
// NEVER carries --include-partial-messages. EVERY occurrence is dropped, even a
// (malformed) duplicate the producer should never have minted.
func TestArmedArgvStrippedForTerminalLaunchMode(t *testing.T) {
	armed := ArmStructuredLiveText(headlessArgv(), true)
	if c := countIncludePartial(armed); c != 1 {
		t.Fatalf("precondition: armed argv must carry the flag once, got %d", c)
	}

	// stripStreamJSONArgs drops the live-text flag (it is in streamJSONStripFlags).
	if c := countIncludePartial(stripStreamJSONArgs(armed)); c != 0 {
		t.Errorf("stripStreamJSONArgs left %d live-text flags, want 0 (terminal must not carry it)", c)
	}

	// The full terminal launch-mode transform also drops it and selects PTY stdio.
	out, stdio, _ := applyLaunchMode(LaunchSpecInput{Command: "/usr/bin/claude", Args: armed}, SessionModeTerminal, TerminalWindow{})
	if c := countIncludePartial(out.Args); c != 0 {
		t.Errorf("terminal-mode argv carries the live-text flag (%d), want 0 (stripped); out.Args=%v", c, out.Args)
	}
	if stdio != runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY {
		t.Errorf("terminal-mode stdio = %v, want PTY", stdio)
	}

	// EVERY occurrence is dropped: a (malformed) argv with TWO live-text flags is
	// fully cleared on the terminal path.
	twice := append(append([]string(nil), armed...), includePartialMessagesFlag)
	if c := countIncludePartial(stripStreamJSONArgs(twice)); c != 0 {
		t.Errorf("stripStreamJSONArgs left %d live-text flags from a double-armed argv, want 0 (drops every occurrence)", c)
	}
}

// TestIncludePartialMessagesFlagIsStrippedAndBareBoolean pins the two structural
// facts ArmStructuredLiveText / stripStreamJSONArgs rely on: the live-text flag is
// in the terminal strip allow-list (so terminal never carries it) and is a BARE
// boolean (NOT value-taking — appending/stripping it never consumes a following
// value token). A future edit that moved it out of the strip set, or made it
// value-taking, would silently break the resolved-mode contract; this catches it.
func TestIncludePartialMessagesFlagIsStrippedAndBareBoolean(t *testing.T) {
	if !streamJSONStripFlags[includePartialMessagesFlag] {
		t.Errorf("%q is not in streamJSONStripFlags — terminal mode would carry the headless live-text flag", includePartialMessagesFlag)
	}
	if streamJSONValueFlags[includePartialMessagesFlag] {
		t.Errorf("%q is in streamJSONValueFlags — it is a BARE boolean and must not consume a following value token", includePartialMessagesFlag)
	}
	if includePartialMessagesFlag != "--include-partial-messages" {
		t.Errorf("includePartialMessagesFlag = %q, want --include-partial-messages (the CC headless live-text launch flag)", includePartialMessagesFlag)
	}
}

// TestArmThenStripRoundTrip pins the full arm→terminal-strip round trip from the
// SAME operator argv used elsewhere: arming for live-text and then resolving to
// terminal leaves an argv byte-identical to the plain terminal-stripped argv (the
// live-text flag is fully erased; the bare interactive argv remains). This is the
// composition the host-agent relies on so a per-session terminal hint never leaks a
// headless flag a structured-armed launch baked in.
func TestArmThenStripRoundTrip(t *testing.T) {
	plainTerminal := stripStreamJSONArgs(headlessArgv())
	armedThenTerminal := stripStreamJSONArgs(ArmStructuredLiveText(headlessArgv(), true))
	if !reflect.DeepEqual(armedThenTerminal, plainTerminal) {
		t.Errorf("arm-then-terminal-strip = %v, want byte-identical to plain terminal strip %v (live-text flag fully erased)", armedThenTerminal, plainTerminal)
	}
}
