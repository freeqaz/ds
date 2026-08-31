// SPDX-License-Identifier: Apache-2.0

// pty_scenario_test.go — the offline always-on FAKE-PTY tier (runs in the wave
// gate) plus the gated live tiers for the TERMINAL (PTY-mode) acceptance harness
// (docs/serpent-cli-mvp/08-spike-and-acceptance.md §4.5, U-LIVE-E2E).
//
// The offline tests drive the REAL client carrier (*hostbridge.TerminalConn over a
// framed UDS, dialed by SocketTransport.DialTerminal) through a synthetic in-process
// pty (scriptedCarriage) — every line the live leg runs except the real pty/VM/
// claude. They prove:
//
//   - the keystroke→output round-trip over the raw frames (frameRawIn → carriage,
//     carriage → frameRawOut → rendered grid);
//   - the grid canonicalizer (renderGrid) tolerates SGR/control noise and asserts on
//     PRINTED text (banner, prompt, echoed line), never raw bytes;
//   - the D144 native-prompt ask surface: the ask is in the pty BYTE stream answered
//     by a `y` keystroke — there is NO attach.v1 ask/grant frame on this carriage
//     (structurally: the carrier exposes RawOut/Write/SendResize only);
//   - the connect-resize + a forwarded resize reach the carriage (the §2.2 path).
//
// The gated tiers (TestPTYDriveKVM, TestPTYDriveReal) skip CLEAN with their env
// unset, so this file is green in the wave gate with no VM/PTY/claude.

package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- the deterministic synthetic fixtures -------------------------------------

// ptyBanner is the connect paint the fake pty emits on attach (a real CC TUI
// repaints on attach). It carries SGR color + a box glyph so the grid canonicalizer
// is exercised on real terminal noise, and a stable banner string to assert on.
const ptyBanner = "\x1b[2J\x1b[H\x1b[1;36m┌─ Claude Code ─┐\x1b[0m\r\n\x1b[32mwelcome to the in-VM session\x1b[0m\r\n> "

// scriptedReactor is the fake pty's reactive program: it echoes each input line and
// renders a deterministic, low-entropy response, modelling CC's reaction to a
// keystroke line. It pins three exchanges the scenario asserts on:
//
//   - "print PONG"  → echoes the line, prints "PONG", redraws the prompt;
//   - "run tool"    → echoes, then renders CC's NATIVE in-terminal ask prompt
//     (D144: the ask is a y/n in the byte stream, NOT an attach.v1 frame);
//   - "y" / "n"     → the ask answer; "y" runs the tool (prints OK), "n" denies;
//   - "exit"        → ends the session (RawOut EOF, modelling CC exiting).
func scriptedReactor(line string) (out []byte, end bool) {
	line = strings.TrimSpace(line)
	switch line {
	case "print PONG":
		// echo + colored output + prompt redraw (SGR noise the grid strips).
		return []byte("print PONG\r\n\x1b[33mPONG\x1b[0m\r\n> "), false
	case "run tool":
		// CC's NATIVE in-terminal permission prompt (D144) — a y/n in the bytes.
		return []byte("run tool\r\n\x1b[1mBash(echo hi)\x1b[0m\r\nDo you want to proceed? (y/n) "), false
	case "y":
		return []byte("y\r\n\x1b[32mTOOL-OK: hi\x1b[0m\r\n> "), false
	case "n":
		return []byte("n\r\nDenied.\r\n> "), false
	case "exit":
		return []byte("exit\r\nbye\r\n"), true
	default:
		return []byte(line + "\r\n> "), false
	}
}

// newFakeTermFleet stands up the in-process terminal server fronting a scriptedCarriage
// with the banner + reactor, under a t.TempDir UDS. The caller defers Close.
func newFakeTermFleet(t *testing.T) *termFleet {
	t.Helper()
	carriage := newScriptedCarriage(ptyBanner, scriptedReactor)
	fleet, err := newTermFleet(t.TempDir(), carriage)
	if err != nil {
		t.Fatalf("newTermFleet: %v", err)
	}
	t.Cleanup(fleet.Close)
	return fleet
}

// --- (1) the always-on FAKE-PTY scenario tier ---------------------------------

// TestPTYScenarioFakeRoundTrip is the offline acceptance keystone: it drives the
// REAL client carrier over the in-process synthetic pty through a scripted
// keystroke→grid exchange, asserting the client faithfully relays raw output to its
// "stdout" and raw input back, and that the canonicalized grid renders the expected
// banner/prompt/echoed lines. NO real pty, VM, or claude.
func TestPTYScenarioFakeRoundTrip(t *testing.T) {
	fleet := newFakeTermFleet(t)
	conn, err := fleet.dialWriter()
	if err != nil {
		t.Fatalf("DialTerminal WRITER: %v", err)
	}

	scenario := TermScenario{
		SettleTimeout: 5 * time.Second,
		Steps: []TermStep{
			// The connect paint: the banner renders before any input.
			{ExpectGridContains: []string{"Claude Code", "welcome to the in-VM session"}},
			// A scripted keystroke→output round-trip: the line echoes and PONG prints.
			{Send: "print PONG\r", ExpectGridContains: []string{"print PONG", "PONG"}},
			// D144: CC's NATIVE in-terminal ask prompt renders in the byte stream.
			{Send: "run tool\r", ExpectNativePrompt: true, ExpectGridContains: []string{"Do you want to proceed?"}},
			// The ask is answered by a `y` KEYSTROKE (no attach.v1 grant frame).
			{Send: "y\r", ExpectGridContains: []string{"TOOL-OK: hi"}},
			// End the session cleanly.
			{Send: "exit\r", ExpectGridContains: []string{"bye"}},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := DriveTermScenario(ctx, conn, scenario)
	if err != nil {
		t.Fatalf("DriveTermScenario: %v", err)
	}

	// The final grid carries every printed line, canonicalized (SGR/control erased).
	grid := res.FinalGrid
	for _, want := range []string{"Claude Code", "welcome to the in-VM session", "PONG", "Do you want to proceed?", "TOOL-OK: hi", "bye"} {
		if !strings.Contains(grid, want) {
			t.Errorf("final grid missing %q; grid:\n%s", want, grid)
		}
	}

	// Canonicalization, not raw equality: the raw output carries the SGR escapes the
	// grid stripped (so the assertion is robust to equivalent escape encodings).
	if !bytes.Contains(res.RawOutput, []byte("\x1b[33mPONG\x1b[0m")) {
		t.Errorf("raw output should carry the colored PONG escape (the grid strips it); raw:\n%q", res.RawOutput)
	}
	if strings.Contains(grid, "\x1b[") {
		t.Errorf("rendered grid still contains a CSI escape (canonicalization leaked); grid:\n%q", grid)
	}

	// The keystrokes round-tripped back to the carriage (frameRawIn forwarded): the
	// carriage saw the input bytes the client sent.
	var allIn []byte
	for _, rec := range fleet.carriage.inputRecords() {
		allIn = append(allIn, rec...)
	}
	for _, want := range []string{"print PONG\r", "run tool\r", "y\r", "exit\r"} {
		if !bytes.Contains(allIn, []byte(want)) {
			t.Errorf("carriage did not receive forwarded keystrokes %q; got %q", want, allIn)
		}
	}

	// The connect-resize reached the carriage (the §2.3/§A7 initial window).
	resizes := fleet.carriage.resizeRecords()
	if len(resizes) == 0 {
		t.Fatalf("no resize reached the carriage; the connect-resize must seed the window")
	}
	if resizes[0].Cols != 80 || resizes[0].Rows != 24 {
		t.Errorf("connect-resize = %dx%d, want 80x24", resizes[0].Cols, resizes[0].Rows)
	}
}

// TestPTYScenarioFakeDenyBranch proves the native-ask DENY branch round-trips: the
// human answers `n` to CC's in-terminal prompt and the deny renders — the D144
// surface answers in BOTH directions through the byte stream, with no grant frame.
func TestPTYScenarioFakeDenyBranch(t *testing.T) {
	fleet := newFakeTermFleet(t)
	conn, err := fleet.dialWriter()
	if err != nil {
		t.Fatalf("DialTerminal WRITER: %v", err)
	}
	scenario := TermScenario{
		SettleTimeout: 5 * time.Second,
		Steps: []TermStep{
			{Send: "run tool\r", ExpectNativePrompt: true},
			{Send: "n\r", ExpectGridContains: []string{"Denied."}},
			{Send: "exit\r", ExpectGridContains: []string{"bye"}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := DriveTermScenario(ctx, conn, scenario)
	if err != nil {
		t.Fatalf("DriveTermScenario (deny): %v", err)
	}
	if strings.Contains(res.FinalGrid, "TOOL-OK") {
		t.Errorf("deny branch should not run the tool; grid:\n%s", res.FinalGrid)
	}
	if !strings.Contains(res.FinalGrid, "Denied.") {
		t.Errorf("deny branch missing the Denied. render; grid:\n%s", res.FinalGrid)
	}
}

// TestPTYScenarioFromFixture proves the committed JSONL TermScenario fixture parses
// and drives the same fake carrier — the determinism keystone (a reviewable cassette
// the gated live tier re-runs against real CC).
func TestPTYScenarioFromFixture(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "pty-scenario.jsonl"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	scenario, err := ParseTermScenario(f, 5*time.Second)
	if err != nil {
		t.Fatalf("ParseTermScenario: %v", err)
	}
	if len(scenario.Steps) == 0 {
		t.Fatal("fixture parsed to zero steps")
	}

	fleet := newFakeTermFleet(t)
	conn, err := fleet.dialWriter()
	if err != nil {
		t.Fatalf("DialTerminal WRITER: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := DriveTermScenario(ctx, conn, scenario); err != nil {
		t.Fatalf("DriveTermScenario over the committed fixture: %v", err)
	}
}

// --- (2) the renderGrid canonicalizer unit tests ------------------------------

// TestRenderGridStripsNoise proves the grid canonicalizer erases SGR color, cursor
// moves, OSC sequences, and C0 control while preserving printed text + line breaks +
// UTF-8 box glyphs — the perturbation tolerance the assertions depend on.
func TestRenderGridStripsNoise(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sgr color", "\x1b[1;31mRED\x1b[0m", "RED"},
		{"cursor move + erase", "\x1b[2J\x1b[H\x1b[Khi", "hi"},
		{"osc title bel", "\x1b]0;a title\x07body", "body"},
		{"osc st terminator", "\x1b]8;;http://x\x1b\\link", "link"},
		{"cr dropped lf kept", "a\r\nb", "a\nb"},
		{"tab to space", "a\tb", "a b"},
		{"backspace dropped", "ab\x08c", "abc"},
		{"utf8 box glyph kept", "┌─┐ ❯", "┌─┐ ❯"},
		{"unterminated csi to eof", "ok\x1b[1;3", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderGrid([]byte(tc.in)); got != tc.want {
				t.Errorf("renderGrid(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseTermScenarioStrict proves the JSONL loader rejects a typo'd key (strict)
// and an empty/all-comment fixture, mirroring ParseScript's discipline.
func TestParseTermScenarioStrict(t *testing.T) {
	if _, err := ParseTermScenario(strings.NewReader(`{"snd":"x"}`), time.Second); err == nil {
		t.Error("a typo'd key must be a loud parse error (DisallowUnknownFields)")
	}
	if _, err := ParseTermScenario(strings.NewReader("# only a comment\n\n"), time.Second); err == nil {
		t.Error("an all-comment fixture must error (no steps)")
	}
	got, err := ParseTermScenario(strings.NewReader(`{"send":"go\r","expect_grid_contains":["ok"]}`), time.Second)
	if err != nil {
		t.Fatalf("valid one-step fixture: %v", err)
	}
	if len(got.Steps) != 1 || got.Steps[0].Send != "go\r" {
		t.Errorf("parsed = %+v, want one step send=go\\r", got.Steps)
	}
}

// --- (3) the gated KVM-PTY tier -----------------------------------------------

// TestPTYDriveKVM is the REAL proof: it dials the per-session KVM-VM RAW_TERMINAL
// writer seat a LIVE terminal-mode VM session serves (resolved from DS_KVM_LIVE_*),
// drives a deterministic scripted prompt over the raw carriage, and asserts on a
// rendered-grid substring + a /work side-effect proof (CC actually ran). It launches
// NO podman/claude/VM itself — the live VM already serves the seat (the transport-
// target swap, mirroring the structured DriveKVMScripted tier).
//
// GATED behind DS_KVM_LIVE=1 AND DS_KVM_LIVE_PTY=1; unfully-armed (every CI / wave /
// go test run) it SKIPS CLEAN. Arming it is an independent operator step: there must
// be a live terminal-mode VM serving the session (see scripts/live-mvp/ds-pty-claude-run.sh
// for the bring-up delta — the host-agent started -session-mode terminal + the new
// PTY-launch ds-entrypoint baked into the M0 image).
func TestPTYDriveKVM(t *testing.T) {
	if os.Getenv(KVMLiveGateEnv) != "1" || os.Getenv(PTYLiveSubGateEnv) != "1" {
		t.Skipf("%s != 1 or %s != 1: the per-session KVM-VM RAW_TERMINAL writer-seat drive is the terminal-MVP deferred manual live step. Skipping; the fake-PTY tier (TestPTYScenarioFakeRoundTrip) proves the carrier+frames+broker+raw-client round-trip offline. Arm with a live terminal-mode VM (scripts/live-mvp/ds-pty-claude-run.sh).", KVMLiveGateEnv, PTYLiveSubGateEnv)
	}

	kvm, err := kvmAttachFromEnv()
	if err != nil {
		t.Fatalf("KVM-tier env: %v", err)
	}
	conn, err := DialKVMTerminal(kvm)
	if err != nil {
		t.Fatalf("DialKVMTerminal over the advertised RAW_TERMINAL writer-seat: %v", err)
	}

	// A deterministic, low-entropy scripted prompt: ask CC to write a proof token to
	// /work (the side-effect anchor "CC actually ran") and reply with a fixed marker
	// (the grid anchor). The exact prompt is operator-overridable via env so the
	// fixture is not pinned to a single CC phrasing; the defaults are deterministic.
	token := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_PTY_TOKEN"))
	if token == "" {
		token = "DS-PTY-PROOF-7Q4T"
	}
	proofFile := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_PTY_PROOFFILE"))
	if proofFile == "" {
		proofFile = "ds-pty-proof.txt"
	}
	prompt := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_PTY_PROMPT"))
	if prompt == "" {
		prompt = "Run exactly: printf '" + token + "' > /work/" + proofFile + " ; then reply with exactly: " + token
	}

	scenario := TermScenario{
		SettleTimeout: 3 * time.Minute,
		Steps: []TermStep{
			// Drive the prompt (terminated by Enter) and wait for the deterministic
			// marker to render in the grid — proving the live in-VM CC answered over
			// the raw terminal carriage.
			{Send: prompt + "\r", ExpectGridContains: []string{token}},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := DriveTermScenario(ctx, conn, scenario)
	if err != nil {
		t.Fatalf("DriveTermScenario over the live KVM RAW_TERMINAL seat: %v", err)
	}
	t.Logf("KVM PTY drive rendered %d bytes; final grid head:\n%s", len(res.RawOutput), headLines(res.FinalGrid, 20))

	// The grid anchor: the live in-VM CC rendered the deterministic marker.
	if !strings.Contains(res.FinalGrid, token) {
		t.Errorf("live KVM PTY grid did not render the marker %q (CC did not answer over the raw carriage); grid:\n%s", token, res.FinalGrid)
	}

	// The side-effect anchor: the proof file CC was instructed to write exists on the
	// host side of the guest /work share and carries the token — CC actually executed
	// the command in the VM, not merely streamed text. Resolved from DS_KVM_LIVE_WORK
	// (the host dir mounted at the guest /work); unset ⇒ a manual operator readback.
	workdir := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_WORK"))
	if workdir == "" {
		t.Logf("DS_KVM_LIVE_WORK unset: the /work side-effect proof readback is a manual operator check (inspect the guest /work/%s for %q). The rendered-grid round-trip above is proven.", proofFile, token)
		return
	}
	proof := filepath.Join(workdir, proofFile)
	got, rerr := os.ReadFile(proof)
	if rerr != nil {
		t.Fatalf("VM-side effect: proof file %s not found on the host side of the guest /work share: %v (CC did not execute the write instruction in the VM over the raw terminal)", proof, rerr)
	}
	if !strings.Contains(string(got), token) {
		t.Errorf("VM-side effect: proof file %s = %q, want it to contain the token %q", proof, string(got), token)
	} else {
		t.Logf("VM-side effect proven on the KVM guest over the raw terminal: %s contains %q", proof, token)
	}
}

// TestPTYDriveKVMGateUnset proves the KVM PTY tier dials NOTHING when the gate is not
// fully armed: DialKVMTerminal returns ErrPTYKVMGateUnset and touches no socket. It
// is the always-on, ungated negative control that proves the gate is not vacuous
// (the §5 self-check discipline — with the gate unset, the live tier launches/dials
// nothing).
func TestPTYDriveKVMGateUnset(t *testing.T) {
	// The wave gate runs with the gate unset; assert the explicit unset behavior
	// regardless of the ambient env (set them off for this assertion).
	t.Setenv(KVMLiveGateEnv, "")
	t.Setenv(PTYLiveSubGateEnv, "")
	_, err := DialKVMTerminal(KVMAttachConfig{Endpoint: "/should/not/be/dialed.sock", SessionUUID: "x", Token: "y"})
	if !errors.Is(err, ErrPTYKVMGateUnset) {
		t.Fatalf("DialKVMTerminal with the PTY gate unset = %v, want ErrPTYKVMGateUnset (the tier must dial nothing unarmed)", err)
	}

	// Half-armed (DS_KVM_LIVE=1 but DS_KVM_LIVE_PTY unset) must ALSO dial nothing —
	// an operator who armed a STRUCTURED KVM drive does not accidentally dial it as a
	// terminal.
	t.Setenv(KVMLiveGateEnv, "1")
	_, err = DialKVMTerminal(KVMAttachConfig{Endpoint: "/should/not/be/dialed.sock", SessionUUID: "x", Token: "y"})
	if !errors.Is(err, ErrPTYKVMGateUnset) {
		t.Fatalf("DialKVMTerminal half-armed (no %s) = %v, want ErrPTYKVMGateUnset", PTYLiveSubGateEnv, err)
	}
}

// --- (4) the podman PTY tier — documented, KVM is the right tier --------------

// TestPTYDriveReal documents why the PODMAN tier is NOT the PTY acceptance tier and
// skips. A faithful PTY drive needs the runtime under a controlling pty with the new
// PTY-launch ds-entrypoint (vm/entrypoint stdioPTY + bridgePTY) and the host-agent's
// -session-mode terminal carriage — which is the M0 GUEST launch path, not the podman
// container path. The podman live-drive tier (live_drive.go) launches CC under
// stream-json PIPES with NO pty allocation and NO terminal-mode serving child, so it
// has no RAW_TERMINAL carriage to dial; retrofitting a pty into the podman launcher
// would test a SECOND, non-production launch path rather than the shipping one.
//
// The production terminal carriage is the per-session KVM VM writer seat
// (TestPTYDriveKVM), so THAT is the gated live tier. This stub keeps the documented
// gate parity (it is behind DS_E2E_LIVE) and records the rationale at the test site.
func TestPTYDriveReal(t *testing.T) {
	t.Skip("DS_E2E_LIVE: the podman tier is NOT the PTY acceptance tier — the production terminal carriage is the per-session KVM VM's PTY-launch ds-entrypoint + -session-mode terminal serving child (see TestPTYDriveKVM, gated DS_KVM_LIVE=1+DS_KVM_LIVE_PTY=1). A podman pty drive would exercise a non-shipping launch path; the fake-PTY tier proves the carrier offline and the KVM tier proves it live.")
}

// headLines returns the first n lines of s (a bounded failure-dump helper so a large
// rendered grid does not flood the test log).
func headLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
