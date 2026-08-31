// SPDX-License-Identifier: Apache-2.0

// sessionmode — the HOST-AGENT-INTERNAL session launch mode (the serpent-CLI
// terminal-MVP control-plane unit; docs/serpent-cli-mvp/10-build-decisions §A3/§A7,
// docs/serpent-cli-mvp/04-control-plane-and-session-mode.md §2.3). SessionMode
// selects HOW the in-guest runtime is launched and HOW its I/O is carried to the
// writer: structured (the M0 default — headless stream-json, the attach.v1
// SessionEvent stream, a DIRECT framed-UDS endpoint) vs terminal (a PTY runtime,
// raw terminal bytes + resize to the writer, a RAW_TERMINAL endpoint).
//
// IT IS NEVER ON THE ORCHESTRATOR WIRE (D38 runtime-ignorance). The orchestrator
// passes only the opaque entrypoint_config_ref in VmSpec and never learns "terminal
// vs structured"; the mode is resolved HOST-SIDE — exactly where the launch argv is
// already resolved (the EntrypointProducer, when it lowers the opaque ref into the
// structured runtimev1.EntrypointConfig). The resolution order is: (1) the
// per-session hint in the opaque overlay body, if present and well-formed; else (2)
// the per-host default (the -session-mode flag → EntrypointFacts.DefaultMode); else
// (3) SessionModeStructured (the unchanged historical behavior — the additive
// default).
//
// D80-CLEAN: this type never crosses a tree boundary and is not on any wire. The
// argv strip is a host-side allow-list on a GENERIC runtimev1.LaunchSpec, NOT a CC
// adapter (D49: CC-isms live only in client/wrapper/adapters/claude-code/); the
// in-guest supervisor stays runtime-agnostic, reading a generic stdio disposition
// (PTY vs PIPES), never a CC-ism.

package libvirt

import (
	"fmt"
	"strings"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// SessionMode selects how the in-guest runtime is launched and how its I/O is
// carried to the writer. It is a HOST-AGENT-INTERNAL choice (never on the wire; the
// orchestrator stays runtime-ignorant, D38) resolved when the opaque
// entrypoint_config_ref is lowered into the structured EntrypointConfig.
type SessionMode int

const (
	// SessionModeStructured (the M0 default — the proto3-zero of this internal type)
	// launches the runtime HEADLESS (stream-json) and carries the attach.v1
	// SessionEvent stream — the current MVP. The writer endpoint is DIRECT (a framed
	// UDS) and LaunchSpec.stdio stays UNSPECIFIED (== PIPES), so a structured session
	// is byte-identical to today.
	SessionModeStructured SessionMode = iota
	// SessionModeTerminal launches the runtime under a PTY and carries raw terminal
	// bytes + resize to the writer (ssh/mosh-style). The writer endpoint is
	// RAW_TERMINAL, LaunchSpec.stdio is PTY, and the stream-json argv flags are
	// stripped (they only make sense for the headless structured driver).
	SessionModeTerminal
)

// String renders the canonical lowercase mode name (the -session-mode flag values
// and the persisted marker body). It is the inverse of ParseSessionMode.
func (m SessionMode) String() string {
	switch m {
	case SessionModeTerminal:
		return "terminal"
	default:
		// Any unknown / zero value renders as the structured default — the type is
		// host-internal and only ever holds the two defined values, so this is the
		// byte-identical historical path.
		return "structured"
	}
}

// ParseSessionMode resolves a flag/marker string to a SessionMode. The empty string
// resolves to the structured default (an unset -session-mode flag, or an absent
// per-session hint) so the historical path is byte-identical. An unrecognized,
// non-empty value is a configuration error surfaced loudly (never a silent default
// to structured — an operator who typed "termnial" must learn it, not get the
// headless path).
func ParseSessionMode(s string) (SessionMode, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "", "structured":
		return SessionModeStructured, nil
	case "terminal":
		return SessionModeTerminal, nil
	default:
		return SessionModeStructured, fmt.Errorf("unknown session mode %q (want \"structured\" or \"terminal\")", s)
	}
}

// DefaultInitialWindow is the pty window size seeded on launch when a terminal
// session's facts carry no explicit window (docs/serpent-cli-mvp/10-build-decisions
// §A7 / G9): a conventional 80x24 so CC paints at a sane geometry from frame 1 with
// no 80x24-then-reflow jump. Only meaningful for SessionModeTerminal; the structured
// path never sets an initial window.
var DefaultInitialWindow = TerminalWindow{Rows: 24, Cols: 80}

// DefaultTerminalTERM is the TERM value the terminal launch-mode injects into the
// LaunchSpec.env when the host facts carry no TERM of their own. Without it CC's
// supports-color resolves level 0 (MONOCHROME): TERM is never otherwise exported into
// the guest CC environment (the host-agent -launch-env list has no TERM, the entrypoint
// config does not add one, and vm/entrypoint's pty launcher execs cmd.Env verbatim), so
// the in-VM TUI renders without color (confirmed live 2026-06-18). applyLaunchMode's
// terminal branch appends `TERM=<this>` so the ALREADY-BAKED pty image picks it up with
// NO rebake (out → BuildEntrypointConfigBytes → config.pb → ds-entrypoint cmd.Env → CC).
//
// SINGLE-SOURCED to the U-IMAGE M0_PTY_TERM pin: this MUST stay equal to
// M0_PTY_TERM=xterm-256color in vm/m0-image/m0-image.env — that pin asserts the baked
// image actually carries this TERM's terminfo entry (/lib/terminfo/x/xterm-256color),
// so injecting a TERM the image does not carry would garble the TUI. A future TERM bump
// must move BOTH in lockstep (bump m0-image.env's M0_PTY_TERM AND this const together).
const DefaultTerminalTERM = "xterm-256color"

// DefaultTerminalCOLORTERM advertises 24-bit color to CC's color detection (a nicer
// truecolor palette than the 256-color terminfo floor). It is additive defence-in-depth
// alongside DefaultTerminalTERM and, like TERM, is only injected by the terminal launch
// mode when the host facts carry no COLORTERM of their own (host override wins).
const DefaultTerminalCOLORTERM = "truecolor"

// envKey returns the KEY of a `KEY=VALUE` env entry (the substring before the first
// `=`), or the whole string when there is no `=`. Used to test whether the facts' env
// already carries a given variable before the terminal launch mode injects a default,
// so a host-provided TERM/COLORTERM always wins over the injected default.
func envKey(entry string) string {
	if i := strings.IndexByte(entry, '='); i >= 0 {
		return entry[:i]
	}
	return entry
}

// envHasKey reports whether env already carries an entry for key (matched on the
// `KEY=` head). The terminal launch mode appends a default TERM/COLORTERM ONLY when the
// key is absent, so an explicit host-resolved value is never clobbered.
func envHasKey(env []string, key string) bool {
	for _, e := range env {
		if envKey(e) == key {
			return true
		}
	}
	return false
}

// TerminalWindow is the host-side plain-data pty window the producer seeds onto the
// LaunchSpec.initial_window field (runtimev1.TerminalSize). Carried on
// EntrypointFacts so a host can override the launch geometry; a zero value (both
// rows and cols 0) means "unset — use DefaultInitialWindow for a terminal session".
type TerminalWindow struct {
	// Rows is the pty window height in character rows (TIOCSWINSZ ws_row).
	Rows uint32
	// Cols is the pty window width in character columns (TIOCSWINSZ ws_col).
	Cols uint32
}

// isZero reports whether the window is unset (both dimensions zero) — the signal to
// fall back to DefaultInitialWindow rather than seed a literal 0x0 window (which a
// pty would treat as "no size", defeating the seed-on-launch goal).
func (w TerminalWindow) isZero() bool { return w.Rows == 0 && w.Cols == 0 }

// streamJSONStripFlags is the allow-list of headless-only argv flags the terminal
// launch-mode strips from the resolved LaunchSpec.Args. They are the
// `--input-format/--output-format stream-json --verbose --permission-prompt-tool`
// surface that only makes sense for the structured headless driver (doc 04 §2.4); a
// PTY runtime running CC's native interactive TUI must not carry them, or CC starts
// headless under a pty and renders garbled. Each entry is matched as a whole token;
// a flag taking a value (e.g. `--output-format stream-json`) also drops the value
// token that follows it (recorded in streamJSONValueFlags).
var streamJSONStripFlags = map[string]bool{
	"--input-format":           true,
	"--output-format":          true,
	"--verbose":                true,
	"--permission-prompt-tool": true,
	// --no-session-persistence is a --print/headless-ONLY flag: CC rejects it in
	// interactive mode ("--no-session-persistence can only be used with --print mode"),
	// so the PTY/terminal launch-mode must strip it too (live-found 2026-06-18). Bare
	// boolean — not in streamJSONValueFlags.
	"--no-session-persistence": true,
	// --include-partial-messages is the live-text (typing-delta) opt-in for the
	// HEADLESS stream-json driver only: it tells CC to emit stream_event records the
	// structured adapter projects as render-only ChatDeltas (the U-PARTIALS-ARM
	// runtime-arming half; doc serpent-cli-mvp/06 Layer 1, D145). It only makes sense
	// alongside --output-format stream-json, so a PTY/terminal launch (the native
	// interactive TUI) must strip it too — a session a per-session overlay hint flips to
	// terminal must NEVER carry it. Bare boolean — not in streamJSONValueFlags. Listing
	// it here makes the terminal-mode strip drop a live-text flag that armStructuredLiveText
	// baked into the host launch argv, so the flag is NEVER present for SessionModeTerminal.
	includePartialMessagesFlag: true,
}

// streamJSONValueFlags are the subset of the stripped flags that take a following
// value token (so the strip drops BOTH the flag and its value). `--verbose` is a
// bare boolean and is NOT here (only the flag token is dropped). This is a
// conservative, documented allow-list — it removes ONLY the known headless flags and
// leaves any other argv (e.g. a working dir, a model selector) untouched.
var streamJSONValueFlags = map[string]bool{
	"--input-format":           true,
	"--output-format":          true,
	"--permission-prompt-tool": true,
}

// includePartialMessagesFlag is the Claude Code headless launch flag that turns ON
// live-streaming text: with it on, CC emits stream_event records (the typing deltas)
// the structured adapter projects as render-only attach.ChatDeltas (claudecode
// WithPartials; doc serpent-cli-mvp/06 Layer 1, D145). It is a CC-ism — it lives in
// this host-side stream-json launch-argv shaping (sessionmode.go already owns the
// stream-json CC flags), NEVER on the orchestrator wire (D38 runtime-ignorance).
const includePartialMessagesFlag = "--include-partial-messages"

// ArmStructuredLiveText returns a copy of the STRUCTURED launch argv with the live-text
// flag (--include-partial-messages) appended when liveText is true — the runtime-arming
// half of the live-text path (U-PARTIALS-ARM). It is the SINGLE place the host decides to
// turn typing deltas on for the headless stream-json driver, called by the daemon
// composition root (cmd/host-agent) when it lifts its config into EntrypointFacts.Launch:
//
//   - liveText=false (the DEFAULT): the args are returned UNCHANGED (a defensive copy),
//     so the structured launch argv is BYTE-IDENTICAL to today (the live-text-off invariant).
//   - liveText=true: --include-partial-messages is appended ONCE (idempotent — an argv that
//     already carries the flag is left unchanged, never duplicated).
//
// It is keyed on the host live-text gate ONLY, not the session mode: a session a
// per-session overlay hint resolves to SessionModeTerminal has this flag STRIPPED by the
// terminal launch-mode transform (stripStreamJSONArgs lists includePartialMessagesFlag),
// so the flag is NEVER present in a terminal (PTY) argv. The structured launch-mode path
// (applyLaunchMode's default branch) returns the argv unchanged, so a flag this function
// armed survives only for a structured session — exactly the resolved-mode contract.
//
// The flag is a bare boolean (no value token), so appending it composes cleanly with
// stripStreamJSONArgs (which drops it whole on the terminal path). Pure: the input slice
// is never mutated.
func ArmStructuredLiveText(args []string, liveText bool) []string {
	if !liveText {
		// Byte-identical default: return the args verbatim (a copy so the caller's slice
		// is never aliased into the produced config — the same copy-in posture
		// BuildEntrypointConfig takes for every field).
		return append([]string(nil), args...)
	}
	out := append([]string(nil), args...)
	for _, a := range out {
		if a == includePartialMessagesFlag {
			// Already armed (idempotent) — never append a duplicate.
			return out
		}
	}
	return append(out, includePartialMessagesFlag)
}

// stripStreamJSONArgs returns a copy of args with the headless-only stream-json
// flags (and their value tokens) removed — the terminal launch-mode argv transform
// (doc 04 §2.4). It is a pure function on the slice (the input is never mutated): for
// each token, a flag in streamJSONStripFlags is dropped, and if it is also in
// streamJSONValueFlags the IMMEDIATELY-FOLLOWING token (its value) is dropped too. A
// flag written as `--output-format=stream-json` (single `=`-joined token) is matched
// on its `--flag` prefix and dropped whole. Any non-matching token is preserved in
// order, so a structured argv passed through this transform with no stream-json flags
// is returned UNCHANGED (the byte-identical guarantee, asserted by the unit test).
func stripStreamJSONArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, 0, len(args))
	skipNext := false
	for _, a := range args {
		if skipNext {
			// This token is the value of a value-taking flag dropped on the prior
			// iteration — drop it and clear the skip.
			skipNext = false
			continue
		}
		// Match a `--flag=value` token on its flag head, and a bare `--flag` token whole.
		flag := a
		joined := false
		if i := strings.IndexByte(a, '='); i >= 0 {
			flag = a[:i]
			joined = true
		}
		if streamJSONStripFlags[flag] {
			// Drop the flag token. If it takes a value AND the value was a SEPARATE
			// following token (not `=`-joined into this one), drop that next token too.
			if streamJSONValueFlags[flag] && !joined {
				skipNext = true
			}
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sessionModeHintKey is the host-private sentinel the EntrypointProducer looks for in
// the OPAQUE overlay body to carry a per-session mode hint (doc 04 §2.2 carrier (A)).
// The orchestrator never writes or inspects it — it is host-resolved, so reading it
// keeps the orchestrator runtime-IGNORANT (D38). A host that drops `DS_SESSION_MODE=
// terminal` into the per-session overlay overrides the per-host default for that one
// session; an overlay with no such token uses the host default.
const sessionModeHintKey = "DS_SESSION_MODE="

// sessionModeHintFromOverlay extracts the per-session mode hint VALUE from the opaque
// overlay bytes, if present. It scans for the host-private `DS_SESSION_MODE=` sentinel
// and returns the token that follows it (up to the next whitespace / newline / NUL),
// found=true. An overlay with no sentinel returns found=false (the normal case — the
// host default applies). The overlay may be arbitrary bytes (a binary blob, a content-
// addressed ref): a missing sentinel is simply "no hint", never an error. The returned
// value is passed to ParseSessionMode, which fail-louds on a malformed value — so a
// present-but-garbage hint is surfaced, an absent hint falls through cleanly.
func sessionModeHintFromOverlay(overlay []byte) (value string, found bool) {
	if len(overlay) == 0 {
		return "", false
	}
	idx := strings.Index(string(overlay), sessionModeHintKey)
	if idx < 0 {
		return "", false
	}
	rest := string(overlay[idx+len(sessionModeHintKey):])
	// The value runs to the first delimiter (whitespace / newline / NUL / the next
	// token). An empty value (sentinel followed immediately by a delimiter) is a
	// PRESENT-but-empty hint — ParseSessionMode resolves "" to structured, so a bare
	// `DS_SESSION_MODE=` is the explicit structured default, not a malformed value.
	end := strings.IndexFunc(rest, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == 0
	})
	if end >= 0 {
		rest = rest[:end]
	}
	return rest, true
}

// applyLaunchMode folds the resolved SessionMode into the LaunchSpecInput the
// EntrypointProducer is about to assemble: it is the SINGLE place the mode shapes the
// launch surface, so the persisted mode, the LaunchSpec.stdio, the argv, and (later,
// U-HOST-SERVE) the minted endpoint transport all derive from one resolution.
//
//   - SessionModeStructured: the input is returned UNCHANGED (a defensive copy of the
//     Args slice) and stdio stays UNSPECIFIED with no initial window — byte-identical
//     to today (the structured default).
//   - SessionModeTerminal: the stream-json argv flags are stripped (stripStreamJSONArgs),
//     stdio is set to PTY, the initial window is seeded (the facts' window, or
//     DefaultInitialWindow when the facts carry none) so CC paints at the right
//     geometry from frame 1 (§A7 / G9), AND TERM=DefaultTerminalTERM (plus
//     COLORTERM=DefaultTerminalCOLORTERM) is appended to out.Env when the facts env does
//     not already carry one — so the in-VM CC resolves a color-capable terminal instead
//     of MONOCHROME (host override wins; a facts-supplied TERM/COLORTERM is never
//     clobbered). The structured branch NEVER touches Env (the byte-identical guard).
//
// It returns the (possibly transformed) launch input plus the resolved stdio
// disposition and initial-window proto the builder stamps onto the LaunchSpec. window
// is the per-host facts window (TerminalWindow; zero == use the default for a terminal
// session, ignored for structured).
func applyLaunchMode(in LaunchSpecInput, mode SessionMode, window TerminalWindow) (out LaunchSpecInput, stdio runtimev1.StdioDisposition, initialWindow *runtimev1.TerminalSize) {
	// Always defensively copy the Args so neither the caller's slice nor the facts'
	// slice is aliased into the produced config (the same posture BuildEntrypointConfig
	// already takes for every field).
	out = in
	out.Args = append([]string(nil), in.Args...)

	if mode != SessionModeTerminal {
		// Structured (the default): no transform, no stdio, no window — the historical
		// byte-identical path.
		return out, runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED, nil
	}

	// Terminal: strip the headless stream-json argv, select PTY stdio, inject the
	// color-capable TERM/COLORTERM when the facts carry none, and seed the launch
	// window so the pty is sized before the agent's first paint.
	out.Args = stripStreamJSONArgs(out.Args)
	// Defensively copy Env before appending so the caller's / facts' slice is never
	// aliased into (and mutated by) the produced config — the same copy-in posture the
	// Args take. The structured branch above returns before this point and never copies
	// Env, preserving its byte-identical guarantee (it does not touch Env at all).
	out.Env = append([]string(nil), in.Env...)
	if !envHasKey(out.Env, "TERM") {
		out.Env = append(out.Env, "TERM="+DefaultTerminalTERM)
	}
	if !envHasKey(out.Env, "COLORTERM") {
		out.Env = append(out.Env, "COLORTERM="+DefaultTerminalCOLORTERM)
	}
	w := window
	if w.isZero() {
		w = DefaultInitialWindow
	}
	return out, runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY, &runtimev1.TerminalSize{Rows: w.Rows, Cols: w.Cols}
}
