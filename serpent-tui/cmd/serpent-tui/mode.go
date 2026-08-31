// SPDX-License-Identifier: Apache-2.0
//
// mode.go — the raw-vs-structured writer-surface decision for serpent claude
// --vm (docs/serpent-cli-mvp/03 §2.2, 10-build-decisions §A3). It is DARK by
// default: rawEndpoint returns (_, false) for every handle until the orchestrator
// mints an ENDPOINT_TRANSPORT_RAW_TERMINAL endpoint (the U-PROTO rider tag), so
// every attach stays structured and this code is a pure no-op — the safe,
// independently-landable ordering (the client lands BEFORE the endpoint appears).

package main

import (
	"flag"
	"os"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/rawterm"
)

// attachMode is the writer surface selectMode picks. modeStructured is today's
// bubbletea folded-delta REPL (the default, unchanged); modeRaw is the termios
// raw-pty passthrough (rawterm.Run) — the dev's terminal IS the in-VM CC.
type attachMode int

const (
	modeStructured attachMode = iota
	modeRaw
)

// rawPref is the --raw operator preference (auto|on|off, §2.8). auto: raw iff a
// raw endpoint is offered AND stdin/stdout are a TTY. on: prefer raw (still
// TTY-guarded — raw on a non-TTY cannot work, so it falls back with a log line).
// off: always the structured REPL.
type rawPref int

const (
	rawAuto rawPref = iota
	rawOn
	rawOff
)

// parseRawPref maps the --raw flag string to a rawPref. An unrecognized value
// defaults to auto (the safe, behavior-unchanged default) rather than erroring —
// a typo never wedges the attach, it just keeps today's surface.
func parseRawPref(s string) rawPref {
	switch s {
	case "on", "true", "1", "yes":
		return rawOn
	case "off", "false", "0", "no":
		return rawOff
	default:
		return rawAuto
	}
}

// rawEndpoint scans the handle for an ENDPOINT_TRANSPORT_RAW_TERMINAL candidate
// (the U-PROTO additive tag) with a non-empty address — the capability signal
// that the session serves the in-VM CC pty byte duplex. Returns the local
// hostbridge handle to dial via SocketTransport.DialTerminal and whether a raw
// endpoint is present. The raw endpoint's address is the per-session attach UDS
// (the same framed-UDS carrier TransportUnix realizes), so it is mapped onto a
// TransportUnix candidate that DialTerminal's unixEndpoint resolves.
//
// false ⇒ no raw endpoint ⇒ selectMode keeps the structured surface. Until the
// orchestrator mints the tag, this ALWAYS returns false (the land-dark default).
func rawEndpoint(h *attachv1.AttachHandle) (hostbridge.AttachHandle, bool) {
	var addr string
	for _, ep := range h.GetEndpoints() {
		if ep.GetTransport() == attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL && ep.GetAddress() != "" {
			addr = ep.GetAddress()
			break
		}
	}
	if addr == "" {
		return hostbridge.AttachHandle{}, false
	}
	// Build the terminal-dial handle: the raw endpoint's address is the framed-UDS
	// carrier DialTerminal dials (it resolves a TransportUnix candidate). Carry the
	// handle's identity (uuid/auth/role/expiry) verbatim so the server validates it
	// identically to the structured path.
	local := hostbridge.AttachHandle{
		SessionUUID: h.GetSessionUuid(),
		Auth:        hostbridge.AuthMaterial{Token: string(h.GetAuth().GetToken())},
		Role:        roleFromProto(h.GetRole()),
		ExpiresAt:   expiresAt(h.GetExpiresAt()),
		Endpoints: []hostbridge.EndpointCandidate{
			{Transport: hostbridge.TransportUnix, Address: addr},
		},
	}
	return local, true
}

// selectMode picks the writer surface (docs/serpent-cli-mvp/03 §2.2). Raw
// requires ALL of: a raw endpoint on the handle, the WRITER seat (raw passthrough
// is meaningless reader-only — the MVP is writer-only, a terminal reader is
// rejected at DialTerminal), and (unless forced AND still a TTY) a real TTY on
// both stdin and stdout. --raw=off forces structured; --raw=on prefers raw but is
// STILL TTY-guarded (raw on a non-TTY cannot work). Everything else is structured
// — including, by construction, every handle until the raw tag is minted.
func selectMode(h *attachv1.AttachHandle, pref rawPref, inTTY, outTTY bool) attachMode {
	if pref == rawOff {
		return modeStructured
	}
	_, hasRaw := rawEndpoint(h)
	writer := h.GetRole() == attachv1.Role_ROLE_WRITER
	if !hasRaw || !writer {
		return modeStructured
	}
	// rawOn and rawAuto both require a TTY (raw on a pipe/CI is garbage). The only
	// difference is messaging upstream (rawOn logs a fall-back line on a non-TTY);
	// the decision is identical.
	if inTTY && outTTY {
		return modeRaw
	}
	return modeStructured
}

// --- the --raw / --detach-key / --no-alt-screen flags (§2.8) -----------------

// rawFlags are the raw bindings registered on a flagset; resolve() collapses them
// to a rawOptions after parse. Held as pointers so registerRawFlags can be called
// before fs.Parse (the flag.FlagSet idiom).
type rawFlags struct {
	raw         *string
	detachKey   *string
	noAltScreen *bool
}

// registerRawFlags adds --raw / --detach-key / --no-alt-screen to fs (the attach
// and up flagsets). They are optional and DARK by default: --raw defaults to auto,
// and auto only goes raw when the handle carries a raw endpoint (which no handle
// does until the orchestrator mints the tag) — so registering them changes no
// behavior until the contract bit lights up.
func registerRawFlags(fs *flag.FlagSet) rawFlags {
	return rawFlags{
		raw:         fs.String("raw", "auto", "raw-terminal writer surface: auto (raw iff offered + TTY) | on (prefer raw) | off (always structured)"),
		detachKey:   fs.String("detach-key", "ctrl-]", "local escape that detaches without killing CC (e.g. ctrl-], ctrl-^, or a single char)"),
		noAltScreen: fs.Bool("no-alt-screen", false, "stay on the main screen buffer in raw mode (no alt-screen) — for scrollback-keeping / dumb terminals"),
	}
}

// rawOptions is the resolved raw configuration threaded into attachSession.
type rawOptions struct {
	pref        rawPref
	detachKey   byte
	noAltScreen bool
}

// resolve collapses the parsed flags into a rawOptions.
func (f rawFlags) resolve() rawOptions {
	return rawOptions{
		pref:        parseRawPref(*f.raw),
		detachKey:   parseDetachKey(*f.detachKey),
		noAltScreen: *f.noAltScreen,
	}
}

// runtime maps the resolved options onto the rawterm.Options the raw loop takes.
func (o rawOptions) runtime() rawterm.Options {
	return rawterm.Options{
		DetachKey:   o.detachKey,
		NoAltScreen: o.noAltScreen,
	}
}

// parseDetachKey maps the --detach-key flag string to a single escape byte. It
// accepts: a "ctrl-X" / "^X" form (the control byte for X, e.g. ctrl-] = 0x1d), or
// a single literal character. An empty/unrecognized value yields 0, which
// rawterm.Run reads as "use DefaultDetachKey (Ctrl-])" — a typo never disables the
// detach, it falls back to the documented default.
func parseDetachKey(s string) byte {
	switch {
	case s == "":
		return 0 // → DefaultDetachKey downstream
	case len(s) >= 6 && (s[:5] == "ctrl-" || s[:5] == "CTRL-"):
		return controlByte(s[5])
	case len(s) == 2 && s[0] == '^':
		return controlByte(s[1])
	case len(s) == 1:
		return s[0]
	default:
		return 0 // → DefaultDetachKey
	}
}

// controlByte maps a printable key to its control byte: Ctrl-@ = 0x00 … Ctrl-_ =
// 0x1f, the standard ASCII control mapping (uppercase the letter, mask the high
// bits). ']' → 0x1d (Ctrl-]), '^' → 0x1e, 'C' → 0x03, etc.
func controlByte(k byte) byte {
	if k >= 'a' && k <= 'z' {
		k -= 'a' - 'A' // uppercase
	}
	return k & 0x1f
}

// isTTY reports whether r is a real terminal (a *os.File whose fd is a tty). The
// raw surface requires a TTY on both stdin and stdout (term.MakeRaw on a pipe is
// garbage); a non-TTY (a pipe, CI, the scripted-prompt path) falls back to the
// structured loop (docs/serpent-cli-mvp/03 §2.2). A non-*os.File (the test's
// strings.Reader / io.Discard) is never a TTY.
func isTTY(r any) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return rawterm.IsTTY(f.Fd())
}
