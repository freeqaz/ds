// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// rawHandle builds an Attach handle carrying a RAW_TERMINAL endpoint (the U-PROTO
// tag) with the given role.
func rawHandle(role attachv1.Role) *attachv1.AttachHandle {
	return &attachv1.AttachHandle{
		SessionUuid: "s",
		Role:        role,
		Auth:        &attachv1.AuthMaterial{Token: []byte("t")},
		Endpoints: []*attachv1.EndpointCandidate{
			{Transport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL, Address: "/run/ds/sess.sock"},
		},
	}
}

// directOnlyHandle builds an Attach handle carrying ONLY a DIRECT endpoint (the
// structured path; no raw tag) — the land-dark default a real session ships today.
func directOnlyHandle(role attachv1.Role) *attachv1.AttachHandle {
	return &attachv1.AttachHandle{
		SessionUuid: "s",
		Role:        role,
		Auth:        &attachv1.AuthMaterial{Token: []byte("t")},
		Endpoints: []*attachv1.EndpointCandidate{
			{Transport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT, Address: "/run/ds/sess.sock"},
		},
	}
}

// TestTransportFromProtoRawTerminal: the frozen RAW_TERMINAL enum maps to the
// local TransportRawTerminal tag (so the candidate list is faithful), distinct
// from the DIRECT→Unix and RELAY→Relay mappings.
func TestTransportFromProtoRawTerminal(t *testing.T) {
	cases := []struct {
		in   attachv1.EndpointTransport
		want hostbridge.EndpointTransport
	}{
		{attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL, hostbridge.TransportRawTerminal},
		{attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT, hostbridge.TransportUnix},
		{attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RELAY, hostbridge.TransportRelay},
		{attachv1.EndpointTransport_ENDPOINT_TRANSPORT_UNSPECIFIED, hostbridge.TransportUnix},
	}
	for _, c := range cases {
		if got := transportFromProto(c.in); got != c.want {
			t.Errorf("transportFromProto(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRawEndpointPresent: a handle carrying a RAW_TERMINAL endpoint resolves to a
// dialable terminal handle (a TransportUnix candidate at the raw endpoint's
// address, so DialTerminal's unixEndpoint finds it) with the identity carried.
func TestRawEndpointPresent(t *testing.T) {
	local, ok := rawEndpoint(rawHandle(attachv1.Role_ROLE_WRITER))
	if !ok {
		t.Fatal("a handle with a RAW_TERMINAL endpoint should resolve a raw dial handle")
	}
	if len(local.Endpoints) != 1 || local.Endpoints[0].Transport != hostbridge.TransportUnix {
		t.Errorf("raw dial handle endpoint = %+v, want a single TransportUnix candidate", local.Endpoints)
	}
	if local.Endpoints[0].Address != "/run/ds/sess.sock" {
		t.Errorf("raw endpoint address not carried: %+v", local.Endpoints[0])
	}
	if local.SessionUUID != "s" || local.Auth.Token != "t" || local.Role != hostbridge.RoleWriter {
		t.Errorf("raw dial handle identity wrong: %+v", local)
	}
}

// TestRawEndpointAbsent: a direct-only handle (the land-dark default) has NO raw
// endpoint — rawEndpoint returns false, so the client stays structured. This is
// the no-op-by-default proof: until the orchestrator mints the tag, raw is dark.
func TestRawEndpointAbsent(t *testing.T) {
	if _, ok := rawEndpoint(directOnlyHandle(attachv1.Role_ROLE_WRITER)); ok {
		t.Error("a direct-only handle must NOT resolve a raw endpoint (land-dark default)")
	}
	// An empty address on a raw tag is also not dialable (capability not real).
	h := rawHandle(attachv1.Role_ROLE_WRITER)
	h.Endpoints[0].Address = ""
	if _, ok := rawEndpoint(h); ok {
		t.Error("a RAW_TERMINAL endpoint with an empty address must NOT be dialable")
	}
}

// TestSelectModeTable crosses {raw endpoint y/n} x {WRITER/READER} x {TTY y/n} x
// {--raw auto/on/off} and asserts raw is chosen ONLY when (endpoint AND WRITER AND
// TTY-on-both AND not --raw=off). The "no raw endpoint ⇒ structured" rows are the
// pinned no-op-by-default proof (docs/serpent-cli-mvp/03 §6.3).
func TestSelectModeTable(t *testing.T) {
	W, R := attachv1.Role_ROLE_WRITER, attachv1.Role_ROLE_READER
	cases := []struct {
		name          string
		hasRaw        bool
		role          attachv1.Role
		pref          rawPref
		inTTY, outTTY bool
		want          attachMode
	}{
		// The happy path: raw endpoint + writer + TTY + auto/on → raw.
		{"auto raw writer tty", true, W, rawAuto, true, true, modeRaw},
		{"on raw writer tty", true, W, rawOn, true, true, modeRaw},

		// --raw=off is an absolute override → always structured.
		{"off forces structured", true, W, rawOff, true, true, modeStructured},

		// No raw endpoint → structured regardless of everything else (the no-op
		// default proof: this is every handle until the tag is minted).
		{"no endpoint auto writer tty", false, W, rawAuto, true, true, modeStructured},
		{"no endpoint on writer tty", false, W, rawOn, true, true, modeStructured},

		// Reader → structured (raw is meaningless reader-only; MVP is writer-only).
		{"raw reader tty", true, R, rawAuto, true, true, modeStructured},
		{"raw reader on tty", true, R, rawOn, true, true, modeStructured},

		// Non-TTY → structured even with --raw=on (raw on a pipe/CI cannot work).
		{"raw writer no-in-tty auto", true, W, rawAuto, false, true, modeStructured},
		{"raw writer no-out-tty auto", true, W, rawAuto, true, false, modeStructured},
		{"raw writer no-tty on", true, W, rawOn, false, false, modeStructured},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h *attachv1.AttachHandle
			if c.hasRaw {
				h = rawHandle(c.role)
			} else {
				h = directOnlyHandle(c.role)
			}
			if got := selectMode(h, c.pref, c.inTTY, c.outTTY); got != c.want {
				t.Errorf("selectMode(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestParseRawPref maps the --raw flag string forms.
func TestParseRawPref(t *testing.T) {
	cases := map[string]rawPref{
		"auto": rawAuto, "": rawAuto, "garbage": rawAuto,
		"on": rawOn, "true": rawOn, "1": rawOn, "yes": rawOn,
		"off": rawOff, "false": rawOff, "0": rawOff, "no": rawOff,
	}
	for in, want := range cases {
		if got := parseRawPref(in); got != want {
			t.Errorf("parseRawPref(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestParseDetachKey maps the --detach-key forms onto a single escape byte; an
// empty/garbage value yields 0 (→ DefaultDetachKey downstream).
func TestParseDetachKey(t *testing.T) {
	cases := map[string]byte{
		"ctrl-]": 0x1d, // the default escape, Ctrl-]
		"CTRL-]": 0x1d,
		"^]":     0x1d,
		"ctrl-c": 0x03, // Ctrl-C
		"ctrl-C": 0x03,
		"^c":     0x03,
		"^^":     0x1e, // Ctrl-^
		"x":      'x',  // a literal single char
		"":       0,    // → DefaultDetachKey
		"ctrl-":  0,    // malformed → default
		"abc":    0,    // multi-char non-ctrl → default
	}
	for in, want := range cases {
		if got := parseDetachKey(in); got != want {
			t.Errorf("parseDetachKey(%q) = %#x, want %#x", in, got, want)
		}
	}
}

// TestRawOptionsRuntime: the resolved options thread the detach key + alt-screen
// into the rawterm.Options the loop takes.
func TestRawOptionsRuntime(t *testing.T) {
	o := rawOptions{pref: rawOn, detachKey: 0x1d, noAltScreen: true}
	rt := o.runtime()
	if rt.DetachKey != 0x1d {
		t.Errorf("runtime DetachKey = %#x, want 0x1d", rt.DetachKey)
	}
	if !rt.NoAltScreen {
		t.Error("runtime NoAltScreen should be true")
	}
}

// TestIsTTYNonFile: a non-*os.File (the test's discard/reader, the scripted-prompt
// path) is never a TTY → the structured fallback. This is what keeps CI + the
// scripted verification path on the structured loop, unperturbed by raw mode.
func TestIsTTYNonFile(t *testing.T) {
	if isTTY(nil) {
		t.Error("nil should not be a TTY")
	}
	type notAFile struct{}
	if isTTY(notAFile{}) {
		t.Error("a non-*os.File should not be a TTY")
	}
}
