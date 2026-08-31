// SPDX-License-Identifier: Apache-2.0

package libvirt

// modeagreement_test.go is the U-HOST-SERVE THREE-WAY MODE-AGREEMENT test (the doc 04
// §5 drift guard, §6 "A three-way mode-agreement test"): a session's RESOLVED mode is
// persisted ONCE (SessionModeStore), and the three host facets that consume it —
//
//	(1) the IssueAttachHandle minter's endpoint TRANSPORT TAG (DIRECT vs RAW_TERMINAL),
//	(2) the serving child's --mode flag (structured ⇒ none; terminal ⇒ `--mode terminal`),
//	(3) the in-guest LaunchSpec.stdio disposition (PIPES/UNSPECIFIED vs PTY),
//
// — all derive from THAT ONE resolution off SessionModeStore.ModeFor, so they cannot
// disagree (a terminal session can never get a DIRECT handle, a structured child, or a
// PIPES stdio). The serving-child --mode half lives in the hostagent package
// (servingChildArgs); here we pin the CANONICAL mode→flag mapping the bridge applies and
// assert the transport-tag + stdio halves directly from the store, so the agreement is
// proven end-to-end across the single resolution.

import (
	"context"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// servingChildModeFlag is the CANONICAL mode→serving-child-flag mapping the host-agent
// AttachBridge applies (hostagent.servingChildArgs): a STRUCTURED session passes NO
// --mode flag (the child defaults to structured), a TERMINAL session passes
// `--mode terminal`. Pinned here so the agreement test asserts the flag half against the
// SAME single resolution; the hostagent package's servingChildArgs tests prove the
// argv-render actually applies this mapping.
func servingChildModeFlag(mode SessionMode) (flag string, present bool) {
	if mode == SessionModeTerminal {
		return "terminal", true
	}
	return "", false
}

// TestThreeWayModeAgreement drives one persisted resolution through all three host
// facets and asserts they agree for BOTH modes.
func TestThreeWayModeAgreement(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	minter, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: dir})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	ctx := context.Background()

	cases := []struct {
		name          string
		mode          SessionMode
		wantTransport attachv1.EndpointTransport
		wantStdio     runtimev1.StdioDisposition
		wantModeFlag  string // the serving-child --mode token; "" ⇒ no flag
		wantFlag      bool
	}{
		{
			name:          "structured",
			mode:          SessionModeStructured,
			wantTransport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT,
			wantStdio:     runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED,
			wantModeFlag:  "",
			wantFlag:      false,
		},
		{
			name:          "terminal",
			mode:          SessionModeTerminal,
			wantTransport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL,
			wantStdio:     runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY,
			wantModeFlag:  "terminal",
			wantFlag:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := "sess-" + tc.name
			// One resolution, persisted ONCE (the producer's PutMode).
			if err := store.PutMode(ctx, sess, tc.mode); err != nil {
				t.Fatalf("PutMode: %v", err)
			}

			// (0) The single source reads back the SAME mode.
			got, found, err := store.ModeFor(ctx, sess)
			if err != nil || !found || got != tc.mode {
				t.Fatalf("ModeFor = (%v, %v, %v), want (%v, true, nil)", got, found, err, tc.mode)
			}

			// (1) The handle transport tag derives from it (the minter reads the SAME store
			// under the SAME OverlayDir).
			h, err := minter.MintAttachHandle(ctx, sess, attachBinding(), attachv1.Role_ROLE_WRITER)
			if err != nil {
				t.Fatalf("MintAttachHandle: %v", err)
			}
			if gotT := h.GetEndpoints()[0].GetTransport(); gotT != tc.wantTransport {
				t.Errorf("handle transport = %v, want %v (must agree with the resolved mode)", gotT, tc.wantTransport)
			}

			// (2) The serving child's --mode derives from it (the canonical mapping the
			// AttachBridge applies).
			flag, present := servingChildModeFlag(got)
			if present != tc.wantFlag || flag != tc.wantModeFlag {
				t.Errorf("serving-child --mode = (%q, present=%v), want (%q, %v)", flag, present, tc.wantModeFlag, tc.wantFlag)
			}

			// (3) The in-guest LaunchSpec.stdio derives from it (the producer's
			// applyLaunchMode lowers the SAME resolution onto the LaunchSpec).
			_, stdio, window := applyLaunchMode(LaunchSpecInput{Command: "/usr/bin/claude"}, got, TerminalWindow{})
			if stdio != tc.wantStdio {
				t.Errorf("LaunchSpec.stdio = %v, want %v (must agree with the resolved mode)", stdio, tc.wantStdio)
			}
			// A terminal session also seeds an initial window; a structured one never does
			// (belt-and-suspenders the stdio agreement).
			if tc.mode == SessionModeTerminal && window == nil {
				t.Error("terminal LaunchSpec missing the seeded initial window")
			}
			if tc.mode == SessionModeStructured && window != nil {
				t.Errorf("structured LaunchSpec seeded a window %v, want none", window)
			}
		})
	}
}
