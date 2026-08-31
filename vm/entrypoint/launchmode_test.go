// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"testing"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// TestStdioFromProto pins the disposition projection: ONLY an explicit PTY maps to
// stdioPTY; PIPES, UNSPECIFIED, and any unknown enum all map to stdioPipes (the
// historical zero value), so a pre-rider config keeps the byte-identical pipes path.
func TestStdioFromProto(t *testing.T) {
	cases := []struct {
		name string
		in   runtimev1.StdioDisposition
		want stdioDisposition
	}{
		{"pty", runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY, stdioPTY},
		{"pipes", runtimev1.StdioDisposition_STDIO_DISPOSITION_PIPES, stdioPipes},
		{"unspecified", runtimev1.StdioDisposition_STDIO_DISPOSITION_UNSPECIFIED, stdioPipes},
		{"unknown", runtimev1.StdioDisposition(99), stdioPipes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stdioFromProto(c.in); got != c.want {
				t.Errorf("stdioFromProto(%v) = %v; want %v", c.in, got, c.want)
			}
		})
	}
}

// TestWinsizeFromProto pins the TerminalSize projection: nil => the zero winsize
// (defaulted to 80x24 only at use), set values pass through as uint16, and a value
// above the uint16 max saturates (never wraps).
func TestWinsizeFromProto(t *testing.T) {
	if got := winsizeFromProto(nil); got != (winsize{}) {
		t.Errorf("winsizeFromProto(nil) = %+v; want zero winsize (defaulted only at use)", got)
	}

	if got := winsizeFromProto(&runtimev1.TerminalSize{Cols: 120, Rows: 40}); got != (winsize{cols: 120, rows: 40}) {
		t.Errorf("winsizeFromProto(120x40) = %+v; want {cols:120 rows:40}", got)
	}

	// A zero on one axis is carried as zero here (resolved() fills it at use).
	if got := winsizeFromProto(&runtimev1.TerminalSize{Cols: 0, Rows: 50}); got != (winsize{cols: 0, rows: 50}) {
		t.Errorf("winsizeFromProto(0x50) = %+v; want {cols:0 rows:50}", got)
	}

	// Saturation: a proto uint32 above the uint16 max clamps to the max, not a wrap.
	const maxU16 = uint16(^uint16(0))
	if got := winsizeFromProto(&runtimev1.TerminalSize{Cols: 70000, Rows: 80000}); got != (winsize{cols: maxU16, rows: maxU16}) {
		t.Errorf("winsizeFromProto(70000x80000) = %+v; want both saturated to %d", got, maxU16)
	}
}

// TestWinsizeResolvedDefaults pins the at-use default: a zero axis becomes 80x24,
// never a literal 0x0; a fully-set winsize is unchanged.
func TestWinsizeResolvedDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   winsize
		want winsize
	}{
		{"both-zero", winsize{}, winsize{cols: defaultWinsizeCols, rows: defaultWinsizeRows}},
		{"zero-cols", winsize{cols: 0, rows: 50}, winsize{cols: defaultWinsizeCols, rows: 50}},
		{"zero-rows", winsize{cols: 120, rows: 0}, winsize{cols: 120, rows: defaultWinsizeRows}},
		{"both-set", winsize{cols: 120, rows: 40}, winsize{cols: 120, rows: 40}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.resolved(); got != c.want {
				t.Errorf("%+v.resolved() = %+v; want %+v", c.in, got, c.want)
			}
		})
	}
	// Sanity: the defaults are exactly 80x24.
	if defaultWinsizeCols != 80 || defaultWinsizeRows != 24 {
		t.Errorf("default winsize = %dx%d; want 80x24", defaultWinsizeCols, defaultWinsizeRows)
	}
}

// TestFromProto_StdioAndWinsize proves the full launch-surface projection through
// the proto-bound fromProto: a PTY config with an initial_window lands on
// launchSpec.{stdio,initialWinsize}, and an absent launch mode defaults to pipes
// (the byte-identical historical path).
func TestFromProto_StdioAndWinsize(t *testing.T) {
	pb := validProto()
	pb.Launch.Stdio = runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY
	pb.Launch.InitialWindow = &runtimev1.TerminalSize{Cols: 132, Rows: 43}

	cfg, err := fromProto(pb)
	if err != nil {
		t.Fatalf("fromProto: %v", err)
	}
	if cfg.launch.stdio != stdioPTY {
		t.Errorf("cfg.launch.stdio = %v; want stdioPTY", cfg.launch.stdio)
	}
	if cfg.launch.initialWinsize != (winsize{cols: 132, rows: 43}) {
		t.Errorf("cfg.launch.initialWinsize = %+v; want {cols:132 rows:43}", cfg.launch.initialWinsize)
	}

	// Absent launch mode (the rider fields unset) defaults to pipes + zero winsize.
	pb2 := validProto()
	cfg2, err := fromProto(pb2)
	if err != nil {
		t.Fatalf("fromProto (no rider): %v", err)
	}
	if cfg2.launch.stdio != stdioPipes {
		t.Errorf("absent stdio => %v; want stdioPipes (historical path)", cfg2.launch.stdio)
	}
	if cfg2.launch.initialWinsize != (winsize{}) {
		t.Errorf("absent initial_window => %+v; want zero winsize", cfg2.launch.initialWinsize)
	}
}

// TestChooseLauncher_SelectsByDisposition pins (*supervisor).chooseLauncher's
// precedence: launcherHook wins, then an explicit s.launch, then the production
// launcher chosen by the launch surface's stdio disposition (PTY => ptyLauncher,
// else execLauncher).
func TestChooseLauncher_SelectsByDisposition(t *testing.T) {
	ptyCfg := entrypointConfig{launch: launchSpec{stdio: stdioPTY, initialWinsize: winsize{cols: 100, rows: 30}}}
	pipesCfg := entrypointConfig{launch: launchSpec{stdio: stdioPipes}}

	// 1. Production, PTY disposition => ptyLauncher seeded with the initial window.
	{
		s := &supervisor{}
		l := s.chooseLauncher(ptyCfg)
		pl, ok := l.(ptyLauncher)
		if !ok {
			t.Fatalf("PTY disposition => %T; want ptyLauncher", l)
		}
		if pl.initialWinsize != (winsize{cols: 100, rows: 30}) {
			t.Errorf("ptyLauncher initialWinsize = %+v; want {cols:100 rows:30}", pl.initialWinsize)
		}
	}

	// 2. Production, pipes disposition => execLauncher (the historical path).
	{
		s := &supervisor{}
		if _, ok := s.chooseLauncher(pipesCfg).(execLauncher); !ok {
			t.Errorf("pipes disposition => %T; want execLauncher", s.chooseLauncher(pipesCfg))
		}
	}

	// 3. An explicitly-set s.launch wins over the disposition (existing-test seam).
	{
		explicit := helperLauncher{mode: "echo"}
		s := &supervisor{launch: explicit}
		if got := s.chooseLauncher(ptyCfg); got != launcher(explicit) {
			t.Errorf("explicit s.launch must win; got %T", got)
		}
	}

	// 4. launcherHook wins over everything (the offline test injection seam).
	{
		fake := &recordingLauncher{inner: helperLauncher{mode: "echo"}}
		prev := launcherHook
		launcherHook = fake
		t.Cleanup(func() { launcherHook = prev })
		s := &supervisor{launch: helperLauncher{mode: "echo"}}
		if got := s.chooseLauncher(ptyCfg); got != launcher(fake) {
			t.Errorf("launcherHook must win over s.launch and disposition; got %T", got)
		}
	}
}
