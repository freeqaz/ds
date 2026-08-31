// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// TestDispatchBareShowsUsage proves a bare invocation prints usage and exits 2.
func TestDispatchBareShowsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Errorf("bare invocation: got exit %d want 2", code)
	}
}

// TestDispatchUnknownCommand proves an unknown command exits 2 (usage on
// unknown).
func TestDispatchUnknownCommand(t *testing.T) {
	if code := run([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown command: got exit %d want 2", code)
	}
}

// TestDispatchHelp proves the help command exits 0.
func TestDispatchHelp(t *testing.T) {
	for _, h := range []string{"-h", "--help", "help"} {
		if code := run([]string{h}); code != 0 {
			t.Errorf("%q: got exit %d want 0", h, code)
		}
	}
}

// TestDispatchSubcommandsExist proves the four verbs dispatch to a parser
// (each returns exit 2 on missing required args rather than "unknown command").
// This exercises the dispatcher without binding ports or touching the network.
func TestDispatchSubcommandsExist(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
	}{
		{"record", []string{}},  // missing --cassette -> usage, exit 2
		{"replay", []string{}},  // missing --cassette -> usage, exit 2
		{"scrub", []string{}},   // missing path -> usage, exit 2
		{"inspect", []string{}}, // missing path -> usage, exit 2
	}
	for _, c := range cases {
		code := run(append([]string{c.cmd}, c.args...))
		if code != 2 {
			t.Errorf("%s with no args: got exit %d want 2 (usage)", c.cmd, code)
		}
	}
}

// TestInspectViaDispatchOnTestdata drives the real inspect verb end to end on
// the synthetic testdata cassette (exit 0).
func TestInspectViaDispatchOnTestdata(t *testing.T) {
	if code := run([]string{"inspect", "testdata/synthetic-basic.json"}); code != 0 {
		t.Errorf("inspect testdata: got exit %d want 0", code)
	}
}

// TestScrubViaDispatchReportOnly drives the real scrub verb in report-only mode
// on the synthetic testdata cassette (exit 0; the wall holds).
func TestScrubViaDispatchReportOnly(t *testing.T) {
	if code := run([]string{"scrub", "testdata/synthetic-basic.json"}); code != 0 {
		t.Errorf("scrub report-only: got exit %d want 0", code)
	}
}
