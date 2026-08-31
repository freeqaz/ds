// SPDX-License-Identifier: Apache-2.0
//
// Command ds-capture is the first-party, compiled replacement for the external
// Python/mitmproxy `cia` tool (see goldentrace/CAPTURE-TOOL-DESIGN.md). It folds
// the goldentrace harness's capture / scrub / replay ideas into one OSS Go
// binary (Apache-2.0, D15/D25), so the drive tiers and the cassette fidelity
// loop run off a tool we ship, not a shell constellation plus an external
// interpreter.
//
// This binary carries the cia-parity CORE — the record / replay / scrub /
// inspect verbs over API-layer (`/v1/messages` SSE) cassettes. The cross-layer
// fidelity / canary verbs are a later migration task and are not built here.
//
// It is runtime-ignorant (D38): it encodes only the cassette format and the
// egress-gateway topology, never any toolu_/task_id vocabulary. Replay is
// hermetic and zero-egress by construction (D50). The egress gateway terminates
// TLS for api.anthropic.com on a free local port — default :18099, NEVER the
// protected shared monitor on :18080.
package main

import (
	"fmt"
	"os"
)

const usage = `ds-capture — first-party capture/replay tool (cia-parity core)

usage: ds-capture <command> [flags]

commands:
  record    Stand up the TLS-terminating egress gateway, tee /v1/messages SSE
            into an API-layer cassette. Default --port :18099 (never :18080).
  replay    Serve a recorded cassette back OFFLINE — never dials upstream.
            --strict (default) returns a synthetic 502 replay-miss on no match.
  scrub     Enforce the D50 wall on a cassette: strip auth/volatile headers,
            assert no Bearer/sk-ant/x-api-key survives, gate provenance.
  inspect   Print the normalized keys / interaction count / per-interaction
            summary of a cassette (the folded slice of cia report).

Run 'ds-capture <command> -h' for that command's flags.
See client/cmd/ds-capture/README.md for the charter and D-number map.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a subcommand and returns the process exit code. Split out from
// main so tests can drive the dispatcher without exiting the test process.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "record":
		return cmdRecord(rest)
	case "replay":
		return cmdReplay(rest)
	case "scrub":
		return cmdScrub(rest)
	case "inspect":
		return cmdInspect(rest)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ds-capture: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}
