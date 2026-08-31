// fidcheck — run the cassette fidelity loop BY COMMAND.
//
//	cd client && go run ./goldentrace/fidelity/cmd/fidcheck
//
// Projects each committed (synthetic, live-equiv) cassette pair through the
// claude-code adapter and asserts the projections are EQUAL id-relative (the
// adapter mints the same attach.v1 structure from both, modulo CC's per-run random
// ids/timing/cost). Prints a reviewable PASS/FAIL report and exits non-zero on any
// divergence — a STALE cassette or genuine CC DRIFT (taskdb 01KTXBGTK6;
// DRIVE-PROTOCOL.md §Determinism). Always-on, zero-egress, no live claude/cia/podman.
//
// Run from the client module root so the relative fixture paths resolve.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/fidelity"
)

func main() {
	a := flag.String("a", "", "leg A cassette (overrides the default pair set; requires -b)")
	b := flag.String("b", "", "leg B cassette (overrides the default pair set; requires -a)")
	flag.Parse()

	var pairs []fidelity.Pair
	if *a != "" || *b != "" {
		if *a == "" || *b == "" {
			fmt.Fprintln(os.Stderr, "fidcheck: -a and -b must be given together")
			os.Exit(2)
		}
		pairs = []fidelity.Pair{{Name: "adhoc", A: *a, B: *b}}
	} else {
		pairs = fidelity.DefaultPairs()
	}

	if failures := fidelity.RunEquality(os.Stdout, pairs); failures > 0 {
		os.Exit(1)
	}
}
