// Command ds is the OSS CLI — part of the open data plane per D15
// (doc 08 §1: "the CLI" is an explicitly open component).
//
// Skeleton stub: standard library only (see ../../go.mod for the pinned
// dependency plan). Real subcommands land with the M0 walking skeleton
// (doc 05 §8): create / attach / destroy against orchestrator-lite.
// The attach path goes through the wrapper (client/wrapper/), which emits
// dreamserpent.attach.v1 events (D38); approval prompts render in the TUI
// (client/tui/, D18) — never in the proxy (D53).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Fprintf(os.Stderr, "ds: %q: subcommands land with the M0 walking skeleton (doc 05 §8)\n", os.Args[1])
		os.Exit(2)
	}
	fmt.Println("ds — Dream Serpent CLI (skeleton; see client/README.md)")
}
