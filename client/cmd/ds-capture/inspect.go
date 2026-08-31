// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// cmdInspect prints a cassette's normalized keys / interaction count /
// per-interaction summary — the folded thin slice of `cia report` (the
// debugging-a-replay-miss view, NOT the analytics product; cut-list §2).
func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ds-capture inspect <cassette>\n")
		fmt.Fprintf(os.Stderr, "\nPrints the normalized keys / interaction count / per-interaction summary\n")
		fmt.Fprintf(os.Stderr, "for debugging a replay miss (the folded slice of cia report).\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "ds-capture inspect: exactly one cassette path is required")
		fs.Usage()
		return 2
	}
	cas, err := cassette.Load(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture inspect: %v\n", err)
		return 1
	}
	writeInspect(os.Stdout, cas)
	return 0
}

// writeInspect renders the inspection summary to w (split out so a test can
// capture the output deterministically).
func writeInspect(w io.Writer, cas *cassette.Cassette) {
	fmt.Fprintf(w, "cassette version: %d\n", cas.Version)
	fmt.Fprintf(w, "interactions: %d\n", cas.Len())
	for i, it := range cas.Interactions {
		events := cassette.EventTypes(it.Body)
		model := "?"
		if m, ok := it.Normalized.Model.(string); ok && m != "" {
			model = m
		}
		fmt.Fprintf(w, "\n[%d] key: %s\n", i, it.Key)
		fmt.Fprintf(w, "    model:   %s\n", model)
		fmt.Fprintf(w, "    turns:   %d\n", len(it.Normalized.Sequence))
		fmt.Fprintf(w, "    status:  %d\n", it.StatusCode)
		fmt.Fprintf(w, "    body:    %d bytes\n", len(it.Body))
		if len(events) > 0 {
			fmt.Fprintf(w, "    events:  %s\n", strings.Join(events, ", "))
		}
		if ct, ok := it.Headers["content-type"]; ok {
			fmt.Fprintf(w, "    content-type: %s\n", ct)
		}
	}
}
