// canary — the goldentrace capture-and-review + nightly CC-latest canary, BY
// COMMAND. Built first-party per CAPTURE-TOOL-DESIGN.md (no ../cia coupling);
// the "Canary" leg of the goldentrace triad (D49).
//
// Subcommands:
//
//	# the nightly lane: pre-flight (detectors must bite) THEN offline drift check.
//	cd client && go run ./goldentrace/canary/cmd/canary lane
//
//	# fixture regen BY COMMAND, offline against committed cassettes.
//	cd client && go run ./goldentrace/canary/cmd/canary regen           # compare (drift → reviewable diff, non-zero exit)
//	cd client && go run ./goldentrace/canary/cmd/canary regen -update   # rewrite goldens (insta-style refresh; review before commit)
//
//	# the detection-machinery pre-flight alone (fails non-zero if a detector is neutered).
//	cd client && go run ./goldentrace/canary/cmd/canary preflight
//
//	# the D50 provenance/scrub gate over a freshly-scrubbed candidate (before fixtures/ landing).
//	cd client && go run ./goldentrace/canary/cmd/canary provenance-gate <candidate.ndjson>
//
//	# the LIVE CC-latest leg — DS_E2E_LIVE-gated, the deferred operator step (never run in-fleet).
//	DS_E2E_LIVE=1 DS_CANARY_RAW_BASELINE=<jobdir>/canary-baseline.ndjson \
//	  go run ./goldentrace/canary/cmd/canary live
//
// Run from the client module root so the relative fixture/golden paths resolve.
// Everything but `live` is offline and hermetic — no claude/cia/podman.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/canary"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	l := canary.DefaultLayout()

	switch cmd {
	case "lane":
		// The nightly always-on lane: pre-flight then offline drift. repoRoot "."
		// is the client module root (cwd), so the subprocess self-tests run.
		res := canary.RunOffline(context.Background(), l, ".", os.Stdout)
		if res.Outcome != canary.OutcomeFaithful {
			os.Exit(1)
		}

	case "regen":
		fs := flag.NewFlagSet("regen", flag.ExitOnError)
		update := fs.Bool("update", false, "rewrite canon goldens (insta-style refresh; review before commit)")
		_ = fs.Parse(rest)
		results, drifts, err := canary.Regenerate(l, *update)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		canary.WriteReport(os.Stdout, results, drifts)
		if !*update && drifts > 0 {
			os.Exit(1)
		}

	case "preflight":
		// The detection-machinery self-check alone. Non-zero exit if neutered.
		if err := canary.RunPreflight(context.Background(), l, ".", func(s string) { fmt.Println(s) }); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("pre-flight OK: every detector bites.")

	case "provenance-gate":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: canary provenance-gate <candidate.ndjson>")
			os.Exit(2)
		}
		path := rest[0]
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		r := canary.EnforceProvenanceGate(path, content)
		canary.WriteProvenanceReport(os.Stdout, path, r)
		if !r.OK {
			os.Exit(1)
		}

	case "live":
		results, drifts, err := canary.DriftAgainstLatest(l)
		if err != nil {
			if errors.Is(err, canary.ErrLiveGateUnset) {
				// The default everywhere but an operator's armed box: report and exit
				// 0 (a skipped deferred step is not a failure).
				fmt.Println(err)
				return
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		canary.WriteReport(os.Stdout, results, drifts)
		if drifts > 0 {
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: canary <lane|regen [-update]|preflight|provenance-gate <file>|live>")
}
