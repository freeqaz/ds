// Command ds-tui is the writer-seat TUI attach client (D18): it renders the
// dreamserpent.attach.v1 event stream as structured deltas — chat, tools, the
// subagent tree, session state, and the approval surface — never forwarded
// frames. It is OSS (Apache-2.0, D25), part of the open data plane (D15).
//
// Modes:
//
//	ds-tui replay <file.attach.ndjson>   render a committed attach golden to
//	                                     stdout (deterministic; the goldentrace
//	                                     replay surface). Use "-" for stdin.
//	ds-tui attach ...                    live attach to a remote CC session —
//	                                     the integration step that waits on the
//	                                     orchestrator (WatchSession leg, D79).
//	                                     Not wired in the skeleton.
//
// The replay mode gates the Phase-2 render enrichments (doc serpent-cli-mvp/06
// Layers 2/3/5) behind flags that DEFAULT OFF, so the default render is
// byte-identical to the bare golden surface:
//
//	--diffs       reconstruct unified diffs for the file-edit tools (Layer 2)
//	--highlight   ANSI syntax highlighting (Layer 3)
//	--panels      collapse tool I/O into foldable panels (Layer 5)
//	--expanded    show panels expanded (only meaningful with --panels)
//	--no-color    the byte-stable plain surface (RenderPlain) — no enrichment
//
// With no flags the output equals the prior `tui.Replay` plain render; the
// enrichments are interactive-`Render`-only and never touch the wire.
//
// HARD FENCE: this binary imports NO proto/gen/go and authors no .proto; it is
// built entirely against client/tui (the OSS renderer over the client/wrapper/attach
// working model until the M0 attach.v1 freeze, D38). Field gaps are taskdb notes
// for the doc 15 §6.1 freeze checklist, never invented here.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "replay":
		if err := runReplay(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ds-tui replay: %v\n", err)
			os.Exit(1)
		}
	case "attach":
		fmt.Fprintln(os.Stderr,
			"ds-tui attach: live attach to a remote CC session is the integration step\n"+
				"that waits on the orchestrator (the WatchSession leg, D79 / doc 15 §5.4).\n"+
				"The client side is built; the remote transport lands with orchestrator-lite.")
		os.Exit(2)
	default:
		usage()
		os.Exit(2)
	}
}

// runReplay folds a committed attach.v1 NDJSON golden and renders it. The render
// path is selected from the --diffs/--highlight/--panels/--expanded/--no-color
// flags: --no-color routes to the byte-stable RenderPlain (the golden surface),
// and otherwise a tui.RenderOpts built from the flags drives RenderRich. With no
// flags set the opts are zero, so RenderRich is byte-identical to Render — and to
// keep the no-flag default exactly the prior plain golden, an all-default
// invocation still renders RenderPlain (the original `tui.Replay` behavior).
func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noColor := fs.Bool("no-color", false, "render the byte-stable plain surface (RenderPlain): no color, no diffs/highlight/panels")
	diffs := fs.Bool("diffs", false, "reconstruct unified diffs for the file-edit tools (Layer 2)")
	highlight := fs.Bool("highlight", false, "apply ANSI syntax highlighting (Layer 3)")
	panels := fs.Bool("panels", false, "collapse tool I/O into foldable panels (Layer 5)")
	expanded := fs.Bool("expanded", false, "show tool panels expanded (only meaningful with --panels)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ds-tui replay [--no-color] [--diffs] [--highlight] [--panels] [--expanded] <file.attach.ndjson | ->")
		fmt.Fprintln(os.Stderr, "  render a committed attach golden. Flags default OFF (byte-identical to the plain golden).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one input file (or '-' for stdin), got %d", len(rest))
	}

	in := os.Stdin
	if rest[0] != "-" {
		f, err := os.Open(rest[0])
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	m, _, err := tui.BuildModel(in, tui.RoleReader, 0)
	if err != nil {
		return err
	}
	return renderModel(os.Stdout, m, *noColor, optsFrom(*diffs, *highlight, *panels, *expanded))
}

// optsFrom builds a tui.RenderOpts from the flag toggles. All-false yields the
// zero RenderOpts (the byte-identical baseline).
func optsFrom(diffs, highlight, panels, expanded bool) tui.RenderOpts {
	return tui.RenderOpts{Diffs: diffs, Highlight: highlight, Panels: panels, Expanded: expanded}
}

// renderModel picks the render surface: --no-color routes to the byte-stable
// RenderPlain (no enrichment, the golden surface), a zero opts routes to the
// prior plain golden too (so the no-flag default is unchanged), and any selected
// enrichment routes to RenderRich. Factored so a test asserts the routing
// directly.
func renderModel(w io.Writer, m *tui.Model, noColor bool, opts tui.RenderOpts) error {
	if noColor || opts.IsZero() {
		// --no-color OR no enrichment selected: the byte-stable plain golden, exactly
		// the prior `tui.Replay` render (default-off is byte-identical to today).
		// opts.IsZero() single-sources the zero-routing (client/tui/render.go) so a
		// non-nil empty *FoldMap (comparable but not the zero struct) still routes to
		// the baseline instead of slipping through the raw struct== into RenderRich.
		return tui.RenderPlain(w, m)
	}
	return tui.RenderRich(w, m, opts)
}

func usage() {
	fmt.Fprintln(os.Stderr, "ds-tui — Dream Serpent writer-seat TUI (D18)")
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  ds-tui replay [--no-color] [--diffs] [--highlight] [--panels] [--expanded] <file.attach.ndjson | ->")
	fmt.Fprintln(os.Stderr, "                                           render a committed attach golden")
	fmt.Fprintln(os.Stderr, "  ds-tui attach ...                        live attach (waits on orchestrator, D79)")
}
