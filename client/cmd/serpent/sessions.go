// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// cmdSessions is the `serpent sessions` management surface — the by-hand way to see
// and tear down VM sessions over the running orchestrator:
//
//	serpent sessions list    [--orchestrator host:port]          # ListSessions   (tabular)
//	serpent sessions destroy <uuid> [--orchestrator host:port]   # DestroySession (one session)
//
// Like `serpent claude --vm` and `serpent up`, the orchestrator dial does NOT happen
// here: this is the stdlib-only OSS client module (client/go.mod: STANDARD LIBRARY
// ONLY), and grpc + the orchestrator.v1 SessionService client live ONLY in the
// serpent-tui sibling (the D80 module fence — serpent-tui is the one place that may
// import google.golang.org/grpc and proto/gen/go's orchestrator client). So `serpent
// sessions` EXECs `serpent-tui sessions <verb>`, forwarding the flags; serpent-tui
// dials orchestratorv1.NewSessionServiceClient and renders the result (ListSessions →
// a table; DestroySession → the torn-down session). serpent inherits the child's stdio
// and surfaces its exit code, exactly the dispatcher contract cmdUp/cmdClaude --vm use.
//
// The leading --serpent-tui-bin (if present) is peeled by serpent (resolve the sibling)
// and not forwarded; everything else after the verb is passed through to serpent-tui.
func cmdSessions(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, sessionsUsage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, sessionsUsage)
		return 0
	case "list", "destroy":
		// Valid verb — forwarded to the serpent-tui sibling below.
	default:
		fmt.Fprintf(os.Stderr, "serpent sessions: unknown subcommand %q\n\n%s", args[0], sessionsUsage)
		return 2
	}

	verb := args[0]
	rest := args[1:]
	// Peel a LEADING --serpent-tui-bin so it is consumed by serpent (to resolve the
	// sibling) and NOT forwarded to serpent-tui — the same peel cmdUp uses. Everything
	// else after the verb is forwarded verbatim through the D80 EXEC seam: the
	// --orchestrator endpoint, the `list` paging flags --limit/--all, and the destroy
	// uuid all ride the child argv unchanged (the no-flag default path forwards just
	// `sessions <verb>`). serpent-tui owns their parsing and semantics — this stdlib
	// wrapper neither interprets nor reorders them, so a flag serpent-tui later adds
	// flows through with no change here.
	explicitBin, rest := peelSerpentTuiBin(rest)

	binPath, err := resolveSerpentTuiBin(explicitBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}

	// EXEC `serpent-tui sessions <verb> <forwarded flags>`. The orchestrator endpoint
	// rides the forwarded --orchestrator (or serpent-tui reads $DS_ORCHESTRATOR), so no
	// gRPC and no orchestrator.v1 import enters this stdlib-only module (D80).
	childArgs := append([]string{"sessions", verb}, rest...)
	return execSerpentTui(binPath, childArgs...)
}

// sessionsUsage is the `serpent sessions` help, printed on a missing/unknown subcommand
// or -h. The detailed flags (the --orchestrator default, paging) belong to serpent-tui;
// `serpent sessions <verb> -h` forwards through to serpent-tui's own usage.
const sessionsUsage = `usage: serpent sessions <list|destroy> [flags]

  list                 enumerate VM sessions (ListSessions) — uuid, state, host,
                       created-at, has-writer — as a table.
  destroy <uuid>       tear one VM session down (DestroySession).

flags (forwarded to the serpent-tui sibling):
  --orchestrator A     orchestrator SessionService endpoint host:port
                       (default: $DS_ORCHESTRATOR)
  --limit N            (list) cap the FIRST ListSessions page at N rows; the
                       server clamps the page size to 1000, so a --limit above
                       that yields ~1000 rows — use --all for the full crawl.
  --all                (list) follow next_page_token across every page and
                       accumulate all rows (the complete paginating crawl).
  --serpent-tui-bin P  path to the serpent-tui binary (peeled by serpent;
                       default: $DS_SERPENT_TUI_BIN, then PATH, then a sibling)

These EXEC the serpent-tui sibling, which dials the orchestrator (the gRPC site, D80);
this stdlib-only client never imports gRPC. Run 'serpent sessions <verb> -h' for the
sibling's own flags.
`
