// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// cmdSessions is the `serpent-tui sessions` management surface — the gRPC site
// (D80: serpent-tui is the ONE module that imports orchestrator.v1 and the gRPC
// SessionService client) behind the stdlib-only `serpent sessions` EXEC wrapper:
//
//	serpent-tui sessions list    [--orchestrator host:port]          # ListSessions   (tabular)
//	serpent-tui sessions destroy <uuid> [--orchestrator host:port]   # DestroySession (one session)
//
// Both verbs dial the orchestrator over the SAME injectable `dialer` package var
// the attach/up paths use (the cmd tests substitute an in-process bufconn fake —
// no live orchestrator). `list` renders the enumeration as a NEWEST-FIRST table
// (the store already sorts CreatedAt desc; we render the order as returned, never
// re-sorting, so the table is faithful to the control plane). `destroy` calls the
// frozen DestroySession RPC for the one uuid and surfaces a non-zero exit on RPC
// error. No proto change: ListSessions and DestroySession are both already in the
// frozen orchestratorv1 generated client.
func cmdSessions(args []string) int {
	if len(args) == 0 {
		sessionsUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		sessionsUsage(os.Stdout)
		return 0
	case "list":
		return cmdSessionsList(args[1:])
	case "destroy":
		return cmdSessionsDestroy(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "serpent-tui sessions: unknown subcommand %q\n", args[0])
		sessionsUsage(os.Stderr)
		return 2
	}
}

// cmdSessionsList enumerates VM sessions (ListSessions) and renders them as a
// table. The orchestrator endpoint rides --orchestrator (or $DS_ORCHESTRATOR),
// exactly like attach/up.
func cmdSessionsList(args []string) int {
	fs := flag.NewFlagSet("serpent-tui sessions list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orchestrator := fs.String("orchestrator", os.Getenv(orchestratorEnv), "orchestrator SessionService endpoint (host:port; env "+orchestratorEnv+")")
	host := fs.String("host", "", "optional host_id filter (empty => fleet-wide)")
	limit := fs.Uint("limit", 0, "page size: cap the first ListSessions page at N rows (0 => server default: all); N>1000 yields ~1000 rows (server clamps page_size to listSessionsMaxPageSize and --limit takes only the first page — use --all for the full crawl)")
	all := fs.Bool("all", false, "follow next_page_token across every page, accumulating all rows (paginating crawl)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent-tui sessions list --orchestrator <addr> [--host <id>] [--limit <n>] [--all]")
		fmt.Fprintln(os.Stderr, "  enumerate VM sessions (ListSessions) as a table: uuid, state, host, created-at.")
		fmt.Fprintln(os.Stderr, "  default (no --limit/--all): a single page_size=0 call (server returns all in one page).")
		fmt.Fprintln(os.Stderr, "  --limit N: cap the FIRST page at N rows. --all: crawl every page (follow next_page_token).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *orchestrator == "" {
		fmt.Fprintf(os.Stderr, "serpent-tui: --orchestrator <addr> is required (or set %s)\n", orchestratorEnv)
		fs.Usage()
		return 2
	}

	c, closeConn, err := dialer(*orchestrator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: %v\n", err)
		return 1
	}
	defer func() { _ = closeConn() }()

	ctx, cancel := context.WithTimeout(context.Background(), sessionsRPCTimeout)
	defer cancel()

	sessions, err := listSessions(ctx, c, *host, *limit, *all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: list sessions failed: %v\n", err)
		return 1
	}
	renderSessions(stdout, sessions)
	return 0
}

// cmdSessionsDestroy tears one VM session down (DestroySession) by uuid.
func cmdSessionsDestroy(args []string) int {
	fs := flag.NewFlagSet("serpent-tui sessions destroy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orchestrator := fs.String("orchestrator", os.Getenv(orchestratorEnv), "orchestrator SessionService endpoint (host:port; env "+orchestratorEnv+")")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent-tui sessions destroy <uuid> --orchestrator <addr>")
		fmt.Fprintln(os.Stderr, "  tear one VM session down (DestroySession).")
		fs.PrintDefaults()
	}
	// The uuid is a positional argument that may appear before OR after the flags
	// (the `serpent sessions` EXEC wrapper forwards `destroy <uuid> --orchestrator A`,
	// i.e. uuid-first; flag.Parse stops at the first non-flag, so a leading uuid would
	// otherwise leave --orchestrator unparsed). Peel the FIRST non-flag token as the
	// uuid and parse the rest as flags, so the uuid is position-independent.
	uuid, flagArgs := peelPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	// A second positional (after the flags) is also accepted as the uuid (uuid-last form).
	if uuid == "" {
		uuid = fs.Arg(0)
	}
	if uuid == "" {
		fmt.Fprintln(os.Stderr, "serpent-tui: sessions destroy requires a <uuid> argument")
		fs.Usage()
		return 2
	}
	if *orchestrator == "" {
		fmt.Fprintf(os.Stderr, "serpent-tui: --orchestrator <addr> is required (or set %s)\n", orchestratorEnv)
		fs.Usage()
		return 2
	}

	c, closeConn, err := dialer(*orchestrator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: %v\n", err)
		return 1
	}
	defer func() { _ = closeConn() }()

	ctx, cancel := context.WithTimeout(context.Background(), sessionsRPCTimeout)
	defer cancel()

	if err := destroySession(ctx, c, uuid); err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: destroy session %q failed: %v\n", uuid, err)
		return 1
	}
	fmt.Fprintf(stdout, "destroyed session %s\n", uuid)
	return 0
}

// sessionsRPCTimeout bounds the list/destroy management RPCs so a wedged control
// plane fails fast rather than hanging the operator's shell.
const sessionsRPCTimeout = 30 * time.Second

// peelPositional pulls the FIRST bare positional token (a token that does not
// start with "-" and is not the VALUE of a known value-taking flag) out of args,
// returning it and the remaining args (flags) with that token removed. It lets
// `sessions destroy <uuid> --orchestrator A` accept the uuid BEFORE the flags (the
// form the `serpent sessions` EXEC wrapper forwards) without flag.Parse stopping
// at the leading uuid. destroy's only value-taking flag is --orchestrator, so a
// token immediately following an unattached --orchestrator/-orchestrator is its
// value, not the positional. Returns ("", args) when no positional is present.
func peelPositional(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// An unattached value-taking flag (no "=") consumes the NEXT token as its
			// value — skip that token so it is never mistaken for the positional.
			if (a == "--orchestrator" || a == "-orchestrator") && i+1 < len(args) {
				i++
			}
			continue
		}
		// First bare token: the positional. Remove it from the flag args.
		rest := make([]string, 0, len(args)-1)
		rest = append(rest, args[:i]...)
		rest = append(rest, args[i+1:]...)
		return a, rest
	}
	return "", args
}

// listSessions runs ListSessions (doc 15 §5.3) and returns sessions in the order
// the control plane returned them (the store sorts CreatedAt desc, so newest-first;
// accumulation across pages preserves that order because each page is appended in
// turn). hostID is an optional fleet-narrowing filter (empty => fleet-wide).
//
// pageSize/all select the read strategy:
//   - both zero/false (the DEFAULT, what every existing single-call client gets):
//     ONE call with page_size=0. Back-compat is mandatory — page_size<=0 returns
//     ALL sessions, so the default never silently truncates a large fleet.
//   - pageSize>0 (--limit N): ONE call with page_size=N, capping the FIRST page at
//     N rows (an opt-in snapshot of the newest N; ignores any next_page_token).
//   - all=true (--all): a paginating CRAWL — repeatedly call ListSessions, carrying
//     the returned next_page_token, accumulating every page's rows until the token
//     comes back empty (the canonical end-of-pages signal). pageSize, when >0, sets
//     the per-page batch size for the crawl; when 0 the server picks the page size.
//
// pageSize is bounded to the wire's uint32 page_size field; values above its max
// are clamped (a page size that large is already "everything").
func listSessions(ctx context.Context, c sessionClient, hostID string, pageSize uint, all bool) ([]*orchestratorv1.Session, error) {
	ps := uint32(pageSize)
	if uint64(pageSize) > uint64(^uint32(0)) {
		ps = ^uint32(0)
	}

	var acc []*orchestratorv1.Session
	token := ""
	for {
		resp, err := c.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{
			HostId:    hostID,
			PageSize:  ps,
			PageToken: token,
		})
		if err != nil {
			return nil, err
		}
		acc = append(acc, resp.GetSessions()...)
		// Single-call strategies (default and --limit) take exactly the first page.
		// Only --all follows the cursor; it stops when the server returns no token.
		token = resp.GetNextPageToken()
		if !all || token == "" {
			return acc, nil
		}
	}
}

// destroySession runs DestroySession for the one uuid.
func destroySession(ctx context.Context, c sessionClient, uuid string) error {
	if uuid == "" {
		return errors.New("destroy requires a session uuid")
	}
	_, err := c.DestroySession(ctx, &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	return err
}

// renderSessions writes the sessions as a left-aligned tab-separated table to w
// (plain stdlib text/tabwriter). The rows are rendered in the order returned —
// the store sorts CreatedAt desc, so newest-first — never re-sorted here, so the
// table is faithful to what the control plane returned. An empty enumeration
// prints just the header (a stable, scriptable shape).
func renderSessions(w io.Writer, sessions []*orchestratorv1.Session) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UUID\tSTATE\tWRITER\tHOST\tCREATED")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			orEmpty(s.GetSessionUuid()),
			stateLabel(s.GetState()),
			writerLabel(s.GetHasWriter()),
			orEmpty(s.GetHostId()),
			createdLabel(s.GetCreatedAt()),
		)
	}
	_ = tw.Flush()
}

// writerLabel renders the Session.has_writer verdict (D78/D61) for the table: a
// human holding the one writer seat (ATTENDED) shows "yes", a writer-less session
// shows "-". This is the value the idle reaper acts on — a "-" session past the
// idle TTL is what gets reaped.
func writerLabel(hasWriter bool) string {
	if hasWriter {
		return "yes"
	}
	return "-"
}

// stateLabel renders a Session's lifecycle state as the short §3 state name with
// the SESSION_STATE_NAME_ prefix stripped (e.g. READY, WORKING) — the legible
// form for a table. A nil/unspecified state renders "-".
func stateLabel(st *attachv1.SessionState) string {
	if st == nil {
		return "-"
	}
	name := st.GetName()
	if name == attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED {
		return "-"
	}
	short := strings.TrimPrefix(name.String(), "SESSION_STATE_NAME_")
	if short == "" {
		return "-"
	}
	return short
}

// createdLabel renders the CreatedAt unix-seconds timestamp as a UTC RFC3339
// string (0 => "-", no timestamp pinned on the wire).
func createdLabel(secs uint64) string {
	if secs == 0 {
		return "-"
	}
	return time.Unix(int64(secs), 0).UTC().Format(time.RFC3339)
}

// orEmpty renders "-" for an empty string so the table never prints a blank cell.
func orEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// sessionsUsage prints the `serpent-tui sessions` help to w.
func sessionsUsage(w *os.File) {
	fmt.Fprintln(w, "usage: serpent-tui sessions <list|destroy> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  list                 enumerate VM sessions (ListSessions) — uuid, state, host, created — as a table.")
	fmt.Fprintln(w, "  destroy <uuid>       tear one VM session down (DestroySession).")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  --orchestrator A     orchestrator SessionService endpoint host:port (default: $%s)\n", orchestratorEnv)
}
