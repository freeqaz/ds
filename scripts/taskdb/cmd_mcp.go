// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// cmdMCP serves the stdio MCP server (`taskdb mcp [--profile worker|curator]
// [--session <s>]`). No subcommands — flags only. Handlers call the same query
// cores as the CLI (cores.go, cmd_doc.go), so there is one write path and
// identical semantics; the binary never shells out to itself.
//
// Profiles are enforced server-side at registration time: the worker server
// only ever knows the 8 read/report tools, the curator server adds the 7 write
// tools. The client's --allowedTools is advisory; the registered set is the
// boundary (docs/22 §5).
func cmdMCP(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	profile := fs.String("profile", "worker", "tool profile: worker|curator")
	session := fs.String("session", "", "session identity (default: TASKDB_SESSION env, else cc-<user>-<pid>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *profile {
	case "worker", "curator":
	default:
		return fmt.Errorf("invalid profile %q; must be one of: worker, curator", *profile)
	}

	sess := mcpSession(*session)
	srv := mcp.NewServer(&mcp.Implementation{Name: "taskdb", Version: "v0.1.0"}, nil)
	registerTools(srv, db, sess, *profile)

	// stdout carries JSON-RPC; all diagnostics go to stderr only.
	fmt.Fprintf(os.Stderr, "taskdb mcp: profile=%s session=%s\n", *profile, sess)
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		// A client that closes its stdin makes Run return an EOF / closed-pipe
		// error (proven gotcha, recon-feasibility §A): that is the normal end of
		// a session, not a failure. Anything else is real.
		if errors.Is(err, io.EOF) || isClosedPipe(err) {
			return nil
		}
		return err
	}
	return nil
}

// mcpSession resolves the server's session identity by the documented
// precedence: the --session flag, then the TASKDB_SESSION env var, then a
// cc-<user>-<pid> fallback so an interactive run always has a stable handle.
func mcpSession(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("TASKDB_SESSION"); env != "" {
		return env
	}
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return fmt.Sprintf("cc-%s-%d", name, os.Getpid())
}

// isClosedPipe reports whether err is the closed-pipe condition that the stdio
// transport surfaces when the client disconnects — a clean end of session, like
// io.EOF.
func isClosedPipe(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "file already closed") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "EOF")
}
