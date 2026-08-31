// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// cmd_serve_api.go serves the taskdb verb set over HTTP so an agent inside a
// gated VM can stay in sync with the live task DAG instead of driving a frozen
// 0444 snapshot (ds-make-workspace.sh). It is the same registerTools MCP server
// as `taskdb mcp`, but over the Streamable-HTTP transport (the go-sdk ships it)
// with a per-request session derived from an injected header — so there is ONE
// write path and identical semantics; the API adds no second store.
//
// Trust model (interim / phased — the honest depth today, docs/13 §3 + D22):
//
//	guest CC → ds-dnsgate (admit taskdb.ds.internal) → ds-tlsproxy (TLS-term,
//	inject the per-session header) → 127.0.0.1:<port> here.
//
// The server binds loopback-only, so only the boundary can reach it; the session
// header is therefore trusted at this depth (a later TLS-5 substitution unit can
// replace the header with a validated grant without changing this face). The
// server REFUSES a non-loopback bind unless --allow-nonloopback is set, so the
// trusted-header posture can never be exposed by a careless --addr.
//
// Interim single-tenant seam (--session-const): before the TLS-5 boundary exists,
// one serve-api per session pins the identity host-side and IGNORES the request
// header, so a gated guest can reach it directly (e.g. bound on its own per-session
// routed-tap gateway, guest-only + host-local) without ever being able to supply
// or forge another session's id. This is strictly safer than the trusted-header
// mode — there is no request identity to forge — so a routable bind is safe; it is
// retired, not migrated, when the durable Validate/grant path arms.
//
// Profile defaults to "session" (worker + task_claim): an agent can orient,
// search, note, report, and take work, but cannot curate the DAG. A claim routes
// to the SAME shared Postgres lock server keyed by the session, so a VM claim is
// indistinguishable from a host claim and the two coordinate cross-machine.
func cmdServeAPI(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("serve-api", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:7757", "host:port to bind (loopback-only unless --allow-nonloopback)")
	profile := fs.String("profile", "session", "tool profile: worker|session|curator")
	header := fs.String("session-header", "X-DS-Session", "request header carrying the per-session identity the boundary injects")
	sessionConst := fs.String("session-const", "", "pin the session identity host-side (interim single-tenant mode): every request is attributed to this id and the request header is IGNORED — a guest can never supply or forge the session (there is no header to set). Requires --allow-nonloopback for a routable --addr.")
	allowNonLoopback := fs.Bool("allow-nonloopback", false, "permit a non-loopback bind (UNSAFE with the default trusted-header mode: the session header is trusted — only do this behind a boundary that injects it, or in --session-const mode where identity is host-fixed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *profile {
	case "worker", "session", "curator":
	default:
		return fmt.Errorf("invalid profile %q; must be one of: worker, session, curator", *profile)
	}
	if *header == "" {
		return fmt.Errorf("--session-header must not be empty")
	}
	// --session-const is the interim single-tenant seam: the boundary that would
	// inject a per-request header is replaced by a host-fixed identity baked into
	// THIS process (one serve-api per session). It is strictly safer than the
	// trusted-header mode — there is no request-supplied identity to forge — so a
	// routable bind carries no header-forgery risk. A later TLS-5 Validate/grant
	// substitution retires this by pointing the guest back at the loopback,
	// trusted-header face; the const seam changes nothing on that durable path.
	constSession := strings.TrimSpace(*sessionConst)
	if constSession != "" && !validSessionID(constSession) {
		return fmt.Errorf("--session-const %q is invalid: must be 1..200 chars with no control characters (it becomes a notes/report author and a lock-holder key)", constSession)
	}
	if !*allowNonLoopback {
		if err := requireLoopback(*addr); err != nil {
			return err
		}
	}

	// getServer runs per request. In --session-const mode the identity is the
	// host-fixed constant (the header is never read). Otherwise it is derived from
	// the injected header; a missing/invalid header returns nil, which the handler
	// serves as 400 Bad Request (fail closed — no header, no session, no tools).
	getServer := func(r *http.Request) *mcp.Server {
		sess := constSession
		if sess == "" {
			var ok bool
			sess, ok = sessionFromRequest(r, *header)
			if !ok {
				return nil
			}
		}
		srv := mcp.NewServer(&mcp.Implementation{Name: "taskdb", Version: "v0.1.0"}, nil)
		registerTools(srv, db, sess, *profile)
		return srv
	}
	// Stateless: each request is self-contained (no Mcp-Session-Id handshake to
	// keep — our identity is the injected header, not an MCP session id).
	// JSONResponse: plain application/json replies, not an SSE stream.
	handler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *addr, err)
	}
	if constSession != "" {
		fmt.Fprintf(os.Stderr, "taskdb serve-api: profile=%s addr=%s session-const=%s (header ignored; host-fixed identity)\n", *profile, ln.Addr(), constSession)
	} else {
		fmt.Fprintf(os.Stderr, "taskdb serve-api: profile=%s addr=%s session-header=%s\n", *profile, ln.Addr(), *header)
	}

	// Graceful shutdown on SIGINT/SIGTERM so a systemd stop drains in flight.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// sessionFromRequest derives the caller's session identity from the injected
// header. It is the single session-derivation seam: the interim "trust-header"
// backend (the boundary is the only reachable client, so the header is trusted),
// which a later TLS-5 / Validate path can replace without touching the rest of
// the server. Returns ok=false on an absent, oversized, or control-char header
// (fail closed → 400).
func sessionFromRequest(r *http.Request, headerName string) (string, bool) {
	v := strings.TrimSpace(r.Header.Get(headerName))
	if !validSessionID(v) {
		return "", false
	}
	return v, true
}

// validSessionID bounds a session identity and rejects control characters: it
// becomes a notes/report author and a lock-holder key, so it must stay a clean
// single-line token. Shared by the header-derivation path and the --session-const
// validation so both seams accept exactly the same identity shape.
func validSessionID(v string) bool {
	return v != "" && len(v) <= 200 && !strings.ContainsAny(v, "\r\n\x00")
}

// requireLoopback rejects an --addr whose host is not a loopback address, so the
// trusted-header posture is never accidentally exposed on a routable interface.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --addr %q: %w", addr, err)
	}
	if host == "" || host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing non-loopback bind %q: the session header is trusted; pass --allow-nonloopback only behind a boundary that injects it", addr)
}
