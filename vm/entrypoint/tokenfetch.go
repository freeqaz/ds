// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// tokenfetch.go fetches the short-lived SESSION TOKEN in-guest at boot from the
// host-local D22 shim named by EntrypointConfig.session_token_endpoint (U5), and
// injects it as the launched runtime's API credential. The token is fetched
// FRESH per boot, lives ONLY in the launched process's environment, and is NEVER
// written to disk or carried in the EntrypointConfig (D17/D39/D50 — no
// credentials in-guest except this fetched-fresh, env-only token).
//
// AUTHZ TRANSPORT — AF_VSOCK (the U5 hardening): the production endpoint is a
// vsock REFERENCE (vsock://host:<port>/token). The guest DIALS the host over
// AF_VSOCK at VMADDR_CID_HOST(2):<port> and is authorized by its OWN unforgeable
// connecting CID — it sends NOTHING identifying (no session UUID, no secret), so
// there is nothing to steal or replay, and a cross-session ask is structurally
// impossible (the host derives the session from the CID and serves ONLY that
// session's token). The legacy http:// path is kept UNCHANGED for back-compat
// with the offline fixtures; the scheme on the endpoint selects the transport.
//
// CC CREDENTIAL VAR: CLAUDE_CODE_OAUTH_TOKEN — the bearer var Claude Code reads
// (its init reports account.tokenSource:CLAUDE_CODE_OAUTH_TOKEN; the podman
// drive path passes exactly this by name, client/goldentrace/e2e/live_drive.go).
// The runtime presents it to the TLS-terminating egress gateway, which swaps it
// for the real upstream key (U7) — the real key never enters the guest.
//
// NO-PROXY FETCH (load-bearing): the runtime's env carries HTTP(S)_PROXY pointing
// at the egress gateway, but the D22 shim is a HOST-LOCAL link-local endpoint
// that must be reached DIRECTLY. This fetch therefore uses a dedicated
// http.Client whose Transport sets Proxy: nil — it must NOT honor *_PROXY / the
// egress gateway (routing the control fetch through the gateway would fail or
// leak). The proxy keys env.go sets are for the RUNTIME, not this control fetch.
//
// FAIL-CLOSED: an empty endpoint skips the fetch entirely (the synthetic/offline
// launch path is unaffected); an endpoint that is set but unreachable (or returns
// non-2xx / an empty body) fails closed — no runtime may run without auth. The
// token VALUE is NEVER logged (D39/D50): only the endpoint + HTTP status appear
// in any diagnostic.

// ccOAuthTokenEnvKey is the env var Claude Code reads as its bearer credential
// (confirmed from client/goldentrace/e2e/live_drive.go's podman drive path and
// CC's init account.tokenSource). The fetched session token is injected under
// this key into the launched runtime's env only.
const ccOAuthTokenEnvKey = "CLAUDE_CODE_OAUTH_TOKEN"

// fetchTokenTimeout bounds the whole in-guest token fetch (dial + response). A
// package var so offline tests can shrink it; the production value is generous
// enough to ride a brief boot-race for the host-local shim, short enough that an
// unreachable endpoint fails closed promptly rather than hanging the boot.
var fetchTokenTimeout = 10 * time.Second

// maxTokenBodyBytes caps how much of the shim's response we read. A session token
// is small; the cap is defense against a misbehaving/oversized endpoint body.
const maxTokenBodyBytes = 64 * 1024

// tokenFetcher is the in-guest session-token fetch seam. It mirrors the
// launcher/dialer/reporter injection pattern: the production implementation is
// httpTokenFetcher, and the supervisor's offline tests inject a fake so the fetch
// is exercised with NO real HTTP.
type tokenFetcher interface {
	// fetch GETs the short-lived session token from the host-local D22 shim at
	// endpoint and returns it. The endpoint is assumed non-empty (the supervisor
	// skips the fetch on an empty endpoint). On any failure it returns a non-nil
	// error and an empty token (fail-closed); it NEVER returns the token value in
	// the error.
	fetch(endpoint string) (string, error)
}

// httpTokenFetcher is the production tokenFetcher. It dispatches on the endpoint
// SCHEME: a vsock:// reference dials the host-local D22 shim over AF_VSOCK and is
// authorized by the guest's unforgeable peer CID (the U5 hardening); an http://
// reference does a stdlib net/http GET with the egress proxy DELIBERATELY bypassed
// (the legacy / offline-fixture path). An unrecognized scheme fails closed.
type httpTokenFetcher struct{}

// vsockTokenScheme is the URL scheme that selects the AF_VSOCK token transport.
const vsockTokenScheme = "vsock"

// fetch dispatches on the endpoint scheme. It is the SINGLE coupling point between
// the host's advertised endpoint string and the in-guest transport: vsock:// dials
// AF_VSOCK (peer-CID authz, no UUID on the wire); http:// does the legacy GET; any
// other scheme fails closed (a typo'd scheme must NEVER silently pick the wrong
// path). The whole dial+read is bounded by fetchTokenTimeout in both paths.
func (f httpTokenFetcher) fetch(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse session token endpoint %q: %w", endpoint, err)
	}
	switch u.Scheme {
	case vsockTokenScheme:
		return f.fetchVsock(u)
	case "http", "https":
		return f.fetchHTTP(endpoint)
	default:
		// Fail closed on an unrecognized scheme — never fall through to the wrong path.
		return "", fmt.Errorf("session token endpoint %q has unsupported scheme %q (want vsock:// or http://)", endpoint, u.Scheme)
	}
}

// fetchVsock dials the host-local D22 shim over AF_VSOCK at VMADDR_CID_HOST:<port>
// and reads the served token. The guest is authorized by its OWN connecting CID
// (the host derives the session from it); the guest sends NOTHING on the wire. The
// host "host" component is a conventional placeholder for VMADDR_CID_HOST(2) — the
// CID the guest reaches the host-agent at — and is NOT resolved as a DNS name; only
// the PORT is read from the reference. The body is read bounded + trimmed, the same
// fail-closed parse as the http path. The token is NEVER logged.
func (httpTokenFetcher) fetchVsock(u *url.URL) (string, error) {
	portStr := u.Port()
	if portStr == "" {
		return "", fmt.Errorf("vsock session token endpoint %q has no port", u.String())
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return "", fmt.Errorf("vsock session token endpoint %q has an invalid port %q: %w", u.String(), portStr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTokenTimeout)
	defer cancel()

	conn, err := dialTokenVsockFn(ctx, vmAddrCIDHost, uint32(port))
	if err != nil {
		return "", fmt.Errorf("dial session token vsock host-CID:%d: %w", port, err)
	}
	defer conn.Close()

	// Bound the read by the same deadline as the dial so a stalled host never hangs
	// the boot past fetchTokenTimeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, maxTokenBodyBytes))
	if err != nil {
		return "", fmt.Errorf("read session token over vsock (port %d): %w", port, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		// Fail closed: the host writes NOTHING for an unauthorized/unknown CID or a
		// source error (the 403 analogue). An empty body is an auth failure, not a
		// success — no runtime may run without auth.
		return "", fmt.Errorf("vsock session token endpoint (port %d) returned an empty token (fail-closed: unauthorized CID or source error)", port)
	}
	return token, nil
}

// vmAddrCIDHost is VMADDR_CID_HOST(2): the host's own AF_VSOCK CID, the context the
// guest dials to reach the host-agent token shim. Named here as the documented
// kernel constant so the dial site reads clearly on every platform (the linux dialer
// uses the unix package constant; this keeps the call site platform-agnostic).
const vmAddrCIDHost uint32 = 2

// dialTokenVsockFn is the vsock-dial seam, indirected so the offline test can inject
// an in-process fake conn (the live AF_VSOCK connect to a host is operator-validated
// on the KVM box, never in a unit test — mirroring attachfwd_test.go, which tests
// Splice over pipes and never a live vsock connect). It defaults to the build-tagged
// dialTokenVsock (real on linux, fail-closed stub elsewhere).
var dialTokenVsockFn = dialTokenVsock

// noProxyTokenClient is the http.Client the token fetch uses. Its Transport sets
// Proxy: nil so the fetch never traverses HTTP(S)_PROXY / the egress gateway (the
// D22 shim is a host-local link-local address reached directly). It is package
// private and NOT http.DefaultClient (which honors *_PROXY env).
var noProxyTokenClient = &http.Client{
	Transport: &http.Transport{
		// CRITICAL: nil Proxy => never use a proxy. Do not fall back to
		// http.ProxyFromEnvironment — that would route this host-local control
		// fetch through the egress gateway.
		Proxy: nil,
	},
}

// fetchHTTP performs the legacy GET (the offline-fixture / back-compat path). It
// reads a bounded body, rejects non-2xx, trims surrounding whitespace, and errors on
// an empty token. The token value is never logged or embedded in an error — only the
// endpoint and HTTP status are.
func (httpTokenFetcher) fetchHTTP(endpoint string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTokenTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build token request for %q: %w", endpoint, err)
	}

	resp, err := noProxyTokenClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET session token from %q: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("session token endpoint %q returned status %d", endpoint, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	if err != nil {
		return "", fmt.Errorf("read session token from %q: %w", endpoint, err)
	}

	// SINGLE COUPLING POINT to the host-side wire format: the D22 shim's response
	// shape is not pinned by a frozen contract (the proto carries
	// session_token_endpoint as an OPAQUE address). We treat the body AS the token
	// (trimmed), matching the "address only" framing. If U5/U7's shim instead
	// returns JSON or a header, only this parse changes.
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("session token endpoint %q returned an empty token", endpoint)
	}
	return token, nil
}

// injectSessionToken appends the fetched session token to env under the CC bearer
// key. It is appended LAST so it wins over any inherited/spec value of the same
// key (os/exec honors the last duplicate). The token is added in the supervisor
// AFTER buildRuntimeEnv composes the env — never inside env.go — so env.go's
// credential-free invariant (TestBuildRuntimeEnv_NoCredentials) holds.
func injectSessionToken(env []string, token string) []string {
	return append(env, ccOAuthTokenEnvKey+"="+token)
}
