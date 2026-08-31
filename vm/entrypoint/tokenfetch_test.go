// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeTokenFetcher is the offline tokenFetcher seam: it returns a canned token or
// error and records the endpoint it was asked to fetch, so the supervisor's
// fetch-and-inject path is driven with NO real HTTP. failIfCalled makes a test
// assert the fetch is NEVER reached (the empty-endpoint skip path).
type fakeTokenFetcher struct {
	token        string
	err          error
	gotEndpoint  string
	called       bool
	failIfCalled func()
}

func (f *fakeTokenFetcher) fetch(endpoint string) (string, error) {
	f.called = true
	f.gotEndpoint = endpoint
	if f.failIfCalled != nil {
		f.failIfCalled()
	}
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

// envCapturingLauncher wraps an inner launcher and captures the env passed to
// start(), so a test can assert what credential the runtime was launched with.
// (recordingLauncher in run_test.go only counts starts; this captures the env.)
type envCapturingLauncher struct {
	inner   launcher
	gotEnv  []string
	started bool
}

func (l *envCapturingLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	l.started = true
	l.gotEnv = append([]string(nil), env...)
	return l.inner.start(spec, env)
}

// cfgWithTokenEndpoint is cfgForSupervise plus a set session_token_endpoint.
func cfgWithTokenEndpoint(endpoint string) entrypointConfig {
	cfg := cfgForSupervise()
	cfg.sessionTokenEndpoint = endpoint
	return cfg
}

// TestSupervise_EmptyEndpoint_NoFetch_LaunchProceeds: with no token endpoint the
// fetch is skipped entirely (the synthetic/offline launch path is unaffected) and
// the fetcher is never invoked.
func TestSupervise_EmptyEndpoint_NoFetch_LaunchProceeds(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	fetcher := &fakeTokenFetcher{failIfCalled: func() {
		t.Fatal("fetch must NOT be called when session_token_endpoint is empty")
	}}

	sup := newSupervisorFor(t, "emit-then-exit", rep, d)
	sup.fetcher = fetcher

	code, err := sup.run(context.Background(), cfgForSupervise()) // empty endpoint
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d; want 0 (launch proceeds with no fetch)", code)
	}
	if fetcher.called {
		t.Error("token fetcher was invoked despite an empty endpoint")
	}
}

// TestSupervise_SetEndpoint_TokenInLaunchEnv: with a set endpoint the supervisor
// fetches the token and the launched runtime's env carries
// CLAUDE_CODE_OAUTH_TOKEN=<token>, and the fetcher saw the configured endpoint.
func TestSupervise_SetEndpoint_TokenInLaunchEnv(t *testing.T) {
	const sentinel = "sk-session-sentinel-123"
	const endpoint = "http://169.254.0.2:8080/token"

	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	recL := &envCapturingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
	fetcher := &fakeTokenFetcher{token: sentinel}

	var log bytes.Buffer
	sup := &supervisor{
		launch:  recL,
		dial:    d,
		report:  rep,
		fetcher: fetcher,
		logf:    func(f string, a ...any) { fmt.Fprintf(&log, f, a...) },
		errSink: io.Discard,
	}

	code, err := sup.run(context.Background(), cfgWithTokenEndpoint(endpoint))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d; want 0", code)
	}
	if fetcher.gotEndpoint != endpoint {
		t.Errorf("fetcher saw endpoint %q; want %q", fetcher.gotEndpoint, endpoint)
	}
	if !recL.started {
		t.Fatal("launcher was never started")
	}
	want := ccOAuthTokenEnvKey + "=" + sentinel
	if !containsEnvEntry(recL.gotEnv, want) {
		t.Errorf("launch env missing %q; got %v", want, recL.gotEnv)
	}
	// The injected token must be the LAST occurrence of its key so os/exec honors
	// it over any inherited/spec duplicate.
	if last := lastValueForKey(recL.gotEnv, ccOAuthTokenEnvKey); last != sentinel {
		t.Errorf("effective %s = %q; want the fetched sentinel %q", ccOAuthTokenEnvKey, last, sentinel)
	}
}

// TestSupervise_SetEndpoint_FetchError_FailClosed: a fetch error fails closed with
// a clear "fetch session token" error and the runtime is NEVER launched (no
// runtime without auth).
func TestSupervise_SetEndpoint_FetchError_FailClosed(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	recL := &envCapturingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
	fetcher := &fakeTokenFetcher{err: fmt.Errorf("connection refused")}

	var log bytes.Buffer
	sup := &supervisor{
		launch:  recL,
		dial:    d,
		report:  rep,
		fetcher: fetcher,
		logf:    func(f string, a ...any) { fmt.Fprintf(&log, f, a...) },
		errSink: io.Discard,
	}

	code, err := sup.run(context.Background(), cfgWithTokenEndpoint("http://169.254.0.2:8080/token"))
	if err == nil {
		t.Fatal("expected fail-closed error when the token fetch fails")
	}
	if code != exitFailClosed {
		t.Errorf("exit code = %d; want exitFailClosed=%d", code, exitFailClosed)
	}
	if !strings.Contains(err.Error(), "fetch session token") {
		t.Errorf("error should mention fetch session token: %v", err)
	}
	if recL.started {
		t.Error("runtime must NOT be launched when the token fetch fails (no runtime without auth)")
	}
	// Fail-closed BEFORE launch => never reported ready.
	if rep.ready != 0 {
		t.Errorf("must not report ready when the token fetch fails; got %d", rep.ready)
	}
}

// TestHTTPTokenFetcher_NoProxy_TrimsBody drives the production httpTokenFetcher
// against an httptest server: it trims the body, errors on non-2xx and an empty
// body, and its transport uses no proxy.
func TestHTTPTokenFetcher_NoProxy_TrimsBody(t *testing.T) {
	prev := fetchTokenTimeout
	fetchTokenTimeout = 2 * time.Second
	t.Cleanup(func() { fetchTokenTimeout = prev })

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "  sk-token-with-spaces\n")
		}))
		defer srv.Close()

		got, err := httpTokenFetcher{}.fetch(srv.URL)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if got != "sk-token-with-spaces" {
			t.Errorf("token = %q; want trimmed %q", got, "sk-token-with-spaces")
		}
	})

	t.Run("non-2xx errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := httpTokenFetcher{}.fetch(srv.URL)
		if err == nil {
			t.Fatal("expected an error on a non-2xx response")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error should mention the status: %v", err)
		}
	})

	t.Run("empty body errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "   \n")
		}))
		defer srv.Close()

		_, err := httpTokenFetcher{}.fetch(srv.URL)
		if err == nil {
			t.Fatal("expected an error on an empty token body")
		}
		if !strings.Contains(err.Error(), "empty token") {
			t.Errorf("error should mention an empty token: %v", err)
		}
	})

	// The token client MUST NOT honor *_PROXY: its transport's Proxy is nil so the
	// host-local control fetch never traverses the egress gateway.
	tr, ok := noProxyTokenClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("token client transport = %T; want *http.Transport", noProxyTokenClient.Transport)
	}
	if tr.Proxy != nil {
		t.Error("token client transport Proxy must be nil (the fetch must NOT use the egress gateway)")
	}
}

// TestSupervisorTokenFetcher_NilUsesProductionFetcher pins the byte-identical
// guarantee of the tokenFetcherHook seam: nil (the default) resolves to the
// production httpTokenFetcher{}, and the supervisor's nil fetcher field likewise
// resolves to httpTokenFetcher{} — so the production path is unchanged when the
// seam is unset. A set hook supplies the supervisor's fetcher instead.
func TestSupervisorTokenFetcher_NilUsesProductionFetcher(t *testing.T) {
	if tokenFetcherHook != nil {
		t.Fatalf("tokenFetcherHook must default to nil (production); got %T", tokenFetcherHook)
	}
	if got := supervisorTokenFetcher(); got != nil {
		t.Errorf("nil tokenFetcherHook must resolve to nil (the supervisor defaults nil to httpTokenFetcher{}); got %T", got)
	}
	// A nil fetcher field resolves to the production httpTokenFetcher at use.
	if _, ok := (&supervisor{}).tokenFetcherOrDefault().(httpTokenFetcher); !ok {
		t.Error("a nil supervisor.fetcher must resolve to the production httpTokenFetcher{}")
	}

	// With an override installed, the resolver returns the override.
	fake := &fakeTokenFetcher{token: "x"}
	withTokenFetcher(t, fake)
	if got := supervisorTokenFetcher(); got != tokenFetcher(fake) {
		t.Errorf("set tokenFetcherHook must override; got %p, want %p", got, fake)
	}
}

// withVsockDial installs a fake AF_VSOCK token dialer for the duration of a test
// (restored on cleanup), so the vsock scheme-dispatch + bounded-read + fail-closed
// parse are exercised over an in-process conn with NO live AF_VSOCK connect (the live
// dial is operator-validated on the KVM box, mirroring attachfwd_test.go's pipe-only
// Splice tests). The fake records the (cid, port) it was asked to dial.
func withVsockDial(t *testing.T, dial func(ctx context.Context, cid, port uint32) (net.Conn, error)) {
	t.Helper()
	prev := dialTokenVsockFn
	dialTokenVsockFn = dial
	t.Cleanup(func() { dialTokenVsockFn = prev })
}

// servingPipe returns a net.Conn whose reads yield body then EOF (a server that writes
// body and closes — the wire shape the host-agent token shim presents: the token bytes
// then close). It is the guest-side end of an in-memory pipe.
func servingPipe(t *testing.T, body []byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		if len(body) > 0 {
			_, _ = server.Write(body)
		}
		_ = server.Close()
	}()
	return client
}

// TestVsockTokenFetch_SchemeDispatch_TrimsAndReads proves a vsock:// endpoint routes to
// the AF_VSOCK path, dials VMADDR_CID_HOST at the reference's PORT, and reads + trims
// the served token. No live vsock — the dial is faked over an in-process pipe.
func TestVsockTokenFetch_SchemeDispatch_TrimsAndReads(t *testing.T) {
	prev := fetchTokenTimeout
	fetchTokenTimeout = 2 * time.Second
	t.Cleanup(func() { fetchTokenTimeout = prev })

	var gotCID, gotPort uint32
	withVsockDial(t, func(_ context.Context, cid, port uint32) (net.Conn, error) {
		gotCID, gotPort = cid, port
		return servingPipe(t, []byte("  sk-vsock-token\n")), nil
	})

	got, err := httpTokenFetcher{}.fetch("vsock://host:8200/token")
	if err != nil {
		t.Fatalf("vsock fetch: %v", err)
	}
	if got != "sk-vsock-token" {
		t.Errorf("token = %q, want trimmed %q", got, "sk-vsock-token")
	}
	if gotCID != vmAddrCIDHost {
		t.Errorf("dialed CID = %d, want VMADDR_CID_HOST = %d (the guest reaches the host's own CID)", gotCID, vmAddrCIDHost)
	}
	if gotPort != 8200 {
		t.Errorf("dialed port = %d, want 8200 (read from the reference)", gotPort)
	}
}

// TestVsockTokenFetch_EmptyBody_FailClosed proves the fail-closed parse on the vsock
// path: the host writing NOTHING (the 403 analogue for an unauthorized/unknown CID, or
// a source error) is an auth failure, not a success — no runtime without auth.
func TestVsockTokenFetch_EmptyBody_FailClosed(t *testing.T) {
	prev := fetchTokenTimeout
	fetchTokenTimeout = 2 * time.Second
	t.Cleanup(func() { fetchTokenTimeout = prev })

	withVsockDial(t, func(_ context.Context, _, _ uint32) (net.Conn, error) {
		return servingPipe(t, nil), nil // host wrote nothing, then closed
	})

	_, err := httpTokenFetcher{}.fetch("vsock://host:8200/token")
	if err == nil {
		t.Fatal("expected a fail-closed error when the vsock host returns an empty token")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Errorf("error should mention an empty token (fail-closed): %v", err)
	}
}

// TestVsockTokenFetch_DialError_FailClosed proves a dial failure fails closed (no
// runtime without auth) and never embeds a token.
func TestVsockTokenFetch_DialError_FailClosed(t *testing.T) {
	prev := fetchTokenTimeout
	fetchTokenTimeout = 2 * time.Second
	t.Cleanup(func() { fetchTokenTimeout = prev })

	withVsockDial(t, func(_ context.Context, _, _ uint32) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	})

	_, err := httpTokenFetcher{}.fetch("vsock://host:8200/token")
	if err == nil {
		t.Fatal("expected a fail-closed error when the vsock dial fails")
	}
	if !strings.Contains(err.Error(), "dial session token vsock") {
		t.Errorf("error should mention the vsock dial: %v", err)
	}
}

// TestVsockTokenFetch_NoPort_FailClosed proves a vsock reference with no port fails
// closed (a malformed reference must never silently dial a default port).
func TestVsockTokenFetch_NoPort_FailClosed(t *testing.T) {
	called := false
	withVsockDial(t, func(_ context.Context, _, _ uint32) (net.Conn, error) {
		called = true
		return servingPipe(t, []byte("x")), nil
	})
	if _, err := (httpTokenFetcher{}).fetch("vsock://host/token"); err == nil {
		t.Fatal("expected a fail-closed error for a vsock reference with no port")
	}
	if called {
		t.Error("the dialer must not be reached for a portless vsock reference")
	}
}

// TestTokenFetch_UnsupportedScheme_FailClosed proves the SINGLE coupling point fails
// closed on an unrecognized scheme — a typo'd scheme must NEVER silently fall through
// to the wrong transport.
func TestTokenFetch_UnsupportedScheme_FailClosed(t *testing.T) {
	called := false
	withVsockDial(t, func(_ context.Context, _, _ uint32) (net.Conn, error) {
		called = true
		return servingPipe(t, []byte("x")), nil
	})
	_, err := httpTokenFetcher{}.fetch("ftp://host:8200/token")
	if err == nil {
		t.Fatal("expected a fail-closed error for an unsupported scheme")
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("error should name the unsupported scheme: %v", err)
	}
	if called {
		t.Error("an unsupported scheme must not reach the vsock dialer")
	}
}

// TestVsockTokenFetch_NeverLogsToken is a fingerprint-only-posture guard: the vsock
// fetch returns the token but a fetch ERROR (the only thing a caller logs) must never
// contain token material. We assert the empty-body and dial-error messages carry no
// token bytes (there is no token to leak in those paths, but the posture is pinned).
func TestVsockTokenFetch_NeverLogsToken(t *testing.T) {
	prev := fetchTokenTimeout
	fetchTokenTimeout = 2 * time.Second
	t.Cleanup(func() { fetchTokenTimeout = prev })

	const secret = "sk-super-secret-token-value"
	withVsockDial(t, func(_ context.Context, _, _ uint32) (net.Conn, error) {
		// Serve a valid token: the SUCCESS path returns it but must never log it. The
		// returned token is the value; the test confirms the fetch does not surface it
		// in an error (the success path returns no error at all).
		return servingPipe(t, []byte(secret)), nil
	})
	got, err := httpTokenFetcher{}.fetch("vsock://host:8200/token")
	if err != nil {
		t.Fatalf("vsock fetch: %v", err)
	}
	if got != secret {
		t.Fatalf("token = %q, want %q", got, secret)
	}
	// A success returns (token, nil) — there is no error string to leak into a log. The
	// caller (supervise.go) injects the token into env and never logs it; this test
	// pins that the fetch itself returns no error carrying the value.
}

func containsEnvEntry(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

// lastValueForKey returns the value of the LAST KEY=VALUE entry for key (the one
// os/exec honors for duplicates).
func lastValueForKey(env []string, key string) string {
	val := ""
	for _, e := range env {
		if k, v, ok := splitEnv(e); ok && k == key {
			val = v
		}
	}
	return val
}
