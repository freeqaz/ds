// SPDX-License-Identifier: Apache-2.0

package nethelperclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperproto"
)

// fakeHelper writes an executable shell script standing in for the installed
// helper: it emits the scripted stdout line and exits with the scripted code,
// echoing $1 so op-echo behavior is scriptable.
func fakeHelper(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ds-nethelper")
	full := "#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\nset -u\n" + script
	if err := os.WriteFile(path, []byte(full), 0o755); err != nil {
		t.Fatalf("write fake helper: %v", err)
	}
	return path
}

func mustClient(t *testing.T, path string) *Client {
	t.Helper()
	c, err := New(path)
	if err != nil {
		t.Fatalf("New(%q): %v", path, err)
	}
	return c
}

func TestNewRejectsNonAbsolutePath(t *testing.T) {
	tests := []string{"", "ds-nethelper", "./ds-nethelper", "bin/ds-nethelper"}
	for _, p := range tests {
		if _, err := New(p); err == nil {
			t.Fatalf("New(%q) accepted a non-absolute helper path", p)
		}
	}
}

func TestOutcomeMapping(t *testing.T) {
	v := nethelperproto.ProtocolVersion
	tests := []struct {
		name    string
		script  string
		wantErr error // nil = success
	}{
		{
			"ok",
			fmt.Sprintf(`printf '{"v":%d,"op":"%%s","ok":true,"code":"OK"}\n' "$1"; exit 0`, v),
			nil,
		},
		{
			"validation nack",
			fmt.Sprintf(`printf '{"v":%d,"op":"%%s","ok":false,"code":"EARG","message":"tap_name disagrees"}\n' "$1"; exit 2`, v),
			ErrValidation,
		},
		{
			"backend fault",
			fmt.Sprintf(`printf '{"v":%d,"op":"%%s","ok":false,"code":"EBACKEND","message":"ds-nft rc=-2"}\n' "$1"; exit 3`, v),
			ErrBackend,
		},
		{
			"not built",
			fmt.Sprintf(`printf '{"v":%d,"op":"%%s","ok":false,"code":"ENOTBUILT"}\n' "$1"; exit 4`, v),
			ErrNotBuilt,
		},
		{
			"version skew",
			fmt.Sprintf(`printf '{"v":%d,"op":"%%s","ok":true,"code":"OK"}\n' "$1"; exit 0`, v+1),
			ErrProtocol,
		},
		{
			"op echo mismatch",
			fmt.Sprintf(`printf '{"v":%d,"op":"delete-tap","ok":true,"code":"OK"}\n'; exit 0`, v),
			ErrProtocol,
		},
		{
			"garbage stdout",
			`echo 'not json'; exit 0`,
			ErrProtocol,
		},
		{
			"exec failure no output",
			`exit 7`,
			ErrProtocol,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustClient(t, fakeHelper(t, tt.script))
			err := c.CreateTap(context.Background(), "dstap-7", 1000, 7, "")
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("want errors.Is(%v), got %v", tt.wantErr, err)
			}
		})
	}
}

// The client must pass exactly one argv (the op) and the params object on
// stdin — the fake records both and the test asserts the wire shape.
func TestWireShape(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "rec")
	script := fmt.Sprintf(
		`{ printf 'argv:%%s\n' "$*"; printf 'stdin:'; cat; } > %q
printf '{"v":%d,"op":"%%s","ok":true,"code":"OK"}\n' "$1"`,
		rec, nethelperproto.ProtocolVersion)
	c := mustClient(t, fakeHelper(t, script))
	if err := c.FlushSession(context.Background(), "dstap-9", 9); err != nil {
		t.Fatalf("flush: %v", err)
	}
	b, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	got := string(b)
	want := "argv:flush-session\nstdin:{\"tap_name\":\"dstap-9\",\"host_session_index\":9}\n"
	if got != want {
		t.Fatalf("wire shape mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// A fully-configured host (+eip: built, effective, inheritable, ambient-
// raisable) probes Ready.
func TestProbeReady(t *testing.T) {
	script := fmt.Sprintf(
		`printf '{"v":%d,"op":"%%s","ok":true,"code":"OK","built":true,"cap_net_admin_effective":true,"cap_net_admin_inheritable":true,"ambient_raise_ok":true}\n' "$1"`,
		nethelperproto.ProtocolVersion)
	c := mustClient(t, fakeHelper(t, script))
	st, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !st.Built || !st.CapNetAdminEffective || !st.CapNetAdminInheritable || !st.AmbientRaiseOK {
		t.Fatalf("probe status = %+v, want all true", st)
	}
	if !st.Ready() {
		t.Fatalf("fully-configured host not Ready(): %+v", st)
	}
}

// The whole capability-propagation graft exists to catch the +ep-only host:
// helper effective-green, but no inheritable/ambient path, so every ip/nft
// child ds-nft execs is stranded unprivileged. Such a host must NOT be Ready.
func TestProbeEpOnlyNotReady(t *testing.T) {
	script := fmt.Sprintf(
		`printf '{"v":%d,"op":"%%s","ok":true,"code":"OK","built":true,"cap_net_admin_effective":true,"cap_net_admin_inheritable":false,"ambient_raise_ok":false}\n' "$1"`,
		nethelperproto.ProtocolVersion)
	c := mustClient(t, fakeHelper(t, script))
	st, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if st.Ready() {
		t.Fatalf("+ep-only host reported Ready(): %+v (the graft failed to catch a stranded-children host)", st)
	}
}

// TeardownAll must run ALL three legs even when an early leg fails, and join
// the failures — a partial unwind is converged by idempotent retry, never by
// skipping legs.
func TestTeardownAllBestEffort(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "ops")
	script := fmt.Sprintf(
		`printf '%%s\n' "$1" >> %q
cat >/dev/null
if [ "$1" = "flush-session" ]; then
  printf '{"v":%d,"op":"%%s","ok":false,"code":"EBACKEND","message":"conntrack fault"}\n' "$1"
  exit 3
fi
printf '{"v":%d,"op":"%%s","ok":true,"code":"OK"}\n' "$1"`,
		rec, nethelperproto.ProtocolVersion, nethelperproto.ProtocolVersion)
	c := mustClient(t, fakeHelper(t, script))
	err := c.TeardownAll(context.Background(), "dstap-3", 3)
	if !errors.Is(err, ErrBackend) {
		t.Fatalf("want joined ErrBackend, got %v", err)
	}
	b, rerr := os.ReadFile(rec)
	if rerr != nil {
		t.Fatalf("read recording: %v", rerr)
	}
	want := "flush-session\nteardown-session\ndelete-tap\n"
	if string(b) != want {
		t.Fatalf("teardown legs = %q, want %q (fixed NFT-6 order, all legs best-effort)", string(b), want)
	}
}
