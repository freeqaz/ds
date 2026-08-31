// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// vsockfetch_other.go is the non-linux companion to vsockfetch_linux.go. AF_VSOCK is a
// Linux-only address family, so the in-guest token dialer cannot exist off Linux — but
// tokenfetch.go references dialTokenVsock UNCONDITIONALLY (the scheme-dispatching
// fetcher is not itself build-tagged), so a non-linux build (developer macOS, a CI
// cross-build) would fail to compile with "undefined: dialTokenVsock" if the symbol
// were absent. This file supplies it on every non-linux platform as an honest,
// fail-closed stub: it never dials anything (there is no AF_VSOCK to dial) and returns
// an error naming the unsupported platform. The guest is ALWAYS linux, so the real
// dialer is always the linux one; this stub only keeps the cross-platform build green.

package entrypoint

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// dialTokenVsock is the non-linux stub: AF_VSOCK does not exist off Linux, so the
// guest->host token dial cannot happen here. It returns a fail-closed error rather than
// a nil conn so any (mis)use on a non-linux platform is loud, never a silent
// no-transport fetch. The real dialer is vsockfetch_linux.go (the only platform the
// guest ever runs on).
func dialTokenVsock(_ context.Context, cid, port uint32) (net.Conn, error) {
	return nil, fmt.Errorf("vsock token dial: AF_VSOCK is linux-only; cannot dial cid=%d port=%d on %s", cid, port, runtime.GOOS)
}
