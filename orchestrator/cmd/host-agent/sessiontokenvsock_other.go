// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// sessiontokenvsock_other.go is the non-linux companion to sessiontokenvsock_linux.go.
// AF_VSOCK is a Linux-only address family, so the host-side token listener cannot exist
// off Linux — but sessiontokenshim.go references listenTokenVsock UNCONDITIONALLY (the
// shim's listener factory is not itself build-tagged), so a non-linux build (developer
// macOS, a CI cross-build) would fail to compile with "undefined: listenTokenVsock" if
// the symbol were absent. This file supplies it on every non-linux platform as an
// honest, fail-closed stub: it never binds anything (there is no AF_VSOCK to bind) and
// returns an error naming the unsupported platform. The daemon only runs on the linux
// KVM host, so the real listener is always the linux one; this stub only keeps the
// cross-platform build green.

package main

import (
	"fmt"
	"runtime"
)

// listenTokenVsock is the non-linux stub: AF_VSOCK does not exist off Linux, so the
// host-side D22 token listener cannot be bound here. It returns a fail-closed error
// rather than a nil listener so any (mis)use on a non-linux platform is loud, never a
// silent no-listener serve. The real listener is sessiontokenvsock_linux.go (the only
// platform the daemon ever runs on).
func listenTokenVsock(port uint32) (peerCIDListener, error) {
	return nil, fmt.Errorf("session-token shim: AF_VSOCK is linux-only; cannot listen on port %d on %s", port, runtime.GOOS)
}
