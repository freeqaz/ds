// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// vsockdial_other.go is the non-linux companion to vsockdial_linux.go. AF_VSOCK is a
// Linux-only address family, so the raw-syscall dialer cannot exist off Linux — but
// main.go references dialVsock UNCONDITIONALLY (the production serve-mode carriage wiring
// is not itself build-tagged), so a non-linux build (developer macOS, a CI cross-build)
// would fail to compile with "undefined: dialVsock" if the symbol were absent. This file
// supplies the symbol on every non-linux platform as an honest, fail-closed stub: it
// never dials anything (there is no AF_VSOCK to dial), it returns an error naming the
// unsupported platform. The host agent that execs this serving child always runs on the
// Linux KVM host, so the real carriage is always the linux dialer; this stub only keeps
// the cross-platform build green (the file header in vsockdial_linux.go promises non-linux
// builds exclude the real dialer — this is what makes that promise true without breaking
// the unconditional call site).

package main

import (
	"fmt"
	"net"
	"runtime"
)

// dialVsock is the non-linux stub: AF_VSOCK does not exist off Linux, so the host→guest
// carriage cannot be dialed here. It returns a fail-closed error rather than a nil conn so
// any (mis)use on a non-linux platform is loud, never a silent no-carriage serve. The real
// dialer is vsockdial_linux.go (the only platform the serving child ever runs on).
func dialVsock(cid, port uint32) (net.Conn, error) {
	return nil, fmt.Errorf("vsock: AF_VSOCK carriage is linux-only; cannot dial cid=%d port=%d on %s", cid, port, runtime.GOOS)
}
