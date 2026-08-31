// SPDX-License-Identifier: Apache-2.0

//go:build linux

// vsockfetch_linux.go is the in-guest AF_VSOCK dialer for the D22 session-token fetch
// (U5). It is the trivial connect-side mirror of vm/attachfwd's listenVsock: the guest
// dials the host-agent token shim at VMADDR_CID_HOST(2):<port> and is authorized by
// its OWN unforgeable connecting CID (the host derives the session from the CID and
// serves ONLY that session's token; the guest sends NOTHING identifying). It uses
// golang.org/x/sys/unix (already a DIRECT dep of vm/ for the attach carriage) — no
// raw-syscall gymnastics, unlike the stdlib-only client tree.
//
// linux-only: AF_VSOCK is a Linux address family. The guest is ALWAYS linux; the
// !linux companion (vsockfetch_other.go) keeps dev/CI cross-builds green.

package entrypoint

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// dialTokenVsock opens a connected AF_VSOCK stream to (cid, port) and returns it as a
// net.Conn. The connect respects ctx by closing the fd if ctx is already done before
// the (non-blocking on a host-local vsock) connect; the caller additionally bounds the
// read with the same deadline. It is the production guest->host token dial — reaching a
// live host only on the KVM box; the offline test injects an in-process fake conn
// through the scheme-dispatching fetcher, so no live vsock connect runs in a unit test.
func dialTokenVsock(ctx context.Context, cid, port uint32) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("vsock token dial: context done before connect: %w", err)
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}
	sa := &unix.SockaddrVM{CID: cid, Port: port}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect(cid=%d port=%d): %w", cid, port, err)
	}
	// os.NewFile takes ownership of fd and registers it with the runtime poller
	// (non-blocking, deadline-capable). net.FileConn CANNOT adopt an AF_VSOCK fd
	// ("protocol not supported", live-found 2026-06-16 — see attachfwd/forwarder.go +
	// vsockdial_linux.go), so wrap the *os.File directly as a net.Conn.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d:%d", cid, port))
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock token dial: os.NewFile on connected fd %d", fd)
	}
	return &vsockConn{File: file, cid: cid, port: port}, nil
}

// vsockConn adapts an AF_VSOCK *os.File to net.Conn (net.FileConn rejects AF_VSOCK).
// Read/Write/Close + the deadline methods come from the embedded pollable *os.File;
// only the two address methods net.Conn additionally requires are supplied here.
type vsockConn struct {
	*os.File
	cid, port uint32
}

func (c *vsockConn) LocalAddr() net.Addr  { return vsockNetAddr{} }
func (c *vsockConn) RemoteAddr() net.Addr { return vsockNetAddr{cid: c.cid, port: c.port} }

// vsockNetAddr is the net.Addr for an AF_VSOCK endpoint.
type vsockNetAddr struct{ cid, port uint32 }

func (vsockNetAddr) Network() string  { return "vsock" }
func (a vsockNetAddr) String() string { return fmt.Sprintf("vsock:%d:%d", a.cid, a.port) }
