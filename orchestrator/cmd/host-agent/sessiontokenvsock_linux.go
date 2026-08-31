// SPDX-License-Identifier: Apache-2.0

//go:build linux

// sessiontokenvsock_linux.go isolates the host-side AF_VSOCK socket creation for the
// D22 session-token shim behind listenTokenVsock, exactly like vm/attachfwd's
// listenVsock and client/cmd/ds-hostbridge's vsockdial. The authz core
// (sessiontokenshim.go) only ever sees a peerCIDConn — it never touches the raw fd —
// so it stays pure + unit-testable over a fake accepted-conn carrying a chosen peer
// CID (NO live vsock needed). This file is the only place a real AF_VSOCK socket is
// bound; it is operator-validated on the KVM box, never in a unit test.
//
// HOST SIDE: the host LISTENS on VMADDR_CID_HOST(2):<port> and the guest dials it.
// (The attach carriage is the mirror: the GUEST listens on VMADDR_CID_ANY and the
// host dials the guest CID.) On accept, unix.Accept returns the peer Sockaddr — a
// *unix.SockaddrVM whose .CID is the connecting guest's UNFORGEABLE CID; that CID is
// the whole credential the shim authorizes on.
//
// linux-only: AF_VSOCK is a Linux address family. The daemon only runs on the linux
// KVM host; the !linux companion (sessiontokenvsock_other.go) keeps cross-builds green.

package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// tokenVsockListener adapts a raw AF_VSOCK listening socket to peerCIDListener so the
// shim's accept loop stays transport-agnostic. Each Accept yields a *tokenVsockConn
// that reports the connecting guest's peer CID.
type tokenVsockListener struct {
	fd   int
	addr tokenVsockAddr
}

// tokenVsockAddr is a net.Addr for an AF_VSOCK endpoint (CID:port).
type tokenVsockAddr struct {
	cid  uint32
	port uint32
}

func (a tokenVsockAddr) Network() string { return "vsock" }
func (a tokenVsockAddr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.cid, a.port) }

// listenTokenVsock binds a SOCK_STREAM AF_VSOCK socket to VMADDR_CID_HOST:port (the
// HOST side — the guest dials this CID) and starts listening. It returns a
// peerCIDListener so the authz core authorizes by the connecting guest's CID.
func listenTokenVsock(port uint32) (peerCIDListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}
	// VMADDR_CID_HOST(2) is the host's own CID: the guest reaches the host-agent token
	// shim at host-CID:port over virtio-vsock. (The guest cannot reach this by naming
	// any other session — it can only present its OWN source CID, which is the authz.)
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind(VMADDR_CID_HOST:%d): %w", port, err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}
	return &tokenVsockListener{fd: fd, addr: tokenVsockAddr{cid: unix.VMADDR_CID_HOST, port: port}}, nil
}

// Accept blocks for the next guest dial and wraps the accepted fd as a peerCIDConn,
// reading the connecting guest's CID from the *unix.SockaddrVM unix.Accept returns —
// that CID is the unforgeable proof of session identity the shim authorizes on.
func (l *tokenVsockListener) Accept() (peerCIDConn, error) {
	nfd, sa, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(nfd)

	// Read the peer CID from the returned Sockaddr. For AF_VSOCK it is a
	// *unix.SockaddrVM; anything else is a kernel/programming error — fail closed.
	vsa, ok := sa.(*unix.SockaddrVM)
	if !ok {
		unix.Close(nfd)
		return nil, fmt.Errorf("session-token shim accept: peer sockaddr is %T, want *unix.SockaddrVM", sa)
	}
	peerCID := vsa.CID

	// os.NewFile takes ownership of nfd and registers it with the runtime poller.
	// net.FileConn CANNOT adopt an AF_VSOCK fd ("protocol not supported", live-found
	// 2026-06-16 — see attachfwd/forwarder.go + vsockdial_linux.go), so wrap the
	// *os.File directly as a net.Conn.
	file := os.NewFile(uintptr(nfd), l.addr.String())
	if file == nil {
		unix.Close(nfd)
		return nil, fmt.Errorf("session-token shim accept: os.NewFile on accepted vsock fd %d", nfd)
	}
	return &tokenVsockConn{File: file, addr: l.addr, peerCID: peerCID}, nil
}

// Close stops the listener; a pending Accept unblocks with an error.
func (l *tokenVsockListener) Close() error { return unix.Close(l.fd) }

// Addr reports the bound AF_VSOCK address (CID:port).
func (l *tokenVsockListener) Addr() net.Addr { return l.addr }

// tokenVsockConn adapts an AF_VSOCK *os.File to peerCIDConn. net.FileConn rejects
// AF_VSOCK, so we embed the pollable *os.File (Read/Write/Close + the deadline methods
// come from it) and supply the address methods plus PeerCID() (the connecting guest's
// unforgeable CID, the whole authz credential).
type tokenVsockConn struct {
	*os.File
	addr    tokenVsockAddr
	peerCID uint32
}

func (c *tokenVsockConn) LocalAddr() net.Addr { return c.addr }
func (c *tokenVsockConn) RemoteAddr() net.Addr {
	return tokenVsockAddr{cid: c.peerCID, port: c.addr.port}
}

// PeerCID reports the connecting guest's AF_VSOCK CID — the unforgeable proof of
// session identity the shim authorizes on.
func (c *tokenVsockConn) PeerCID() uint32 { return c.peerCID }
