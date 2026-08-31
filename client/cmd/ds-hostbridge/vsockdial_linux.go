// SPDX-License-Identifier: Apache-2.0

//go:build linux

// vsockdial_linux.go is the host→guest AF_VSOCK carriage dialer for ds-hostbridge's
// serve mode. The attach control channel rides virtio-vsock (m1-live-session-transport
// spike): the host agent dials the session's deterministic per-session guest context id
// (Binding.VsockCID) on the fixed attach port, replacing the old GuestIP:4242 TCP dial —
// no tap, no guest IP, no nft on the attach path.
//
// STDLIB-ONLY (client/go.mod is standard-library only, D80). There is no AF_VSOCK net
// dialer in the stdlib and the client tree may NOT pull golang.org/x/sys or a third-party
// vsock package, so this dials with a RAW SYSCALL: syscall.Socket(AF_VSOCK, SOCK_STREAM)
// + a manually-encoded sockaddr_vm fed to SYS_CONNECT via syscall.Syscall, then wraps the
// connected fd as a net.Conn (os.NewFile + net.FileConn). The sockaddr_vm encoding is split
// out as a PURE function (encodeSockaddrVM) so the offline unit test asserts the byte layout
// without any live connect — the real AF_VSOCK byte path to a guest is operator-validated on
// the KVM box (DS_HOSTAGENT_LIVE), never in a test.
//
// linux-only: AF_VSOCK is a Linux address family; this file is build-tagged so non-linux
// builds (developer macOS, CI cross-builds) exclude it. The host agent that execs this
// serving child runs on the Linux KVM host, so the production path is always linux.

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// AF_VSOCK is the Linux address family for virtio-vsock sockets (include/linux/socket.h
// AF_VSOCK = 40). It is not exported by the syscall package on all toolchains, so it is
// named here as the documented kernel constant.
const afVsock = 40

// vsockSockaddrLen is the wire size of struct sockaddr_vm (linux/vm_sockets.h):
//
//	struct sockaddr_vm {
//	    __kernel_sa_family_t svm_family;   // 2 bytes
//	    unsigned short       svm_reserved1; // 2 bytes
//	    unsigned int         svm_port;      // 4 bytes
//	    unsigned int         svm_cid;       // 4 bytes
//	    __u8 svm_zero[sizeof(struct sockaddr) - ...]; // 4 trailing zero bytes
//	};
//
// 16 bytes total (the same size as struct sockaddr) — the connect(2) addrlen the kernel
// expects for an AF_VSOCK address.
const vsockSockaddrLen = 16

// encodeSockaddrVM builds the raw struct sockaddr_vm bytes for (cid, port) in NATIVE byte
// order — the layout the kernel's connect(2) reads. It is a PURE function (no syscall) so
// the offline test asserts the exact field offsets/values without a live AF_VSOCK connect.
// Native byte order matches how the kernel copies the struct from user memory (the family,
// port, and cid are host-endian integers in the C struct, not network order).
func encodeSockaddrVM(cid, port uint32) [vsockSockaddrLen]byte {
	var sa [vsockSockaddrLen]byte
	// svm_family (offset 0, __kernel_sa_family_t = unsigned short, native order).
	*(*uint16)(unsafe.Pointer(&sa[0])) = uint16(afVsock)
	// svm_reserved1 (offset 2) stays zero.
	// svm_port (offset 4, unsigned int, native order).
	*(*uint32)(unsafe.Pointer(&sa[4])) = port
	// svm_cid (offset 8, unsigned int, native order).
	*(*uint32)(unsafe.Pointer(&sa[8])) = cid
	// svm_zero (offset 12..15) stays zero.
	return sa
}

// dialVsock opens a connected AF_VSOCK stream to (cid, port) and returns it as a net.Conn.
// It is the production host→guest carriage dial: a raw syscall.Socket + connect(2) via
// SYS_CONNECT, the fd then adopted by the os/net machinery (os.NewFile + net.FileConn) so
// the rest of serve mode treats it as an ordinary net.Conn (Pump / Bridge / Splice are
// transport-agnostic). The real connect reaches a live guest only on the KVM box; in the
// offline test the dialer is never invoked (the test feeds an in-process fake conn through
// the same serveUDS core), so no live vsock-to-a-guest is exercised here.
func dialVsock(cid, port uint32) (net.Conn, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock: socket(AF_VSOCK, SOCK_STREAM): %w", err)
	}
	sa := encodeSockaddrVM(cid, port)
	_, _, errno := syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sa[0])),
		uintptr(vsockSockaddrLen),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock: connect(cid=%d port=%d): %w", cid, port, errno)
	}
	// Adopt the connected fd as a net.Conn. os.NewFile takes ownership of fd and
	// registers it with the runtime poller (non-blocking, deadline-capable).
	// net.FileConn CANNOT adopt an AF_VSOCK fd ("protocol not supported", live-found
	// 2026-06-16), so wrap the *os.File directly — Pump/Bridge/Splice need only
	// Read/Write/Close + deadlines, all provided by *os.File.
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d:%d", cid, port))
	if f == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock: os.NewFile failed for fd %d", fd)
	}
	return &vsockConn{File: f, cid: cid, port: port}, nil
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
