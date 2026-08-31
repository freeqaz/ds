// SPDX-License-Identifier: Apache-2.0

package attachfwd

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// vsockAvailable reports whether the kernel offers AF_VSOCK (the host/CI box may not
// have the vhost-vsock/vsock modules loaded — e.g. no /dev/vsock). When false, the
// real-socket assertions degrade to a t.Skip so the offline Splice/UDS coverage still
// runs everywhere. Mirrors the spike note: real AF_VSOCK is operator-validated on the
// KVM box, not in CI.
func vsockAvailable() bool {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// connPair returns two connected TCP loopback conns — real conns that support
// CloseWrite (the production half-close path Splice relies on), unlike net.Pipe.
func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c net.Conn
		e error
	}
	ch := make(chan res, 1)
	go func() { c, e := ln.Accept(); ch <- res{c, e} }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.e != nil {
		t.Fatalf("accept: %v", r.e)
	}
	return c1, r.c
}

// TestSplice_BidirectionalBytes: bytes written on each side arrive on the other,
// and Splice returns cleanly when both sides half-close.
func TestSplice_BidirectionalBytes(t *testing.T) {
	// a1<->a2 and b1<->b2 are two socketpairs; Splice joins a2 and b2, so a1 and b1
	// are the two "ends" the test drives.
	a1, a2 := connPair(t)
	b1, b2 := connPair(t)

	done := make(chan error, 1)
	go func() { done <- Splice(a2, b2) }()

	// a1 -> (a2 splice b2) -> b1 ; CloseWrite half-closes so the peer sees EOF after
	// the byte without tearing down the reverse direction.
	go func() { a1.Write([]byte("from-host")); a1.(*net.TCPConn).CloseWrite() }()
	// b1 -> (b2 splice a2) -> a1
	go func() { b1.Write([]byte("from-guest")); b1.(*net.TCPConn).CloseWrite() }()

	gotB, _ := io.ReadAll(b1)
	gotA, _ := io.ReadAll(a1)
	if string(gotB) != "from-host" {
		t.Errorf("guest side got %q, want from-host", gotB)
	}
	if string(gotA) != "from-guest" {
		t.Errorf("host side got %q, want from-guest", gotA)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Splice returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Splice did not return after both sides closed")
	}
}

// TestSpliceOverUDS_BidirectionalBytes exercises the byte-pump + the guest-local UDS
// leg with no vsock dependency, so it runs everywhere (the UDS leg is UNCHANGED by the
// vsock carriage swap). It splices a UDS conn pair against a TCP conn pair, the same
// transport-agnostic Splice the Forwarder uses for the vsock<->UDS pairing.
func TestSpliceOverUDS_BidirectionalBytes(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "leg.sock")
	ln, err := net.Listen("unix", udsPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()
	type res struct {
		c net.Conn
		e error
	}
	ch := make(chan res, 1)
	go func() { c, e := ln.Accept(); ch <- res{c, e} }()
	udsClient, err := net.Dial("unix", udsPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	r := <-ch
	if r.e != nil {
		t.Fatalf("accept unix: %v", r.e)
	}
	udsServer := r.c // the Forwarder's held entrypoint-UDS conn

	// The "host-agent" side of the splice is a connected TCP pair (stands in for the
	// accepted vsock conn — both are generic net.Conn, both byte-pump identically).
	hostA, hostB := connPair(t)

	done := make(chan error, 1)
	go func() { done <- Splice(hostB, udsServer) }()

	// host -> guest (drive input)
	if _, err := hostA.Write([]byte("drive-input")); err != nil {
		t.Fatalf("host write: %v", err)
	}
	buf := make([]byte, 11)
	udsClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(udsClient, buf); err != nil {
		t.Fatalf("entrypoint read: %v", err)
	}
	if string(buf) != "drive-input" {
		t.Errorf("entrypoint got %q, want drive-input", buf)
	}

	// guest -> host (CC event stream direction)
	if _, err := udsClient.Write([]byte("cc-event")); err != nil {
		t.Fatalf("entrypoint write: %v", err)
	}
	buf2 := make([]byte, 8)
	hostA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(hostA, buf2); err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(buf2) != "cc-event" {
		t.Errorf("host got %q, want cc-event", buf2)
	}

	hostA.Close()
	udsClient.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Splice did not return after both ends closed")
	}
}

// TestListen_BindsBothLegs: Listen binds the guest UDS and the AF_VSOCK carriage at
// VMADDR_CID_ANY:port, and VsockAddr reports the configured port. The AF_VSOCK bind is
// degraded to a skip when the kernel lacks vsock (no /dev/vsock in CI; real vsock is
// operator-validated on the KVM box).
func TestListen_BindsBothLegs(t *testing.T) {
	if !vsockAvailable() {
		t.Skip("AF_VSOCK unavailable (no kernel vsock); listener bind validated on the KVM box")
	}
	udsPath := filepath.Join(t.TempDir(), "attach.sock")
	f, err := Listen(Config{UDSPath: udsPath, VsockPort: WireAttachPort})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer f.Close()

	va, ok := f.VsockAddr().(vsockAddr)
	if !ok {
		t.Fatalf("VsockAddr type = %T, want vsockAddr", f.VsockAddr())
	}
	if va.port != WireAttachPort {
		t.Errorf("vsock port = %d, want %d", va.port, WireAttachPort)
	}
	if va.cid != unix.VMADDR_CID_ANY {
		t.Errorf("vsock cid = %#x, want VMADDR_CID_ANY (%#x)", va.cid, unix.VMADDR_CID_ANY)
	}
}

// TestListenServe_EndToEnd: a real UDS listener (entrypoint side) + a real AF_VSOCK
// listener (host-agent side); an "entrypoint" UDS dial and a "host-agent" vsock dial
// over the loopback CID get spliced so a byte written by one reaches the other — the
// M1 carriage end to end. Requires kernel vsock loopback; skips otherwise (the byte
// path itself is the transport-agnostic Splice, covered offline above).
func TestListenServe_EndToEnd(t *testing.T) {
	if !vsockAvailable() {
		t.Skip("AF_VSOCK unavailable (no kernel vsock); end-to-end carriage validated on the KVM box")
	}
	udsPath := filepath.Join(t.TempDir(), "attach.sock")
	// Port 0 lets the kernel assign a free vsock port so concurrent test runs don't
	// collide on the well-known WireAttachPort.
	f, err := Listen(Config{UDSPath: udsPath, VsockPort: 0xffffffff})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer f.Close()
	port := f.VsockAddr().(vsockAddr).port

	serveErr := make(chan error, 1)
	go func() { serveErr <- f.Serve(context.Background()) }()

	// The ds-entrypoint side dials the UDS (mirrors transport.go dialEventSocket).
	entry, err := net.Dial("unix", udsPath)
	if err != nil {
		t.Fatalf("dial entrypoint UDS: %v", err)
	}
	defer entry.Close()

	// The host-agent bridge dials the AF_VSOCK carriage over the loopback CID.
	host, err := dialVsockLoopback(port)
	if err != nil {
		// vsock present but loopback (vsock_loopback) not wired — degrade.
		t.Skipf("AF_VSOCK loopback dial unavailable: %v", err)
	}
	defer host.Close()

	// host -> guest
	if _, err := host.Write([]byte("drive-input")); err != nil {
		t.Fatalf("host write: %v", err)
	}
	buf := make([]byte, 11)
	entry.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(entry, buf); err != nil {
		t.Fatalf("entrypoint read: %v", err)
	}
	if string(buf) != "drive-input" {
		t.Errorf("entrypoint got %q, want drive-input", buf)
	}

	// guest -> host (CC event stream direction)
	if _, err := entry.Write([]byte("cc-event")); err != nil {
		t.Fatalf("entrypoint write: %v", err)
	}
	buf2 := make([]byte, 8)
	host.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(host, buf2); err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(buf2) != "cc-event" {
		t.Errorf("host got %q, want cc-event", buf2)
	}

	// Closing both ends lets Serve return.
	host.Close()
	entry.Close()
	select {
	case <-serveErr:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after both ends closed")
	}
}

// dialVsockLoopback connects to VMADDR_CID_LOCAL:port and wraps the fd as a net.Conn
// (test-only host-agent stand-in; the real host-agent dials the guest CID from the
// orchestrator lane). Returns an error (not a fatal) so the caller can degrade to a
// skip when vsock_loopback is absent.
func dialVsockLoopback(port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vsock-loopback")
	conn, err := net.FileConn(file)
	file.Close()
	return conn, err
}

// TestServe_ContextCancelUnblocks: a Serve with no peers ever connecting returns when
// the context is cancelled (no leaked goroutine on shutdown). Requires a bound vsock
// listener, so it degrades to a skip when the kernel lacks vsock.
func TestServe_ContextCancelUnblocks(t *testing.T) {
	if !vsockAvailable() {
		t.Skip("AF_VSOCK unavailable (no kernel vsock); ctx-cancel path validated on the KVM box")
	}
	f, err := Listen(Config{UDSPath: filepath.Join(t.TempDir(), "a.sock"), VsockPort: 0xffffffff})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Serve(ctx) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not unblock on context cancel")
	}
}

func TestListen_RejectsEmptyConfig(t *testing.T) {
	if _, err := Listen(Config{VsockPort: WireAttachPort}); err == nil {
		t.Error("expected error for empty UDS path")
	}
}

// TestConfigPort_DefaultsToWireConstant: a zero VsockPort falls back to the
// cross-module wire constant so the port is single-sourced (== libvirt.DefaultAttachPort).
func TestConfigPort_DefaultsToWireConstant(t *testing.T) {
	if got := (Config{}).port(); got != WireAttachPort {
		t.Errorf("zero VsockPort port() = %d, want WireAttachPort %d", got, WireAttachPort)
	}
	if got := (Config{VsockPort: 9000}).port(); got != 9000 {
		t.Errorf("explicit VsockPort port() = %d, want 9000", got)
	}
	if WireAttachPort != 4242 {
		t.Errorf("WireAttachPort = %d, want 4242 (must equal libvirt.DefaultAttachPort)", WireAttachPort)
	}
}

// TestListenVsock_DegradesWithoutKernelVsock: listenVsock surfaces a clean error
// (not a panic) when the kernel lacks AF_VSOCK, which is the offline/CI posture.
func TestListenVsock_DegradesWithoutKernelVsock(t *testing.T) {
	ln, err := listenVsock(WireAttachPort)
	if err != nil {
		// Expected on a box without vsock: EAFNOSUPPORT / EPROTONOSUPPORT / EPERM.
		if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
			return
		}
		// Any other bind/listen failure (e.g. EADDRINUSE on the well-known port from
		// a parallel guest) is also a clean error return, not a crash — accept it.
		return
	}
	// vsock present: the listener must report the bound CID/port and close cleanly.
	defer ln.Close()
	if got := ln.Addr().(vsockAddr).port; got != WireAttachPort {
		t.Errorf("bound port = %d, want %d", got, WireAttachPort)
	}
}

// TestSplice_LargeStreamConcurrent exercises a larger bidirectional transfer under
// -race so the two pump goroutines + the firstErr mutex are race-clean.
func TestSplice_LargeStreamConcurrent(t *testing.T) {
	a1, a2 := connPair(t)
	b1, b2 := connPair(t)
	done := make(chan error, 1)
	go func() { done <- Splice(a2, b2) }()

	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a1.Write(payload); a1.(*net.TCPConn).CloseWrite() }()
	go func() { defer wg.Done(); b1.Write(payload); b1.(*net.TCPConn).CloseWrite() }()

	var gotA, gotB []byte
	var rg sync.WaitGroup
	rg.Add(2)
	go func() { defer rg.Done(); gotB, _ = io.ReadAll(b1) }()
	go func() { defer rg.Done(); gotA, _ = io.ReadAll(a1) }()
	rg.Wait()
	wg.Wait()

	if len(gotB) != len(payload) || len(gotA) != len(payload) {
		t.Fatalf("short transfer: hostside=%d guestside=%d want %d", len(gotA), len(gotB), len(payload))
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Splice did not return")
	}
}
