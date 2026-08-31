// SPDX-License-Identifier: Apache-2.0

// attachfwd — the guest-side attach CARRIAGE forwarder (M1; runtime.v1 AttachWiring
// OQ-C carriage realization, doc 15 §5.4). The runtime.v1 contract pins the attach
// event socket as a guest-local UDS (ds-entrypoint emits CC stdio onto it,
// vm/entrypoint/transport.go) but leaves the guest<->host CARRIAGE free. For M1 the
// carriage is virtio-vsock: the guest LISTENs on AF_VSOCK and the host-agent dials
// the guest CID (docs/sessions/spikes/m1-live-session-transport.md — vsock is the
// control channel, no tap/IP/nft, off the egress dataplane). This forwarder bridges
// the two: it LISTENs on the guest-local UDS (so ds-entrypoint's dial connects to it)
// and on AF_VSOCK at VMADDR_CID_ANY:port (so the HOST-AGENT's per-session attach
// bridge dials in over vsock), then SPLICEs the two connections byte-for-byte.
//
// IT IS A 1:1 SPLICE, NOT A FAN-OUT. Exactly ONE pipe crosses the VM boundary — CC's
// single stdio stream. The D61 one-writer/N-reader fan-out + the token-auth + the
// writer-seat arbitration all live HOST-SIDE at the host-agent attach Server (the
// guest is the untrusted runtime; enforcement must not live here). So this forwarder
// holds the one ds-entrypoint UDS connection and splices it to the one host-agent TCP
// connection; the host-agent multiplexes clients on its own side.
//
// RUNTIME-AGNOSTIC (D20/D38, the entrypoint transport.go posture): it never parses
// the bytes — io.Copy in both directions and nothing else. If a parser appears here
// it is a bug.

package attachfwd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// WireAttachPort is the in-guest attach carriage port. It is the AF_VSOCK port the
// guest forwarder listens on and the host-agent dials (guestCID:WireAttachPort).
//
// CROSS-MODULE AGREEMENT: this value MUST equal orchestrator's
// libvirt.DefaultAttachPort (orchestrator/internal/hypervisor/libvirt/attachminter.go,
// const DefaultAttachPort = 4242). The two trees cannot import each other (vm/ may
// only import proto/gen/go), so the constant is single-sourced PER MODULE and kept
// in lockstep by this comment. The host<->guest leg moved from TCP GuestIP:4242 to
// vsock guestCID:4242 in the m1vsock wave — the port number is unchanged.
const WireAttachPort uint32 = 4242

// Splice wires two connections together byte-for-byte in both directions, returning
// when BOTH directions have finished (either side closed). The first non-EOF error
// from either direction is returned (nil on clean EOF). It mirrors the entrypoint's
// transport bridge: a CloseWrite on EOF half-closes the peer's write side so it sees
// EOF, and it takes io interfaces so it is unit-testable with in-memory pipes.
func Splice(a, b io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	record := func(err error) {
		if err == nil || err == io.EOF {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	pump := func(dst, src io.ReadWriteCloser, dir string) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		record(wrapCopyErr(dir, err))
		// Half-close the destination's write side so the peer sees EOF; fall back to
		// a full close for conns that do not support CloseWrite.
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	wg.Add(2)
	go pump(a, b, "host->guest")
	go pump(b, a, "guest->host")
	wg.Wait()
	return firstErr
}

func wrapCopyErr(dir string, err error) error {
	if err == nil || err == io.EOF {
		return nil
	}
	return fmt.Errorf("attach carriage copy %s: %w", dir, err)
}

// Config is the forwarder's wiring: the guest-local UDS path ds-entrypoint emits onto
// (AttachWiring.event_socket_path) and the AF_VSOCK port the host-agent bridge dials.
type Config struct {
	// UDSPath is the guest-local event-socket UDS the runtime wrapper (ds-entrypoint)
	// emits CC stdio onto. The forwarder is the SERVER on this socket; ds-entrypoint
	// dials it. Must match the EntrypointConfig.AttachWiring.event_socket_path.
	UDSPath string
	// VsockPort is the AF_VSOCK port the forwarder accepts the host-agent's carriage
	// dial on. The forwarder binds VMADDR_CID_ANY:VsockPort; the host-agent reaches it
	// at guestCID:VsockPort over virtio-vsock. The host-agent is the only legitimate
	// dialer (a guest-internal process reaching it is harmless — it gets the same 1:1
	// splice the host would, and the host-agent's token-auth gates any actual drive).
	// Zero falls back to WireAttachPort (the cross-module wire constant, == 4242).
	VsockPort uint32
}

func (c Config) validate() error {
	if c.UDSPath == "" {
		return fmt.Errorf("attach forwarder: empty UDS path")
	}
	return nil
}

// port returns the configured vsock port, defaulting a zero value to WireAttachPort
// so the offline module never hardcodes the wire port at more than one site.
func (c Config) port() uint32 {
	if c.VsockPort == 0 {
		return WireAttachPort
	}
	return c.VsockPort
}

// Forwarder is a constructed, listening forwarder: it owns the two listeners so the
// caller can Close them on shutdown. Build it with Listen, then Serve.
type Forwarder struct {
	uds   net.Listener
	vsock net.Listener
}

// Listen binds both the guest UDS and the AF_VSOCK carriage. It is split from Serve so
// a supervisor (or a test) can confirm the listeners are up before announcing
// readiness, and so a bind failure is reported distinctly from a serve error.
func Listen(cfg Config) (*Forwarder, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	uds, err := net.Listen("unix", cfg.UDSPath)
	if err != nil {
		return nil, fmt.Errorf("attach forwarder: listen unix %q: %w", cfg.UDSPath, err)
	}
	vsock, err := listenVsock(cfg.port())
	if err != nil {
		uds.Close()
		return nil, fmt.Errorf("attach forwarder: listen vsock port %d: %w", cfg.port(), err)
	}
	return &Forwarder{uds: uds, vsock: vsock}, nil
}

// VsockAddr returns the resolved AF_VSOCK listen address (CID:port).
func (f *Forwarder) VsockAddr() net.Addr { return f.vsock.Addr() }

// Close stops both listeners.
func (f *Forwarder) Close() error {
	err1 := f.uds.Close()
	err2 := f.vsock.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// Serve accepts the ds-entrypoint UDS connection and the host-agent vsock connection
// and splices them. It blocks until the splice finishes or ctx is cancelled. The two
// accepts run concurrently (the entrypoint dials at guest boot, the host-agent dials
// when the session becomes attachable — either order). A ctx cancel closes both
// listeners so a pending accept unblocks.
//
// M1 single-splice: it serves ONE session pair then returns. The supervising unit
// (the guest systemd service) is per-session, so one Serve per session is the model;
// a re-attach is a fresh host-agent dial within the same Serve (the held UDS conn is
// re-spliced) — for M1 the simplest correct form is one persistent host-agent
// connection per session, matching the persistent ds-entrypoint UDS connection.
func (f *Forwarder) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()

	type acc struct {
		conn net.Conn
		err  error
	}
	udsCh := make(chan acc, 1)
	vsockCh := make(chan acc, 1)
	go func() { c, e := f.uds.Accept(); udsCh <- acc{c, e} }()
	go func() { c, e := f.vsock.Accept(); vsockCh <- acc{c, e} }()

	udsRes := <-udsCh
	if udsRes.err != nil {
		return fmt.Errorf("attach forwarder: accept entrypoint UDS: %w", udsRes.err)
	}
	defer udsRes.conn.Close()

	vsockRes := <-vsockCh
	if vsockRes.err != nil {
		return fmt.Errorf("attach forwarder: accept host-agent vsock: %w", vsockRes.err)
	}
	defer vsockRes.conn.Close()

	return Splice(vsockRes.conn, udsRes.conn)
}

// --- AF_VSOCK listener ---------------------------------------------------------
//
// The AF_VSOCK socket creation is isolated here behind listenVsock so the Splice and
// UDS legs stay transport-agnostic and unit-testable over pipes/UDS. The accepted fd
// is wrapped as a net.Conn (os.NewFile + net.FileConn) so Splice is unchanged — it
// only ever sees io.ReadWriteCloser / net.Conn, never the raw fd.

// vsockListener adapts a raw AF_VSOCK listening socket to net.Listener so the
// Forwarder can hold both legs as net.Listener and Serve/Close are transport-agnostic.
type vsockListener struct {
	fd   int
	addr vsockAddr
}

// vsockAddr is a net.Addr for an AF_VSOCK endpoint (CID:port).
type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.cid, a.port) }

// listenVsock binds a SOCK_STREAM AF_VSOCK socket to VMADDR_CID_ANY:port and starts
// listening. VMADDR_CID_ANY means "any local CID" — the guest accepts on its own
// (qemu-assigned) CID, so the forwarder need not know its own CID ahead of boot.
func listenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind(VMADDR_CID_ANY:%d): %w", port, err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}
	return &vsockListener{fd: fd, addr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: port}}, nil
}

// Accept blocks for the next host-agent vsock dial and wraps the accepted fd as a
// net.Conn so the byte-pump (Splice) is unchanged.
func (l *vsockListener) Accept() (net.Conn, error) {
	nfd, _, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(nfd)
	// os.NewFile takes ownership of nfd and registers it with the runtime poller
	// (non-blocking, deadline-capable). net.FileConn CANNOT adopt an AF_VSOCK fd
	// ("protocol not supported", live-found 2026-06-16), so wrap the *os.File
	// directly as a net.Conn — Splice/io.Copy need only Read/Write/Close + deadlines,
	// all provided by *os.File. No CloseWrite — Splice falls back to a full Close.
	file := os.NewFile(uintptr(nfd), l.addr.String())
	if file == nil {
		unix.Close(nfd)
		return nil, fmt.Errorf("attach forwarder: os.NewFile on accepted vsock fd %d", nfd)
	}
	return &vsockConn{File: file, addr: l.addr}, nil
}

// vsockConn adapts an AF_VSOCK *os.File to net.Conn. net.FileConn rejects AF_VSOCK,
// so we embed the pollable *os.File (Read/Write/Close + the deadline methods come
// from it) and supply the two address methods net.Conn additionally requires.
type vsockConn struct {
	*os.File
	addr vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr  { return c.addr }
func (c *vsockConn) RemoteAddr() net.Addr { return c.addr }

// Close stops the listener; a pending Accept unblocks with an error.
func (l *vsockListener) Close() error { return unix.Close(l.fd) }

// Addr reports the bound AF_VSOCK address (CID:port).
func (l *vsockListener) Addr() net.Addr { return l.addr }
