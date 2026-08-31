// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// ptywire.go is the in-guest TERMINAL-mode byte path (U-GUEST-WIRE): a FRAMED
// bidirectional bridge between the runtime's pty master (the ptmx the ptyLauncher
// owns, runtimeStdio.ptyMaster) and the attach carriage — the SAME guest-local
// transport the structured path emits onto (ds-attachfwd splices it 1:1 onto the
// AF_VSOCK conn the host agent dials). It is the guest twin of the host's terminal
// serving leg (client/cmd/ds-hostbridge/serveterminal.go).
//
// FRAMED DUPLEX — MATCHES THE HOST WIRE (U-RESIZE). The host↔guest vsock carriage
// is a FRAMED channel: a 1-byte type + 4-byte BE length + payload, with three
// message types (mirroring the host's vsockTerminalCarriage codec, which lives in a
// different Go module so the small codec is duplicated by design):
//   - wireRawOut  guest→host : a chunk of the pty master's OUTPUT (what the TUI
//                              paints). The host reads it off the carriage as
//                              RawOut() and forwards it as a client frameRawOut.
//   - wireRawIn   host→guest : the writer's raw KEYSTROKE bytes (host RawInput).
//                              Written VERBATIM to the pty master — byte-exact.
//   - wireResize  host→guest : an 8-byte TIOCSWINSZ control (host Resize). The
//                              guest applies it to the pty master, and the kernel
//                              then SIGWINCHes the runtime (CC) so it reflows.
//
// The DATA path stays byte-exact: a wireRawIn / wireRawOut payload reproduces the
// EXACT pty bytes (framing only wraps each chunk; a zero-length wireRawOut is a
// legal empty chunk, NOT EOF). The resize control rides its OWN frame type, so an
// 8-byte winsize never touches the opaque pty byte stream (the old raw-passthrough
// could not carry it; that limitation is now lifted). Nothing inspects the rawIn/
// rawOut payload bytes (D20/D38 runtime-agnostic — a parser here would be a bug,
// the same rule as transport.go).
//
// RESIZE (MVP, supported). Live window resize IS deliverable: the host Resize now
// writes a wireResize frame, and this guest leg applies it to the pty master via
// TIOCSWINSZ (applyWinsize, supervise.go wires setWinsize on the real master fd),
// so a mid-session SIGWINCH on the dev terminal → frameResize (client↔host) →
// wireResize (host↔guest) → TIOCSWINSZ → SIGWINCH to CC → reflow. The INITIAL
// window is still seeded at launch (ptyLauncher's TIOCSWINSZ from
// LaunchSpec.initial_window, G9) so CC paints sized from frame 1, and the client's
// startup SendResize carries the dev's TRUE size over this same path right after
// connect. See docs/serpent-cli-mvp/10 §A4/§A7.

// --- host↔guest frame codec (leg-local, the guest twin of the host carriage's
// codec in client/cmd/ds-hostbridge/serveterminal.go) ------------------------
//
// This is a LEG-LOCAL wire contract (it never appears in proto — the host↔guest
// vsock leg is internal, the same way the client↔host frames in
// client/hostbridge/socket.go are file-local). The host end (vsockTerminalCarriage)
// and this guest end are the only two speakers; they renumber together or not at all.

// wireFrameType is the 1-byte tag discriminating a host↔guest vsock frame.
type wireFrameType byte

const (
	// wireRawOut carries opaque pty-output bytes guest→host. Payload: raw bytes, no
	// inner framing; a zero-length payload is a legal empty chunk, NOT EOF.
	wireRawOut wireFrameType = 1
	// wireRawIn carries opaque keystroke bytes host→guest, written verbatim to the
	// pty master (byte-exact).
	wireRawIn wireFrameType = 2
	// wireResize carries an 8-byte BE rows|cols|xpix|ypix window-size control
	// host→guest; the guest applies it to the pty master via TIOCSWINSZ.
	wireResize wireFrameType = 3
)

// maxWireFrameBytes caps a single host↔guest frame payload so a malformed length
// cannot drive an unbounded alloc. A pty chunk never approaches it; a resize is 8
// bytes.
const maxWireFrameBytes = 1 << 20

// writeWireFrame writes one type-length-payload frame to w as a SINGLE Write so the
// frame is atomic on the wire. The 4-byte length is big-endian; payload may be nil
// (length 0 — a legal empty rawOut chunk).
func writeWireFrame(w io.Writer, t wireFrameType, payload []byte) error {
	if len(payload) > maxWireFrameBytes {
		return fmt.Errorf("entrypoint: wire frame payload %d exceeds cap %d", len(payload), maxWireFrameBytes)
	}
	buf := make([]byte, 5+len(payload))
	buf[0] = byte(t)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

// readWireFrame reads one type-length-payload frame from r. io.EOF (a clean peer
// close) is returned verbatim. A length over the cap is a clean protocol error
// (never a panic, never an unbounded alloc).
func readWireFrame(r io.Reader) (wireFrameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := wireFrameType(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxWireFrameBytes {
		return 0, nil, fmt.Errorf("entrypoint: wire frame length %d exceeds cap %d", n, maxWireFrameBytes)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return t, payload, nil
}

// wireWinsize is the 8-byte wireResize payload: the terminal window geometry the
// host forwards from the client's frameResize. rows|cols|xpix|ypix, mirroring the
// kernel's struct winsize. The guest applies it to the pty master via TIOCSWINSZ.
type wireWinsize struct {
	rows uint16
	cols uint16
	xpix uint16
	ypix uint16
}

// decodeWireWinsize unpacks an 8-byte wireResize payload. A non-8-byte payload is a
// clean protocol error (never a panic, never a silent drop).
func decodeWireWinsize(payload []byte) (wireWinsize, error) {
	if len(payload) != 8 {
		return wireWinsize{}, fmt.Errorf("entrypoint: malformed resize (%d bytes, want 8)", len(payload))
	}
	return wireWinsize{
		rows: binary.BigEndian.Uint16(payload[0:]),
		cols: binary.BigEndian.Uint16(payload[2:]),
		xpix: binary.BigEndian.Uint16(payload[4:]),
		ypix: binary.BigEndian.Uint16(payload[6:]),
	}, nil
}

// encodeWireWinsize packs a wireWinsize into its 8-byte BE wireResize payload — the
// inverse of decodeWireWinsize (used to drive a resize frame in).
func encodeWireWinsize(ws wireWinsize) []byte {
	var b [8]byte
	binary.BigEndian.PutUint16(b[0:], ws.rows)
	binary.BigEndian.PutUint16(b[2:], ws.cols)
	binary.BigEndian.PutUint16(b[4:], ws.xpix)
	binary.BigEndian.PutUint16(b[6:], ws.ypix)
	return b[:]
}

// --- the framed pty bridge ---------------------------------------------------

// ptyOutChunk caps a single pty-output read (and thus one wireRawOut frame). It
// matches the host carriage's 32 KiB RawOut buffer so a frame never exceeds what
// the host expects, while staying well under maxWireFrameBytes.
const ptyOutChunk = 32 * 1024

// applyWinsizeFunc applies a wireResize winsize toward the pty master (TIOCSWINSZ).
// A nil applier drops resize frames silently (a resize is cosmetic — never a session
// fault). A test supplies a recording applier to assert the winsize round-tripped.
type applyWinsizeFunc func(ws wireWinsize) error

// winsizeApplier is the optional capability a pty master exposes so the framed
// bridge can apply a wireResize (TIOCSWINSZ) WITHOUT widening bridgePTY's two-arg
// signature (supervise.go's call site is frozen). The production master (*os.File
// wrapping the ptmx) satisfies it via ptyMasterFd's Fd() — masterWinsizeApplier
// turns that fd into setWinsize. A test master records the applied winsize. A master
// that exposes neither (a bare io.ReadWriter) drops resize frames (cosmetic).
type winsizeApplier interface {
	// applyWinsize applies a window-size control to this master (TIOCSWINSZ).
	applyWinsize(ws wireWinsize) error
}

// ptyMasterFd is the fd-bearing capability the real pty master (*os.File) satisfies.
// masterWinsizeApplier uses it to apply TIOCSWINSZ on the real master fd, so the
// production path needs no signature change and no test touches a real fd.
type ptyMasterFd interface {
	Fd() uintptr
}

// masterApplier resolves the resize applier for a master: a master that already
// implements winsizeApplier (a test recorder) uses its own; a master that exposes a
// real fd (the production *os.File ptmx) gets masterWinsizeApplier (TIOCSWINSZ on the
// fd); anything else gets nil (resize frames are dropped — cosmetic, never a fault).
// The winsizeApplier check comes FIRST so a test master that ALSO has an Fd() (e.g. a
// real *os.File pipe) still records rather than issuing a real ioctl.
func masterApplier(master io.ReadWriter) applyWinsizeFunc {
	if wa, ok := master.(winsizeApplier); ok {
		return wa.applyWinsize
	}
	if fd, ok := master.(ptyMasterFd); ok {
		return func(ws wireWinsize) error { return masterWinsizeApplier(fd.Fd(), ws) }
	}
	return nil
}

// masterWinsizeApplier applies a wireResize to the real pty master fd via
// TIOCSWINSZ — sizing the MASTER propagates to the slave's termios, and the kernel
// then SIGWINCHes the foreground process group (CC), which re-reads TIOCGWINSZ and
// reflows. It carries all four axes (rows|cols|xpix|ypix) so a graphical terminal's
// pixel geometry passes through unchanged. It uses golang.org/x/sys/unix (the SAME
// dependency pty_linux.go's setWinsize uses), so it is unix-family only — exactly
// like the rest of this package, which is already non-portable to windows/plan9
// (supervise.go's syscall.Kill/Setpgid). A zero axis is delivered verbatim (the
// initial-window default lives at launch, not here).
func masterWinsizeApplier(fd uintptr, ws wireWinsize) error {
	return unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{
		Row:    ws.rows,
		Col:    ws.cols,
		Xpixel: ws.xpix,
		Ypixel: ws.ypix,
	})
}

// bridgePTY is the FRAMED bidirectional terminal bridge: it splices the pty master
// and the framed attach carriage in BOTH directions. The resize applier is resolved
// from the master itself (masterApplier) so the call site (supervise.go) is
// UNCHANGED — the real *os.File ptmx supplies TIOCSWINSZ on its fd, a test master
// records the winsize, and a bare master drops resizes.
//
//   - master  -> carriage : the runtime's pty OUTPUT, read in chunks and written as
//     wireRawOut frames. The host reads each as RawOut(). When the child exits and
//     the last slave reference closes, a pty-master read returns Linux EIO
//     (isPTYHangup) — the NORMAL pty hangup, not an error.
//   - carriage -> master  : the host's wireRawIn / wireResize frames. A wireRawIn
//     payload is written VERBATIM to the master (byte-exact keystrokes); a
//     wireResize applies TIOCSWINSZ to the master (applyWinsize), and the kernel
//     SIGWINCHes the runtime. When the carriage EOFs/closes the input stream ends.
//
// HALF-CLOSE / TEARDOWN: closing one side tears down the other. The moment EITHER
// direction finishes (the child hung up the pty, or the carriage closed), the
// bridge closes the carriage so a blocked carriage->master read unblocks, and the
// supervisor (proc.wait, which owns the single Close of the master fd) reaps the
// child. We do NOT close the master here — the supervisor owns its lifecycle
// (ptyProcess.wait closes it exactly once after the child is reaped), matching how
// transport.go leaves the pty-master Close to the supervisor. bridgePTY returns
// when BOTH directions have finished, returning the first non-hangup error (nil on
// a clean pty hangup / EOF).
//
// bridgePTY takes io interfaces (not *os.File / net.Conn) so it is unit-testable
// with an in-memory pipe/socketpair in BOTH directions — no real pty or vsock
// required (the OFFLINE test contract). The resize applier is the only platform
// hook; it is resolved from the master (masterApplier) so the signature stays the
// landed two-arg shape supervise.go calls.
func bridgePTY(master io.ReadWriter, carriage io.ReadWriteCloser) error {
	applyWinsize := masterApplier(master)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	record := func(err error) {
		if err == nil || err == io.EOF || isPTYHangup(err) || isTeardownClose(err) {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	// master -> carriage (pty output out, FRAMED as wireRawOut). This is the
	// SESSION-ENDING direction: when the runtime hangs up its pty (child exit => EIO,
	// or a clean EOF) the terminal session is over. We first CloseWrite the carriage
	// (so the host's RawOut sees EOF and tears its end down), THEN full-Close it so a
	// carriage->master read still blocked on input unblocks — closing THIS side tears
	// down the other. All pty output has been framed to the carriage before we
	// CloseWrite (the loop drains the master first), so the teardown cannot truncate
	// output.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := pumpPTYOut(carriage, master)
		record(wrapPTYCopyErr("master->carriage", err))
		if hc, ok := carriage.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		_ = carriage.Close()
	}()

	// carriage -> master (host frames in: wireRawIn -> master bytes, wireResize ->
	// TIOCSWINSZ). This leg ends when the host closes the carriage (EOF), full-closes it
	// (a disconnect → isTeardownClose), or sends a protocol FAULT (an unknown frame).
	// In EVERY case the host side is gone, so we close the carriage to unblock a
	// master->carriage frame write that is back-pressured on a quiet/slow host — the
	// "either leg ends, close both" discipline the host's serveTerminal uses. We do NOT
	// close the MASTER: the supervisor (ptyProcess.wait) owns its single Close; closing
	// the carriage makes the output leg's next frame write fail (isTeardownClose),
	// unwinding it cleanly. A FAULT is recorded (so bridgePTY surfaces it); a clean
	// EOF / teardown-close is swallowed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := pumpPTYIn(master, carriage, applyWinsize)
		record(wrapPTYCopyErr("carriage->master", err))
		// Unblock the output leg: closing the carriage makes its in-flight/next
		// wireRawOut write fail, so pumpPTYOut returns even when the master is still
		// producing (the host is gone — there is no consumer for further output).
		_ = carriage.Close()
	}()

	wg.Wait()
	return firstErr
}

// pumpPTYOut reads pty-master output in chunks and writes each as a wireRawOut frame
// to the carriage. A chunk is whatever one master Read returns (chunk boundaries
// carry no meaning — the host concatenates the payloads), so the DATA path is
// byte-exact across the frame boundary. It returns on a master read EOF / EIO hangup
// (the clean session end) or the first carriage write fault.
func pumpPTYOut(carriage io.Writer, master io.Reader) error {
	buf := make([]byte, ptyOutChunk)
	for {
		n, rerr := master.Read(buf)
		if n > 0 {
			if werr := writeWireFrame(carriage, wireRawOut, buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			return rerr // io.EOF / EIO hangup (clean) or a real master fault
		}
	}
}

// pumpPTYIn decodes host→guest frames off the carriage and dispatches them:
//   - wireRawIn  : the payload is written VERBATIM to the pty master (byte-exact
//     keystrokes — never inspected, D20/D38). An empty wireRawIn is a no-op (a legal
//     empty frame carries nothing).
//   - wireResize : the 8-byte payload is decoded and applied via applyWinsize
//     (TIOCSWINSZ on the master); a nil applier or a malformed payload DROPS the
//     resize (cosmetic — never a session fault). The kernel SIGWINCHes the runtime.
//   - any other type : an unknown frame is a protocol fault that ends the in leg.
//
// It returns on a carriage read EOF / close (the host hung up — the SIGHUP path) or
// the first master write fault.
func pumpPTYIn(master io.Writer, carriage io.Reader, applyWinsize applyWinsizeFunc) error {
	for {
		ft, payload, err := readWireFrame(carriage)
		if err != nil {
			return err // io.EOF (clean host close) / a teardown-close read / a read fault
		}
		switch ft {
		case wireRawIn:
			if len(payload) == 0 {
				continue // a legal empty frame carries nothing
			}
			if _, werr := master.Write(payload); werr != nil {
				return werr
			}
		case wireResize:
			ws, derr := decodeWireWinsize(payload)
			if derr != nil {
				// A malformed resize is cosmetic, never a session fault: DROP it and
				// keep pumping (symmetric with the host's malformed-resize handling).
				continue
			}
			if applyWinsize != nil {
				// A TIOCSWINSZ failure is non-fatal (the window just doesn't update);
				// keep the session alive rather than tear it down over a cosmetic miss.
				_ = applyWinsize(ws)
			}
		default:
			return fmt.Errorf("entrypoint: unexpected host frame %d on terminal carriage", ft)
		}
	}
}

// wrapPTYCopyErr normalises a framed-bridge pump error: a clean EOF, the pty-master
// hangup (EIO after the child exits, isPTYHangup), or a teardown-close (the OTHER
// direction closed the carriage to unblock this one, isTeardownClose) is the NORMAL
// end of a terminal session, not a bridge fault, so it is swallowed to nil. Any
// other error is wrapped with its direction for diagnosis.
func wrapPTYCopyErr(dir string, err error) error {
	if err == nil || err == io.EOF || isPTYHangup(err) || isTeardownClose(err) {
		return nil
	}
	return fmt.Errorf("terminal bridge copy %s: %w", dir, err)
}

// isTeardownClose reports whether err is the EXPECTED result of tearing the bridge
// down by closing the carriage: once EITHER direction finishes and closes the shared
// carriage conn, the OTHER in-flight pump surfaces a use-of-closed error —
// io.ErrClosedPipe on an in-memory pipe (tests) or net.ErrClosed on the real
// *net.UnixConn carriage (production). That is the half-close teardown completing,
// never a session fault, so the bridge swallows it to a clean return. (A clean EOF /
// pty EIO is handled separately.)
func isTeardownClose(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}
