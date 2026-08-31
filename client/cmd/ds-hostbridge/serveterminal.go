// SPDX-License-Identifier: Apache-2.0

// serveterminal.go — the TERMINAL serving surface of the gap-3 serving leg
// (`ds-hostbridge --serve-uds … --mode terminal`, the serpent claude --vm raw-pty
// path; docs/serpent-cli-mvp/04-control-plane-and-session-mode.md §2.5 + 10
// build-decisions §A3/§A5/§A6). It is the SIBLING of serveUDS's STRUCTURED surface:
// same host-local UDS, same per-session token store (validate-against-the-minter's
// file), same AF_VSOCK guestCID:port host→guest carriage, same D61 writer-seat
// arbitration — only the SURFACE differs. Structured pumps the attach.v1 event
// stream; terminal pumps the guest pty's RAW BYTE DUPLEX + resize.
//
// SINGLE-WRITER, NO READER-MIRROR (§A5): this unit serves the writer's raw pty
// bridge only. A TERMINAL-mode READER is rejected at the hostbridge server
// (rejectTerminalReaderUnsupported) — the reader-mirror is the deferred phase-2
// U-READER-MIRROR. The wire layer (client/hostbridge socket.go serveTerminal /
// terminalOutPump) owns the BLOCKING lossless raw-out pump + the input-free reader
// boundary; this file only supplies the carriage (the guest end) and registers it.
//
// COUNT-ONLY INPUT-ACTIVITY (§A6): the serving leg wires a payload-free
// WithInputActivityObserver so the wire layer ticks the D78 attendedness "driver
// typed" signal once per inbound raw-input frame WITHOUT parsing the opaque
// keystrokes. The observer here is the minimal count hook (a counter on the
// carriage); the real attendedness sink folds in behind this same seam later.
//
// The guest-side pty bridge (the in-guest leg that owns the ptmx + TIOCSWINSZ) is
// U-GUEST-WIRE; here we serve the HOST end of the terminal carriage: a FRAMED byte
// duplex + winsize over the SAME vsock conn the structured leg dials.
//
// HOST<->GUEST FRAMING (U-RESIZE). The host<->guest vsock leg is FRAMED (a 1-byte
// type + 4-byte BE length + payload), the guest twin of which is vm/entrypoint
// ptywire.go's codec (a DIFFERENT Go module, so the small codec is duplicated by
// design). RawOut reads + strips frames and returns wireRawOut payloads; RawInput
// writes a wireRawIn frame; Resize writes a wireResize frame (no longer a no-op —
// live window resize now reaches the guest pty's TIOCSWINSZ). The DATA path stays
// byte-exact: a wireRawIn/wireRawOut payload reproduces the EXACT pty bytes; the
// resize control rides its OWN frame type, so an 8-byte winsize never touches the
// opaque pty byte stream. This is the SEPARATE leg from the client<->host frames in
// client/hostbridge/socket.go (frameResize there is already frozen).

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// serveMode is the resolved serving SURFACE the host agent passes via --mode. It is
// the host-internal twin of the libvirt SessionMode (the single source the producer
// resolved once); the host agent renders the SAME resolution as the handle transport
// tag, the LaunchSpec.stdio, and this child flag, so the three cannot drift.
type serveMode int

const (
	serveModeStructured serveMode = iota // attach.v1 event stream (the default — UNCHANGED)
	serveModeTerminal                    // raw pty byte duplex + resize (serpent claude --vm)
)

// parseServeMode resolves the --mode flag string. "structured" / "" → structured (the
// byte-identical default); "terminal" → terminal. Any other value is a HARD config
// error (never a silent default — an operator who typed "termnial" must learn it, not
// get the structured surface), mirroring libvirt.ParseSessionMode's fail-loud posture.
func parseServeMode(s string) (serveMode, error) {
	switch s {
	case "", "structured":
		return serveModeStructured, nil
	case "terminal":
		return serveModeTerminal, nil
	default:
		return serveModeStructured, fmt.Errorf("unknown --mode %q (want \"structured\" or \"terminal\")", s)
	}
}

// vsockTerminalCarriage is the HOST end of the terminal carriage: a FRAMED byte
// duplex + winsize over the host→guest vsock conn, satisfying
// hostbridge.TerminalCarriage. The host↔guest leg is FRAMED (1-byte type + 4-byte BE
// length + payload), the guest twin of which is vm/entrypoint ptywire.go's codec.
// RawOut reads + strips frames and returns wireRawOut payloads; RawInput writes a
// wireRawIn frame; Resize writes a wireResize frame (TIOCSWINSZ in-guest); Close
// closes the conn (the in-guest SIGHUP path). The DATA path is byte-exact — a
// wireRawIn/wireRawOut payload reproduces the exact pty bytes.
type vsockTerminalCarriage struct {
	conn net.Conn
	br   *bufio.Reader // frames the guest→host direction so RawOut reads whole frames

	// writeMu serializes wireRawIn / wireResize frames so a keystroke frame and a
	// resize frame never interleave bytes on the shared conn (RawInput and Resize run
	// on the serveTerminalDrive goroutine here, but the lock keeps the wire atomic and
	// is cheap; it also guards against any future concurrent caller).
	writeMu sync.Mutex

	// inputActivity counts inbound raw-input frames (the §A6 count-only signal). It is
	// the minimal attendedness "driver typed" hook: payload-free, never the keystrokes.
	inputActivity uint64
}

// newVsockTerminalCarriage wraps a host→guest conn as the FRAMED terminal carriage.
func newVsockTerminalCarriage(conn net.Conn) *vsockTerminalCarriage {
	return &vsockTerminalCarriage{conn: conn, br: bufio.NewReaderSize(conn, 64*1024)}
}

// RawOut reads one wireRawOut frame and returns its payload — one chunk of the guest
// pty's output. It SKIPS any non-rawOut frame defensively (the guest only ever sends
// wireRawOut on this direction; an unexpected type is dropped rather than handed up as
// pty bytes — it must never corrupt the data path). A clean conn EOF ends the terminal
// session (CC exited / pty closed) — returned as io.EOF so the wire layer emits a
// single frameEnd. A zero-length wireRawOut payload is a LEGAL empty chunk (NOT EOF);
// the wire layer frames it onward and the client concatenates.
func (c *vsockTerminalCarriage) RawOut() ([]byte, error) {
	for {
		ft, payload, err := readWireFrame(c.br)
		if err != nil {
			return nil, err // io.EOF on a clean guest close, else the carriage fault
		}
		if ft != wireRawOut {
			// The guest→host direction carries only wireRawOut; an unexpected type is
			// dropped (never surfaced as pty data) and we read the next frame.
			continue
		}
		return payload, nil // a fresh slice from readWireFrame; safe to hand up
	}
}

// RawInput writes opaque keystroke bytes toward the guest pty master as a wireRawIn
// frame. Called once per client frameRawIn; the bytes are NEVER inspected here (the
// carriage is opaque, §A6) — they ride the frame payload byte-exact.
func (c *vsockTerminalCarriage) RawInput(p []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeWireFrame(c.conn, wireRawIn, p); err != nil {
		return fmt.Errorf("terminal carriage raw-input write: %w", err)
	}
	return nil
}

// Resize writes a wireResize frame toward the guest, which applies it to the pty
// master via TIOCSWINSZ (the kernel then SIGWINCHes CC → reflow). The 8-byte payload
// (rows|cols|xpix|ypix BE) rides its OWN frame type, so the winsize never touches the
// opaque pty byte stream (the prior no-op seam is now a real delivery — U-RESIZE). A
// dropped resize is a cosmetic redraw miss, so a write fault is wrapped but not fatal
// to the byte path; the wire layer surfaces it only if it recurs on the data legs.
func (c *vsockTerminalCarriage) Resize(ws hostbridge.Winsize) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeWireFrame(c.conn, wireResize, encodeWireWinsize(toWireWinsize(ws))); err != nil {
		return fmt.Errorf("terminal carriage resize write: %w", err)
	}
	return nil
}

// --- host↔guest frame codec (the host twin of vm/entrypoint ptywire.go's codec;
// the two live in DIFFERENT Go modules, so the small codec is duplicated by design) -
//
// This is a LEG-LOCAL wire contract — it never appears in proto (the host↔guest vsock
// leg is internal, the same way the client↔host frames in client/hostbridge/socket.go
// are file-local). The guest end (vm/entrypoint ptywire.go) and this host end are the
// only two speakers; they renumber together or not at all. NOTE: this is the SEPARATE
// leg from the client↔host frameResize (hostbridge.frameResize, already frozen) — that
// one carries resize client→host; THIS one carries it host→guest.

// wireFrameType is the 1-byte tag discriminating a host↔guest vsock frame.
type wireFrameType byte

const (
	// wireRawOut carries opaque pty-output bytes guest→host (the pty master's output
	// the host pumps to the client as frameRawOut). Payload: raw bytes, no inner
	// framing; a zero-length payload is a legal empty chunk, NOT EOF.
	wireRawOut wireFrameType = 1
	// wireRawIn carries opaque keystroke bytes host→guest (the writer's frameRawIn the
	// host forwards). Payload: raw bytes written verbatim to the pty master.
	wireRawIn wireFrameType = 2
	// wireResize carries an 8-byte BE rows|cols|xpix|ypix window-size control
	// host→guest (the client's frameResize the host forwards). The guest applies it to
	// the pty master via TIOCSWINSZ (the kernel then SIGWINCHes CC).
	wireResize wireFrameType = 3
)

// maxWireFrameBytes caps a single host↔guest frame payload so a malformed length
// cannot drive an unbounded alloc. A pty chunk never approaches it; a resize is 8
// bytes. It MUST match the guest end's cap (vm/entrypoint ptywire.go) so neither side
// rejects a frame the other will send.
const maxWireFrameBytes = 1 << 20

// writeWireFrame writes one type-length-payload frame to w as a SINGLE Write so the
// frame is atomic on the wire (no peer interleave across the header/payload boundary).
// The 4-byte length is big-endian; payload may be nil (length 0 — a legal empty
// frame). A net.Conn writes through, so no flush is needed.
func writeWireFrame(w io.Writer, t wireFrameType, payload []byte) error {
	if len(payload) > maxWireFrameBytes {
		return fmt.Errorf("ds-hostbridge: wire frame payload %d exceeds cap %d", len(payload), maxWireFrameBytes)
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
// close) is returned verbatim so the caller distinguishes a graceful end from a fault.
// A length over the cap is a clean protocol error (never a panic, never an unbounded
// alloc). It allocates a fresh payload slice per frame so the caller may hand it up
// without copying.
func readWireFrame(r io.Reader) (wireFrameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := wireFrameType(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxWireFrameBytes {
		return 0, nil, fmt.Errorf("ds-hostbridge: wire frame length %d exceeds cap %d", n, maxWireFrameBytes)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return t, payload, nil
}

// wireWinsize is the 8-byte wireResize payload: rows|cols|xpix|ypix BE, mirroring the
// kernel's struct winsize. toWireWinsize maps the hostbridge.Winsize the client sent
// (frameResize → carriage.Resize) onto it, byte-for-byte (the host carries the same
// four axes the client did — no axis is dropped on the host↔guest leg).
type wireWinsize struct {
	rows uint16
	cols uint16
	xpix uint16
	ypix uint16
}

// toWireWinsize maps a hostbridge.Winsize onto the host↔guest wireWinsize, carrying
// all four axes unchanged so a graphical terminal's pixel geometry survives the leg.
func toWireWinsize(ws hostbridge.Winsize) wireWinsize {
	return wireWinsize{rows: ws.Rows, cols: ws.Cols, xpix: ws.Xpix, ypix: ws.Ypix}
}

// encodeWireWinsize packs a wireWinsize into its 8-byte BE wireResize payload.
func encodeWireWinsize(ws wireWinsize) []byte {
	var b [8]byte
	binary.BigEndian.PutUint16(b[0:], ws.rows)
	binary.BigEndian.PutUint16(b[2:], ws.cols)
	binary.BigEndian.PutUint16(b[4:], ws.xpix)
	binary.BigEndian.PutUint16(b[6:], ws.ypix)
	return b[:]
}

// decodeWireWinsize unpacks an 8-byte wireResize payload — the inverse of
// encodeWireWinsize (the guest end decodes the host's frame the same way). A non-8-byte
// payload is a clean protocol error (never a panic). It is the symmetric reader the
// guest's decodeWireWinsize is; the host keeps it for round-trip checks and any future
// host-side resize introspection.
func decodeWireWinsize(payload []byte) (wireWinsize, error) {
	if len(payload) != 8 {
		return wireWinsize{}, fmt.Errorf("ds-hostbridge: malformed resize (%d bytes, want 8)", len(payload))
	}
	return wireWinsize{
		rows: binary.BigEndian.Uint16(payload[0:]),
		cols: binary.BigEndian.Uint16(payload[2:]),
		xpix: binary.BigEndian.Uint16(payload[4:]),
		ypix: binary.BigEndian.Uint16(payload[6:]),
	}, nil
}

// Close releases the carriage: it closes the host→guest conn so a blocked RawOut Read
// unblocks (returning an error) — the io.Closer-on-a-blocked-reader discipline the wire
// layer's terminalOutPump requires. Idempotent enough for the serving leg (a double
// close on a net.Conn returns an already-closed error the caller ignores).
func (c *vsockTerminalCarriage) Close() error {
	return c.conn.Close()
}

// noteInputActivity is the count-only §A6 sink the wire layer's
// WithInputActivityObserver fires once per inbound raw-input frame. It increments the
// payload-free counter — the attendedness "driver typed" signal — without ever seeing
// the keystroke bytes (the observer takes no argument by construction).
func (c *vsockTerminalCarriage) noteInputActivity() { atomic.AddUint64(&c.inputActivity, 1) }

// inputActivityCount reports how many raw-input frames the count-only sink observed (so
// a test can assert the D78 "driver typed" tick fired per frame without any keystroke
// parsing).
func (c *vsockTerminalCarriage) inputActivityCount() uint64 {
	return atomic.LoadUint64(&c.inputActivity)
}

var _ hostbridge.TerminalCarriage = (*vsockTerminalCarriage)(nil)

// inputActivityNoter is the COUNT-ONLY input-activity seam (§A6) the serve core looks
// for on the carriage: a payload-free "the writer typed" tick the wire layer fires per
// inbound raw-input frame. The production vsockTerminalCarriage implements it; a carriage
// without it gets a no-op observer (the attendedness tick is optional, never required to
// serve). The method takes NO argument by construction, so a noter can never reach the
// opaque keystroke bytes.
type inputActivityNoter interface {
	noteInputActivity()
}

var _ inputActivityNoter = (*vsockTerminalCarriage)(nil)

// serveTerminalUDSConfig parameterizes the terminal serve core so the CLI entrypoint and
// the offline test drive the SAME helper (the serveUDSConfig twin). dialGuest is the
// host→guest carriage resolver (AF_VSOCK in production; an in-process fake conn in tests
// through the same seam — a real socketpair, no live vsock).
type serveTerminalUDSConfig struct {
	sessionUUID  string
	dialGuest    func() (net.Conn, error)
	udsPath      string
	sessionToken string // the minter's hex token; the session's AuthMaterial token

	// carriageOverride, when set, is used as the terminal carriage instead of building a
	// vsockTerminalCarriage from the dialed guest conn. It is the OFFLINE TEST SEAM (the
	// dialGuest/adapterClock-seam idiom of serveUDSConfig): the test injects the SAME
	// *vsockTerminalCarriage it inspects (the count-only input-activity counter) so it can
	// assert the §A6 tick without reaching into the serve core. Production leaves it nil —
	// the carriage is always built from the real vsock conn. When set, dialGuest is still
	// called (the carriage owns the conn lifecycle), so the override MUST wrap that same
	// conn (the test builds it from net.Pipe's host end and returns that end from dialGuest).
	carriageOverride hostbridge.TerminalCarriage
}

// runServeTerminalUDS is the terminal serve-mode CLI entrypoint: it reads + validates
// the token file, then stands up the host-local UDS terminal server bridged to the
// AF_VSOCK guestCID:port carriage, blocking until the bridged session ends or the
// process is signalled. Mirrors runServeUDS verbatim except the surface (terminal vs
// structured); it launches NO VM/container/claude/cia — it only dials the guest CID.
func runServeTerminalUDS(sessionUUID, udsPath string, guestVsockCID, guestVsockPort uint32, sessionTokenFile string) error {
	if udsPath == "" {
		return fmt.Errorf("serve-uds requires a non-empty --serve-uds path")
	}
	if guestVsockCID == 0 {
		return fmt.Errorf("serve-uds requires --guest-vsock-cid (the in-guest AF_VSOCK context id; the derived per-session CID)")
	}
	if guestVsockPort == 0 {
		return fmt.Errorf("serve-uds requires --guest-vsock-port (the in-guest AF_VSOCK attach port)")
	}
	token, err := readSessionToken(sessionTokenFile)
	if err != nil {
		return err
	}
	cfg := serveTerminalUDSConfig{
		sessionUUID:  sessionUUID,
		dialGuest:    func() (net.Conn, error) { return dialVsock(guestVsockCID, guestVsockPort) },
		udsPath:      udsPath,
		sessionToken: token,
	}
	return serveTerminalUDS(context.Background(), cfg)
}

// serveTerminalUDS is the offline-testable core of terminal serve mode. It:
//
//  1. dials the host→guest carriage (cfg.dialGuest — AF_VSOCK guestCID:port in
//     production), with the SAME boot-race retry the structured leg uses;
//  2. registers the session on a token-pinned Server (WithTokenMinter, the SAME
//     shared-store validate the structured leg uses) and SETS the terminal carriage
//     (SetTerminalCarriage) so a TERMINAL attach has a guest pty to serve;
//  3. wires the COUNT-ONLY input-activity observer (WithInputActivityObserver → the
//     carriage's payload-free counter, §A6) so the D78 "driver typed" signal ticks
//     per raw-input frame without parsing keystrokes;
//  4. serves the host-local UDS with hostbridge.ServeBridge — the SAME accept loop;
//     the client's DialTerminal negotiates the terminal surface (frameMode{TERMINAL})
//     and the server's serveTerminal pumps the raw pty duplex. A TERMINAL-mode READER
//     is rejected at the server (single-writer, no reader-mirror — §A5).
//
// No bridge / adapter / structured history ring is built: a terminal conn consumes no
// attach.v1 events. The Server still needs a registered Session (for seat arbitration +
// token validate), so a nil-CC bridge is registered — the terminal attach never pumps
// it (the carriage is its only byte path).
func serveTerminalUDS(ctx context.Context, cfg serveTerminalUDSConfig) error {
	if cfg.sessionToken == "" {
		// Defence in depth: runServeTerminalUDS already fails closed on an empty token.
		return fmt.Errorf("serve-uds (terminal): empty session token (fail-closed)")
	}
	if cfg.dialGuest == nil {
		return fmt.Errorf("serve-uds (terminal): no guest carriage dialer (fail-closed)")
	}

	// (1) Dial the host→guest carriage with the boot-race retry (the in-guest forwarder
	// may not yet be listening right after clone — the SAME absorb the structured leg does).
	guest, err := dialGuestWithRetry(ctx, cfg.dialGuest)
	if err != nil {
		return fmt.Errorf("serve-uds (terminal): dial guest attach carriage: %w", err)
	}
	defer guest.Close()

	// The carriage is the production vsock carriage over the dialed conn; the offline test
	// may inject the SAME carriage it inspects (the count-only counter) via carriageOverride.
	var carriage hostbridge.TerminalCarriage = newVsockTerminalCarriage(guest)
	if cfg.carriageOverride != nil {
		carriage = cfg.carriageOverride
	}

	// (2)+(3) A token-pinned Server with the count-only input-activity observer wired.
	// The observer is payload-free (§A6): it ticks the carriage's counter, never the
	// keystrokes. The carriage's count-only noter is found via the inputActivityNoter seam
	// (the production vsockTerminalCarriage implements it; a carriage with none falls back
	// to a no-op observer, keeping the attendedness tick OPTIONAL). MVP no-auth posture
	// (DS_HOSTBRIDGE_NO_AUTH=1) matches the structured leg.
	noAuth := os.Getenv("DS_HOSTBRIDGE_NO_AUTH") == "1"
	observe := func() {}
	if noter, ok := carriage.(inputActivityNoter); ok {
		observe = noter.noteInputActivity
	}
	srv := hostbridge.NewServer(
		hostbridge.WithTokenMinter(func() string { return cfg.sessionToken }),
		hostbridge.WithNoAuth(noAuth),
		hostbridge.WithInputActivityObserver(observe),
	)
	// A terminal session carries NO structured CC stdio (the carriage is its byte path),
	// so register with a nil-CC bridge: seat arbitration + token validate need a Session,
	// the terminal attach never pumps the bridge.
	sess := srv.AddSession(cfg.sessionUUID, hostbridge.NewBridge(io.Discard, hostbridge.BridgeConfig{}))
	sess.SetTerminalCarriage(carriage)

	// (4) Serve the host-local UDS. The accept loop peeks frameMode and dispatches a
	// TERMINAL attach to serveTerminal (the raw pty duplex); a structured attach to the
	// same session still works (it just has no event stream). Run it until ctx is
	// cancelled or the carriage EOFs.
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hostbridge.ServeBridge(serveCtx, cfg.udsPath, srv) }()
	if err := waitForSocket(cfg.udsPath, 5*time.Second); err != nil {
		return err
	}

	// Block until the carriage EOFs (CC exited → the guest conn closes) or ctx is
	// cancelled. The terminal serve goroutines (serveTerminal) own the conn lifecycle
	// while a client is attached; with no client attached, a guest EOF must still tear
	// the serve down. Watch the guest conn for EOF by a parallel read is unnecessary —
	// the serving leg's lifetime is the session's; the host agent reaps this child at
	// session destroy (AttachBridge.Destroy). So just block on the serve loop ending.
	select {
	case se := <-serveErr:
		if se != nil && !isExpectedServeShutdown(se) {
			return fmt.Errorf("serve-uds (terminal): serve UDS %q: %w", cfg.udsPath, se)
		}
		return nil
	case <-ctx.Done():
		cancelServe()
		<-serveErr
		return nil
	}
}
