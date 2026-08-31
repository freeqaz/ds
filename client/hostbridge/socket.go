// socket.go — the framed UDS/socket realization of the M0 AttachHandle seam: the
// SECOND transport, which crosses a REAL process/namespace boundary (the
// production-shaped one), against which LoopbackTransport (loopback.go) is the
// in-process latency floor. Same seam, same Server.Attach arbitration, same
// rejection sentinels, same bounded history ring for resume — only the carrier
// differs (the transport-ambivalent D79 handle; docs/15 §5.4; DRIVE-PROTOCOL.md
// tier 2).
//
// IMPORT, DON'T DUPLICATE (the same invariant bridge.go holds). The socket
// transport adds ONLY the wire framing + the cross-process Conn/serve loop; it
// reuses verbatim:
//
//   - Server.Attach for handle validation + D61 seat arbitration (the SAME path
//     LoopbackTransport.Dial uses — so a socket attach is accepted/rejected
//     identically, by the same sentinels);
//   - the typed DriveInput / DriveGrant shapes (carried as JSON over the wire,
//     decoded back to the SAME types) and the bridge's existing-driver-backed
//     DriveInput / DriveGrant — the Driver stays the ONLY encoder, so the bytes
//     that land on CC stdin are byte-identical to loopback's (DRIVE-PROTOCOL.md:
//     "only the Driver shapes CC records; the bridge carries them");
//   - Bridge.ReplayFrom for resume — the SAME bounded history ring loopback
//     Conn.Resume reads, never a second ring (the single-ring property below).
//
// The transport never re-encodes a CC record and never projects an event: it
// frames an already-projected attach.Event out and an already-typed
// DriveInput/DriveGrant in.
//
// This IS the byte bridge DRIVE-PROTOCOL.md §"Language & performance" names as
// the one genuinely latency-critical surface ("the writer/PTY path") and the
// place its Go-vs-Rust verdict is decided "by measurement, not up front." The
// benchmarks in socket_test.go profile THIS path against the loopback baseline
// and feed the README verdict.
//
// Wire framing (declared LOCALLY here — attach/v1 is README-only until the M0
// freeze; no proto stub body, proto/FREEZE.md). Every message is:
//
//	┌────────┬───────────────┬──────────────────────┐
//	│ 1 byte │ 4 bytes (BE)  │ N bytes              │
//	│ frame  │ payload len N │ payload (JSON or raw)│
//	└────────┴───────────────┴──────────────────────┘
//
// The opening client→server frame is frameAttach carrying the AttachHandle
// JSON; the server replies frameAccept (granted role) or frameReject (a code
// that maps back to the exact sentinel via rejectionSentinel, so errors.Is holds
// identically across the wire — the transport-ambivalent promise). Thereafter the
// server pushes frameEvent (attach.Event JSON) and frameEnd (terminal); the
// client pushes frameInput (DriveInput JSON) and frameGrant (a 1-byte GrantRoute
// + DriveGrant JSON).
//
// Resume on the wire (frameResume / frameResumeReply / frameResumeReject). A slow
// cross-process READER drops events exactly as a loopback reader does (the
// server-side outbox below is bounded and DROPS on overflow, never stalling the
// shared bridge pump — docs/15 §5.4 N-reader independence); recovery is therefore
// symmetric. The client sends frameResume{afterSeq} (8-byte BE); the server
// answers ONLY from Bridge.ReplayFrom — the SAME bounded history ring the
// loopback Conn.Resume reads, never a second ring — with frameResumeReply (the
// recovered span: a 4-byte BE count, then per event a 4-byte BE length + the
// event JSON) or frameResumeReject (a resumeRejectCode). A window-exceeded resume
// is a CLEAN REPLY (frameResumeReject → ErrResumeWindowExceeded via errors.Is),
// never a dropped connection, and so is a malformed/oversized resume request. The
// recovered span is RETURNED from SocketConn.Resume, never re-injected into
// Events() — identical client-facing semantics to loopback Conn.Resume
// (exactly-once, Seq-ordered, all-or-nothing).
//
// Stdlib-only (client/go.mod): net, encoding/binary, encoding/json, bufio,
// errors, fmt, io, sync, time (the terminal-mode mode-peek read deadline).
package hostbridge

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// TransportUnix is the EndpointCandidate.Transport the SocketTransport serves and
// dials — the framed-UDS realization of the M0 direct client→host-agent endpoint.
// It is a concrete carrier under the same "direct" D79 endpoint class the handle
// admits; the loopback transport uses TransportDirect for its in-process carrier,
// the socket transport adds this one for a real UDS so a client OUTSIDE the
// process/container can dial in (live.go tier 2).
const TransportUnix EndpointTransport = "unix"

// frameType discriminates a wire frame (the 1-byte tag).
type frameType byte

const (
	frameAttach       frameType = 1  // client→server: opening AttachHandle JSON
	frameAccept       frameType = 2  // server→client: attach granted (payload: granted Role string)
	frameReject       frameType = 3  // server→client: attach rejected (payload: rejectCode + optional message)
	frameEvent        frameType = 4  // server→client: one attach.Event JSON
	frameInput        frameType = 5  // client→server: one DriveInput JSON
	frameGrant        frameType = 6  // client→server: 1-byte GrantRoute + one DriveGrant JSON
	frameEnd          frameType = 7  // server→client: session terminal (payload: optional error string)
	frameResume       frameType = 8  // client→server: resume request (payload: 8-byte BE afterSeq)
	frameResumeReply  frameType = 9  // server→client: recovered span (payload: 4-byte BE count + count×[4-byte BE len | attach.Event JSON])
	frameResumeReject frameType = 10 // server→client: resume refused (payload: resumeRejectCode + optional message)

	// --- terminal-mode frames (U-FRAMES, docs/serpent-cli-mvp/01 §2.2; 10
	// build-decisions §A4). These extend THIS file's local number space (NOT
	// attach.v1 — check-freeze-riders.sh CHECK 4 forbids any proto naming them),
	// exactly as the resume frames 8/9/10 do. They carry the raw-terminal byte
	// duplex + winsize for serpent claude --vm; the STRUCTURED path (frames 1-10)
	// is byte-identical when no frameMode is sent (back-compat negative control).
	frameMode   frameType = 11 // client→server: 1-byte attachMode (STRUCTURED|TERMINAL), sent immediately after frameAttach, before frameAccept
	frameRawOut frameType = 12 // server→client: opaque terminal output bytes from the guest pty master (payload: raw bytes, no inner framing)
	frameRawIn  frameType = 13 // client→server: opaque terminal input bytes to the guest pty master (payload: raw bytes; WRITER only)
	frameResize frameType = 14 // client→server: a Winsize control message (payload: 8 bytes BE rows|cols|xpix|ypix; WRITER only)
)

// maxFrameBytes caps a single wire frame payload (matching the bridge's
// maxLineBytes so a full attach.Event with a large tool input still crosses),
// bounded so a malformed length cannot drive an unbounded alloc.
const maxFrameBytes = maxLineBytes

// maxResumeSpanBytes caps an entire frameResumeReply payload (the count-prefixed
// recovered span). It is larger than maxFrameBytes because a span is many events,
// but still bounded so a malformed count/length cannot drive an unbounded alloc.
// The history ring (DefaultHistorySize events) is the real bound on a span; this
// is the wire backstop for a forged/oversized reply.
const maxResumeSpanBytes = 64 << 20

// rejectCode is the wire form of an attach rejection: a stable byte that maps
// back to exactly one sentinel via rejectionSentinel, so errors.Is holds
// identically across the wire (the transport-ambivalent promise). The codes are
// part of the local wire contract; they never renumber.
type rejectCode byte

const (
	rejectWriterSeatTaken rejectCode = 1
	rejectReaderCannotWr  rejectCode = 2 // reserved: a write refusal is client-side, never an attach reject; kept for code stability
	rejectAuthInvalid     rejectCode = 3
	rejectHandleExpired   rejectCode = 4
	rejectHandleMalformed rejectCode = 5
	rejectUnknownSession  rejectCode = 6
	rejectInternal        rejectCode = 7 // a server fault, not a handle defect
	// rejectTerminalReaderUnsupported is a TERMINAL-mode attach with ROLE_READER
	// (the terminal MVP is writer-only; spectate is the structured path —
	// docs/serpent-cli-mvp/01 §2.3). It maps to ErrTerminalReaderUnsupported so a
	// terminal client's errors.Is holds across the wire, the same pattern as every
	// other reject code. Part of the local wire contract; never renumbers.
	rejectTerminalReaderUnsupported rejectCode = 8
)

// sentinelReject maps an attach sentinel to its wire code (server side). An
// error outside the closed set maps to rejectInternal so a server fault still
// crosses the wire as a clean rejection rather than a dropped connection.
func sentinelReject(err error) rejectCode {
	switch {
	case errors.Is(err, ErrWriterSeatTaken):
		return rejectWriterSeatTaken
	case errors.Is(err, ErrReaderCannotWrite):
		return rejectReaderCannotWr
	case errors.Is(err, ErrAuthInvalid):
		return rejectAuthInvalid
	case errors.Is(err, ErrHandleExpired):
		return rejectHandleExpired
	case errors.Is(err, ErrHandleMalformed):
		return rejectHandleMalformed
	case errors.Is(err, ErrUnknownSession):
		return rejectUnknownSession
	case errors.Is(err, ErrTerminalReaderUnsupported):
		return rejectTerminalReaderUnsupported
	default:
		return rejectInternal
	}
}

// rejectionSentinel maps a wire code back to its sentinel (client side), so the
// caller's errors.Is(err, ErrAuthInvalid) holds whether the attach was loopback
// or socket. rejectInternal wraps a generic, non-sentinel error (the server
// supplies a message).
func rejectionSentinel(code rejectCode, msg string) error {
	switch code {
	case rejectWriterSeatTaken:
		return ErrWriterSeatTaken
	case rejectReaderCannotWr:
		return ErrReaderCannotWrite
	case rejectAuthInvalid:
		return ErrAuthInvalid
	case rejectHandleExpired:
		return ErrHandleExpired
	case rejectHandleMalformed:
		return ErrHandleMalformed
	case rejectUnknownSession:
		return ErrUnknownSession
	case rejectTerminalReaderUnsupported:
		return ErrTerminalReaderUnsupported
	default:
		if msg == "" {
			msg = "attach rejected (internal)"
		}
		return fmt.Errorf("hostbridge: %s", msg)
	}
}

// resumeRejectCode is the wire form of a resume refusal (frameResumeReject), the
// SAME rejectCode/sentinelReject pattern extended to the resume path: a stable
// byte that maps back to exactly one sentinel via resumeRejectSentinel so
// errors.Is(err, ErrResumeWindowExceeded) holds across the wire identically to
// loopback Conn.Resume. The codes are part of the local wire contract; they never
// renumber.
type resumeRejectCode byte

const (
	resumeRejectWindowExceeded resumeRejectCode = 1 // → ErrResumeWindowExceeded (the aged-out span)
	resumeRejectInternal       resumeRejectCode = 2 // a server fault answering the resume (e.g. a malformed request), not a window miss
)

// sentinelResumeReject maps a resume error to its wire code (server side). Only
// ErrResumeWindowExceeded is a clean window miss; anything else is a server fault
// that still crosses as a clean reject rather than a dropped connection.
func sentinelResumeReject(err error) resumeRejectCode {
	if errors.Is(err, ErrResumeWindowExceeded) {
		return resumeRejectWindowExceeded
	}
	return resumeRejectInternal
}

// resumeRejectSentinel maps a resume wire code back to its sentinel (client
// side), so SocketConn.Resume's errors.Is(err, ErrResumeWindowExceeded) holds
// identically to loopback Conn.Resume's. resumeRejectInternal wraps a generic,
// non-sentinel error (the server supplies a message).
func resumeRejectSentinel(code resumeRejectCode, msg string) error {
	switch code {
	case resumeRejectWindowExceeded:
		return ErrResumeWindowExceeded
	default:
		if msg == "" {
			msg = "resume rejected (internal)"
		}
		return fmt.Errorf("hostbridge: %s", msg)
	}
}

// --- framing primitives ------------------------------------------------------

// writeFrame writes one type-length-payload frame. The 4-byte length is
// big-endian; payload may be nil (length 0). It flushes so the peer sees the
// frame immediately (an attach handshake, a single event, or a resume reply must
// not stall in a buffer). The cap is maxResumeSpanBytes — the largest legal
// payload (a frameResumeReply span); every smaller frame stays well under it.
func writeFrame(w *bufio.Writer, t frameType, payload []byte) error {
	if len(payload) > maxResumeSpanBytes {
		return fmt.Errorf("hostbridge: frame payload %d exceeds cap %d", len(payload), maxResumeSpanBytes)
	}
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return w.Flush()
}

// readFrame reads one type-length-payload frame. io.EOF (clean peer close) is
// returned verbatim so callers can distinguish a graceful end from a fault. A
// frameResumeReply is the only oversized frame (a whole recovered span); every
// other frame is capped at maxFrameBytes so a malformed length on a non-span
// frame cannot drive an unbounded alloc.
func readFrame(r *bufio.Reader) (frameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := frameType(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:])
	limit := uint32(maxFrameBytes)
	if t == frameResumeReply {
		limit = uint32(maxResumeSpanBytes)
	}
	if n > limit {
		return 0, nil, fmt.Errorf("hostbridge: frame length %d exceeds cap %d", n, limit)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return t, payload, nil
}

// encodeSpan packs a recovered []attach.Event into a frameResumeReply payload: a
// 4-byte BE count, then for each event a 4-byte BE length and the event JSON. A
// nil/empty span encodes as a zero count (a clean "already caught up").
func encodeSpan(span []attach.Event) ([]byte, error) {
	var buf []byte
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(span)))
	buf = append(buf, cnt[:]...)
	for i := range span {
		ej, err := json.Marshal(span[i])
		if err != nil {
			return nil, fmt.Errorf("hostbridge: marshal resume event: %w", err)
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(ej)))
		buf = append(buf, l[:]...)
		buf = append(buf, ej...)
	}
	return buf, nil
}

// decodeSpan unpacks a frameResumeReply payload into the recovered span. A
// malformed length/count is rejected cleanly (an error, never a panic) so an
// oversized or truncated reply cannot wedge or over-allocate the client.
func decodeSpan(payload []byte) ([]attach.Event, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("hostbridge: resume reply truncated (no count)")
	}
	count := binary.BigEndian.Uint32(payload[:4])
	off := 4
	out := make([]attach.Event, 0, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(payload) {
			return nil, fmt.Errorf("hostbridge: resume reply truncated at event %d/%d", i, count)
		}
		l := int(binary.BigEndian.Uint32(payload[off : off+4]))
		off += 4
		if l < 0 || off+l > len(payload) {
			return nil, fmt.Errorf("hostbridge: resume reply event %d length %d overruns payload", i, l)
		}
		var ev attach.Event
		if err := json.Unmarshal(payload[off:off+l], &ev); err != nil {
			return nil, fmt.Errorf("hostbridge: decode resume event %d: %w", i, err)
		}
		out = append(out, ev)
		off += l
	}
	return out, nil
}

// --- terminal-mode encodings (attachMode + Winsize) --------------------------
//
// These are the frameMode / frameResize payload codecs — wire-local, the same
// way rejectCode/resumeRejectCode are. They keep the file's existing helper
// idiom: a fixed-size big-endian layout, a clean error on a malformed length
// (never a panic, never a silent drop — symmetric with decodeSpan / answerResume).

// attachMode is the 1-byte frameMode payload: which serving surface the conn
// negotiates after frameAttach. modeUnspecified (0) is rejected; modeStructured
// (1) is today's event/input/grant/resume behavior; modeTerminal (2) is the raw
// pty byte duplex + resize. An absent frameMode defaults to modeStructured, so an
// old client that never sends it is byte-compatible (the back-compat negative
// control, docs/serpent-cli-mvp/01 §2.2).
type attachMode byte

const (
	modeUnspecified attachMode = 0 // reserved; an explicit frameMode{0} is rejected
	modeStructured  attachMode = 1 // the existing event/input/grant/resume surface (default)
	modeTerminal    attachMode = 2 // raw pty bytes (frameRawIn/frameRawOut) + frameResize
)

// Winsize mirrors struct winsize (the TIOCSWINSZ argument): the terminal window
// geometry the client sends on SIGWINCH. Rows/Cols are the character cell grid;
// Xpix/Ypix are the pixel geometry (usually 0 — most terminals report only
// rows/cols, but a graphical terminal passes pixel size through unchanged). The
// guest-side launcher applies it via ioctl(ptmx, TIOCSWINSZ, &ws) (its job, not
// this transport's).
type Winsize struct {
	Rows uint16
	Cols uint16
	Xpix uint16
	Ypix uint16
}

// encodeWinsize packs a Winsize into the fixed 8-byte big-endian frameResize
// payload: rows|cols|xpix|ypix, each a u16 BE — the on-wire layout documented in
// docs/serpent-cli-mvp/01 §2.2.
func encodeWinsize(ws Winsize) []byte {
	var b [8]byte
	binary.BigEndian.PutUint16(b[0:], ws.Rows)
	binary.BigEndian.PutUint16(b[2:], ws.Cols)
	binary.BigEndian.PutUint16(b[4:], ws.Xpix)
	binary.BigEndian.PutUint16(b[6:], ws.Ypix)
	return b[:]
}

// decodeWinsize unpacks an 8-byte frameResize payload into a Winsize. A non-8-byte
// payload is a clean protocol error (never a panic, never a silent drop) —
// symmetric with answerResume's malformed-request handling; the caller turns it
// into a frameEnd rather than wedging.
func decodeWinsize(payload []byte) (Winsize, error) {
	if len(payload) != 8 {
		return Winsize{}, fmt.Errorf("hostbridge: malformed resize (%d bytes, want 8)", len(payload))
	}
	return Winsize{
		Rows: binary.BigEndian.Uint16(payload[0:]),
		Cols: binary.BigEndian.Uint16(payload[2:]),
		Xpix: binary.BigEndian.Uint16(payload[4:]),
		Ypix: binary.BigEndian.Uint16(payload[6:]),
	}, nil
}

// --- client transport --------------------------------------------------------

// SocketTransport is the UDS realization of the transport seam. Dial connects the
// handle's "unix" endpoint, performs the attach handshake, and returns a
// SocketConn streaming events in / driving typed input out / resuming a dropped
// span over the framed protocol. It is stateless; one instance serves any number
// of concurrent Dials.
type SocketTransport struct{}

// NewSocketTransport constructs the UDS transport.
func NewSocketTransport() *SocketTransport { return &SocketTransport{} }

// unixEndpoint returns the handle's first "unix" endpoint, if present. The
// socket transport serves only TransportUnix; a handle with no unix candidate
// has no servable endpoint for THIS transport (ErrHandleMalformed at Dial).
func unixEndpoint(h AttachHandle) (EndpointCandidate, bool) {
	for _, ep := range h.Endpoints {
		if ep.Transport == TransportUnix {
			return ep, true
		}
	}
	return EndpointCandidate{}, false
}

// Dial resolves handle's "unix" endpoint into a live SocketConn. A handle with
// no "unix" candidate, an empty UUID, no auth, or an unknown role is
// ErrHandleMalformed BEFORE any socket is touched (a caller error should not
// require a round trip; the server re-validates — defence in depth). The attach
// handshake outcome maps to the SAME sentinels as loopback via rejectionSentinel.
func (t *SocketTransport) Dial(handle AttachHandle) (*SocketConn, error) {
	// Shape-validate locally first so a malformed handle fails identically to the
	// loopback path (no socket touched). Mirror Server.validate's structural
	// checks: non-empty UUID, ≥1 endpoint, valid role, and (for this transport) a
	// unix endpoint plus a non-empty auth token.
	if handle.SessionUUID == "" || len(handle.Endpoints) == 0 || !handle.Role.valid() || handle.Auth.Token == "" {
		return nil, ErrHandleMalformed
	}
	ep, ok := unixEndpoint(handle)
	if !ok {
		return nil, ErrHandleMalformed
	}

	raw, err := net.Dial("unix", ep.Address)
	if err != nil {
		return nil, fmt.Errorf("hostbridge: dial unix %s: %w", ep.Address, err)
	}
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	// Handshake: send the AttachHandle, await accept-or-reject.
	hjson, err := json.Marshal(handle)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: marshal handle: %w", err)
	}
	if err := writeFrame(bw, frameAttach, hjson); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: send attach: %w", err)
	}
	ft, payload, err := readFrame(br)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: read attach reply: %w", err)
	}
	switch ft {
	case frameReject:
		_ = raw.Close()
		if len(payload) == 0 {
			return nil, rejectionSentinel(rejectInternal, "")
		}
		return nil, rejectionSentinel(rejectCode(payload[0]), string(payload[1:]))
	case frameAccept:
		// payload is the granted role string (authoritative — the server may
		// downgrade, though M0 grants exactly the requested role).
		role := Role(payload)
		if !role.valid() {
			role = handle.Role
		}
		return newSocketConn(raw, br, bw, role), nil
	default:
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: unexpected attach reply frame %d", ft)
	}
}

// DialTerminal dials handle's "unix" endpoint and negotiates TERMINAL mode (the
// serpent claude --vm raw-pty surface, docs/serpent-cli-mvp/01 §2.5). It is a
// DISTINCT surface from Dial: it returns a *TerminalConn (RawOut/Write/SendResize/
// Done) — never a *SocketConn — so a terminal caller cannot accidentally call
// DriveInput and an event caller cannot accidentally call Write. The two conn
// types are disjoint, selected here at dial time; the structured Dial path is
// untouched (the land-dark invariant).
//
// The handshake is the SAME frameAttach as Dial, with frameMode{TERMINAL} sent
// immediately after frameAttach and before the server's accept/reject (the §2.3
// ordering). A TERMINAL-mode READER is refused with ErrTerminalReaderUnsupported
// (the MVP is writer-only; spectate is the structured path) — surfaced via
// errors.Is across the wire like every other reject sentinel. Local shape
// validation mirrors Dial so a malformed handle fails identically with no socket
// touched.
func (t *SocketTransport) DialTerminal(handle AttachHandle) (*TerminalConn, error) {
	if handle.SessionUUID == "" || len(handle.Endpoints) == 0 || !handle.Role.valid() || handle.Auth.Token == "" {
		return nil, ErrHandleMalformed
	}
	ep, ok := unixEndpoint(handle)
	if !ok {
		return nil, ErrHandleMalformed
	}

	raw, err := net.Dial("unix", ep.Address)
	if err != nil {
		return nil, fmt.Errorf("hostbridge: dial unix %s: %w", ep.Address, err)
	}
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	// Handshake: frameAttach, THEN frameMode{TERMINAL}, then await accept/reject.
	// Mode rides BEFORE the accept (§2.3) so the server records the surface before
	// it replies — a terminal reader is rejected at the handshake, never served.
	hjson, err := json.Marshal(handle)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: marshal handle: %w", err)
	}
	if err := writeFrame(bw, frameAttach, hjson); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: send attach: %w", err)
	}
	if err := writeFrame(bw, frameMode, []byte{byte(modeTerminal)}); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: send mode: %w", err)
	}
	ft, payload, err := readFrame(br)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: read attach reply: %w", err)
	}
	switch ft {
	case frameReject:
		_ = raw.Close()
		if len(payload) == 0 {
			return nil, rejectionSentinel(rejectInternal, "")
		}
		return nil, rejectionSentinel(rejectCode(payload[0]), string(payload[1:]))
	case frameAccept:
		role := Role(payload)
		if !role.valid() {
			role = handle.Role
		}
		return newTerminalConn(raw, br, bw, role), nil
	default:
		_ = raw.Close()
		return nil, fmt.Errorf("hostbridge: unexpected attach reply frame %d", ft)
	}
}

// SocketConn is the client end of a framed UDS attach — the cross-process twin of
// the loopback Conn, with the SAME client-facing surface (Events / Role /
// DriveInput / DriveGrant / Resume / Close). A reader goroutine decodes
// frameEvent → Events and frameEnd → done, and demultiplexes frameResumeReply /
// frameResumeReject onto the resume channel the in-flight Resume waits on;
// DriveInput/DriveGrant frame the typed shapes out. A READER refuses drives
// before touching the wire (D61), so a reader's write is local and never races
// the server.
type SocketConn struct {
	role Role
	raw  net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	events chan attach.Event
	done   chan error

	writeMu   sync.Mutex // serializes frame writes so two drive/resume records never interleave
	closeOnce sync.Once
	doneOnce  sync.Once

	// resumeMu serializes Resume calls (one in-flight resume at a time); the
	// reader goroutine demuxes the reply/reject onto resumeCh, which the waiting
	// Resume drains. The buffer of 1 lets the reader deliver without blocking.
	resumeMu sync.Mutex
	resumeCh chan resumeResult
}

// resumeResult is the reader goroutine's decoded answer to an in-flight resume.
type resumeResult struct {
	span []attach.Event
	err  error
}

func newSocketConn(raw net.Conn, br *bufio.Reader, bw *bufio.Writer, role Role) *SocketConn {
	c := &SocketConn{
		role:     role,
		raw:      raw,
		br:       br,
		bw:       bw,
		events:   make(chan attach.Event),
		done:     make(chan error, 1),
		resumeCh: make(chan resumeResult, 1),
	}
	go c.readLoop()
	return c
}

// readLoop decodes server frames until frameEnd, EOF, or a fault. Each frameEvent
// is unmarshaled to an attach.Event and forwarded; frameResumeReply /
// frameResumeReject are decoded and handed to the in-flight Resume via resumeCh;
// frameEnd carries the terminal error. The loop owns the Events channel close.
func (c *SocketConn) readLoop() {
	defer close(c.events)
	for {
		ft, payload, err := readFrame(c.br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.signalDone(nil) // clean server close
			} else {
				c.signalDone(fmt.Errorf("hostbridge: socket read: %w", err))
			}
			return
		}
		switch ft {
		case frameEvent:
			var ev attach.Event
			if err := json.Unmarshal(payload, &ev); err != nil {
				c.signalDone(fmt.Errorf("hostbridge: decode event: %w", err))
				return
			}
			// Forward, but stay interruptible by Close so a caller that stops
			// draining does not wedge the read loop.
			select {
			case c.events <- ev:
			case <-c.done:
				return
			}
		case frameResumeReply:
			span, derr := decodeSpan(payload)
			c.deliverResume(resumeResult{span: span, err: derr})
		case frameResumeReject:
			var code resumeRejectCode
			var msg string
			if len(payload) > 0 {
				code = resumeRejectCode(payload[0])
				msg = string(payload[1:])
			} else {
				code = resumeRejectInternal
			}
			c.deliverResume(resumeResult{err: resumeRejectSentinel(code, msg)})
		case frameEnd:
			var termErr error
			if len(payload) > 0 {
				termErr = errors.New(string(payload))
			}
			c.signalDone(termErr)
			return
		default:
			c.signalDone(fmt.Errorf("hostbridge: unexpected server frame %d", ft))
			return
		}
	}
}

// deliverResume hands a decoded resume answer to the waiting Resume. resumeCh is
// buffered depth 1 and Resume drains it before issuing the next request, so a
// send never blocks the reader loop; an answer with no waiter (a protocol error
// or a late reply after the Resume gave up) is dropped rather than wedging the
// loop.
func (c *SocketConn) deliverResume(res resumeResult) {
	select {
	case c.resumeCh <- res:
	default:
	}
}

// signalDone delivers the terminal error once and closes the conn's socket so a
// blocked write/read/resume unblocks. Idempotent.
func (c *SocketConn) signalDone(err error) {
	c.doneOnce.Do(func() {
		c.done <- err
		close(c.done)
		_ = c.raw.Close()
	})
}

// Events is the attach.v1 fan-out for this attachment, closed at session end. The
// recovered resume span is NOT delivered here (it is returned from Resume) —
// identical to loopback Conn.Events / Conn.Resume.
func (c *SocketConn) Events() <-chan attach.Event { return c.events }

// Done yields the terminal error (nil on clean end) — a select-able completion
// signal for consumers that don't range over Events.
func (c *SocketConn) Done() <-chan error { return c.done }

// Role reports the granted subscriber class (D61).
func (c *SocketConn) Role() Role { return c.role }

// DriveInput frames a typed DriveInput as frameInput and writes it. A READER conn
// refuses with ErrReaderCannotWrite BEFORE the wire (D61). The server decodes the
// SAME DriveInput type and forwards it to the bridge's existing-driver-backed
// DriveInput, so the bytes that land on CC stdin are the Driver's output —
// identical to loopback (the transport adds no encoding).
func (c *SocketConn) DriveInput(in DriveInput) error {
	if c.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("hostbridge: marshal drive input: %w", err)
	}
	return c.frame(frameInput, payload)
}

// DriveGrant frames a typed DriveGrant + its GrantRoute as frameGrant. A READER
// refuses (D61). The server decodes both and forwards to the bridge's
// existing-driver-backed DriveGrant with the same route — the Driver remains the
// only encoder.
func (c *SocketConn) DriveGrant(grant DriveGrant, route GrantRoute) error {
	if c.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	gjson, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("hostbridge: marshal drive grant: %w", err)
	}
	// Prefix the route byte so the server drives via the SAME route the caller
	// chose (prompt-tool vs native control_response).
	payload := append([]byte{byte(route)}, gjson...)
	return c.frame(frameGrant, payload)
}

func (c *SocketConn) frame(t frameType, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeFrame(c.bw, t, payload); err != nil {
		return fmt.Errorf("hostbridge: drive: %w", err)
	}
	return nil
}

// Resume recovers the events this reader missed after afterSeq, with the SAME
// client-facing contract as loopback Conn.Resume: the recovered span is RETURNED
// (never re-injected into Events()), exactly once, in ascending Seq order,
// all-or-nothing. The server answers from Bridge.ReplayFrom — the same bounded
// history ring loopback uses, never a second ring (the single-ring property).
//
//   - afterSeq == 0 backfills whatever the ring still holds (the late-joiner /
//     fresh-attach case); it never fails the window check.
//   - a RESUME (afterSeq > 0) whose missing span has aged out of the ring returns
//     a nil span and ErrResumeWindowExceeded — errors.Is holds across the wire,
//     identical to loopback.
//   - already caught up (afterSeq >= the bridge's LastSeq) returns an empty span
//     and no error.
//
// One resume is in flight at a time (resumeMu); a Resume after the session has
// ended returns the terminal cause rather than blocking forever.
func (c *SocketConn) Resume(afterSeq uint64) ([]attach.Event, error) {
	c.resumeMu.Lock()
	defer c.resumeMu.Unlock()

	// Drain any stale answer so this request correlates to its own reply.
	select {
	case <-c.resumeCh:
	default:
	}

	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], afterSeq)
	c.writeMu.Lock()
	werr := writeFrame(c.bw, frameResume, seq[:])
	c.writeMu.Unlock()
	if werr != nil {
		return nil, fmt.Errorf("hostbridge: send resume: %w", werr)
	}

	select {
	case res := <-c.resumeCh:
		if res.err != nil {
			return nil, res.err
		}
		return res.span, nil
	case err := <-c.done:
		// Session ended before the reply landed; surface the terminal cause so a
		// Resume after Close/EOF never blocks forever.
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
}

// Close releases the attach: it signals done (which closes the socket), waking
// the read loop, and detaches server-side via the socket close (the server's
// drive reader hits EOF and releases the seat). Idempotent.
func (c *SocketConn) Close() error {
	c.closeOnce.Do(func() { c.signalDone(nil) })
	return nil
}

// --- client terminal conn ----------------------------------------------------

// TerminalConn is the client end of a TERMINAL-mode attach (serpent claude --vm).
// It is a SIBLING of SocketConn, NOT a mode-branch on it: the two conn types are
// disjoint and selected at Dial vs DialTerminal, so the structured surface
// (Events/DriveInput/Resume) and the raw surface (RawOut/Write/SendResize) never
// share a method — a terminal caller cannot accidentally drive a structured input
// and vice-versa (docs/serpent-cli-mvp/01 §2.5). It shares the framing primitives
// (writeFrame/readFrame) but speaks ONLY the raw frames + frameEnd.
//
// A reader goroutine decodes server frames: frameRawOut → the rawOut channel,
// frameEnd → done. frameResume/frameResumeReply/etc. are STRUCTURED-only and have
// no place here; an unexpected frame ends the conn (§2.8 — the surfaces do not
// share the resume verb). The write side (Write = frameRawIn, SendResize =
// frameResize) refuses for a non-writer BEFORE the wire (D61), the byte-for-byte
// pattern of SocketConn.DriveInput.
type TerminalConn struct {
	role Role
	raw  net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	rawOut chan []byte
	done   chan error

	writeMu   sync.Mutex // serializes frameRawIn/frameResize writes so two never interleave
	closeOnce sync.Once
	doneOnce  sync.Once
}

func newTerminalConn(raw net.Conn, br *bufio.Reader, bw *bufio.Writer, role Role) *TerminalConn {
	c := &TerminalConn{
		role:   role,
		raw:    raw,
		br:     br,
		bw:     bw,
		rawOut: make(chan []byte),
		done:   make(chan error, 1),
	}
	go c.readLoop()
	return c
}

// readLoop decodes server frames until frameEnd, EOF, or a fault. Each frameRawOut
// payload is delivered to the rawOut channel (a chunk of the opaque pty byte
// stream; chunk boundaries carry no meaning — the consumer concatenates). An empty
// frameRawOut is legal and is forwarded as a zero-length slice (it is NOT EOF —
// EOF is frameEnd). The loop owns the rawOut channel close.
func (c *TerminalConn) readLoop() {
	defer close(c.rawOut)
	for {
		ft, payload, err := readFrame(c.br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.signalDone(nil) // clean server close
			} else {
				c.signalDone(fmt.Errorf("hostbridge: socket read: %w", err))
			}
			return
		}
		switch ft {
		case frameRawOut:
			// Forward the raw chunk, but stay interruptible by Close so a caller
			// that stops draining does not wedge the read loop. Copy out of the
			// reusable readFrame buffer is unnecessary (readFrame allocates a fresh
			// slice per frame), so the payload is handed over directly.
			select {
			case c.rawOut <- payload:
			case <-c.done:
				return
			}
		case frameEnd:
			var termErr error
			if len(payload) > 0 {
				termErr = errors.New(string(payload))
			}
			c.signalDone(termErr)
			return
		default:
			// frameResume*/frameEvent and anything else have no place on a TERMINAL
			// conn (§2.8): the surfaces do not share verbs. Treat as a protocol fault.
			c.signalDone(fmt.Errorf("hostbridge: unexpected server frame %d on terminal conn", ft))
			return
		}
	}
}

// signalDone delivers the terminal error once and closes the conn's socket so a
// blocked write/read unblocks. Idempotent.
func (c *TerminalConn) signalDone(err error) {
	c.doneOnce.Do(func() {
		c.done <- err
		close(c.done)
		_ = c.raw.Close()
	})
}

// RawOut is the stream of opaque pty output chunks, closed at session end. The
// consumer (the client terminal pump) concatenates the chunks and writes them to
// the dev's stdout — chunk boundaries are meaningless (a pty byte stream has no
// record boundary). Identical receive idiom to SocketConn.Events.
func (c *TerminalConn) RawOut() <-chan []byte { return c.rawOut }

// Done yields the terminal error (nil on clean end) — a select-able completion
// signal, the same shape as SocketConn.Done.
func (c *TerminalConn) Done() <-chan error { return c.done }

// Role reports the granted subscriber class (D61). A TerminalConn is always a
// WRITER in this MVP (a terminal READER is rejected at DialTerminal), but the
// field is carried for symmetry and a clean defence-in-depth refusal on Write.
func (c *TerminalConn) Role() Role { return c.role }

// Write frames raw keystroke bytes as frameRawIn and sends them — the io.Writer-ish
// input leg (the client's stdin pump calls it). A READER conn refuses with
// ErrReaderCannotWrite BEFORE the wire (D61), the byte-for-byte pattern of
// SocketConn.DriveInput; the server also refuses defensively. A frameRawIn larger
// than maxFrameBytes must be split by the caller (a pty byte stream has no record
// boundary, so splitting is lossless); Write enforces the cap rather than silently
// truncating. An empty write is a no-op (an empty frameRawIn is legal but carries
// nothing). Returns the number of bytes accepted (len(p) on success) so it
// satisfies the io.Writer shape callers expect.
func (c *TerminalConn) Write(p []byte) (int, error) {
	if c.role != RoleWriter {
		return 0, ErrReaderCannotWrite
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > maxFrameBytes {
		return 0, fmt.Errorf("hostbridge: raw input %d exceeds frame cap %d (split before Write)", len(p), maxFrameBytes)
	}
	if err := c.frame(frameRawIn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SendResize frames a Winsize as frameResize and sends it (the client's SIGWINCH
// handler calls it). A READER refuses (D61). The server forwards the 8-byte
// payload to the guest, which applies it via TIOCSWINSZ.
func (c *TerminalConn) SendResize(ws Winsize) error {
	if c.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	return c.frame(frameResize, encodeWinsize(ws))
}

// frame serializes one client→server raw frame under writeMu so a frameRawIn and a
// frameResize never interleave bytes on the wire. A write error wraps cleanly so
// the caller can surface a dead carriage (identical idiom to SocketConn.frame).
func (c *TerminalConn) frame(t frameType, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeFrame(c.bw, t, payload); err != nil {
		return fmt.Errorf("hostbridge: terminal write: %w", err)
	}
	return nil
}

// Close releases the attach: it signals done (closing the socket), waking the read
// loop, and detaches server-side via the socket close (the server's raw-in reader
// hits EOF → frameEnd → the in-guest SIGHUP path). Idempotent — the same shape as
// SocketConn.Close.
func (c *TerminalConn) Close() error {
	c.closeOnce.Do(func() { c.signalDone(nil) })
	return nil
}

// --- server accept loop ------------------------------------------------------

// Serve accepts framed UDS attachments on ln and resolves each through
// srv.Attach — the SAME arbitration path the loopback transport uses, so the
// seat logic (D61) and sentinels are identical across transports. It blocks until
// ln is closed (Accept returns an error), then returns that error (net.ErrClosed
// on a clean Close). Each accepted conn is handled in its own goroutine; one bad
// client never stalls another. Serve launches NO live process — it is the
// in-fleet, synthetic-verified server half (the cross-container wiring is the
// live.go DS_E2E_LIVE-gated deferred step).
func Serve(ln net.Listener, srv *Server) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go serveConn(raw, srv)
	}
}

// modePeekTimeout bounds how long serveConn waits for the optional frameMode that
// rides BETWEEN frameAttach and the accept (docs/serpent-cli-mvp/01 §2.3). A
// TERMINAL client (DialTerminal) flushes frameAttach+frameMode back-to-back before
// reading the reply, so the mode frame is already on the wire by the time the
// server has decoded the attach; a STRUCTURED client (Dial) sends ONLY frameAttach
// and then blocks reading the reply, so no mode frame ever arrives — the peek
// times out and the conn defaults to STRUCTURED, byte-identical to today (the
// back-compat negative control). It is a var so a test can tighten/loosen it; the
// default is generous enough that a legitimately-pipelined mode frame is never
// missed under load. The timeout NEVER ends the conn — it only resolves the mode.
var modePeekTimeout = 250 * time.Millisecond

// peekedFrame is a frame the mode-peek read off the wire that is NOT a frameMode
// (an old client pipelining a structured drive after frameAttach). It is carried
// into the structured serve so the frame is dispatched, not lost.
type peekedFrame struct {
	ft      frameType
	payload []byte
}

// peekMode reads the one optional frame between frameAttach and the accept reply
// (docs/serpent-cli-mvp/01 §2.3), under a short read deadline so a STRUCTURED
// client — which sends NOTHING after frameAttach and blocks reading the reply —
// resolves cleanly to STRUCTURED on timeout rather than the server blocking
// forever. Returns:
//
//   - modeTerminal, nil, nil       when the client sent frameMode{TERMINAL};
//   - modeStructured, nil, nil     when the client sent frameMode{STRUCTURED}, an
//     unspecified/garbage mode, or NOTHING (peek timed out — the old-client /
//     serpent watch path; the byte-identical back-compat default);
//   - modeStructured, &frame, nil  when the client pipelined a non-mode frame (a
//     drive) instead of a mode frame — that frame is handed back for the
//     structured serve to dispatch first, never lost.
//
// A genuine read fault (not a timeout) returns a non-nil error: the client left
// mid-handshake and serveConn drops the conn. The deadline is always cleared
// before returning so the live serve loop reads with no deadline. The peek NEVER
// rejects the conn — it only resolves the surface (a non-terminal mode always
// becomes STRUCTURED; an unspecified mode is not a wire error, it just defaults).
func peekMode(raw net.Conn, br *bufio.Reader) (attachMode, *peekedFrame, error) {
	// A timeout with zero bytes consumed is the STRUCTURED-client signal; bufio
	// has nothing buffered when no bytes arrived, so the live serve loop reads
	// cleanly afterward. A terminal/pipelining client flushes its frame promptly,
	// so a complete frame is read well within the window.
	_ = raw.SetReadDeadline(time.Now().Add(modePeekTimeout))
	ft, payload, err := readFrame(br)
	_ = raw.SetReadDeadline(time.Time{}) // clear: the live loop blocks with no deadline
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// No mode frame within the window → STRUCTURED (the old-client default).
			return modeStructured, nil, nil
		}
		// EOF or a real read fault: the client left mid-handshake.
		return modeStructured, nil, err
	}
	if ft == frameMode {
		if len(payload) == 1 && attachMode(payload[0]) == modeTerminal {
			return modeTerminal, nil, nil
		}
		// frameMode{STRUCTURED}, frameMode{UNSPECIFIED}, or a malformed length:
		// the structured surface is the safe, byte-identical default — an explicit
		// structured-mode client and an old no-mode client serve identically.
		return modeStructured, nil, nil
	}
	// A non-mode frame (a pipelined structured drive): default STRUCTURED and hand
	// the frame to the structured serve so it is dispatched, not dropped.
	return modeStructured, &peekedFrame{ft: ft, payload: payload}, nil
}

// serveTerminal serves a TERMINAL-mode attach (serpent claude --vm): the guest
// pty's raw byte duplex + winsize over the SAME framed carriage, instead of the
// structured event stream. It is the server-side half of the §2.4 design and the
// highest-risk detail in this unit — the BLOCKING raw-out pump.
//
//   - A TERMINAL-mode READER is refused with rejectTerminalReaderUnsupported (the
//     MVP is writer-only; spectate is the structured path, §2.3) BEFORE any seat
//     is taken.
//   - A session with no registered TerminalCarriage rejects internally (a terminal
//     attach against a structured-only session has no pty to serve).
//   - srv.Attach takes the writer seat (the SAME D61 arbitration the structured
//     path uses — a second terminal writer is ErrWriterSeatTaken) with a NO-OP
//     subscriber: a TERMINAL conn consumes NO structured events, so it is not on
//     the bridge fan-out / the bounded event outbox at all.
//   - frameRawOut is pumped from the carriage to the client with a DEDICATED
//     BLOCKING writer (terminalOutPump). It does NOT route through the bounded
//     event outbox (socketSubscriber.OnEvent's drop-on-overflow) — a dropped chunk
//     of a pty byte stream is an UNRECOVERABLE hole (no per-byte Seq, no replay,
//     §2.4). A wedged client back-pressures the pump → the carriage read → the
//     guest pty → CC's own pty write, exactly how a real terminal flow-controls a
//     program. This is the correct lossless semantics; do NOT "fix" it into a
//     drop.
//   - frameRawIn/frameResize are forwarded to the carriage through the writer-seat
//     Attachment (defence-in-depth: a non-writer is refused server-side too).
func serveTerminal(raw net.Conn, br *bufio.Reader, bw *bufio.Writer, srv *Server, handle AttachHandle) {
	// Reject a terminal READER before taking any seat (§2.3): the MVP is
	// writer-only; spectate is the structured path. This is a HANDLE-role check, so
	// it precedes Attach.
	if handle.Role == RoleReader {
		_ = writeFrame(bw, frameReject, []byte{byte(rejectTerminalReaderUnsupported)})
		return
	}

	// A no-op subscriber: a TERMINAL conn carries no structured events, so it must
	// NOT be on the bounded event outbox. The seat arbitration + handle validation
	// are the SAME (srv.Attach), but the fan-out is bypassed — the raw-out pump is
	// the conn's only server→client writer (§2.4).
	att, err := srv.Attach(handle, terminalNoopSubscriber{})
	if err != nil {
		code := sentinelReject(err)
		body := []byte{byte(code)}
		if code == rejectInternal {
			body = append(body, []byte(err.Error())...)
		}
		_ = writeFrame(bw, frameReject, body)
		return
	}
	defer att.Detach()

	tc := att.session.terminalCarriage()
	if tc == nil {
		// A terminal attach against a structured-only session: no pty to serve.
		// Clean internal reject (the seat is released by the deferred Detach).
		_ = writeFrame(bw, frameReject,
			append([]byte{byte(rejectInternal)}, []byte("no terminal carriage for session")...))
		return
	}

	// Accept: the client's DialTerminal awaits this before pumping. There is no
	// event outbox / drainer in TERMINAL mode — this conn has exactly two
	// goroutines (the out pump + the in reader) writing/reading bw, and bw is
	// written ONLY by the out pump, so no writeMu is needed (the §2.4 single-writer
	// property). The accept is written here, before the out pump starts, so the
	// client sees accept FIRST.
	if err := writeFrame(bw, frameAccept, []byte(att.Role())); err != nil {
		return
	}

	// done is closed by whichever leg ends first (carriage EOF, a client read
	// fault, or a write fault); the other leg unwinds via the shared raw.Close +
	// tc.Close.
	done := make(chan struct{})
	var endOnce sync.Once
	end := func() { endOnce.Do(func() { close(done) }) }

	// When EITHER leg ends, close BOTH the carriage and the socket so the OTHER leg
	// unblocks promptly: tc.Close releases a blocked out-pump RawOut read (CC
	// exited / client gone — the in-guest SIGHUP path), and raw.Close releases a
	// blocked in-reader readFrame. Without this, a client close that ends the in
	// reader would leave the out pump blocked forever on a quiet carriage (and
	// vice-versa). The carriage Close contract REQUIRES it to unblock a pending
	// RawOut — the standard io.Closer-on-a-blocked-reader discipline.
	go func() {
		<-done
		_ = tc.Close()
		_ = raw.Close()
	}()

	// The raw-in reader: client frameRawIn/frameResize → the carriage (through the
	// writer-seat Attachment). Runs in its own goroutine so the out pump can block
	// independently. On EOF (client closed) it ends the session.
	go func() {
		defer end()
		serveTerminalDrive(br, att)
	}()

	// The BLOCKING raw-out pump (the highest-risk leg): carriage → frameRawOut →
	// client, on the calling goroutine. A slow client back-pressures the bw write,
	// which back-pressures the carriage read, which back-pressures the guest pty /
	// CC — lossless end-to-end flow control, NO drop, NO bounded queue (§2.4). It
	// ends on carriage EOF (CC exited → a single frameEnd) or a client write fault.
	pumpErr := terminalOutPump(bw, tc, done)
	end()

	// Best-effort frameEnd so the client's Done resolves with the cause (CC exit
	// cause or nil on clean EOF). A dead wire just means the client already left.
	// The in reader has stopped (end() closed done; the shared raw.Close on the
	// deferred Detach path / client close wakes its blocked read), so this is the
	// sole final write — no interleave hazard.
	var body []byte
	if pumpErr != nil {
		body = []byte(pumpErr.Error())
	}
	_ = writeFrame(bw, frameEnd, body)
	_ = tc.Close()
}

// terminalOutPump is the BLOCKING server→client raw-out pump (§2.4): it reads
// opaque pty output chunks from the carriage and writes each as a frameRawOut to
// the client, with NO bounded queue and NO drop. A dropped chunk of a pty byte
// stream is an unrecoverable hole (no per-byte Seq), so a slow client must
// BACK-PRESSURE the pump rather than lose bytes — which back-pressures the carriage
// read and, in turn, CC's own write to its pty (real-terminal flow control). It
// returns:
//
//   - nil on carriage EOF (CC exited / the pty closed cleanly) — the caller emits a
//     frameEnd with no cause;
//   - the carriage read error (a non-EOF carriage fault) — surfaced on frameEnd;
//   - nil when done is closed (the in reader / client ended first) — a clean stop.
//
// A frameRawOut write that fails (the client wedged the wire and then left) ends
// the pump; the carriage read is unblocked by the caller's tc.Close on return.
func terminalOutPump(bw *bufio.Writer, tc TerminalCarriage, done <-chan struct{}) error {
	for {
		// Stop promptly if the other leg ended first (a closed done) — but only
		// CHECK, never block on it: the blocking point is the carriage read below,
		// which the caller unblocks with tc.Close when done closes.
		select {
		case <-done:
			return nil
		default:
		}
		chunk, err := tc.RawOut()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // CC exited / pty closed — a clean terminal end.
			}
			return fmt.Errorf("hostbridge: terminal carriage read: %w", err)
		}
		// writeFrame BLOCKS on a slow client (the dedicated raw-out pump's
		// back-pressure, §2.4) — this is the lossless semantics, never a drop.
		if werr := writeFrame(bw, frameRawOut, chunk); werr != nil {
			// The client wedged then left; the carriage read on the next loop would
			// block forever, so stop now. The caller's tc.Close releases it.
			return nil
		}
	}
}

// serveTerminalDrive reads client→server raw frames (frameRawIn / frameResize) and
// forwards them to the guest pty through the writer-seat Attachment (defence-in-
// depth: a non-writer is refused server-side too, the §2.2 pattern). It returns on
// EOF (client closed — the in-guest SIGHUP path) or a forward fault. frameResume
// and the structured drive frames have NO place on a terminal conn (§2.8); an
// unexpected frame ends the in reader, which unwinds the session.
func serveTerminalDrive(br *bufio.Reader, att *Attachment) {
	for {
		ft, payload, err := readFrame(br)
		if err != nil {
			return // client closed (EOF) or a read fault: end the in leg
		}
		switch ft {
		case frameRawIn:
			// COUNT-ONLY input-activity (D78 "driver typed", §A6): tick the payload-free
			// sink on EVERY inbound raw-input frame — BEFORE forwarding and WITHOUT
			// inspecting payload (the bytes are opaque keystrokes the carriage must never
			// parse). A reader's forged frame is refused below (defence-in-depth), but the
			// activity signal is the WRITER-seat fact "a frame arrived"; it fires for the
			// accepted terminal writer's keystrokes only (a reader is rejected at attach).
			att.server.noteInputActivity()
			// Forward opaque keystroke bytes to the guest pty. A reader's frame is
			// refused server-side (defence-in-depth); a non-reader forward fault ends
			// the session.
			if derr := att.RawInput(payload); derr != nil && !errors.Is(derr, ErrReaderCannotWrite) {
				return
			}
		case frameResize:
			ws, derr := decodeWinsize(payload)
			if derr != nil {
				// A malformed (non-8-byte) resize is a clean protocol end, never a
				// silent drop or a wedge (§2.2, symmetric with answerResume's
				// malformed-request handling). The deferred frameEnd carries the cause.
				return
			}
			if derr := att.Resize(ws); derr != nil && !errors.Is(derr, ErrReaderCannotWrite) {
				return
			}
		default:
			// frameResume / frameInput / frameGrant etc. are STRUCTURED-only; the
			// surfaces do not share verbs (§2.8). End the in leg on an unexpected frame.
			return
		}
	}
}

// terminalNoopSubscriber is the Subscriber a TERMINAL attach hands to srv.Attach.
// A TERMINAL conn consumes NO structured events (the raw-out pump is its only
// server→client path), so this drops every fan-out callback on the floor — it is
// never on the bounded event outbox, by construction (§2.4). srv.Attach still
// subscribes it to the bridge, but the bridge's events are simply ignored for a
// terminal conn; OnClose is a no-op because terminal teardown is driven by the
// carriage EOF / client close, not the structured bridge close.
type terminalNoopSubscriber struct{}

func (terminalNoopSubscriber) OnEvent(attach.Event) {}
func (terminalNoopSubscriber) OnClose(error)        {}

// serveConn runs one accepted attachment: read the attach handshake, PEEK the
// optional frameMode (default STRUCTURED), resolve it through Server.Attach
// (validation + seat arbitration), reply accept/reject, and then serve the
// negotiated surface — STRUCTURED (events out as frameEvent, drive/resume frames
// in) or TERMINAL (the guest pty's raw byte duplex + resize). It runs until the
// session ends or the client closes.
func serveConn(raw net.Conn, srv *Server) {
	defer raw.Close()
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	ft, payload, err := readFrame(br)
	if err != nil || ft != frameAttach {
		// A client that does not open with frameAttach is malformed; reply a
		// reject best-effort and drop.
		_ = writeFrame(bw, frameReject, append([]byte{byte(rejectHandleMalformed)}, []byte("expected attach frame")...))
		return
	}
	var handle AttachHandle
	if err := json.Unmarshal(payload, &handle); err != nil {
		_ = writeFrame(bw, frameReject, append([]byte{byte(rejectHandleMalformed)}, []byte("undecodable handle")...))
		return
	}

	// Mode-peek (§2.3): read one frame after frameAttach. If it is frameMode,
	// consume it and record the surface. A STRUCTURED client never sends one — it
	// is already blocked reading the accept reply — so the peek times out and the
	// conn defaults to STRUCTURED, leaving the structured path byte-identical to
	// today. A non-mode frame (an old client pipelining a drive) is handed to the
	// structured serve to dispatch, never lost (pendingFrame).
	mode, pendingFrame, perr := peekMode(raw, br)
	if perr != nil {
		// A read fault during the peek window: the client left mid-handshake.
		return
	}

	if mode == modeTerminal {
		serveTerminal(raw, br, bw, srv, handle)
		return
	}

	// --- STRUCTURED surface (unchanged) -------------------------------------
	// A subscriber that frames every projected event out to this client. It is
	// the socket twin of loopbackSubscriber: the same Subscriber interface the
	// bridge fans to, only the carrier (a UDS frame) differs, and — like the
	// loopback subscriber — it DROPS on a bounded overflow so a slow cross-process
	// reader never stalls the shared bridge pump (docs/15 §5.4 N-reader
	// independence), the drop being recoverable via frameResume.
	sub := newSocketSubscriber(bw)
	att, err := srv.Attach(handle, sub)
	if err != nil {
		code := sentinelReject(err)
		body := []byte{byte(code)}
		if code == rejectInternal {
			body = append(body, []byte(err.Error())...)
		}
		_ = writeFrame(bw, frameReject, body)
		return
	}
	// Accepted: release the seat (and unsubscribe) when this conn ends.
	defer att.Detach()

	// The session's bridge owns the single history ring (Bridge.ReplayFrom) that
	// answers a frameResume — the SAME ring loopback Conn.Resume reads, never a
	// second ring. Captured here so the resume answer path never re-derives events.
	bridge := att.session.bridge

	// Write frameAccept (and flush any events that arrived during Attach) under
	// the subscriber's writeMu, so the accept reply and every frameEvent are
	// serialized on the wire and the client sees accept FIRST. start also launches
	// the outbox drainer goroutine that owns frameEvent emission thereafter.
	if err := sub.start(att.Role()); err != nil {
		return
	}

	// Drive/resume reader: client→server frames off the SAME reader the handshake
	// used (a client may have pipelined drive frames after the attach; a fresh
	// reader would lose buffered bytes). EOF (client closed) is a clean terminal. A
	// READER's drive never reaches here (it refuses client-side), and the
	// Attachment also refuses defensively (ErrReaderCannotWrite), so a forged
	// reader drive frame is rejected, not honored. A frameResume is answered from
	// the bridge ring (any role may resume — recovery is a READER concern too). A
	// frame the mode-peek already consumed (a pipelined drive from a STRUCTURED
	// client that sent no frameMode) is dispatched first so no frame is lost.
	go serveDrive(br, att, sub, bridge, pendingFrame)

	// Block until the subscriber's stream ends (CC stdout EOF / bridge shutdown,
	// delivered via the subscriber's OnClose, or a drive/resume reader fault), then
	// the drainer goroutine emits a best-effort frameEnd so the client's Done
	// resolves with the cause.
	<-sub.closed
}

// serveDrive reads client→server drive/resume frames. Drives forward to the
// writer seat through the SAME Attachment.DriveInput/DriveGrant the loopback path
// uses (so the Driver is the only encoder and the bytes on CC stdin are identical
// across transports). A frameResume is answered from the bridge's history ring
// (Bridge.ReplayFrom — never a second ring). It returns on EOF (client close), a
// decode/forward fault, or when the subscriber's stream has already closed.
//
// pending, when non-nil, is a frame the mode-peek already read off br (a pipelined
// drive from a STRUCTURED client that sent no frameMode); it is dispatched FIRST so
// no client frame is lost across the peek.
func serveDrive(br *bufio.Reader, att *Attachment, sub *socketSubscriber, bridge *Bridge, pending *peekedFrame) {
	if pending != nil {
		if stop := dispatchDriveFrame(pending.ft, pending.payload, att, sub, bridge); stop {
			return
		}
	}
	for {
		ft, payload, err := readFrame(br)
		if err != nil {
			// Client closed (EOF) or a read fault: ensure the serve loop unblocks.
			sub.requestEnd(nil)
			return
		}
		if stop := dispatchDriveFrame(ft, payload, att, sub, bridge); stop {
			return
		}
	}
}

// dispatchDriveFrame routes one client→server STRUCTURED frame (drive/grant/
// resume) to the writer seat / history ring. It returns true when the serve loop
// should stop (a decode/forward fault or an unexpected frame, each having already
// requested end). Extracted from serveDrive so the mode-peek's pending frame and
// the live read loop dispatch through identical logic.
func dispatchDriveFrame(ft frameType, payload []byte, att *Attachment, sub *socketSubscriber, bridge *Bridge) (stop bool) {
	switch ft {
	case frameInput:
		var in DriveInput
		if err := json.Unmarshal(payload, &in); err != nil {
			sub.requestEnd(fmt.Errorf("hostbridge: decode drive input: %w", err))
			return true
		}
		// Forward to the writer seat; a drive error (e.g. input closed) ends
		// the session.
		if derr := att.DriveInput(in); derr != nil && !errors.Is(derr, ErrReaderCannotWrite) {
			sub.requestEnd(fmt.Errorf("hostbridge: drive input: %w", derr))
			return true
		}
	case frameGrant:
		if len(payload) < 1 {
			sub.requestEnd(errors.New("hostbridge: empty grant frame"))
			return true
		}
		route := GrantRoute(payload[0])
		var grant DriveGrant
		if err := json.Unmarshal(payload[1:], &grant); err != nil {
			sub.requestEnd(fmt.Errorf("hostbridge: decode drive grant: %w", err))
			return true
		}
		if derr := att.DriveGrant(grant, route); derr != nil && !errors.Is(derr, ErrReaderCannotWrite) {
			sub.requestEnd(fmt.Errorf("hostbridge: drive grant: %w", derr))
			return true
		}
	case frameResume:
		// Answer from the bridge's single history ring. A window-exceeded or a
		// malformed/oversized request is a clean reject, NOT a session-ending
		// fault — the reader keeps the live stream and may resume again.
		sub.answerResume(bridge, payload)
	default:
		sub.requestEnd(fmt.Errorf("hostbridge: unexpected client frame %d", ft))
		return true
	}
	return false
}

// socketSubscriber is the server-side Subscriber that frames every projected
// attach.Event out to one socket client. It is the cross-process twin of
// loopbackSubscriber: the bridge fans to the SAME Subscriber interface, and this
// implementation marshals each event onto a BOUNDED outbox drained by a single
// writer goroutine. Two slow-reader properties mirror loopback verbatim:
//
//   - OnEvent enqueues NON-BLOCKINGLY and DROPS on overflow, so a slow
//     cross-process reader never stalls the shared bridge pump (docs/15 §5.4) —
//     the exact loopback slow-reader drop, recovered the same way via frameResume.
//   - OnClose is also NON-BLOCKING: it records the terminal cause and signals the
//     writer goroutine (never touches the wire), so the bridge pump's closeFanout
//     returns immediately even when a slow client has the wire backed up.
//
// The writer goroutine is the SOLE frameEvent/frameEnd emitter; answerResume is
// the only other writer, so writeMu serializes just those two against each other
// (and the frameAccept handshake reply) — a resume reply must never interleave a
// frameEvent mid-frame on the wire.
type socketSubscriber struct {
	// writeMu serializes EVERY write to bw — the frameAccept handshake reply, each
	// frameEvent (from the drainer goroutine), the terminal frameEnd, and every
	// frameResumeReply/Reject (from answerResume) — so two writers never interleave
	// bytes on the wire.
	writeMu sync.Mutex
	bw      *bufio.Writer

	// started gates frameEvent emission until serveConn has written frameAccept.
	// Until then OnEvent queues into the bounded outbox; start() writes frameAccept
	// and launches the drainer goroutine that owns the wire thereafter.
	started bool

	// outbox holds pre-marshaled frameEvent payloads; bounded so a slow client
	// causes a DROP (recoverable via resume), never a pump stall.
	outbox chan []byte

	closed    chan struct{} // closed by the drainer as it exits (serveConn waits on it)
	stopCh    chan struct{} // closed by requestEnd to wind the drainer down
	stopOnce  sync.Once     // guards the single close(stopCh) so concurrent requestEnd callers can't double-close (panic)
	endOnce   sync.Once     // guards the single terminal frameEnd write (flushEnd) — a DISTINCT teardown phase from stopOnce
	closeOnce sync.Once

	mu      sync.Mutex
	endErr  error  // terminal cause, recorded once
	dropped uint64 // events dropped for this slow conn (a Seq hole to resume)
}

// socketOutboxDepth is the server-side per-conn event queue depth — the socket
// twin of loopback's eventBuffer. A reader may lag by up to this many events
// before the server starts dropping for it; smaller than DefaultHistorySize so
// the dropped span is normally still resumable from the ring. It is a var (not a
// const) only so a test can shrink it to force a deterministic slow-reader drop
// over a real socket; production never reassigns it.
var socketOutboxDepth = eventBuffer

func newSocketSubscriber(bw *bufio.Writer) *socketSubscriber {
	return &socketSubscriber{
		bw:     bw,
		outbox: make(chan []byte, socketOutboxDepth),
		closed: make(chan struct{}),
		stopCh: make(chan struct{}),
	}
}

// start writes frameAccept under writeMu, marks the subscriber started so OnEvent
// enqueues to the outbox, and launches the single drainer goroutine that owns
// frameEvent/frameEnd emission. It guarantees the client sees frameAccept before
// any frameEvent (the accept is written before the drainer can emit). Returns a
// write error (the client left mid-handshake), in which case no drainer is
// launched and the conn unwinds.
func (s *socketSubscriber) start(role Role) error {
	s.writeMu.Lock()
	werr := writeFrame(s.bw, frameAccept, []byte(role))
	if werr == nil {
		s.started = true
	}
	s.writeMu.Unlock()
	if werr != nil {
		// No drainer launched; nothing waits on closed, so close it so serveConn's
		// <-sub.closed does not block.
		s.closeOnce.Do(func() { close(s.closed) })
		return werr
	}
	s.startWriter()
	return nil
}

// startWriter launches the outbox drainer (one per conn). It drains the bounded
// event queue to the wire and, when wound down (requestEnd / EOF), emits the
// terminal frameEnd best-effort and signals serveConn via closed. A blocking
// flush here is the slow client's own backpressure; it holds writeMu only against
// answerResume, never against the bridge pump (OnEvent/OnClose never take
// writeMu).
func (s *socketSubscriber) startWriter() {
	go func() {
		defer s.closeOnce.Do(func() { close(s.closed) })
		for {
			select {
			case payload := <-s.outbox:
				s.writeMu.Lock()
				werr := writeFrame(s.bw, frameEvent, payload)
				s.writeMu.Unlock()
				if werr != nil {
					s.flushEnd() // client gone; emit terminal best-effort and exit
					return
				}
			case <-s.stopCh:
				// Drain whatever is still queued, then emit the terminal frameEnd.
				s.drainRemaining()
				s.flushEnd()
				return
			}
		}
	}()
}

// drainRemaining flushes any events still queued when the writer is winding down,
// so a clean shutdown does not silently swallow buffered deltas. Best-effort: a
// dead wire stops it early.
func (s *socketSubscriber) drainRemaining() {
	for {
		select {
		case payload := <-s.outbox:
			s.writeMu.Lock()
			werr := writeFrame(s.bw, frameEvent, payload)
			s.writeMu.Unlock()
			if werr != nil {
				return
			}
		default:
			return
		}
	}
}

// flushEnd writes the terminal frameEnd once with the recorded cause. Called by
// the writer goroutine as it unwinds (so the wire write is off the bridge pump's
// path). Best-effort: a dead wire just means the client already left.
func (s *socketSubscriber) flushEnd() {
	s.endOnce.Do(func() {
		s.mu.Lock()
		err := s.endErr
		s.mu.Unlock()
		var body []byte
		if err != nil {
			body = []byte(err.Error())
		}
		s.writeMu.Lock()
		_ = writeFrame(s.bw, frameEnd, body)
		s.writeMu.Unlock()
	})
}

// requestEnd records the terminal cause (once) and signals the writer goroutine
// to wind down and emit frameEnd. It NEVER touches the wire or writeMu, so it is
// safe to call from the bridge pump (OnClose) — closeFanout returns immediately —
// and from serveDrive on a client fault.
//
// Teardown is IDEMPOTENT under concurrent callers: the two end-signal paths
// (serveDrive's client-fault path and OnClose's bridge-pump path) can race, so the
// single close(stopCh) is guarded by stopOnce. The prior racy
// select{ case <-stopCh: default: close(stopCh) } let both callers fall through to
// default and double-close stopCh, panicking with "close of closed channel"
// (socket.go ~1611). The endErr first-writer-wins record stays under s.mu.
func (s *socketSubscriber) requestEnd(err error) {
	s.mu.Lock()
	if s.endErr == nil {
		s.endErr = err
	}
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// OnEvent frames ev out for the writer goroutine, NON-BLOCKING: if the outbox is
// full (a slow client) the event is DROPPED for this conn and the drop count
// advances — the bridge pump is never stalled by one slow reader (docs/15 §5.4).
// Until start() has written frameAccept the event still queues to the outbox (the
// drainer only runs after start, so the client never sees an event before
// accept). The dropped Seq is a hole the client recovers via Resume.
func (s *socketSubscriber) OnEvent(ev attach.Event) {
	ej, err := json.Marshal(ev)
	if err != nil {
		return
	}
	select {
	case s.outbox <- ej:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// OnClose records the terminal cause and signals the writer to emit frameEnd —
// NON-BLOCKING, so the bridge pump's closeFanout is never stalled by a slow
// client's backed-up wire.
func (s *socketSubscriber) OnClose(err error) { s.requestEnd(err) }

// dropCount reports how many events the fan-out dropped for this conn because its
// bounded outbox was full when they arrived — the server-side twin of
// loopbackSubscriber.droppedCount.
func (s *socketSubscriber) dropCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// answerResume reads the afterSeq from a frameResume payload, asks the bridge's
// single history ring (Bridge.ReplayFrom — never a second ring), and replies
// frameResumeReply (the recovered span) or frameResumeReject (the code). A
// window-exceeded resume is a clean frameResumeReject (→ ErrResumeWindowExceeded
// via errors.Is on the client), never a dropped connection; a malformed/oversized
// resume request is rejected cleanly the same way. The reply is serialized
// against the drainer's frameEvent writes by writeMu.
func (s *socketSubscriber) answerResume(b *Bridge, payload []byte) {
	if len(payload) != 8 {
		s.writeMu.Lock()
		_ = writeFrame(s.bw, frameResumeReject,
			append([]byte{byte(resumeRejectInternal)}, []byte("malformed resume request")...))
		s.writeMu.Unlock()
		return
	}
	afterSeq := binary.BigEndian.Uint64(payload)
	span, err := b.ReplayFrom(afterSeq)
	if err != nil {
		code := sentinelResumeReject(err)
		body := []byte{byte(code)}
		if code == resumeRejectInternal {
			body = append(body, []byte(err.Error())...)
		}
		s.writeMu.Lock()
		_ = writeFrame(s.bw, frameResumeReject, body)
		s.writeMu.Unlock()
		return
	}
	replyPayload, merr := encodeSpan(span)
	if merr != nil {
		s.writeMu.Lock()
		_ = writeFrame(s.bw, frameResumeReject,
			append([]byte{byte(resumeRejectInternal)}, []byte(merr.Error())...))
		s.writeMu.Unlock()
		return
	}
	s.writeMu.Lock()
	_ = writeFrame(s.bw, frameResumeReply, replyPayload)
	s.writeMu.Unlock()
}

// --- live tier-2 serve entry point (gated) -----------------------------------

// ServeBridge is the server-side glue an operator wires in the DS_E2E_LIVE
// tier-2 step: it binds a UDS at socketPath and serves the framed transport over
// srv until ctx is cancelled or the listener errors. It is the realized socket
// carrier behind the LoopbackTransport seam — the cross-container client dials
// socketPath and drives in. It launches NO container/claude/cia: the live
// container launch is the RunLiveBridge (live.go) deferred manual step; this
// helper only serves the socket. Returns the bind error, or the Serve error when
// the listener closes.
//
// ctx cancellation closes the listener, which unblocks Serve. The caller owns the
// CC process lifecycle (Bridge.Pump) separately, exactly as live.go's step list
// describes.
func ServeBridge(ctx context.Context, socketPath string, srv *Server) error {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("hostbridge: bind unix %s: %w", socketPath, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return Serve(ln, srv)
}
