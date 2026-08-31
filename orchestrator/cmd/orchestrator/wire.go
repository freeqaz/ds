// SPDX-License-Identifier: Apache-2.0

package main

// wire.go is the SINGLE source of the orchestrator-side mirror of the host-agent bridge's
// documented framed-UDS wire contract (client/hostbridge/socket.go). Both relay legs speak it:
// the WRITE leg (drivesink_live.go) forwards an admitted DriveInput host-ward to Claude Code's
// stdin; the READ leg (contentsource_live.go) subscribes to CC's projected content stream. Both
// were built against the SAME frame codec, attach-handshake handle, reject mapping, and wire
// string/number space — this file holds that shared surface so the two legs cannot drift apart
// and the cross-tree byte pin (assurance/conformance-adapter/hostbridgewire) covers BOTH legs'
// full wire surface through ONE tracked file.
//
// WHY A HAND-ROLLED WIRE, NOT AN IMPORT OF client/hostbridge. The host-agent bridge's framed-UDS
// carrier lives in the client/ tree (a SEPARATE Go module). The orchestrator may not import it
// (the import-boundary gate forbids any cross-tree Go import but proto/gen/go), so — exactly as
// the ds-nft ingest client, the revocation-delta producer, and the WatchPolicies carrier all do
// — the relay legs speak the bridge's DOCUMENTED framed-UDS wire directly with a hand-rolled,
// stdlib-only codec (the SAME no-shared-crate, no-FFI discipline, D40/D67). The wire mirrored
// here is the one client/hostbridge/socket.go documents:
//
//	Every message is a FRAME: 1 byte frame-type, 4 bytes BIG-ENDIAN payload length N, N bytes
//	payload. The opening client→server frame is frameAttach carrying the AttachHandle JSON; the
//	server replies frameAccept (granted role string) or frameReject (a 1-byte rejectCode +
//	optional message). Thereafter the WRITER pushes frameInput (a DriveInput JSON: {"text": ...})
//	and the server pushes frameEvent / frameEnd; a READER additionally resumes the bridge's
//	bounded history ring with frameResume{afterSeq} (8-byte BE) → frameResumeReply (the recovered
//	span) / frameResumeReject (a resumeRejectCode). The transport re-encodes NOTHING.
//
// A host-agent bridge that renumbers a frame or renames a JSON tag is a coordinated both-sides
// change; the cross-tree pin turns RED the moment either tree drifts (it reads this file's ACTUAL
// consts + tags, not a second hand-copied literal).
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs a payload or the attach token; the bytes cross
// the wire opaquely and every error names only the structural fault.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// --- the documented host-agent bridge framed-UDS wire contract (mirrored, NOT imported) ---
//
// bridgeFrameType is the producer/consumer half of client/hostbridge/socket.go's frame number
// space. The relay legs name the frames they use: the attach handshake (attach/accept/reject),
// the write-leg frameInput, the read-leg frameEvent, the terminal frameEnd, and the read-leg
// resume ring (resume/resumeReply/resumeReject — the D61 slow-reader recovery the content leg
// replays on re-open). The numbers are pinned to the golden; a renumber on either tree is RED.

type bridgeFrameType byte

const (
	bridgeFrameAttach       bridgeFrameType = 1  // client→server: opening AttachHandle JSON
	bridgeFrameAccept       bridgeFrameType = 2  // server→client: attach granted (payload: granted role string)
	bridgeFrameReject       bridgeFrameType = 3  // server→client: attach rejected (1-byte rejectCode + optional message)
	bridgeFrameEvent        bridgeFrameType = 4  // server→client: one attach.Event JSON (the read leg decodes; the write leg discards)
	bridgeFrameInput        bridgeFrameType = 5  // client→server: one DriveInput JSON — the write leg
	bridgeFrameEnd          bridgeFrameType = 7  // server→client: session terminal (drain/stream end-marker)
	bridgeFrameResume       bridgeFrameType = 8  // client→server: resume request (payload: 8-byte BE afterSeq) — the read leg
	bridgeFrameResumeReply  bridgeFrameType = 9  // server→client: recovered span (4-byte BE count + count×[4-byte BE len | attach.Event JSON])
	bridgeFrameResumeReject bridgeFrameType = 10 // server→client: resume refused (1-byte resumeRejectCode + optional message)
)

// bridgeRejectCode is the wire form of an attach rejection (client/hostbridge/socket.go
// rejectCode). Both legs map the codes they surface back to a readable cause; an unknown code is
// a generic internal reject.
type bridgeRejectCode byte

const (
	bridgeRejectWriterSeatTaken           bridgeRejectCode = 1
	bridgeRejectAuthInvalid               bridgeRejectCode = 3
	bridgeRejectHandleExpired             bridgeRejectCode = 4
	bridgeRejectHandleMalformed           bridgeRejectCode = 5
	bridgeRejectUnknownSession            bridgeRejectCode = 6
	bridgeRejectInternal                  bridgeRejectCode = 7
	bridgeRejectTerminalReaderUnsupported bridgeRejectCode = 8
)

// bridgeResumeRejectCode is the wire form of a resume refusal (client/hostbridge/socket.go
// resumeRejectCode). A window-exceeded resume is a CLEAN reject (the ring aged the requested span
// out — the read leg rejoins at the live head, accepting the gap), never a dropped connection;
// an internal fault is a server-side answer error. It is a SEPARATE code space from the attach
// rejectCode above (a resume reject rides frameResumeReject, not frameReject).
type bridgeResumeRejectCode byte

const (
	bridgeResumeRejectWindowExceeded bridgeResumeRejectCode = 1 // the aged-out span (unrecoverable — rejoin at live head)
	bridgeResumeRejectInternal       bridgeResumeRejectCode = 2 // a server fault answering the resume (e.g. a malformed request)
)

// bridgeMaxFrameBytes caps a single wire frame payload (matching client/hostbridge's maxLineBytes
// so a full attach.Event with a large tool input still crosses), bounded so a malformed length
// cannot drive an unbounded alloc on a drain/pump leg.
const bridgeMaxFrameBytes = 10 << 20

// bridgeMaxResumeSpanBytes caps an entire frameResumeReply payload (the count-prefixed span of
// recovered events), larger than a single frame because it carries a whole window at once —
// matching client/hostbridge's maxResumeSpanBytes. Still bounded so a malformed span length
// cannot over-allocate the read leg.
const bridgeMaxResumeSpanBytes = 64 << 20

// bridgeTransportUnix is the EndpointCandidate.Transport the host-agent bridge's framed-UDS server
// dials/serves (client/hostbridge TransportUnix). The RESERVED RELAY endpoint (attach.v1
// ENDPOINT_TRANSPORT_RELAY) is realized on this framed-UDS carrier: the tag names the RELAY class,
// the bytes ride the same per-session attach UDS the DIRECT carrier serves.
const bridgeTransportUnix = "unix"

// bridgeRoleWriter / bridgeRoleReader are the D61 seat roles the two legs attach as
// (client/hostbridge RoleWriter/RoleReader): the WRITER is the one seat that may drive input onto
// CC stdin; a READER is an N-th read-only subscription (events out, no write in). The write leg
// presents WRITER, the content leg presents READER.
const (
	bridgeRoleWriter = "WRITER"
	bridgeRoleReader = "READER"
)

// wireAttachHandle is the local Go shape of the host-agent bridge's AttachHandle JSON
// (client/hostbridge/handle.go), declared here with the SAME json tags so the marshaled bytes are
// the ones the bridge decodes. It is NOT the frozen proto (the orchestrator can import
// proto/gen/go, but the bridge speaks its own local JSON handle, not the proto): the five fields
// are the M0-frozen AttachHandle shape verbatim. Both legs present it (only the Role differs).
type wireAttachHandle struct {
	SessionUUID string                  `json:"session_uuid"`
	Endpoints   []wireEndpointCandidate `json:"endpoints"`
	Auth        wireAuthMaterial        `json:"auth"`
	Role        string                  `json:"role"`
	ExpiresAt   time.Time               `json:"expires_at"`
}

type wireEndpointCandidate struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
}

type wireAuthMaterial struct {
	Token string `json:"token"`
}

// wireDriveInput is the local Go shape of the host-agent bridge's write-side DriveInput JSON
// (client/hostbridge aliases claudecode.DriveInput, whose single field is `text`). The bridge
// decodes this SAME shape and hands it to its existing Driver.EncodeInput, so the bytes on CC
// stdin are the Driver's output — the write leg re-encodes nothing.
type wireDriveInput struct {
	Text string `json:"text"`
}

// --- frame codec (the hand-rolled shared half of the bridge wire) ---

// writeBridgeFrame writes one type-length-payload frame (1-byte type, 4-byte BIG-ENDIAN length,
// payload) and flushes so the peer sees it immediately (an attach handshake, a single drive frame,
// or a resume request must not stall in the buffer). A payload over the cap is rejected before any
// byte is written.
func writeBridgeFrame(w *bufio.Writer, t bridgeFrameType, payload []byte) error {
	if len(payload) > bridgeMaxFrameBytes {
		return fmt.Errorf("bridge wire: frame payload %d exceeds cap %d", len(payload), bridgeMaxFrameBytes)
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

// readBridgeFrame reads one type-length-payload frame. A length over the cap is a malformed frame
// the reader rejects fail-closed (never allocating an unbounded buffer). The frameResumeReply span
// is the ONLY oversized frame (a whole recovered window); it is admitted up to
// bridgeMaxResumeSpanBytes, every other frame stays under bridgeMaxFrameBytes. A clean peer close
// surfaces as the underlying read error (io.EOF), which a drain/pump treats as terminal.
func readBridgeFrame(r *bufio.Reader) (bridgeFrameType, []byte, error) {
	var hdr [5]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := bridgeFrameType(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:])
	limit := uint32(bridgeMaxFrameBytes)
	if t == bridgeFrameResumeReply {
		limit = uint32(bridgeMaxResumeSpanBytes)
	}
	if n > limit {
		return 0, nil, fmt.Errorf("bridge wire: frame length %d exceeds cap %d", n, limit)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := readFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return t, payload, nil
}

// readFull fills buf from r (io.ReadFull semantics), surfacing a short read as an error so a
// truncated frame never yields a half-decoded handle/reply. Delegating to io.ReadFull matters for
// the FINAL frame of a stream: a Read that returns the last bytes together with io.EOF still
// counts as a full read (err == nil), so a frameEnd coincident with the peer close is decoded, not
// mistaken for a transport fault.
func readFull(r *bufio.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// rejectError maps a frameReject payload (a 1-byte rejectCode + optional message) back to a
// readable cause (client/hostbridge rejectionSentinel). Both legs surface it so the operator can
// see WHY an attach was refused (a taken seat, an invalid/expired token, an unknown session)
// rather than an opaque transport fault.
func rejectError(sessionUUID string, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("bridge wire: relay attach for session %q rejected (no reason)", sessionUUID)
	}
	code := bridgeRejectCode(payload[0])
	msg := string(payload[1:])
	var reason string
	switch code {
	case bridgeRejectWriterSeatTaken:
		reason = "writer seat already taken"
	case bridgeRejectAuthInvalid:
		reason = "attach auth invalid"
	case bridgeRejectHandleExpired:
		reason = "attach handle expired"
	case bridgeRejectHandleMalformed:
		reason = "attach handle malformed"
	case bridgeRejectUnknownSession:
		reason = "unknown session"
	case bridgeRejectTerminalReaderUnsupported:
		reason = "terminal reader unsupported"
	default:
		reason = "internal reject"
		if msg != "" {
			reason = msg
		}
	}
	return fmt.Errorf("bridge wire: relay attach for session %q rejected: %s", sessionUUID, reason)
}
