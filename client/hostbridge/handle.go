// handle.go — the locally-declared Go shape of the D79 transport-ambivalent
// AttachHandle (proto/dreamserpent/attach/v1/README.md; docs/15 §5.4).
//
// The attach.v1 proto is README-only at M0 (proto/FREEZE.md: no stub message
// bodies before the freeze), so the transport-bridge declares the handle,
// endpoint, auth, and role types LOCALLY rather than importing a not-yet-frozen
// proto. These are the working Go model of the M0-frozen AttachHandle:
//
//	AttachHandle = { session_uuid, endpoints []EndpointCandidate, auth
//	                 AuthMaterial, role WRITER|READER, expires_at }
//
// When attach.v1 freezes (FREEZE.md M0 row, the §6.1 checklist row 8) these
// shapes become the generated proto's Go view and this file collapses to a thin
// alias — the contract surface (the five fields, the two transports admitted
// from day one, the one-writer/N-reader role split) is deliberately identical so
// the freeze is a substitution, not a redesign.
package hostbridge

import (
	"errors"
	"time"
)

// Role is the D61 one-writer/N-reader subscriber class carried on the handle.
// A WRITER handle may drive input and answer asks; a READER receives the event
// stream but every write attempt is refused server-side (the WatchSession
// terminator enforces this, docs/15 §5.3-5.4). Arbitration is NOT a property of
// the handle alone — a second WRITER handle is also rejected (Server.Attach),
// because the writer seat lives in the session record, not in the handle.
type Role string

const (
	// RoleWriter holds the one writer seat: drives DriveInput + DriveGrant.
	RoleWriter Role = "WRITER"
	// RoleReader is an N-th read-only subscriber: events out, no write in.
	RoleReader Role = "READER"
)

// valid reports whether r is one of the two D61 roles. An unknown role is a
// rejected attach (fail closed) rather than a defaulted reader.
func (r Role) valid() bool { return r == RoleWriter || r == RoleReader }

// EndpointTransport names the transport an EndpointCandidate addresses. M0 ships
// only the direct client→host-agent transport; the relay (M2 web client) and the
// D61 spectate multiplexer (M4) join later. Admitting the list shape — and the
// transport tag — from day one costs one field; deciding later costs a v2 handle
// (D79; attach.v1 README "Admitting both transports from day one costs one field").
type EndpointTransport string

const (
	// TransportDirect is the M0 direct client→host-agent endpoint.
	TransportDirect EndpointTransport = "direct"
	// TransportRelay is the M2 relay endpoint (web client). Reserved, not served
	// at M0 — admitted in the candidate list shape only.
	TransportRelay EndpointTransport = "relay"
	// TransportRawTerminal is the serpent claude --vm raw-pty endpoint: a handle
	// carrying it advertises the in-VM CC pty byte-duplex surface the client dials
	// via SocketTransport.DialTerminal (returning a *TerminalConn, NOT a
	// *SocketConn) instead of the structured Dial (10-build-decisions §A3,
	// docs/serpent-cli-mvp/03 §2.2). It is the local mirror of the frozen
	// attach.v1 ENDPOINT_TRANSPORT_RAW_TERMINAL tag (transportFromProto maps the
	// two). Like TransportUnix it is realized by the framed-UDS carrier — the raw
	// endpoint's Address is the same per-session attach UDS; the tag is the
	// CAPABILITY signal that the session serves a terminal (pty) surface there.
	TransportRawTerminal EndpointTransport = "raw_terminal"
)

// EndpointCandidate is one reachable address for the session's event/drive
// stream. M0 emits exactly one (TransportDirect); the repeated shape is reserved
// from day one so the relay endpoint joins without a v2 handle (D79; docs/15
// §5.4). Address is an opaque transport-scoped locator — for the M0 in-process /
// loopback transport it is the loopback registry key; for a future socket
// transport it is the dial string. The bridge treats it opaquely; the transport
// resolves it.
type EndpointCandidate struct {
	Transport EndpointTransport `json:"transport"`
	Address   string            `json:"address"`
}

// AuthMaterial is the short-lived, session-scoped attach credential (D39: never
// a long-lived cred). It is opaque to the bridge: the bridge checks it against
// what the issuing Server minted for this session and that the handle has not
// expired; it never interprets the bytes. A captured token dies with the session
// and is useless against another session (HARDENING-NOTES §1.2). Modeled as an
// opaque token rather than a structured cred precisely so the M1 minimal-CA / M3
// SPIFFE swap is a substrate change behind a stable field (docs/15 §6, Identity
// seam).
type AuthMaterial struct {
	// Token is the opaque session-scoped secret. Compared by constant-time
	// equality at attach (Server.validate); never logged (HARDENING-NOTES §2.2).
	Token string `json:"token"`
}

// AttachHandle is the transport-ambivalent attach handle (D79; docs/15 §5.4),
// declared locally per the unit charter (attach.v1 is README-only at M0). It is
// what a client presents to the bridge to attach; the Server issues it
// (IssueHandle) and validates it (Attach). The five fields are the M0-frozen
// AttachHandle shape verbatim.
type AttachHandle struct {
	// SessionUUID joins the handle to the session record (the writer seat lives
	// there, not on the handle — docs/15 §5.4).
	SessionUUID string `json:"session_uuid"`
	// Endpoints is the candidate list (≥1 at M0, the direct endpoint). Reserved
	// repeated shape: the relay endpoint joins at M2 without a v2 (D79).
	Endpoints []EndpointCandidate `json:"endpoints"`
	// Auth is the short-lived session-scoped attach credential (D39).
	Auth AuthMaterial `json:"auth"`
	// Role is WRITER or READER (D61 one-writer/N-reader).
	Role Role `json:"role"`
	// ExpiresAt is the handle's hard expiry. An attach with ExpiresAt in the past
	// is rejected (Server.validate), so a stale handle cannot attach even with the
	// right token.
	ExpiresAt time.Time `json:"expires_at"`
}

// Handle-validation error sentinels. The Server returns these on a rejected
// attach so callers (and tests) can assert the exact rejection reason without
// string-matching. They are the four ACCEPTANCE rejection classes:
// bad-role/no-endpoints (malformed), wrong-token (auth), expired (expiry), and
// the seat-arbitration refusals live on the Server (ErrWriterSeatTaken /
// ErrReaderCannotWrite).
var (
	// ErrHandleMalformed is returned when the handle is structurally invalid:
	// empty SessionUUID, no endpoints, or an unknown Role.
	ErrHandleMalformed = errors.New("hostbridge: malformed attach handle")
	// ErrAuthInvalid is returned when AuthMaterial does not match what the Server
	// minted for the session (or is empty). The invalid-AuthMaterial rejection.
	ErrAuthInvalid = errors.New("hostbridge: invalid attach auth material")
	// ErrHandleExpired is returned when ExpiresAt is at or before now. The
	// expired-at-in-the-past rejection.
	ErrHandleExpired = errors.New("hostbridge: attach handle expired")
	// ErrUnknownSession is returned when the handle's SessionUUID is not a session
	// this Server serves.
	ErrUnknownSession = errors.New("hostbridge: unknown session for attach handle")
)

// expired reports whether the handle is at or past its expiry as of now.
func (h AttachHandle) expired(now time.Time) bool {
	return !now.Before(h.ExpiresAt)
}

// directEndpoint returns the M0 direct endpoint candidate, if present. The
// loopback transport serves only TransportDirect at M0; a handle with only relay
// endpoints has no direct endpoint (M2). Returns the first direct candidate and
// whether one exists.
func (h AttachHandle) directEndpoint() (EndpointCandidate, bool) {
	for _, ep := range h.Endpoints {
		if ep.Transport == TransportDirect {
			return ep, true
		}
	}
	return EndpointCandidate{}, false
}

// servableEndpoint returns the first endpoint a REALIZED M0 transport can serve
// — TransportDirect (the in-process loopback carrier, loopback.go) or
// TransportUnix (the framed UDS carrier, socket.go). A handle with only a relay
// endpoint has no servable carrier yet (M2) and is malformed at M0; the
// arbitration (Server.validate) keys on this so a handle for EITHER realized
// transport attaches, while a relay-only handle is still rejected. Returns the
// first servable candidate and whether one exists.
func (h AttachHandle) servableEndpoint() (EndpointCandidate, bool) {
	for _, ep := range h.Endpoints {
		if ep.Transport == TransportDirect || ep.Transport == TransportUnix {
			return ep, true
		}
	}
	return EndpointCandidate{}, false
}
