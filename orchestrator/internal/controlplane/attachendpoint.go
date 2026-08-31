// SPDX-License-Identifier: Apache-2.0

// attachendpoint.go is the gap-3 orchestrator wiring: the attach.EndpointResolver
// that turns a session UUID into the M0 DIRECT EndpointCandidate the issued
// attach.v1.AttachHandle advertises (doc 15 §5.4, D79). The candidate's Address is
// the HOST-LOCAL UDS path the gap-3 serving leg (the per-session ds-hostbridge
// child the host agent execs, hostagent/attachbridge.go) serves the session on; the
// client's serpent-tui maps the proto DIRECT transport to hostbridge.TransportUnix
// and dials exactly that UDS (serpent-tui/cmd/serpent-tui/main.go). Wiring the
// resolver into the issuer (wiring.go: attach.NewIssuer(d.Store,
// attach.WithEndpointResolver(...))) is what flips the Attach RPC from issuing a
// seat-and-auth-only handle (no endpoint candidate, handle.go's documented degrade)
// to a SERVABLE handle — so serpent-tui takes its writer-seat branch rather than
// reader-only.
//
// THE ORCHESTRATOR STAYS RUNTIME-IGNORANT (Plan ae5168). The host-local UDS path is
// a DETERMINISTIC per-session host fact (a socket under a host-configured base dir,
// keyed on the session UUID) — NOT a runtime detail the orchestrator computes from
// GuestIP / overlay / event-socket (those live in the host agent, which alone builds
// the structured runtimev1.EntrypointConfig). The orchestrator only needs to know
// (1) the host-local socket dir the host agent serves under (a host bring-up fact,
// doc 13 §4) and (2) whether the session is PLACED yet (so a not-yet-bound session
// yields no fabricated address — handle.go's ok==false degrade). The path render
// mirrors the libvirt attach minter's token-store keying (attachminter.go: one file
// per session under a hidden per-host subdir) and the cabundlesource ref→bytes
// posture: a host-local artifact path derived from the session UUID, never a dialed
// resolution.
//
// SERVABILITY GATE (ok==false ⇒ no candidate). The resolver reads the session record
// through a NARROW store seam (GetSession) and reports ok only once the session is in
// a state the serving leg can serve — PLACED + RUNNING (READY/ATTACHED/WORKING). A
// not-yet-placed (PENDING/CREATING) or torn-down (DESTROYING/terminal) session yields
// ok==false, so the handle issues with the seat + auth but NO endpoint candidate
// rather than an address pointing at a socket the host agent is not serving (the
// fail-closed posture: never a fabricated endpoint, doc 15 §5.4).

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// defaultAttachSocketDir is the host-local directory the gap-3 serving leg serves the
// per-session attach UDS under when the wiring supplies no override. It is a host
// bring-up FACT (doc 13 §4) surfaced as a default so the offline module never hardcodes
// a deployment path elsewhere; the daemon composition root (main.go) overrides it per
// host. A hidden run dir sibling to the other per-host attach state (.ds-attach-tokens /
// .ds-ca-bundles under OverlayDir) on the operator host.
//
// SINGLE-SOURCED with the host-agent AttachBridge (hostagent.DefaultAttachSocketDir): the
// resolver advertises the DIRECT candidate under the SAME directory the bridge SERVES the
// per-session UDS under, so the path the client dials is exactly the path the bridge binds.
// Defining it ONCE (here, by reference to the one home) makes that agreement structural —
// the two sides cannot silently diverge to two different default dirs (a handle that
// resolved to a socket no bridge serves). The daemon root overrides BOTH from one config
// value per host.
const defaultAttachSocketDir = hostagent.DefaultAttachSocketDir

// attachSocketSuffix is the per-session socket filename suffix (so the path is a clear
// UDS, never mistaken for another per-session artifact).
const attachSocketSuffix = ".sock"

// endpointSessionReader is the NARROW store seam the resolver depends on: read the
// session record (to gate the endpoint on the session being placed + servable). It is a
// slice of the ControlPlaneStore surface — *store.Memory / *store.Postgres satisfy it
// natively — so the resolver adds NO method to any store interface (the storeseams
// discipline). The Attach RPC seat arbitration already reads GetSession, so this is the
// same authority, not a second one.
type endpointSessionReader interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
}

// sessionModeReader is the NARROW seam the resolver reads the host-resolved per-session
// launch mode through (terminal vs structured). It is a slice of the libvirt
// SessionModeStore surface (ModeFor) — *libvirt.fileSessionModeStore (via
// libvirt.SessionModeStore) satisfies it natively, so the resolver adds NO new store and
// reads the SAME <OverlayDir>/.ds-session-mode/<uuid> marker the host-agent
// EntrypointProducer wrote (doc 04 §2.7). It is OPTIONAL: a nil reader means the
// orchestrator was not co-located with the host overlay dir (DS_ORCH_OVERLAY_DIR unset),
// so every session tags DIRECT (fail-safe — no terminal tagging without a mode source).
type sessionModeReader interface {
	ModeFor(ctx context.Context, sessionUUID string) (mode libvirt.SessionMode, found bool, err error)
}

// sessionEndpointResolver resolves a session UUID to its host-local attach endpoint — the
// UDS path the gap-3 serving leg serves the session on. It is the orchestrator-side
// attach.EndpointResolver (handle.go) AND the optional attach.EndpointTransportResolver,
// wired into the issuer in wiring.go. It holds the host-local socket base dir (a host
// bring-up fact), the narrow session reader (the servability gate), and the OPTIONAL
// per-session mode reader (the transport-tag source). It dials nothing and computes no
// runtime detail — the orchestrator stays runtime-ignorant: it selects a TRANSPORT
// DELIVERY TAG from a host-written marker, it does not interpret runtime semantics (D38).
type sessionEndpointResolver struct {
	store     endpointSessionReader
	socketDir string
	// modes is the OPTIONAL per-session resolved-mode reader (the shared
	// <OverlayDir>/.ds-session-mode marker the host-agent wrote). It tags the endpoint
	// transport (DIRECT vs RAW_TERMINAL) from the SAME host resolution the libvirt minter
	// reads, so the single-box MVP — where the orchestrator control-plane (not the
	// host-agent minter) answers serpent-tui's Attach — still renders RAW_TERMINAL for a
	// terminal session. nil ⇒ DIRECT for every session (the fail-safe default: an
	// orchestrator with no overlay dir cannot read the marker, so it never fabricates a
	// terminal tag).
	modes sessionModeReader
}

// NewSessionEndpointResolver builds the resolver over the single backing store and the
// host-local attach socket dir. An empty socketDir falls back to defaultAttachSocketDir
// (so the offline module never hardcodes a deployment path elsewhere; main.go overrides
// it per host). It refuses a nil store fail-closed — a resolver with no record authority
// could not honor the servability gate. The mode source is wired separately via
// WithSessionModeReader (an optional, fail-safe refinement — DIRECT when absent).
func NewSessionEndpointResolver(st endpointSessionReader, socketDir string, opts ...endpointResolverOption) (*sessionEndpointResolver, error) {
	if st == nil {
		return nil, fmt.Errorf("controlplane: attach endpoint resolver requires a session store")
	}
	if socketDir == "" {
		socketDir = defaultAttachSocketDir
	}
	r := &sessionEndpointResolver{store: st, socketDir: socketDir}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// endpointResolverOption configures the resolver at construction (the additive wiring
// seam — the mode reader is optional, so it does not widen the constructor's required
// arguments and keeps the structured/no-overlay path unchanged).
type endpointResolverOption func(*sessionEndpointResolver)

// WithSessionModeReader wires the OPTIONAL per-session mode source the resolver reads to
// tag the endpoint transport (RAW_TERMINAL for a terminal session, DIRECT otherwise). A
// nil reader is tolerated (it leaves the resolver tagging DIRECT for every session — the
// fail-safe default the daemon root selects when DS_ORCH_OVERLAY_DIR is unset).
func WithSessionModeReader(m sessionModeReader) endpointResolverOption {
	return func(r *sessionEndpointResolver) { r.modes = m }
}

// socketPathFor renders the deterministic host-local UDS path for a session: a
// per-session socket under the host's attach socket dir, keyed on the (sanitized)
// session UUID so a retry re-derives the same path and the serving leg + the resolver
// name the SAME socket (mint there, advertise here, one shared path). The session UUID
// is sanitized to a single safe path component so a crafted UUID can never escape the
// socket dir.
func (r *sessionEndpointResolver) socketPathFor(sessionUUID string) string {
	return filepath.Join(r.socketDir, sanitizeSocketComponent(sessionUUID)+attachSocketSuffix)
}

// DirectEndpoint resolves the M0 DIRECT attach endpoint for a session (the
// attach.EndpointResolver seam). It returns:
//
//   - the host-local UDS path as the candidate Address, with an EMPTY ServerName (the
//     host-local direct hop has no SNI to verify — the per-session CA guards the EXTERNAL
//     egress path, never this host-local socket; this matches the libvirt minter's M0
//     directEndpoint posture, attachminter.go), and ok==true, ONCE the session is placed
//     and in a servable RUNNING state;
//   - ok==false (no candidate, no error) when the session is not yet placed
//     (PENDING/CREATING) or is tearing down (DESTROYING/terminal) — the handle then
//     issues with the seat + auth but no endpoint (handle.go's documented degrade), never
//     a fabricated address.
//
// A store read fault (the record authority unavailable) is surfaced as an error so the
// issuer fails the Attach rather than silently dropping the endpoint — the Attach handler
// maps it to a transient status. A missing record (ErrNotFound) is NOT an error here: an
// Attach against a non-existent session is already refused by the seat arbitration
// (handle.go runs AcquireWriter/AcquireReader, which reads GetSession first), so the
// endpoint resolve only needs to skip the candidate fail-closed.
func (r *sessionEndpointResolver) DirectEndpoint(ctx context.Context, sessionUUID string) (address, serverName string, ok bool, err error) {
	if sessionUUID == "" {
		return "", "", false, nil
	}
	rec, gerr := r.store.GetSession(ctx, sessionUUID)
	if gerr != nil {
		// A missing record is the seat arbitration's authority, not ours: skip the
		// candidate fail-closed (the seat read already refuses the attach). Any other read
		// fault (the record store stalled) is surfaced — the issuer must not advertise an
		// endpoint it could not gate.
		if isEndpointNotFound(gerr) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("controlplane: resolve attach endpoint for session %q: %w", sessionUUID, gerr)
	}
	if !endpointServable(rec.State) {
		// Not yet placed, or tearing down: no fabricated address — the handle issues with
		// the seat + auth only (handle.go ok==false degrade).
		return "", "", false, nil
	}
	// ServerName is empty: the host-local direct hop has no SNI (the per-session CA guards
	// the external path, not this socket) — exactly the libvirt minter's M0 directEndpoint.
	return r.socketPathFor(sessionUUID), "", true, nil
}

// EndpointTransport selects the transport TAG for the session's endpoint (the optional
// attach.EndpointTransportResolver seam, consulted by the issuer ONLY after DirectEndpoint
// reported a servable candidate). It mirrors the libvirt minter's transport-from-mode tag
// (attachminter.go directEndpoint): SessionModeTerminal → RAW_TERMINAL, everything else →
// DIRECT. The single-box MVP routes serpent-tui's Attach through THIS resolver (not the
// host-agent minter), so without this tag a terminal session would carry a DIRECT
// candidate and serpent-tui would fall back to the structured loop — the live-found bug.
//
// THE ORCHESTRATOR STAYS D38-RUNTIME-IGNORANT. The mode is a host-written fact (the
// <OverlayDir>/.ds-session-mode marker the EntrypointProducer persisted) — the resolver
// SELECTS a transport delivery tag from it (the byte-format serpent-tui's carrier picks:
// DialTerminal vs Dial; RAW_TERMINAL is a fourth byte-format on the SAME DIRECT host-local
// UDS path, not a new network transport), it does not interpret runtime semantics. With no
// mode source wired (nil modes — DS_ORCH_OVERLAY_DIR unset, so the orchestrator cannot read
// the marker) it returns UNSPECIFIED, and the issuer keeps DIRECT (the fail-safe default).
//
// A corrupt marker is fail-loud (an error): a marker the host wrote but the resolver could
// not interpret must NOT silently downgrade a terminal session to a DIRECT handle and
// mis-route the client onto the wrong carrier — the SAME posture the libvirt minter takes.
// An absent marker is the structured default (found=false → DIRECT, no error) so a session
// created before the terminal MVP, or on a host that never persisted, tags DIRECT cleanly.
func (r *sessionEndpointResolver) EndpointTransport(ctx context.Context, sessionUUID string) (attachv1.EndpointTransport, error) {
	if r.modes == nil || sessionUUID == "" {
		// No mode source (no overlay dir) ⇒ no terminal tagging: the issuer keeps DIRECT.
		return attachv1.EndpointTransport_ENDPOINT_TRANSPORT_UNSPECIFIED, nil
	}
	mode, _, err := r.modes.ModeFor(ctx, sessionUUID)
	if err != nil {
		return attachv1.EndpointTransport_ENDPOINT_TRANSPORT_UNSPECIFIED, fmt.Errorf("controlplane: resolve session mode for %q: %w", sessionUUID, err)
	}
	if mode == libvirt.SessionModeTerminal {
		return attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL, nil
	}
	return attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT, nil
}

// endpointServable reports whether a session in state s is one the gap-3 serving leg can
// serve an attach to: it is PLACED (a host binding exists) and RUNNING. READY (booted,
// pre-attach), ATTACHED (a writer already seated), and WORKING (driving) are all servable
// — an attach in any of them lands a (or another, reader) seat on a live session. PENDING
// / CREATING are pre-placement (no socket yet); SNAPSHOTTING / MIGRATING / PARKED /
// SUSPENDED / RESUMING are mid-lifecycle states whose carriage is not the steady serving
// leg (suspend/park/resume is its own choreography, doc 15 §4.3); DESTROYING + terminal
// are torn down. All of those yield ok==false (no candidate).
func endpointServable(s store.SessionState) bool {
	switch s {
	case store.SessionReady, store.SessionAttached, store.SessionWorking:
		return true
	default:
		return false
	}
}

// isEndpointNotFound reports whether a GetSession error is the not-found sentinel (the
// session has no record). Declared narrow so the resolver depends only on the one store
// sentinel it special-cases.
func isEndpointNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}

// sanitizeSocketComponent reduces a session UUID to a single safe path component for the
// socket filename: any path separator or traversal byte is replaced with '_' so the
// rendered path can never escape the socket dir (defense in depth — session UUIDs are
// orchestrator-minted, but the resolver renders a filesystem path from one). It mirrors
// the libvirt tree's sanitizeAnchorComponent intent without importing that tree (D80: the
// resolver is in-tree, replicating the keying invariant, not crossing a tree boundary).
func sanitizeSocketComponent(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}

// Compile-time proof the resolver satisfies the attach issuer's endpoint seam AND the
// optional transport-tag refinement (so the issuer renders RAW_TERMINAL for a terminal
// session instead of always DIRECT).
var (
	_ attach.EndpointResolver          = (*sessionEndpointResolver)(nil)
	_ attach.EndpointTransportResolver = (*sessionEndpointResolver)(nil)
)
