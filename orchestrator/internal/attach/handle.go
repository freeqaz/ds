package attach

// handle.go is the D79 attach-handle issuance (doc 15 §5.4): Attach (the
// orchestrator.v1 SessionService leg) and IssueAttachHandle (the hypervisor.v1
// HypervisorDriver leg) both return the FROZEN, transport-ambivalent
// attach.v1.AttachHandle — endpoint candidates (M0 is the DIRECT
// client→host-agent endpoint ONLY), short-lived session-scoped AuthMaterial
// (NEVER a long-lived cred, D39), the WRITER/READER Role the seat arbitration
// granted, and an expiry. Issuing a WRITER handle takes the seat through the
// seat arbitration (seat.go), so the handle and the session record never disagree
// about who holds the one writer seat (D61).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// defaultHandleTTL bounds an issued handle (and its auth material) when the
// issuer does not override it. It is short-lived by construction (D39 — the
// handle carries session-scoped auth, never a long-lived cred); the value is a
// strawman, not a frozen contract (the FROZEN surface is the handle SHAPE).
const defaultHandleTTL = 5 * time.Minute

// ErrUnknownRole is returned by Issue when the requested attach.v1.Role is
// neither WRITER nor READER (e.g. ROLE_UNSPECIFIED on the wire): the seat class a
// handle grants must be a real D61 class.
var ErrUnknownRole = errors.New("attach: attach handle requires ROLE_WRITER or ROLE_READER (D61 seat class)")

// Issuer mints the D79 attach handle. It composes the seat arbitration (seat.go,
// over the store) with the DIRECT endpoint the host agent advertises and a
// freshly-minted short-lived session-scoped credential. The same Issuer backs
// both Attach (orchestrator.v1) and IssueAttachHandle (hypervisor.v1) — the two
// RPCs return the identical handle SHAPE, so this is the one implementation. A
// zero Issuer is not usable; construct with NewIssuer.
type Issuer struct {
	store seatStore

	// endpoint resolves the DIRECT client→host-agent attach endpoint for a
	// session (M0: direct only — the host agent that runs the session terminates
	// the attach stream, doc 15 §5.4). A nil resolver yields a handle with no
	// endpoint candidate (the seat/auth still issue); a real deployment wires the
	// host-agent address resolver.
	endpoint EndpointResolver

	ttl   time.Duration
	now   func() time.Time
	token func() []byte
}

// EndpointResolver yields the M0 DIRECT attach endpoint for a session — the
// host-agent address/SNI the client connects to (doc 15 §5.4: M0 is direct
// client→host-agent ONLY; M2 the relay endpoint joins; M4 the relay becomes the
// D61 spectate multiplexer — all behind this same repeated-candidates field, no
// v2). Returning ok == false means the endpoint is not yet resolvable (the
// session is not placed): the handle issues with no candidate rather than a
// fabricated address.
type EndpointResolver interface {
	DirectEndpoint(ctx context.Context, sessionUUID string) (address, serverName string, ok bool, err error)
}

// EndpointResolverFunc adapts a function to an EndpointResolver.
type EndpointResolverFunc func(ctx context.Context, sessionUUID string) (string, string, bool, error)

// DirectEndpoint calls the function.
func (f EndpointResolverFunc) DirectEndpoint(ctx context.Context, sessionUUID string) (string, string, bool, error) {
	return f(ctx, sessionUUID)
}

// EndpointTransportResolver is an OPTIONAL refinement an EndpointResolver may also
// satisfy to select the endpoint's TRANSPORT TAG (the byte-format the serving leg
// realizes on the SAME host-local hop), rather than always advertising DIRECT. The
// terminal-MVP wires it: the orchestrator control-plane resolver
// (controlplane.sessionEndpointResolver) reads the host-resolved per-session mode
// marker and tags RAW_TERMINAL for a terminal session, DIRECT otherwise — a single-box
// MVP parity with the host-agent minter (libvirt/attachminter.go), which already tags
// the transport from the SAME marker (doc 04 §2.7).
//
// THE ORCHESTRATOR STAYS D38-RUNTIME-IGNORANT. The transport is a DELIVERY TAG selected
// from a host-written marker (the byte-format serpent-tui's carrier picks: DialTerminal
// vs Dial), NOT a runtime semantic the orchestrator interprets — RAW_TERMINAL is a
// fourth byte-format on the SAME DIRECT host-local UDS path (the address render is
// identical; only the enum differs). A resolver that does NOT implement this interface
// (e.g. EndpointResolverFunc, or a deployment with no mode source) keeps DIRECT — the
// byte-identical historical path.
type EndpointTransportResolver interface {
	// EndpointTransport returns the transport tag for the session's resolved endpoint.
	// It is consulted ONLY after DirectEndpoint has reported a servable candidate
	// (ok==true). An error fails the issuance fail-loud (a host-written marker the
	// resolver could not interpret must not silently mis-route the client onto the
	// wrong carrier). When the tag is UNSPECIFIED the issuer keeps DIRECT (fail-safe).
	EndpointTransport(ctx context.Context, sessionUUID string) (attachv1.EndpointTransport, error)
}

// IssuerOption configures an Issuer.
type IssuerOption func(*Issuer)

// WithEndpointResolver wires the DIRECT endpoint resolver (the M0 host-agent
// attach address). Without it, issued handles carry no endpoint candidate.
func WithEndpointResolver(r EndpointResolver) IssuerOption { return func(i *Issuer) { i.endpoint = r } }

// WithHandleTTL overrides the handle/credential lifetime (default
// defaultHandleTTL). The handle stays short-lived regardless (D39).
func WithHandleTTL(d time.Duration) IssuerOption {
	return func(i *Issuer) {
		if d > 0 {
			i.ttl = d
		}
	}
}

// WithClock overrides the issuer clock (test seam for expiry).
func WithClock(now func() time.Time) IssuerOption { return func(i *Issuer) { i.now = now } }

// WithTokenGen overrides the credential generator (test seam; the default is
// crypto/rand). A real deployment may inject a token minted against the D22
// session-scoped material — the SHAPE the handle carries is unchanged (opaque
// bytes + expiry, D39).
func WithTokenGen(gen func() []byte) IssuerOption { return func(i *Issuer) { i.token = gen } }

// NewIssuer constructs an attach-handle issuer over the seat store seam.
func NewIssuer(st seatStore, opts ...IssuerOption) *Issuer {
	i := &Issuer{
		store: st,
		ttl:   defaultHandleTTL,
		now:   time.Now,
		token: randomAttachToken,
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// Issue mints the attach handle for sessionUUID at role (doc 15 §5.4, D79). It
// runs the D61 seat arbitration first (server-side, seat.go):
//
//   - ROLE_WRITER: AcquireWriter takes the one writer seat (refused with
//     ErrWriterSeatHeld if held and !handoff; a record mutation with attribution
//     when granted/handed off). seatID is the writer's holder identity.
//   - ROLE_READER: AcquireReader admits one of the N readers (unbounded; seatID
//     is ignored — readers are not recorded as seat holders).
//
// Then it assembles the FROZEN attach.v1.AttachHandle: the M0 DIRECT endpoint
// candidate (or none if unresolved), a freshly-minted short-lived session-scoped
// AuthMaterial (D39), the granted Role, and a whole-handle expiry. The seat
// outcome (and any handoff) is returned alongside so the caller can audit a
// driver handoff. An unknown role is ErrUnknownRole.
func (i *Issuer) Issue(ctx context.Context, sessionUUID, seatID string, role attachv1.Role, handoff bool) (*attachv1.AttachHandle, SeatGrant, error) {
	var grant SeatGrant
	var err error
	switch role {
	case attachv1.Role_ROLE_WRITER:
		grant, err = AcquireWriter(ctx, i.store, sessionUUID, seatID, handoff)
	case attachv1.Role_ROLE_READER:
		grant, err = AcquireReader(ctx, i.store, sessionUUID)
	default:
		return nil, SeatGrant{}, ErrUnknownRole
	}
	if err != nil {
		return nil, SeatGrant{}, err
	}

	now := i.now()
	expires := uint64(now.Add(i.ttl).Unix())

	handle := &attachv1.AttachHandle{
		SessionUuid: sessionUUID,
		Role:        grant.Role,
		Auth: &attachv1.AuthMaterial{
			Token:     i.token(),
			ExpiresAt: expires, // credential expiry <= handle expiry (here they coincide, D39)
		},
		ExpiresAt: expires,
	}

	// M0: exactly the DIRECT candidate, when the session's host-agent endpoint is
	// resolvable (doc 15 §5.4 — direct client→host-agent only; M2 RELAY joins this
	// repeated field, no v2). An unresolved endpoint yields a handle with the seat
	// and auth but no candidate rather than a fabricated address.
	if i.endpoint != nil {
		addr, sni, ok, eerr := i.endpoint.DirectEndpoint(ctx, sessionUUID)
		if eerr != nil {
			return nil, SeatGrant{}, fmt.Errorf("attach: resolve direct endpoint for session %q: %w", sessionUUID, eerr)
		}
		if ok {
			// The endpoint transport defaults to DIRECT (the M0 byte-identical tag). A
			// resolver that ALSO satisfies the optional EndpointTransportResolver may
			// refine it (terminal-MVP: RAW_TERMINAL for a host-resolved terminal session
			// — the SAME UDS address, a different byte-format tag). The orchestrator stays
			// runtime-ignorant: it selects a delivery tag from the host-written marker,
			// it does not interpret runtime semantics (D38).
			transport := attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT
			if tr, ok2 := i.endpoint.(EndpointTransportResolver); ok2 {
				t, terr := tr.EndpointTransport(ctx, sessionUUID)
				if terr != nil {
					return nil, SeatGrant{}, fmt.Errorf("attach: resolve endpoint transport for session %q: %w", sessionUUID, terr)
				}
				if t != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_UNSPECIFIED {
					transport = t
				}
			}
			handle.Endpoints = []*attachv1.EndpointCandidate{{
				Transport:  transport,
				Address:    addr,
				ServerName: sni,
			}}
		}
	}

	return handle, grant, nil
}

// randomAttachToken mints the opaque short-lived session-scoped credential bytes
// the handle carries (D39 — NEVER a long-lived cred; the long-lived credentials
// never enter the VM and never ride this handle). crypto/rand does not fail in
// practice; a panic here is correct — the orchestrator must not issue a
// non-random attach credential.
func randomAttachToken() []byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("attach: crypto/rand failed: " + err.Error())
	}
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b[:])
	return dst
}
