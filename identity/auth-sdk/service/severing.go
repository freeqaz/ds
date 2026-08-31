// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// SeveringRegistry is the auth-SDK-side seam onto ds-tlsproxy's connection-
// severing primitive (D53/D76). On token revocation the SDK hands every jti in
// the lineage chain to this registry, which severs any in-flight upstream
// connection bound to a revoked agent token (doc 23 §8).
//
// D50 SYNTHETIC-ONLY: this is a pure Go interface (a seam). Production wires it
// to a cross-process ds-tlsproxy client — the Rust sever primitives are consumed
// out-of-tree — while in-tree the revocation path is exercised against a
// synthetic fake. No live ds-tlsproxy/ds-nft datapath is touched here.
type SeveringRegistry interface {
	// Sever cuts any live connection bound to jti. It is idempotent: severing an
	// unknown or already-severed jti is a no-op and returns nil.
	Sever(ctx context.Context, jti string) error
}

// RevocationSweep applies a lineage-chain revocation across the SeveringRegistry
// seam (doc 23 §8: RevocationSweep.apply). It severs each distinct jti exactly
// once and reports how many were severed.
type RevocationSweep struct {
	registry SeveringRegistry
}

// NewRevocationSweep builds a RevocationSweep over reg. A nil reg yields a sweep
// whose apply is a no-op (deployments without a wired severing datapath).
func NewRevocationSweep(reg SeveringRegistry) *RevocationSweep {
	return &RevocationSweep{registry: reg}
}

// apply severs every distinct, non-empty jti in jtis exactly once, preserving
// input order for deterministic behavior. It short-circuits to (0, nil) when no
// registry is wired. The first Sever error stops the sweep and is returned with
// the count severed so far.
func (s *RevocationSweep) apply(ctx context.Context, jtis []string) (int, error) {
	if s == nil || s.registry == nil {
		return 0, nil
	}
	seen := make(map[string]struct{}, len(jtis))
	severed := 0
	for _, jti := range jtis {
		if jti == "" {
			continue
		}
		if _, dup := seen[jti]; dup {
			continue
		}
		seen[jti] = struct{}{}
		if err := s.registry.Sever(ctx, jti); err != nil {
			return severed, fmt.Errorf("sever jti %q: %w", jti, err)
		}
		severed++
	}
	return severed, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Concrete cross-process SeveringRegistry — ds-tlsproxy sever primitive client
// ────────────────────────────────────────────────────────────────────────────
//
// SeveringClient is the CONCRETE SeveringRegistry (D53/D76): a cross-process
// client that hands a revoked jti to ds-tlsproxy's connection-sever primitive
// (`sever_pair` / `sever_legs`, doc 12 §8 / doc 14 §5.4) over a host-local UDS.
// ds-tlsproxy owns the datapath — it walks its live-tunnel + pooled-socket
// registries and severs any established connection bound to the jti's admitted
// pair — so the auth SDK holds only the ENCODER + delivery half here. The two
// processes share NO crate (D40/D67): there is no gRPC/tonic/FFI seam onto the
// Rust proxy, so the contract is bytes-on-the-wire, mirrored below.
//
// THE SEVER-REQUEST WIRE CONTRACT (binding; hand-rolled UDS codec — the same
// length-prefixed-frame discipline as the §8.1 revocation-delta feed). Every
// message is a length-prefixed FRAME: a 4-byte BIG-ENDIAN body length, then the
// body. All multi-byte integers are big-endian.
//
//	Request body:
//	  op:   u8    (opSeverPair=1 — sever BOTH legs of the jti's pair (D76 sever_pair);
//	               opSeverLegs=2 — sever only the legs named in the mask (D76 sever_legs))
//	  legs: u8    (bitmask: legUpstream=0x1 · legDownstream=0x2 · legsBoth=0x3)
//	  jti:  len(u32) + utf8 bytes   (the revoked token's jti fingerprint — NEVER token bytes)
//
//	Response body:
//	  status:  u8    (severStatusOK=0 — request applied, including the idempotent
//	                  no-op of an unknown/already-severed jti; any non-zero is a
//	                  remote failure the client surfaces)
//	  severed: u32   (count of connections torn down; 0 for an idempotent no-op)
//
// A body larger than severFrameMaxBody (== the Rust consumer's MAX_FRAME_BODY,
// 64 KiB) is malformed and refused rather than emitted (a silently-dropped sever
// is a missed sever). Severing an unknown or already-severed jti is idempotent:
// the proxy returns severStatusOK / severed=0 and Sever returns nil.
//
// DEFAULT-OFF / DEFERRED-MANUAL LIVE LEG. The live UDS dial to the real proxy
// socket is reached ONLY through NewLiveSeveringClient, gated behind
// DS_SEVER_LIVE (presence-only). With the gate UNSET (the default) that
// constructor dials NOTHING and reports "not enabled" — the wrapping deployment
// simply leaves the SeveringRegistry unwired, exactly as before, so the offline
// build never opens a socket. The encode + frame shape are unit-proven against a
// synthetic IN-PROCESS server (D50, severing_test.go) regardless of the gate.
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs token bytes; error paths name
// only the jti fingerprint + the structural defect, never any credential.

const (
	// opSeverPair severs both legs of the jti's admitted connection pair
	// (D76 sever_pair) — the default for a token revocation.
	opSeverPair byte = 1
	// opSeverLegs severs only the legs named in the request's legs mask
	// (D76 sever_legs). Reserved for callers that target a single direction.
	opSeverLegs byte = 2

	// legUpstream / legDownstream are the two leg-nibble selectors (mirroring the
	// DS_MARK_MASK 0x1/0x2 leg nibbles, doc 14 §5.4); legsBoth severs the pair.
	legUpstream   byte = 0x1
	legDownstream byte = 0x2
	legsBoth      byte = legUpstream | legDownstream

	// severStatusOK is the only success status; the idempotent no-op of an
	// unknown/already-severed jti also returns it.
	severStatusOK byte = 0

	// severFrameMaxBody bounds a single request/response body (== the Rust
	// consumer's MAX_FRAME_BODY). A larger frame is malformed by construction.
	severFrameMaxBody = 64 * 1024

	// severRespBodyLen is the fixed response body size: status(1) + severed(4).
	severRespBodyLen = 5

	// envSeverLive presence-arms the live cross-process dial (deferred-manual).
	envSeverLive = "DS_SEVER_LIVE"
	// envSeverSock overrides the default proxy sever-socket path.
	envSeverSock = "DS_SEVER_SOCK"
	// defaultSeverSock is the host-local UDS ds-tlsproxy binds its sever
	// primitive on (doc 12 §8 host-local listener convention).
	defaultSeverSock = "/run/ds-tlsproxy/sever.sock"

	// defaultSeverTimeout bounds a single Sever round-trip when the caller's
	// context carries no deadline.
	defaultSeverTimeout = 5 * time.Second
)

// SeverDialFunc opens a fresh connection to the ds-tlsproxy sever endpoint. It
// is injected so the concrete client is driven over a synthetic in-process
// server offline (D50) and over the real host-local UDS only behind DS_SEVER_LIVE.
type SeverDialFunc func(ctx context.Context) (net.Conn, error)

// SeveringClient is a concrete SeveringRegistry that dials ds-tlsproxy's sever
// primitive across the process boundary. It is safe for concurrent use: each
// Sever opens, uses, and closes its own connection.
type SeveringClient struct {
	dial    SeverDialFunc
	op      byte
	legs    byte
	timeout time.Duration
}

// SeveringClientOption tunes a SeveringClient.
type SeveringClientOption func(*SeveringClient)

// WithSeverTimeout sets the per-call round-trip deadline used when the caller's
// context carries no deadline of its own.
func WithSeverTimeout(d time.Duration) SeveringClientOption {
	return func(c *SeveringClient) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithSeverLegs pins which legs a Sever targets and switches the op to
// sever_legs when the mask is not the full pair (D76). An out-of-range or empty
// mask is ignored (the client keeps its sever_pair default).
func WithSeverLegs(mask byte) SeveringClientOption {
	return func(c *SeveringClient) {
		mask &= legsBoth
		if mask == 0 {
			return
		}
		c.legs = mask
		if mask == legsBoth {
			c.op = opSeverPair
		} else {
			c.op = opSeverLegs
		}
	}
}

// NewSeveringClient builds a concrete SeveringRegistry over dial. Production
// passes a UDS dialer (see NewLiveSeveringClient); tests pass a synthetic
// in-process dialer. A nil dial yields a client whose Sever always errors
// (misconfiguration surfaces loudly rather than silently no-op'ing a sever).
func NewSeveringClient(dial SeverDialFunc, opts ...SeveringClientOption) *SeveringClient {
	c := &SeveringClient{
		dial:    dial,
		op:      opSeverPair,
		legs:    legsBoth,
		timeout: defaultSeverTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewLiveSeveringClient builds a concrete SeveringClient dialing ds-tlsproxy's
// real host-local sever socket — the DEFERRED-MANUAL live leg. It is armed ONLY
// when DS_SEVER_LIVE is present in the environment; otherwise it returns
// (nil, false) and dials nothing, so the offline/default build never opens a
// socket. The socket path defaults to defaultSeverSock and is overridable via
// DS_SEVER_SOCK. The returned client, when wired via WithSeveringRegistry,
// severs the lineage chain over the live datapath.
func NewLiveSeveringClient(opts ...SeveringClientOption) (*SeveringClient, bool) {
	if os.Getenv(envSeverLive) == "" {
		return nil, false
	}
	sock := os.Getenv(envSeverSock)
	if sock == "" {
		sock = defaultSeverSock
	}
	d := &net.Dialer{}
	dial := func(ctx context.Context) (net.Conn, error) {
		return d.DialContext(ctx, "unix", sock)
	}
	return NewSeveringClient(dial, opts...), true
}

// Sever cuts any live connection bound to jti by handing the jti to ds-tlsproxy's
// sever primitive over a fresh connection. It is idempotent: an empty jti is a
// no-op, and an unknown/already-severed jti returns nil (the proxy answers
// severStatusOK / severed=0). It satisfies SeveringRegistry.
func (c *SeveringClient) Sever(ctx context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	if c.dial == nil {
		return fmt.Errorf("severing client: no dialer configured")
	}
	frame, err := encodeSeverRequest(c.op, c.legs, jti)
	if err != nil {
		return err
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("severing client: dial: %w", err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if c.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("severing client: write jti %q: %w", jti, err)
	}
	st, _, err := readSeverResponse(conn)
	if err != nil {
		return fmt.Errorf("severing client: read response for jti %q: %w", jti, err)
	}
	if st != severStatusOK {
		return fmt.Errorf("severing client: remote status %d for jti %q", st, jti)
	}
	return nil
}

// encodeSeverRequest builds one length-prefixed sever-request frame per the wire
// contract above. It refuses (rather than emits) an over-large frame so a
// silently-dropped sever can never happen.
func encodeSeverRequest(op, legs byte, jti string) ([]byte, error) {
	body := make([]byte, 0, 2+4+len(jti))
	body = append(body, op, legs)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(jti)))
	body = append(body, lp[:]...)
	body = append(body, jti...)
	if len(body) > severFrameMaxBody {
		return nil, fmt.Errorf("severing client: request body %d exceeds max %d", len(body), severFrameMaxBody)
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

// readSeverResponse reads and decodes one length-prefixed response frame. A body
// outside [severRespBodyLen, severFrameMaxBody] is fail-closed as malformed.
func readSeverResponse(r io.Reader) (status byte, severed uint32, err error) {
	var lp [4]byte
	if _, err := io.ReadFull(r, lp[:]); err != nil {
		return 0, 0, fmt.Errorf("read response length: %w", err)
	}
	n := binary.BigEndian.Uint32(lp[:])
	if n < severRespBodyLen || n > severFrameMaxBody {
		return 0, 0, fmt.Errorf("malformed response body length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, fmt.Errorf("read response body: %w", err)
	}
	return body[0], binary.BigEndian.Uint32(body[1:5]), nil
}
