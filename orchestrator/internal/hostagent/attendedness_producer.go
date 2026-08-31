// SPDX-License-Identifier: Apache-2.0

package hostagent

// attendedness_producer.go is the host agent's CROSS-PROCESS PRODUCER half of the
// D78 ATTENDEDNESS-FACT feed (doc 12 §12, doc 15 §5.5; D78). It is the host-agent
// (Go) ENCODER + DELIVERY half of the same wire ds-tlsproxy CONSUMES
// (dataplane/services/ds-tlsproxy/src/main.rs AttendednessFactWire /
// serve_attendedness_feed, behind DS_ATTENDEDNESS_FEED_LIVE).
//
// The orchestrator computes a session's attendedness (a human holds the writer seat
// AND produced input within the last T minutes, doc 15 §5.5) and folds it onto the
// FROZEN hostagent.v1 SessionLifecycleUpdate attended=4 / attended_at=5 slots
// (internal/attendedness/transport.go BuildLifecycleUpdate). This producer decodes
// those slots off a delivered SessionLifecycleUpdate and — behind the live gate —
// fans the attendedness fact host-ward over a host-local UDS the ds-tlsproxy ingest
// binds, so a delivered FRESH attended fact lets that session's D77 ask-posture
// connection HOLD (the present human can answer). Without this producer the proxy's
// AttendednessFeed had zero non-test callers, so every session read UNATTENDED — THIS
// is the missing cross-process WRITE leg.
//
// SCOPE: the orchestrator->host-agent host-ward RPC that would carry the
// SessionLifecycleUpdate to the host agent is OUT of scope (no RPC carries it today;
// internal/attendedness BuildLifecycleUpdate/StampAttendedness exist with zero
// callers — a follow-up rider owns that leg). This producer is DRIVEN by a
// SessionLifecycleUpdate the caller already holds (a synthetic fixture in tests); the
// forward-to-socket encode + delivery is what lands here.
//
// THE CROSS-PROCESS ATTENDEDNESS-FACT WIRE CONTRACT (binding — mirrored BYTE-FOR-BYTE
// from the Rust consumer's AttendednessFactWire in main.rs, and pinned by the
// assurance/conformance-adapter/attendwire fixture). Every message is a
// length-prefixed FRAME: a 4-byte BIG-ENDIAN body length, then the body. Body layout
// (all multi-byte ints big-endian):
//
//	session_uuid:        len(u32) + utf8 bytes
//	host_id:             len(u32) + utf8 bytes
//	host_session_index:  u32
//	tap_name:            len(u32) + utf8 bytes
//	attended:            u8  (0 = UNATTENDED, 1 = ATTENDED)
//	attended_at_unix_s:  u64 (the server-stamped freshness clock; §5.5/D78)
//
// THE WIRE DOES NOT CARRY THE FRESHNESS BUDGET. AttendednessFact needs a
// freshness_budget_s (the fact is fresh while now-computed_at <= min(budget, cap)),
// but that is a proxy-side POLICY value, NOT a frozen field: the ds-tlsproxy ingest
// supplies it from a rig-tuned env. The producer therefore never encodes a budget —
// the two services share NO crate (D40/D67), no gRPC/tonic, no FFI; this producer
// matches the bytes-on-the-wire shape EXACTLY or the consumer drops the frame and
// records nothing.
//
// A body over attendednessFrameMaxBody (64*1024, == AttendednessFactWire::MAX_FRAME_BODY)
// is a malformed frame the consumer drops fail-closed; the producer therefore refuses
// to emit one.
//
// NEVER FABRICATE ATTENDED (the load-bearing fail-closed property). A false/absent
// attended field forwards HONESTLY as attended=0 (the consumer records an explicit
// UNATTENDED); the producer never upgrades a false/absent signal to attended=1. An
// absent fact is simply not forwarded — the empty feed reads UNATTENDED.
//
// DEFAULT-OFF / BYTE-IDENTICAL. The live UDS dial is reached ONLY behind
// DS_ATTENDEDNESS_FEED_LIVE (the SAME presence-only gate the consumer's
// attendedness_feed_live_enabled reads). With the gate UNSET (the default launch
// path) Forward is a clean no-op after building the fact — no socket is dialed, no
// frame is written, and the host-agent daemon is byte-identical to the pre-producer
// build. The encode + frame shape are unit-proven over a synthetic in-process server
// regardless of the gate (attendedness_producer_test.go).
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs a client byte; the fact carries only
// session join-keys, a boolean, and a unix timestamp — error paths name only the
// structural defect, never payload.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// ── the session join-key quartet the fact carries ──

// AttendednessSessionRef is the doc 14 §2/§4 SessionRef quartet the host agent resolves
// for a session (from its own session mapping — the SessionLifecycleUpdate carries only
// session_uuid; the other three join-keys are the host's). It is the producer-side mirror
// of the Rust ds_contracts SessionRef the consumer decodes into. The tap name is the
// authoritative join key the consumer's AttendednessFeed is keyed by.
type AttendednessSessionRef struct {
	// SessionUUID is the orchestrator session UUID — the global identity.
	SessionUUID string
	// HostID is the host the session runs on.
	HostID string
	// HostSessionIndex is the host-local session index (its 14-bit residue rides the mark).
	HostSessionIndex uint32
	// TapName is the never-recycled `dstap-<idx>` tap name — the authoritative join key.
	TapName string
}

// ── the attendedness fact (the producer-side mirror of the Rust decode target) ──

// AttendednessFact is ONE attendedness fact the host fans host-ward for a session — the
// producer-side mirror of the (SessionRef, attended, attended_at) the Rust consumer
// decodes into an AttendednessFact + a proxy-supplied freshness budget. The freshness
// budget is DELIBERATELY absent (a proxy-side policy value the wire never carries).
type AttendednessFact struct {
	// Session is the join-key quartet the fact is computed for.
	Session AttendednessSessionRef
	// Attended is the orchestrator's computed verdict (a human recently active on the
	// writer seat, §5.5). false is an explicit UNATTENDED — forwarded honestly.
	Attended bool
	// AttendedAtUnixS is the server-stamped freshness clock (unix seconds); the proxy
	// measures the fact's freshness against it.
	AttendedAtUnixS uint64
}

// FactFromLifecycleUpdate projects the D78 attendedness fields off a
// SessionLifecycleUpdate onto an AttendednessFact for a session whose join-key quartet
// the caller resolved. It reads ONLY the frozen attended=4 / attended_at=5 slots
// (update.GetAttended / update.GetAttendedAt) — the SAME slots
// internal/attendedness.BuildLifecycleUpdate folds the computed Signal onto. A nil update
// is rejected (there is no fact to forward). It NEVER fabricates attended: a false/absent
// attended field yields Attended=false (an honest UNATTENDED), never an upgrade.
//
// The session quartet is the CALLER's (the host agent's session mapping is the authority
// for the host_id / host_session_index / tap_name join-keys the SessionLifecycleUpdate
// does not carry); update.SessionUuid is the orchestrator's session identity, which the
// caller has already joined to the quartet. This keeps the projection a pure, clock-free,
// I/O-free mapping (mirroring internal/attendedness.BuildLifecycleUpdate).
func FactFromLifecycleUpdate(ref AttendednessSessionRef, update *hostagentv1.SessionLifecycleUpdate) (*AttendednessFact, error) {
	if update == nil {
		return nil, fmt.Errorf("hostagent: attendedness producer: nil SessionLifecycleUpdate (no fact to forward)")
	}
	return &AttendednessFact{
		Session:         ref,
		Attended:        update.GetAttended(),   // false/absent ⇒ false (never fabricated true)
		AttendedAtUnixS: update.GetAttendedAt(), // server-stamped freshness clock (§5.5)
	}, nil
}

// ── the wire codec (byte-for-byte the consumer's AttendednessFactWire) ──

// attendednessFrameMaxBody is the hard cap on a single attendedness-fact frame body —
// MUST match AttendednessFactWire::MAX_FRAME_BODY (64*1024) in the ds-tlsproxy consumer.
// A body over the cap is a malformed frame the consumer drops fail-closed, so the
// producer REFUSES to emit one.
const attendednessFrameMaxBody = 64 * 1024

// attMaxU32 is the largest value a u32 length-prefix can carry. Field lengths are checked
// against it so an oversized input fails loud rather than wrapping a u32 cast.
const attMaxU32 = int(^uint32(0))

// encodeAttendednessFact encodes a fact body (NO frame length prefix), the exact layout
// the consumer's AttendednessFactWire::decode_fact parses — the byte-for-byte inverse of
// the Rust decoder and the byte-for-byte match of the attendwire fixture's encoder. A
// field whose length does not fit a u32 is rejected (unreachable for well-formed
// session strings, guarded so an oversized input fails loud rather than wrapping).
func encodeAttendednessFact(fact *AttendednessFact) ([]byte, error) {
	if fact == nil {
		return nil, fmt.Errorf("hostagent: attendedness producer: nil fact")
	}
	out := make([]byte, 0, 32)
	var err error
	if out, err = putAttWireStr(out, fact.Session.SessionUUID); err != nil {
		return nil, fmt.Errorf("hostagent: attendedness producer: encode session_uuid: %w", err)
	}
	if out, err = putAttWireStr(out, fact.Session.HostID); err != nil {
		return nil, fmt.Errorf("hostagent: attendedness producer: encode host_id: %w", err)
	}
	out = binary.BigEndian.AppendUint32(out, fact.Session.HostSessionIndex)
	if out, err = putAttWireStr(out, fact.Session.TapName); err != nil {
		return nil, fmt.Errorf("hostagent: attendedness producer: encode tap_name: %w", err)
	}
	// attended: 1 iff true, 0 otherwise — an honest UNATTENDED is a real 0 byte, never
	// omitted or upgraded.
	if fact.Attended {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = binary.BigEndian.AppendUint64(out, fact.AttendedAtUnixS)
	return out, nil
}

// putAttWireStr appends a length-prefixed string (len(u32 BE) + utf8 bytes) — the SAME
// put_str the consumer's take_str reads. A string whose byte length does not fit a u32 is
// rejected (unreachable for a real session join-key, guarded for safety).
func putAttWireStr(out []byte, s string) ([]byte, error) {
	if len(s) > attMaxU32 {
		return nil, fmt.Errorf("string length %d exceeds u32", len(s))
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	out = append(out, s...)
	return out, nil
}

// writeAttendednessFrame writes ONE length-prefixed frame (a 4-byte big-endian body
// length + the body) to w — the SAME framing the consumer's read_attendedness_frame
// expects. A body over attendednessFrameMaxBody is rejected BEFORE any byte is written
// (the consumer would drop it fail-closed), so the producer never half-writes an over-cap
// frame.
func writeAttendednessFrame(w net.Conn, body []byte) error {
	if len(body) > attendednessFrameMaxBody {
		return fmt.Errorf("hostagent: attendedness producer: frame body %d over cap %d (consumer would drop it fail-closed)", len(body), attendednessFrameMaxBody)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// ── the env gate + endpoint (single-sourced with the consumer) ──

// attendednessFeedLiveEnv is the host-integration gate that ARMS the live UDS dial. MUST
// match ATTENDEDNESS_FEED_LIVE_ENV in the ds-tlsproxy consumer (main.rs): UNSET keeps the
// producer a no-op (byte-identical default); SET arms the cross-process delivery.
// Presence-only (the value is never read), like the consumer's gate. Distinct from the
// read-side DS_ATTENDEDNESS_LIVE gate (which arms the proxy's per-connection consume).
const attendednessFeedLiveEnv = "DS_ATTENDEDNESS_FEED_LIVE"

// attendednessFeedEndpointEnv is the env var that single-sources the attendedness-fact
// feed UDS endpoint path. Unset/empty => AttendednessFeedDefaultEndpoint. MUST match
// ATTENDEDNESS_FEED_ENDPOINT_ENV in the consumer (main.rs), so the producer dials EXACTLY
// the path the subscriber binds.
const attendednessFeedEndpointEnv = "DS_TLSPROXY_ATTENDEDNESS_LISTEN"

// AttendednessFeedDefaultEndpoint is the default host-local UDS the producer dials and the
// ds-tlsproxy subscriber binds when neither side overrides it. MUST match
// ATTENDEDNESS_FEED_DEFAULT_ENDPOINT in the consumer (main.rs).
const AttendednessFeedDefaultEndpoint = "/run/ds-tlsproxy/attendedness.sock"

// AttendednessFeedLiveEnabled reports whether the host-integration gate is set — the
// kill-switch that arms the live UDS dial. Presence-only (mirrors the consumer's
// attendedness_feed_live_enabled); UNSET keeps the producer a no-op (byte-identical
// default).
func AttendednessFeedLiveEnabled() bool {
	_, set := os.LookupEnv(attendednessFeedLiveEnv)
	return set
}

// AttendednessFeedEndpoint resolves the UDS endpoint the producer dials — the env override
// (attendednessFeedEndpointEnv) when set non-empty, else AttendednessFeedDefaultEndpoint.
// The ONE place the path resolves on the producer side (mirrors the consumer's
// attendedness_feed_endpoint), so the producer dials the path the subscriber binds.
func AttendednessFeedEndpoint() string {
	if v := os.Getenv(attendednessFeedEndpointEnv); v != "" {
		return v
	}
	return AttendednessFeedDefaultEndpoint
}

// ── the producer (the attendedness-fact forward leg) ──

// defaultAttendednessDialTimeout bounds the live UDS connect so a wedged / absent
// ds-tlsproxy listener never hangs the forward leg indefinitely. The dial is a host-LOCAL
// UDS connect (no network), so a healthy listener connects in microseconds; a few seconds
// is a generous ceiling.
const defaultAttendednessDialTimeout = 3 * time.Second

// AttendednessProducer is the host-local D78 ATTENDEDNESS-FACT producer (doc 12 §12): on
// each SessionLifecycleUpdate it projects the D78 attended/attended_at slots onto an
// AttendednessFact, encodes the AttendednessFactWire frame byte-for-byte, and (behind
// DS_ATTENDEDNESS_FEED_LIVE) DIALS the ds-tlsproxy subscriber's UDS and delivers the frame
// — so a delivered FRESH attended fact lets that session's ask-posture connection hold.
//
// DEFAULT-OFF: with DS_ATTENDEDNESS_FEED_LIVE unset, Forward is a clean no-op (no dial, no
// frame written) after building the fact — byte-identical to the pre-producer daemon. The
// encode + frame shape are unit-proven regardless of the gate; the live e2e is the gated
// cross-process leg.
type AttendednessProducer struct {
	// endpoint is the resolved UDS path the producer dials (AttendednessFeedEndpoint by
	// default; overridable for tests via NewAttendednessProducerAt).
	endpoint string
	// live gates the cross-process dial. When false, Forward is a no-op after building the
	// fact (the gate-unset default). Captured at construction from the env gate.
	live bool
	// dialTimeout bounds the live UDS connect.
	dialTimeout time.Duration
}

// NewAttendednessProducer builds the producer, resolving the endpoint
// (AttendednessFeedEndpoint) and the live gate (AttendednessFeedLiveEnabled) from the env
// — the production constructor the host-agent daemon calls.
func NewAttendednessProducer() *AttendednessProducer {
	// Env-resolved construction never fails (no source to validate); the live+empty-endpoint
	// guard lives in NewAttendednessProducerAt for the explicit-endpoint path.
	p, _ := NewAttendednessProducerAt(AttendednessFeedEndpoint(), AttendednessFeedLiveEnabled())
	return p
}

// NewAttendednessProducerAt builds the producer over an EXPLICIT endpoint + live gate —
// the seam the live e2e (and the production constructor) build over so a test can dial a
// temp UDS without setting process env. An empty endpoint with live==true is rejected (a
// live producer with no path could never deliver). The dial timeout defaults to
// defaultAttendednessDialTimeout.
func NewAttendednessProducerAt(endpoint string, live bool) (*AttendednessProducer, error) {
	if live && endpoint == "" {
		return nil, fmt.Errorf("hostagent: NewAttendednessProducer: live producer with empty endpoint (set %s or pass an explicit path)", attendednessFeedEndpointEnv)
	}
	return &AttendednessProducer{
		endpoint:    endpoint,
		live:        live,
		dialTimeout: defaultAttendednessDialTimeout,
	}, nil
}

// Live reports whether the cross-process dial is armed (DS_ATTENDEDNESS_FEED_LIVE set, or
// live==true passed to NewAttendednessProducerAt). False on the default-OFF path.
func (p *AttendednessProducer) Live() bool { return p.live }

// Endpoint returns the resolved UDS path the producer dials — the value a deployment must
// single-source with the ds-tlsproxy subscriber's DS_TLSPROXY_ATTENDEDNESS_LISTEN so the
// two halves resolve the same socket.
func (p *AttendednessProducer) Endpoint() string { return p.endpoint }

// Forward projects the D78 attendedness fields off update onto an AttendednessFact for the
// session identified by ref, and — behind the live gate — encodes + delivers the
// AttendednessFactWire frame to the proxy UDS. A nil update is rejected (no fact to
// forward). It NEVER fabricates attended: a false/absent attended field forwards honestly
// as attended=0 (the consumer records an explicit UNATTENDED).
//
// DEFAULT-OFF: with the gate unset Forward builds the fact (so the projection is exercised
// identically on both paths) and returns nil WITHOUT dialing — byte-identical to the
// pre-producer daemon. On the LIVE path a dial/encode/write failure is returned (the
// caller may re-drive on the next lifecycle update); the fact is a self-contained snapshot,
// so a dropped delivery is simply superseded by the next fresh fact.
func (p *AttendednessProducer) Forward(ctx context.Context, ref AttendednessSessionRef, update *hostagentv1.SessionLifecycleUpdate) error {
	fact, err := FactFromLifecycleUpdate(ref, update)
	if err != nil {
		return err
	}
	return p.ForwardFact(ctx, fact)
}

// ForwardFact is Forward's already-projected sibling: it delivers a fully-built
// AttendednessFact (the seam a caller with its own fact, or a test, uses directly). A nil
// fact is rejected. Default-OFF is a no-op; the live path dials + writes one frame.
func (p *AttendednessProducer) ForwardFact(ctx context.Context, fact *AttendednessFact) error {
	if fact == nil {
		return fmt.Errorf("hostagent: attendedness producer: nil fact")
	}
	if !p.live {
		// Default-OFF: the gate is unset — no socket is dialed, no frame is written. The
		// host-agent daemon is byte-identical to the pre-producer build. (The fact was
		// built above so the projection seam is exercised identically on both paths.)
		return nil
	}
	if err := p.deliver(ctx, fact); err != nil {
		return fmt.Errorf("hostagent: attendedness producer: deliver fact for tap %q: %w", fact.Session.TapName, err)
	}
	return nil
}

// deliver dials the ds-tlsproxy subscriber's UDS, encodes the AttendednessFactWire frame,
// and writes it — the live cross-process leg (behind DS_ATTENDEDNESS_FEED_LIVE). The encode
// runs BEFORE the dial so an encode defect (an over-cap body) fails without touching the
// socket. The dial is bounded by p.dialTimeout; the connection is closed after the single
// frame is written (one fact per connection — the consumer's serve_attendedness_feed drains
// every framed fact until the peer closes). The ctx deadline (if any) bounds the connect +
// write too.
func (p *AttendednessProducer) deliver(ctx context.Context, fact *AttendednessFact) error {
	body, err := encodeAttendednessFact(fact)
	if err != nil {
		return err
	}
	if len(body) > attendednessFrameMaxBody {
		return fmt.Errorf("attendedness fact body %d over cap %d (consumer would drop it fail-closed)", len(body), attendednessFrameMaxBody)
	}
	dialer := net.Dialer{Timeout: p.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", p.endpoint)
	if err != nil {
		return fmt.Errorf("dial attendedness feed %q: %w", p.endpoint, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := writeAttendednessFrame(conn, body); err != nil {
		return fmt.Errorf("write attendedness frame to %q: %w", p.endpoint, err)
	}
	return nil
}
