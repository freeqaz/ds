// SPDX-License-Identifier: Apache-2.0

package hostagent

// grantreturn_producer.go is the host agent's CROSS-PROCESS PRODUCER half of the
// D77 GRANT-RETURN feed (docs/09 §5 TLS-1, doc 12 §12; D77/D22). It is the host-agent
// (Go) ENCODER + DELIVERY half of the same wire ds-tlsproxy CONSUMES
// (dataplane/services/ds-tlsproxy/src/main.rs GrantReturnWire / serve_grant_feed,
// behind DS_GRANT_RETURN_FEED_LIVE).
//
// Once a human approves an outstanding Ask, the orchestrator appends a TTL'd,
// session-scoped ask-grant to the policy_log (POL-5, orchestrator.v1.ApproveAskRequest
// → a POLICY_ROW_KIND_ASK_GRANT PolicyLogRow, doc 15 §5.3). This producer PROJECTS that
// frozen grant onto an AllowGrant (the session join-key quartet + the SNI domain the
// grant permits + the grant's ABSOLUTE expiry) and — behind the live gate — fans it
// host-ward over a host-local UDS the ds-tlsproxy ingest binds, so the matching held
// D77 ask-posture connection PROCEEDS the instant its grant lands within the 30–60 s
// window. Without this producer the proxy's GrantReturnFeed had zero non-test callers,
// so every held Ask reached window expiry and CLOSED on timeout — THIS is the missing
// cross-process WRITE leg that makes a human approval actually release a held Ask.
//
// SCOPE: the grant's ABSOLUTE expiry is the grant's server-stamped append instant
// (PolicyLogRow.appended_at) plus its TTL (ApproveAskRequest.ttl_seconds) — computed
// from the frozen grant, never a producer-side wall-clock guess. The grant_scope →
// sni_domain resolution is the CALLER's (the host agent joins grant_scope to the
// domain the grant permits, exactly as it joins session_uuid to the SessionRef
// quartet); this projection is a pure, clock-free, I/O-free mapping. The
// orchestrator→host-agent RPC that would carry the grant host-ward is OUT of scope (no
// live carrier emits it yet — the same deferred-manual posture the attendedness leg
// shipped with); this producer is DRIVEN by a grant the caller already holds (a
// synthetic fixture in tests), and the forward-to-socket encode + delivery is what
// lands here.
//
// THE CROSS-PROCESS GRANT-RETURN WIRE CONTRACT (binding — mirrored BYTE-FOR-BYTE from
// the Rust consumer's GrantReturnWire in main.rs, and pinned by the
// assurance/conformance-adapter/grantwire fixture). Every message is a length-prefixed
// FRAME: a 4-byte BIG-ENDIAN body length, then the body. Body layout (all multi-byte
// ints big-endian):
//
//	session_uuid:        len(u32) + utf8 bytes
//	host_id:             len(u32) + utf8 bytes
//	host_session_index:  u32
//	tap_name:            len(u32) + utf8 bytes
//	sni_domain:          len(u32) + utf8 bytes  (the domain the grant allows)
//	expires_at_unix_s:   u64 (the grant's ABSOLUTE TTL expiry; docs/09 §5)
//
// The two services share NO crate (D40/D67), no gRPC/tonic, no FFI; this producer
// matches the bytes-on-the-wire shape EXACTLY or the consumer drops the frame and
// records nothing. A body over grantFrameMaxBody (64*1024, == GrantReturnWire::MAX_FRAME_BODY)
// is a malformed frame the consumer drops fail-closed; the producer refuses to emit one.
//
// NEVER FABRICATE A GRANT (the load-bearing fail-closed property). Absent approval ⇒
// nothing is forwarded ⇒ the empty feed times the held Ask out. The producer never
// invents an expiry, never upgrades a missing TTL, and never forwards a grant with no
// session/domain: an ill-formed grant is rejected, not smoothed into an allow. A grant
// that is already expired at append-time (ttl_seconds == 0) is forwarded honestly — the
// consumer's resolution-time TTL check (expires_at > now) fails it closed exactly like
// an absent one.
//
// DEFAULT-OFF / BYTE-IDENTICAL. The live UDS dial is reached ONLY behind
// DS_GRANT_RETURN_FEED_LIVE (the SAME presence-only gate the consumer's
// grant_feed_live_enabled reads). With the gate UNSET (the default launch path) Forward
// is a clean no-op after building the grant — no socket is dialed, no frame is written,
// and the host-agent daemon is byte-identical to the pre-producer build. The encode +
// frame shape are unit-proven over a synthetic in-process server regardless of the gate
// (grantreturn_producer_test.go).
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs a client byte; the grant carries only
// session join-keys, an SNI domain, and a unix timestamp — error paths name only the
// structural defect, never payload.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// ── the session join-key quartet the grant carries ──

// GrantReturnSessionRef is the doc 14 §2/§4 SessionRef quartet the host agent resolves
// for a session (the ApproveAskRequest carries only session_uuid; the other three
// join-keys are the host's). It is the producer-side mirror of the Rust ds_contracts
// SessionRef the consumer decodes into. The tap name is the authoritative join key the
// consumer's GrantReturnFeed is keyed by (with the SNI domain).
type GrantReturnSessionRef struct {
	// SessionUUID is the orchestrator session UUID — the global identity.
	SessionUUID string
	// HostID is the host the session runs on.
	HostID string
	// HostSessionIndex is the host-local session index (its 14-bit residue rides the mark).
	HostSessionIndex uint32
	// TapName is the never-recycled `dstap-<idx>` tap name — the authoritative join key.
	TapName string
}

// ── the allow grant (the producer-side mirror of the Rust decode target) ──

// AllowGrant is ONE session-scoped TTL'd allow grant the host fans host-ward for a
// session — the producer-side mirror of the (SessionRef, sni_domain, expires_at) the
// Rust consumer decodes into an AllowGrant recorded into the shared GrantReturnFeed.
// The expiry is ABSOLUTE (unix seconds) and travels on the wire (unlike the
// attendedness fact's proxy-supplied freshness budget): the grant is a TTL'd allow,
// never a permanent one.
type AllowGrant struct {
	// Session is the join-key quartet the grant is scoped to.
	Session GrantReturnSessionRef
	// SniDomain is the domain the grant permits — it must match the held connection's
	// SNI for the hold to proceed.
	SniDomain string
	// ExpiresAtUnixS is the grant's absolute expiry (unix seconds). The consumer's
	// resolution-time check (expires_at > now) fails a past expiry closed.
	ExpiresAtUnixS uint64
}

// GrantFromApproval projects a frozen POL-5 ask-grant (an orchestrator.v1
// ApproveAskRequest appended as a POLICY_ROW_KIND_ASK_GRANT PolicyLogRow) onto an
// AllowGrant for a session whose join-key quartet + granted SNI domain the caller has
// resolved. It reads ONLY frozen slots — req.session_uuid / req.ttl_seconds and
// row.appended_at (the server-stamped append instant) — and computes the ABSOLUTE
// expiry as appended_at + ttl_seconds (saturating). It NEVER fabricates a grant:
//
//   - a nil row or nil req is rejected (there is no grant to forward);
//   - a row whose kind is not POLICY_ROW_KIND_ASK_GRANT is rejected (only an ask-grant
//     row carries an approval — an org-edit / fleet-block row is not an approval);
//   - an empty sni_domain is rejected (a grant with no domain could never match a hold);
//   - a session_uuid mismatch between req and the resolved ref is rejected (the caller's
//     quartet must be the SAME session the orchestrator approved — never a cross-session
//     grant).
//
// The session quartet + sni_domain are the CALLER's resolved values (the host agent's
// session mapping is the authority for the host_id / host_session_index / tap_name
// join-keys the ApproveAskRequest does not carry, and grant_scope → domain is the
// caller's join). This keeps the projection a pure, clock-free, I/O-free mapping
// (mirroring the attendedness leg's FactFromLifecycleUpdate). A ttl_seconds of 0 yields
// an already-expired grant (expires_at == appended_at) — forwarded honestly; the
// consumer fails it closed at resolution.
func GrantFromApproval(ref GrantReturnSessionRef, sniDomain string, row *orchestratorv1.PolicyLogRow, req *orchestratorv1.ApproveAskRequest) (*AllowGrant, error) {
	if row == nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: nil PolicyLogRow (no grant to forward)")
	}
	if req == nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: nil ApproveAskRequest (no grant to forward)")
	}
	if row.GetKind() != orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT {
		return nil, fmt.Errorf("hostagent: grant-return producer: row kind %v is not an ask-grant (never an approval)", row.GetKind())
	}
	if sniDomain == "" {
		return nil, fmt.Errorf("hostagent: grant-return producer: empty sni_domain (a grant with no domain could never match a hold)")
	}
	if uuid := req.GetSessionUuid(); uuid != "" && uuid != ref.SessionUUID {
		return nil, fmt.Errorf("hostagent: grant-return producer: grant session_uuid does not match the resolved session (never a cross-session grant)")
	}
	// ABSOLUTE expiry = the server-stamped append instant + the grant's TTL (saturating
	// so a hostile TTL can never wrap). ttl_seconds == 0 ⇒ expires_at == appended_at (an
	// already-expired grant, forwarded honestly; the consumer fails it closed).
	expiresAt := saturatingAddU64(row.GetAppendedAt(), req.GetTtlSeconds())
	return &AllowGrant{
		Session:        ref,
		SniDomain:      sniDomain,
		ExpiresAtUnixS: expiresAt,
	}, nil
}

// saturatingAddU64 adds two u64s, clamping at the max on overflow (a hostile TTL can
// never wrap the absolute expiry around to a small value).
func saturatingAddU64(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

// ── the wire codec (byte-for-byte the consumer's GrantReturnWire) ──

// grantFrameMaxBody is the hard cap on a single grant frame body — MUST match
// GrantReturnWire::MAX_FRAME_BODY (64*1024) in the ds-tlsproxy consumer. A body over the
// cap is a malformed frame the consumer drops fail-closed, so the producer REFUSES to
// emit one.
const grantFrameMaxBody = 64 * 1024

// grantMaxU32 is the largest value a u32 length-prefix can carry. Field lengths are
// checked against it so an oversized input fails loud rather than wrapping a u32 cast.
const grantMaxU32 = int(^uint32(0))

// encodeAllowGrant encodes a grant body (NO frame length prefix), the exact layout the
// consumer's GrantReturnWire::decode_grant parses — the byte-for-byte inverse of the
// Rust decoder and the byte-for-byte match of the grantwire fixture's encoder. A field
// whose length does not fit a u32 is rejected (unreachable for well-formed session
// strings, guarded so an oversized input fails loud rather than wrapping).
func encodeAllowGrant(grant *AllowGrant) ([]byte, error) {
	if grant == nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: nil grant")
	}
	out := make([]byte, 0, 48)
	var err error
	if out, err = putGrantWireStr(out, grant.Session.SessionUUID); err != nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: encode session_uuid: %w", err)
	}
	if out, err = putGrantWireStr(out, grant.Session.HostID); err != nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: encode host_id: %w", err)
	}
	out = binary.BigEndian.AppendUint32(out, grant.Session.HostSessionIndex)
	if out, err = putGrantWireStr(out, grant.Session.TapName); err != nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: encode tap_name: %w", err)
	}
	if out, err = putGrantWireStr(out, grant.SniDomain); err != nil {
		return nil, fmt.Errorf("hostagent: grant-return producer: encode sni_domain: %w", err)
	}
	out = binary.BigEndian.AppendUint64(out, grant.ExpiresAtUnixS)
	return out, nil
}

// putGrantWireStr appends a length-prefixed string (len(u32 BE) + utf8 bytes) — the SAME
// put_str the consumer's take_str reads. A string whose byte length does not fit a u32
// is rejected (unreachable for a real session join-key, guarded for safety).
func putGrantWireStr(out []byte, s string) ([]byte, error) {
	if len(s) > grantMaxU32 {
		return nil, fmt.Errorf("string length %d exceeds u32", len(s))
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	out = append(out, s...)
	return out, nil
}

// writeGrantFrame writes ONE length-prefixed frame (a 4-byte big-endian body length +
// the body) to w — the SAME framing the consumer's read_grant_frame expects. A body over
// grantFrameMaxBody is rejected BEFORE any byte is written (the consumer would drop it
// fail-closed), so the producer never half-writes an over-cap frame.
func writeGrantFrame(w net.Conn, body []byte) error {
	if len(body) > grantFrameMaxBody {
		return fmt.Errorf("hostagent: grant-return producer: frame body %d over cap %d (consumer would drop it fail-closed)", len(body), grantFrameMaxBody)
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

// grantFeedLiveEnv is the host-integration gate that ARMS the live UDS dial. MUST match
// GRANT_RETURN_FEED_LIVE_ENV in the ds-tlsproxy consumer (main.rs): UNSET keeps the
// producer a no-op (byte-identical default); SET arms the cross-process delivery.
// Presence-only (the value is never read), like the consumer's gate. Distinct from the
// read-side DS_GRANT_RETURN_LIVE gate (which arms the proxy's per-connection window await).
const grantFeedLiveEnv = "DS_GRANT_RETURN_FEED_LIVE"

// grantFeedEndpointEnv is the env var that single-sources the grant-return feed UDS
// endpoint path. Unset/empty => GrantFeedDefaultEndpoint. MUST match
// GRANT_RETURN_FEED_ENDPOINT_ENV in the consumer (main.rs), so the producer dials EXACTLY
// the path the subscriber binds.
const grantFeedEndpointEnv = "DS_TLSPROXY_GRANT_LISTEN"

// GrantFeedDefaultEndpoint is the default host-local UDS the producer dials and the
// ds-tlsproxy subscriber binds when neither side overrides it. MUST match
// GRANT_RETURN_FEED_DEFAULT_ENDPOINT in the consumer (main.rs).
const GrantFeedDefaultEndpoint = "/run/ds-tlsproxy/grants.sock"

// GrantFeedLiveEnabled reports whether the host-integration gate is set — the kill-switch
// that arms the live UDS dial. Presence-only (mirrors the consumer's
// grant_feed_live_enabled); UNSET keeps the producer a no-op (byte-identical default).
func GrantFeedLiveEnabled() bool {
	_, set := os.LookupEnv(grantFeedLiveEnv)
	return set
}

// GrantFeedEndpoint resolves the UDS endpoint the producer dials — the env override
// (grantFeedEndpointEnv) when set non-empty, else GrantFeedDefaultEndpoint. The ONE place
// the path resolves on the producer side (mirrors the consumer's grant_feed_endpoint), so
// the producer dials the path the subscriber binds.
func GrantFeedEndpoint() string {
	if v := os.Getenv(grantFeedEndpointEnv); v != "" {
		return v
	}
	return GrantFeedDefaultEndpoint
}

// ── the producer (the grant-return forward leg) ──

// defaultGrantDialTimeout bounds the live UDS connect so a wedged / absent ds-tlsproxy
// listener never hangs the forward leg indefinitely. The dial is a host-LOCAL UDS connect
// (no network), so a healthy listener connects in microseconds; a few seconds is a
// generous ceiling.
const defaultGrantDialTimeout = 3 * time.Second

// GrantReturnProducer is the host-local D77 GRANT-RETURN producer (doc 12 §12): on each
// approved ask-grant it projects the frozen POL-5 grant onto an AllowGrant, encodes the
// GrantReturnWire frame byte-for-byte, and (behind DS_GRANT_RETURN_FEED_LIVE) DIALS the
// ds-tlsproxy subscriber's UDS and delivers the frame — so a delivered grant lets that
// session's held ask-posture connection proceed.
//
// DEFAULT-OFF: with DS_GRANT_RETURN_FEED_LIVE unset, Forward is a clean no-op (no dial, no
// frame written) after building the grant — byte-identical to the pre-producer daemon. The
// encode + frame shape are unit-proven regardless of the gate; the live e2e is the gated
// cross-process leg.
type GrantReturnProducer struct {
	// endpoint is the resolved UDS path the producer dials (GrantFeedEndpoint by default;
	// overridable for tests via NewGrantReturnProducerAt).
	endpoint string
	// live gates the cross-process dial. When false, Forward is a no-op after building the
	// grant (the gate-unset default). Captured at construction from the env gate.
	live bool
	// dialTimeout bounds the live UDS connect.
	dialTimeout time.Duration
}

// NewGrantReturnProducer builds the producer, resolving the endpoint (GrantFeedEndpoint)
// and the live gate (GrantFeedLiveEnabled) from the env — the production constructor the
// host-agent daemon calls.
func NewGrantReturnProducer() *GrantReturnProducer {
	// Env-resolved construction never fails (no source to validate); the live+empty-endpoint
	// guard lives in NewGrantReturnProducerAt for the explicit-endpoint path.
	p, _ := NewGrantReturnProducerAt(GrantFeedEndpoint(), GrantFeedLiveEnabled())
	return p
}

// NewGrantReturnProducerAt builds the producer over an EXPLICIT endpoint + live gate — the
// seam the live e2e (and the production constructor) build over so a test can dial a temp
// UDS without setting process env. An empty endpoint with live==true is rejected (a live
// producer with no path could never deliver). The dial timeout defaults to
// defaultGrantDialTimeout.
func NewGrantReturnProducerAt(endpoint string, live bool) (*GrantReturnProducer, error) {
	if live && endpoint == "" {
		return nil, fmt.Errorf("hostagent: NewGrantReturnProducer: live producer with empty endpoint (set %s or pass an explicit path)", grantFeedEndpointEnv)
	}
	return &GrantReturnProducer{
		endpoint:    endpoint,
		live:        live,
		dialTimeout: defaultGrantDialTimeout,
	}, nil
}

// Live reports whether the cross-process dial is armed (DS_GRANT_RETURN_FEED_LIVE set, or
// live==true passed to NewGrantReturnProducerAt). False on the default-OFF path.
func (p *GrantReturnProducer) Live() bool { return p.live }

// Endpoint returns the resolved UDS path the producer dials — the value a deployment must
// single-source with the ds-tlsproxy subscriber's DS_TLSPROXY_GRANT_LISTEN so the two
// halves resolve the same socket.
func (p *GrantReturnProducer) Endpoint() string { return p.endpoint }

// Forward projects a frozen POL-5 ask-grant onto an AllowGrant for the session identified
// by ref + the resolved sni_domain, and — behind the live gate — encodes + delivers the
// GrantReturnWire frame to the proxy UDS. An ill-formed grant (nil row/req, wrong row
// kind, empty domain, session mismatch) is rejected (no fabrication). It NEVER invents an
// approval: absent a real ask-grant, nothing is forwarded and the empty feed times the
// held Ask out.
//
// DEFAULT-OFF: with the gate unset Forward builds the grant (so the projection is exercised
// identically on both paths) and returns nil WITHOUT dialing — byte-identical to the
// pre-producer daemon. On the LIVE path a dial/encode/write failure is returned (the caller
// may re-drive; the grant is a self-contained snapshot, so a dropped delivery is superseded
// by the next re-drive or a fresh grant).
func (p *GrantReturnProducer) Forward(ctx context.Context, ref GrantReturnSessionRef, sniDomain string, row *orchestratorv1.PolicyLogRow, req *orchestratorv1.ApproveAskRequest) error {
	grant, err := GrantFromApproval(ref, sniDomain, row, req)
	if err != nil {
		return err
	}
	return p.ForwardGrant(ctx, grant)
}

// ForwardGrant is Forward's already-projected sibling: it delivers a fully-built AllowGrant
// (the seam a caller with its own grant, or a test, uses directly). A nil grant is
// rejected. Default-OFF is a no-op; the live path dials + writes one frame.
func (p *GrantReturnProducer) ForwardGrant(ctx context.Context, grant *AllowGrant) error {
	if grant == nil {
		return fmt.Errorf("hostagent: grant-return producer: nil grant")
	}
	if !p.live {
		// Default-OFF: the gate is unset — no socket is dialed, no frame is written. The
		// host-agent daemon is byte-identical to the pre-producer build. (The grant was
		// built above so the projection seam is exercised identically on both paths.)
		return nil
	}
	if err := p.deliver(ctx, grant); err != nil {
		return fmt.Errorf("hostagent: grant-return producer: deliver grant for tap %q: %w", grant.Session.TapName, err)
	}
	return nil
}

// deliver dials the ds-tlsproxy subscriber's UDS, encodes the GrantReturnWire frame, and
// writes it — the live cross-process leg (behind DS_GRANT_RETURN_FEED_LIVE). The encode
// runs BEFORE the dial so an encode defect (an over-cap body) fails without touching the
// socket. The dial is bounded by p.dialTimeout; the connection is closed after the single
// frame is written (one grant per connection — the consumer's serve_grant_feed drains
// every framed grant until the peer closes). The ctx deadline (if any) bounds the connect +
// write too.
func (p *GrantReturnProducer) deliver(ctx context.Context, grant *AllowGrant) error {
	body, err := encodeAllowGrant(grant)
	if err != nil {
		return err
	}
	if len(body) > grantFrameMaxBody {
		return fmt.Errorf("grant body %d over cap %d (consumer would drop it fail-closed)", len(body), grantFrameMaxBody)
	}
	dialer := net.Dialer{Timeout: p.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", p.endpoint)
	if err != nil {
		return fmt.Errorf("dial grant-return feed %q: %w", p.endpoint, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := writeGrantFrame(conn, body); err != nil {
		return fmt.Errorf("write grant frame to %q: %w", p.endpoint, err)
	}
	return nil
}
