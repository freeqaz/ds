package controlplane

// writerrelay.go is the W2 server-side WriterRelayService (the D137 browser
// writer-seat WRITE leg, sessions/10 §2.1/§3/§6 W2; D61/D136/D137/D138). It is the
// orchestrator's single arbitration terminator for the one writer seat: it
// VALIDATES who is asking (the D22/D55 human identity assertion AND the D39 attach
// auth token), runs the D61/D138 seat arbitration through the single attach.SeatArbiter
// choke point, and returns the attributed, short-lived WriterSeatGrant — or a typed
// RPC refusal (never a second live seat).
//
// THE THREE RPCs (attach.v1.WriterRelayService):
//   - RequestWriterSeat — take the one seat (the D61 handoff). Auth-gated, arbitrated,
//     attributed; a loser is REFUSED (AlreadyExists / FailedPrecondition); a steal of
//     an attended seat without approval is PermissionDenied (D138).
//   - YieldWriterSeat — release the held seat (the cooperative half). Idempotent;
//     released_seq is observable on the read stream.
//   - DriveSession — W3 (the host-agent relay leg). Registered here so the seam is
//     served from one owner, but returns codes.Unimplemented until W3 lands.
//
// THE READ-LEG PROJECTION. The arbiter emits the attach.v1 WRITER_SEAT_CHANGED event
// on the WatchSession Fanout (the SAME read stream every N-reader subscribes to) on
// each grant/steal/yield, and the Fanout-stamped seq IS the granted_seq /
// released_seq this service returns — so a steal cannot be silent (D137) and the
// write-side caller + every spectator agree on the one ordering point.
//
// AUTH IS TWO KEYS (D22/D55 + D39). RequestWriterSeat carries BOTH the
// identity_assertion (the human identity, D22/D55 — WHO is asking; validated to a
// driver_identity that becomes the seat attribution) AND the attach_auth (the v1
// AttachHandle.AuthMaterial.token, D39 — the short-lived session-scoped credential
// proving the caller already holds a valid attach to THIS session). Missing/invalid
// identity → Unauthenticated; missing/invalid attach auth → PermissionDenied. No
// seat without a valid human identity (D22/D55) AND a valid session-scoped attach
// (D39): the only path to the seat is through both.

import (
	"context"
	"errors"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attendedness"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// seatAttendednessReader is the narrow record read the D138 steal-gate attendedness
// probe needs: the §5.6 session record (its writer-seat fields), the D61 source of
// truth the attendedness signal is computed from. The single ControlPlaneStore
// satisfies it via GetSession.
type seatAttendednessReader interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
}

// writerSeatAttendedness builds the attach.AttendednessProbe the SeatArbiter's D138
// force_steal gate consults: it reads the session record and computes the D78
// attendedness verdict over the AUTHORITATIVE writer-seat state (the M0/M1 interim is
// writer-attached-only — a human holding the seat counts as attended; doc 15 §5.5).
// A held seat with a real driver therefore reads as ATTENDED, so a force_steal of it
// is refused by default (D138) unless the seat is idle/writer-less. A read fault
// surfaces to the arbiter, which fails the steal closed (a steal cannot proceed on an
// unreadable record). A nil store yields a nil probe (the arbiter then treats every
// held seat as attended — fail-closed).
func writerSeatAttendedness(recs seatAttendednessReader) attach.AttendednessProbe {
	if recs == nil {
		return nil
	}
	return attach.AttendednessProbeFunc(func(ctx context.Context, sessionUUID string) (bool, error) {
		rec, err := recs.GetSession(ctx, sessionUUID)
		if err != nil {
			return false, err
		}
		// Writer-attached-only interim (doc 15 §5.5): no input-activity signal is threaded,
		// so Compute reports attended iff a human holds the one writer seat. The zero Policy
		// + empty Input is exactly that interim.
		sig := attendedness.Compute(
			attendedness.SeatViewFromRecord(rec),
			attendedness.Input{},
			attendedness.Policy{},
			time.Now(),
		)
		return sig.Attended, nil
	})
}

// IdentityAssertionValidator validates the D22/D55 human-identity assertion a seat
// request carries and resolves it to the driver_identity that becomes the seat
// attribution (doc 15 §5.4 / D8 / D55). It is a NARROW seam this package declares
// (the orchestrator may not import the identity/SSO module directly — the only legal
// cross-tree import is proto/gen/go): main.go adapts the real D55/SSO identity face
// onto it, tests supply a fake. An invalid/empty assertion returns ok=false (the
// handler refuses Unauthenticated — no seat without a valid human identity).
type IdentityAssertionValidator interface {
	// ValidateAssertion validates the human-identity assertion for a seat request on
	// sessionUUID and returns the resolved driver identity (the D8/D55 attribution)
	// when it is valid. ok=false is a clean refusal (invalid/expired/empty assertion);
	// a non-nil err is a transient validator fault (the handler surfaces Unavailable).
	ValidateAssertion(ctx context.Context, sessionUUID string, assertion string) (driverIdentity string, ok bool, err error)
}

// AttachAuthValidator validates the D39 attach-auth token a seat request carries —
// the v1 AttachHandle.AuthMaterial.token proving the caller already holds a valid,
// short-lived, session-scoped attach to THIS session (the same token the attach
// minter issued; orchestrator/internal/hypervisor/libvirt/attachminter.go validates
// it host-side). It is a NARROW seam: main.go adapts the attach-token store onto it,
// tests supply a fake. An invalid/empty token returns ok=false (the handler refuses
// PermissionDenied — the seat requires a valid attach, D39).
type AttachAuthValidator interface {
	// ValidateAttachAuth validates the attach-auth token for sessionUUID. ok=false is a
	// clean refusal (invalid/expired/absent token / token for another session); a
	// non-nil err is a transient validator fault (the handler surfaces Unavailable).
	ValidateAttachAuth(ctx context.Context, sessionUUID string, token []byte) (ok bool, err error)
}

// DriveSink is the NARROW seam the W3 DriveSession leg forwards an ADMITTED DriveInput
// through to Claude Code's stdin via the host-agent relay (the reserved RELAY endpoint
// transport, attach_handle.proto ENDPOINT_TRANSPORT_RELAY). It is the SYMMETRIC twin of
// the read-leg relay (attachrelay.go feeds the Fanout from host-ward heartbeats; this
// carries an admitted write frame host-ward to CC stdin via client/hostbridge's
// Bridge.DriveInput → writeRecord). The orchestrator is the SINGLE choke point: the
// arbiter admits the frame for the live seat-holder, then this seam carries ONLY that
// admitted frame — the relay ORIGINATES no input of its own (the confused-deputy
// mitigation, sessions/10 §5 claim 5).
//
// It is declared narrow here (the orchestrator may not import the host-agent runtime
// directly): main.go adapts the LIVE host-agent bridge onto it behind DS_ORCH_LIVE,
// tests supply a fake. A nil sink FAILS CLOSED — DriveSession refuses (no live relay
// configured ⇒ the RPC refuses, never silently drops an admitted frame).
type DriveSink interface {
	// Drive forwards an admitted DriveInput for sessionUUID to Claude Code's stdin via
	// the host-agent relay. It returns nil once the frame is on the wire to CC stdin; a
	// non-nil err is a transport fault (the handler surfaces it as Unavailable and emits
	// NO InputActivity — an input that did not reach stdin is not projected as activity).
	Drive(ctx context.Context, sessionUUID string, in *attachv1.DriveInput) error
}

// WriterRelayService is the orchestrator-side attach.v1.WriterRelayService server. It
// gates RequestWriterSeat / YieldWriterSeat behind the D22/D55 identity + D39 attach
// auth, drives the single attach.SeatArbiter, and serves the W3 DriveSession leg
// (validate-seat → forward-to-stdin → emit InputActivity). Construct with
// newWriterRelayService (via NewControlPlane). It embeds the generated Unimplemented
// server so any later additive RPC stays buildable.
type WriterRelayService struct {
	attachv1.UnimplementedWriterRelayServiceServer

	arbiter    *attach.SeatArbiter
	identity   IdentityAssertionValidator
	attachAuth AttachAuthValidator

	// fanout is the SAME D18 WatchSession terminator the SeatArbiter emits
	// WRITER_SEAT_CHANGED through (watch.go) — W3 emits the v1 InputActivity read-leg
	// projection of an ACCEPTED input through it, so the activity event lands on the one
	// ordering point spectators already subscribe to (the seq it stamps IS the returned
	// emitted_input_activity_seq). Nil leaves DriveSession unable to project activity (it
	// then refuses Unavailable — an accepted input that cannot be made observable is not
	// admitted, the D78/D138 attendedness clock must advance).
	fanout inputActivityPublisher

	// drive is the host-agent relay seam an admitted DriveInput is forwarded to CC stdin
	// through (DriveSink). Nil FAILS CLOSED — DriveSession refuses rather than silently
	// drop an admitted frame (no live relay configured ⇒ the RPC refuses).
	drive DriveSink

	// nowFn stamps the v1 InputActivity.at server-side (the D78 freshness clock,
	// sessions/10 §5.5 — the timestamp is SERVER-stamped, never wire-supplied). nil ⇒
	// time.Now; tests pin it for determinism. Read through s.now().
	nowFn func() time.Time
}

// inputActivityPublisher is the narrow read-stream publish seam W3 emits the
// InputActivity through — exactly attach.Fanout.Publish (watch.go), the SAME publish
// the SeatArbiter emits WRITER_SEAT_CHANGED through, so the two read-leg projections
// share one seq authority. Declared narrow so the drive leg depends only on the one
// method (a test fake records what was published without standing up the whole Fanout).
type inputActivityPublisher interface {
	Publish(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64
}

// newWriterRelayService builds the service over the arbiter, the read-stream Fanout
// (the InputActivity publish target), the host-agent drive sink, the two auth seams, and
// the server clock (the InputActivity.at stamp; nil ⇒ time.Now). A nil arbiter (the
// attach legs unwired) has the RPCs refuse Unavailable rather than arbitrate without a
// seat owner; nil validators are treated as fail-closed (every request is refused) so a
// half-wired deployment never grants an unauthenticated seat; a nil drive sink leaves
// DriveSession refusing fail-closed (no live relay ⇒ no drive).
func newWriterRelayService(arbiter *attach.SeatArbiter, fanout inputActivityPublisher, drive DriveSink, identity IdentityAssertionValidator, attachAuth AttachAuthValidator, clock func() time.Time) *WriterRelayService {
	return &WriterRelayService{arbiter: arbiter, fanout: fanout, drive: drive, identity: identity, attachAuth: attachAuth, nowFn: clock}
}

// now returns the current server time through the InputActivity.at clock seam (the D78
// freshness clock, sessions/10 §5.5 — SERVER-stamped). It defaults to time.Now when
// unset so a service constructed without an explicit clock still stamps a real time.
func (s *WriterRelayService) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// Compile-time proof the handler satisfies the frozen attach.v1 server interface.
var _ attachv1.WriterRelayServiceServer = (*WriterRelayService)(nil)

// RequestWriterSeat is the frozen attach.v1.WriterRelayService.RequestWriterSeat
// server method (sessions/10 §2.1 / §3 W2; D61/D137/D138). It validates the two auth
// keys, then drives the single-terminator arbitration:
//
//  1. D22/D55 — validate identity_assertion → the driver_identity (the seat
//     attribution). Missing/invalid → Unauthenticated (no seat without a valid human
//     identity).
//  2. D39 — validate attach_auth (the v1 AttachHandle.AuthMaterial.token) against
//     THIS session. Missing/invalid → PermissionDenied (the seat requires a valid
//     attach).
//  3. D61/D138 — RequestSeat at the single choke point: exactly one live seat; a
//     loser is refused (AlreadyExists/FailedPrecondition); a steal of an attended
//     seat without approval is PermissionDenied. On a grant/steal the attributed
//     holder is mirrored onto the record and a WRITER_SEAT_CHANGED event is emitted
//     on the read stream (granted_seq).
func (s *WriterRelayService) RequestWriterSeat(ctx context.Context, req *attachv1.RequestWriterSeatRequest) (*attachv1.RequestWriterSeatResponse, error) {
	if req == nil || req.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: RequestWriterSeat requires a session_uuid")
	}
	if s.arbiter == nil {
		return nil, status.Error(codes.Unavailable, "controlplane: WriterRelay seat arbiter not served (attach legs unwired)")
	}

	sessionUUID := req.GetSessionUuid()

	// (1) D22/D55 — validate the human identity assertion → the driver identity.
	driver, err := s.validateIdentity(ctx, sessionUUID, req.GetIdentityAssertion())
	if err != nil {
		return nil, err
	}

	// (2) D39 — validate the attach-auth token against THIS session.
	if err := s.validateAttachAuth(ctx, sessionUUID, req.GetAttachAuth()); err != nil {
		return nil, err
	}

	// (3) D61/D138 — arbitrate the one seat at the single terminator.
	grant, err := s.arbiter.RequestSeat(ctx, attach.SeatRequest{
		SessionUUID:    sessionUUID,
		DriverIdentity: driver,
		ForceSteal:     req.GetForceSteal(),
		// D138: an M0 force_steal carries no separate approval token (the policy seam
		// threads it at the M2 multi-org auth boundary). At M0 a force_steal of an
		// ATTENDED seat is refused (default-refuse); an idle seat is taken. StealApproved
		// stays false here so the arbiter's attended-seat gate is the choke point.
		StealApproved: false,
	})
	if err != nil {
		return nil, mapSeatError(err)
	}

	return &attachv1.RequestWriterSeatResponse{Grant: grant}, nil
}

// YieldWriterSeat is the frozen attach.v1.WriterRelayService.YieldWriterSeat server
// method (sessions/10 §2.1 W2): the cooperative release. It validates the attach auth
// (the caller must still hold a valid attach to release its seat) and drives the
// arbiter's YieldSeat. Idempotent: yielding a seat that is not the live grant is a
// clean ack (released_seq 0). On a real release the record's writer seat is cleared
// and a WRITER_SEAT_CHANGED kind=YIELD is emitted on the read stream (released_seq).
//
// A yield validates the D39 attach auth (a stale attach cannot release a seat) but
// does NOT re-validate the human identity assertion — the seat is matched by its
// live writer_seat_id under the arbiter's per-session lock, so only the holder of the
// live seat id can release it.
func (s *WriterRelayService) YieldWriterSeat(ctx context.Context, req *attachv1.YieldWriterSeatRequest) (*attachv1.YieldWriterSeatResponse, error) {
	if req == nil || req.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: YieldWriterSeat requires a session_uuid")
	}
	if s.arbiter == nil {
		return nil, status.Error(codes.Unavailable, "controlplane: WriterRelay seat arbiter not served (attach legs unwired)")
	}
	if req.GetWriterSeatId() == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: YieldWriterSeat requires a writer_seat_id")
	}

	releasedSeq, err := s.arbiter.YieldSeat(ctx, req.GetSessionUuid(), req.GetWriterSeatId())
	if err != nil {
		return nil, mapSeatError(err)
	}
	return &attachv1.YieldWriterSeatResponse{ReleasedSeq: releasedSeq}, nil
}

// DriveSession is the W3 drive channel (the host-agent relay leg, sessions/10 §2.1;
// D78/D137/D138). It is a BIDI stream the CURRENT seat-holder opens to type into Claude
// Code: the client streams DriveSessionRequest{input: DriveInput}, the server streams
// DriveSessionResponse acks. The orchestrator is the SINGLE choke point — for each
// inbound DriveInput it, in order:
//
//  1. VALIDATES the writer_seat_id against the LIVE grant at the single attach.SeatArbiter
//     terminator (ValidateDrive). ONLY the current live seat-holder may drive: a stale /
//     forged / absent id — and a seat that EXPIRED or was YIELDED mid-stream — reaches NO
//     stdin and emits NO InputActivity (sessions/10 §5 claim 2). The frame is REFUSED
//     in-band (a zeroed-ack DriveSessionResponse, driveRefusal) and the stream continues
//     (a bad frame refuses, it does not tear the channel) so a renew-and-retry resumes
//     driving — the permission semantics live on the seat the frame is checked against,
//     not a per-frame RPC status that would kill the open bidi channel.
//  2. REPLAY-REJECTS a non-monotonic client_seq (at-most-once, sessions/10 §5 claim 4):
//     the first frame must carry client_seq > 0 and each subsequent frame must STRICTLY
//     increase it. A replayed/stale client_seq reaches NO stdin and emits NO InputActivity;
//     it is refused in-band (as in step 1) and the stream continues.
//  3. FORWARDS the ADMITTED DriveInput to CC stdin via the host-agent relay (the DriveSink
//     seam, the RELAY endpoint transport). A nil sink FAILS CLOSED (Unavailable — no live
//     relay ⇒ the RPC refuses, never silently drops). A transport fault is Unavailable and
//     emits NO InputActivity (an input that did not reach stdin is not projected).
//  4. EMITS the v1 events.proto InputActivity {writer_seat_id, at(SERVER-STAMPED), kind,
//     seq} on the read stream through the SAME Fanout the seat handoff rides (so every
//     spectator sees the driver typed and the D78 attendedness clock advances, D138). NO
//     input payload rides the read leg (only writer_seat_id/at/kind/seq) — the body rides
//     ONLY DriveInput.payload on this write leg.
//  5. ACKS with DriveSessionResponse{accepted_client_seq = the admitted client_seq,
//     emitted_input_activity_seq = the Fanout seq of the emitted InputActivity}.
//
// The relay ORIGINATES no input of its own (the confused-deputy mitigation, claim 5): it
// only forwards frames the arbiter admitted for the live seat-holder. A nil arbiter (the
// attach legs unwired) refuses Unavailable; a nil Fanout refuses Unavailable (an accepted
// input that cannot be made observable is not admitted).
func (s *WriterRelayService) DriveSession(stream attachv1.WriterRelayService_DriveSessionServer) error {
	if s.arbiter == nil {
		return status.Error(codes.Unavailable, "controlplane: DriveSession seat arbiter not served (attach legs unwired)")
	}
	if s.fanout == nil {
		return status.Error(codes.Unavailable, "controlplane: DriveSession read-stream fan-out not served (cannot project InputActivity)")
	}
	if s.drive == nil {
		// Fail CLOSED: no live host-agent relay is configured, so an admitted frame would
		// have nowhere to go. Refuse the whole stream rather than accept-then-drop (an
		// admitted input MUST reach stdin, never silently vanish).
		return status.Error(codes.Unavailable, "controlplane: DriveSession host-agent relay not served (no live drive sink wired — fail-closed)")
	}

	ctx := stream.Context()
	// lastClientSeq is the per-stream at-most-once high-water mark: the first admitted
	// frame must carry client_seq > 0 and each later one must strictly exceed it (replay
	// rejection). It advances ONLY on a fully-admitted frame, so a refused frame never
	// moves the bar (a renew-and-retry of the SAME client_seq after a seat refusal is not
	// itself a replay).
	var lastClientSeq uint64

	for {
		req, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// The client half-closed the drive stream (done typing): a clean end.
				return nil
			}
			return err // a transport error on the inbound leg — surface it.
		}
		in := req.GetInput()
		if in == nil {
			return status.Error(codes.InvalidArgument, "controlplane: DriveSession request carries no input")
		}
		clientSeq := in.GetClientSeq()

		// (1) LIVE-GRANT seat validation at the single terminator. The drive wire carries
		// only the seat-id (no session key); the arbiter that minted it resolves it to its
		// session + attributed driver and re-validates it against the live record. A stale/
		// forged/absent id — or a seat that expired/yielded mid-stream — reaches no stdin
		// and emits no InputActivity (sessions/10 §5 claim 2): refuse in-band, continue.
		seat, err := s.arbiter.ValidateDrive(ctx, in.GetWriterSeatId())
		if err != nil {
			if serr := stream.Send(driveRefusal(clientSeq)); serr != nil {
				return serr
			}
			continue
		}

		// (2) AT-MOST-ONCE / replay rejection: client_seq must be strictly monotonic for
		// the stream (and the first frame > 0). A replayed/stale seq reaches no stdin and
		// emits no InputActivity.
		if clientSeq == 0 || clientSeq <= lastClientSeq {
			if serr := stream.Send(driveRefusal(clientSeq)); serr != nil {
				return serr
			}
			continue
		}

		// (3) FORWARD the admitted frame to CC stdin via the host-agent relay, keyed on the
		// session the arbiter resolved (never a wire-supplied session). A transport fault
		// means the input did not reach stdin → emit NO InputActivity (do not project
		// activity for an input CC never received). The stream continues so a retry recovers.
		if derr := s.drive.Drive(ctx, seat.SessionUUID, in); derr != nil {
			if serr := stream.Send(driveRefusal(clientSeq)); serr != nil {
				return serr
			}
			continue
		}

		// (4) EMIT the v1 InputActivity read-leg projection on the SAME Fanout the seat
		// handoff rides, keyed on the resolved session. Server-stamped `at` (the D78
		// freshness clock); NO input payload on the read leg (only writer_seat_id/at/kind/
		// seq). The Fanout stamps the per-event seq + session_id (it is the seq authority),
		// so they are left zero here. Its returned seq is the emitted_input_activity_seq.
		activitySeq := s.fanout.Publish(ctx, seat.SessionUUID, &attachv1.SessionEvent{
			Type: attachv1.EventType_EVENT_TYPE_INPUT_ACTIVITY,
			Payload: &attachv1.SessionEvent_InputActivity{
				InputActivity: &attachv1.InputActivity{
					SessionUuid:  seat.SessionUUID,
					WriterSeatId: in.GetWriterSeatId(),
					At:           uint64(s.now().Unix()),
					Kind:         inputActivityKindFromDriveBlock(in.GetKind()),
				},
			},
		})

		// The frame is fully admitted: advance the at-most-once bar and ack.
		lastClientSeq = clientSeq
		if serr := stream.Send(&attachv1.DriveSessionResponse{
			AcceptedClientSeq:       clientSeq,
			EmittedInputActivitySeq: activitySeq,
		}); serr != nil {
			return serr
		}
	}
}

// driveRefusal builds the ack the server streams for a REFUSED DriveInput (a stale/
// forged/absent seat, a replayed client_seq, or a relay transport fault): it carries
// emitted_input_activity_seq = 0 (NO InputActivity was emitted — the input reached no
// stdin) and echoes the client_seq the caller presented so the driver can correlate the
// refusal with its frame. The refusal does NOT tear the stream (a bad frame refuses, it
// does not abort the channel) — the seat can be renewed and driving resumes. accepted_
// client_seq is left zero: nothing was admitted at that frame.
//
// (A typed RPC error is reserved for a stream-fatal condition — an unwired arbiter/
// fanout/sink, or an inbound transport error; a per-frame refusal stays in-band so one
// bad frame does not kill the driver's open channel.)
func driveRefusal(_ uint64) *attachv1.DriveSessionResponse {
	return &attachv1.DriveSessionResponse{
		AcceptedClientSeq:       0,
		EmittedInputActivitySeq: 0,
	}
}

// inputActivityKindFromDriveBlock maps the write-leg DriveBlockKind union onto the
// read-leg InputActivityKind taxonomy for the projected activity event. The two enums
// MIRROR each other by intent (writer_relay.proto / events.proto) and carry identical
// numeric values for the shared kinds (text=1, tool_result=2, image=3, multi_block=4),
// but they are SEPARATE enums on the two legs (so they evolve independently), so the
// map is explicit, never a numeric cast. An unknown/unspecified write kind projects as
// UNSPECIFIED (the read-leg zero value) rather than guessing.
func inputActivityKindFromDriveBlock(k attachv1.DriveBlockKind) attachv1.InputActivityKind {
	switch k {
	case attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT:
		return attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_TEXT
	case attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TOOL_RESULT:
		return attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_TOOL_RESULT
	case attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_IMAGE:
		return attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_IMAGE
	case attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_MULTI_BLOCK:
		return attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_MULTI_BLOCK
	default:
		return attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_UNSPECIFIED
	}
}

// validateIdentity runs the D22/D55 identity-assertion validation. A nil validator
// fails CLOSED (Unauthenticated — no seat without a wired human-identity check). An
// empty assertion, an invalid one (ok=false), or an empty resolved driver is
// Unauthenticated; a validator fault is Unavailable.
func (s *WriterRelayService) validateIdentity(ctx context.Context, sessionUUID, assertion string) (string, error) {
	if s.identity == nil {
		return "", status.Error(codes.Unauthenticated, "controlplane: RequestWriterSeat identity validation not served (no seat without a valid human identity, D22/D55)")
	}
	if assertion == "" {
		return "", status.Error(codes.Unauthenticated, "controlplane: RequestWriterSeat requires an identity_assertion (D22/D55 human identity)")
	}
	driver, ok, err := s.identity.ValidateAssertion(ctx, sessionUUID, assertion)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "controlplane: validate identity assertion for session %q: %v", sessionUUID, err)
	}
	if !ok || driver == "" {
		return "", status.Error(codes.Unauthenticated, "controlplane: RequestWriterSeat identity_assertion invalid (D22/D55)")
	}
	return driver, nil
}

// validateAttachAuth runs the D39 attach-auth-token validation against THIS session.
// A nil validator fails CLOSED (PermissionDenied — no seat without a wired attach
// check). An empty token or an invalid one (ok=false) is PermissionDenied; a
// validator fault is Unavailable.
func (s *WriterRelayService) validateAttachAuth(ctx context.Context, sessionUUID string, token []byte) error {
	if s.attachAuth == nil {
		return status.Error(codes.PermissionDenied, "controlplane: RequestWriterSeat attach-auth validation not served (the seat requires a valid attach, D39)")
	}
	if len(token) == 0 {
		return status.Error(codes.PermissionDenied, "controlplane: RequestWriterSeat requires attach_auth (the v1 AttachHandle.AuthMaterial.token, D39)")
	}
	ok, err := s.attachAuth.ValidateAttachAuth(ctx, sessionUUID, token)
	if err != nil {
		return status.Errorf(codes.Unavailable, "controlplane: validate attach auth for session %q: %v", sessionUUID, err)
	}
	if !ok {
		return status.Error(codes.PermissionDenied, "controlplane: RequestWriterSeat attach_auth invalid for this session (D39)")
	}
	return nil
}

// mapSeatError maps the arbiter's typed seat-arbitration errors onto gRPC status
// codes by failure class (D61/D138). A held seat (the D61 one-writer loser) →
// AlreadyExists (a live seat already exists; the loser is refused, never a second
// seat). An attended-steal refusal (D138 default-refuse) → PermissionDenied. A
// missing driver identity → Unauthenticated. Anything else (a store fault under the
// record mutation) → Unavailable (the record store is the seat authority; a stalled
// store cannot arbitrate the seat).
func mapSeatError(err error) error {
	switch {
	case errors.Is(err, attach.ErrSeatHeld):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, attach.ErrStealAttended):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, attach.ErrDriverIdentityRequired):
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		return status.Errorf(codes.Unavailable, "controlplane: writer seat arbitration: %v", err)
	}
}
