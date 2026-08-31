// SPDX-License-Identifier: Apache-2.0

package controlplane

// digestpublishwire_test.go drives the FLAG-GATED (DS_ORCH_DIGEST_PUBLISH_WIRE) doc 16
// §6.1 mint-before-attach ROUTABLE gate (D73/D84) at the CreateSession RPC surface, over
// the synthetic fixtures (D50, no live VM/host-agent/Identity).
//
// The §4.1 create spine already DRIVES the gate BETWEEN cred-mint and mark-routable
// (createspine.go's runCreateDigestPublish; the spine-level fail-closed / disarmed cases
// are unit-tested in internal/sessions/createspine_digest_test.go). This test pins the
// CONTROL-PLANE bridge's behavior at the RPC boundary:
//
//   - FLAG OFF (the wave default): CreateSession reaches ATTACHED as today — byte-for-byte
//     the pre-wire behavior (the spine skips the digest-publish step entirely).
//   - FLAG ON (no publisher threaded into the coordinator's CreateSpineRequest — the
//     production wiring gap this unit surfaces): the spine fails the create CLOSED
//     (ErrDigestPublisherUnwired), and the RPC surfaces it as an ATTRIBUTABLE
//     FailedPrecondition ("digest publish fail-closed") rather than an opaque Internal —
//     the mapCreateError classification this unit adds. An armed-but-unwired deployment
//     therefore never presents a routable session, and the refusal names the digest edge.
//
// The armed HAPPY path (a committed ack → routable) is unreachable until a publisher is
// threaded through the coordinator's CreateSpineRequest.DigestPublisher (a deferred step in
// internal/sessions/sessioncreate.go, outside this unit's owned files); that seam + its fake
// are exercised at the spine level in createspine_digest_test.go.

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
)

// TestCreateSession_DigestPublish_FlagOff proves the DEFAULT (disarmed) path is byte-for-byte
// the pre-wire behavior: a flag-off create reaches ATTACHED, the spine skipping the
// digest-publish step (D50).
func TestCreateSession_DigestPublish_FlagOff(t *testing.T) {
	t.Setenv(sessions.DigestPublishWireFlag, "0")
	f := newFixture(t, fixtureOpts{})

	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (flag off): unexpected error: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("CreateSession (flag off): state = %v, want ATTACHED (byte-identical to pre-wire)", got)
	}
}

// TestCreateSession_DigestPublish_FlagOnUnwired proves the ARMED-but-UNWIRED fail-closed
// posture the RPC surface now attributes: with the flag armed and no publisher threaded into
// the coordinator, the spine fails the create closed (ErrDigestPublisherUnwired), and
// CreateSession maps it onto an ATTRIBUTABLE FailedPrecondition naming the digest edge —
// NOT an opaque Internal. The armed deployment never presents a routable session.
func TestCreateSession_DigestPublish_FlagOnUnwired(t *testing.T) {
	t.Setenv(sessions.DigestPublishWireFlag, "1")
	f := newFixture(t, fixtureOpts{})

	_, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatal("CreateSession (armed, unwired): want a fail-closed error, got nil (session presented routable)")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("CreateSession (armed, unwired): code = %v, want FailedPrecondition (attributable, not Internal); err=%v", st.Code(), err)
	}
	if !strings.Contains(st.Message(), "digest publish fail-closed") {
		t.Errorf("CreateSession (armed, unwired): message = %q, want it to name the digest-publish fail-closed cause", st.Message())
	}
}
