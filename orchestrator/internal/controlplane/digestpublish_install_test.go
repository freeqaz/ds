// SPDX-License-Identifier: Apache-2.0

package controlplane

// digestpublish_install_test.go pins the CONTROL-PLANE INSTALL of the §6.1 mint-before-attach
// digest-publish seam (D73/D84, doc 16 §6.1): NewControlPlane now threads Deps.DigestPublisher
// into the create coordinator's CreateSeams (wiring.go), so a WIRED publisher is actually
// driven per create — closing the gap where the coordinator seam existed but NewControlPlane
// never SET it (an armed orchestrator-lite then failed every create closed).
//
// It drives the real NewControlPlane over the synthetic fixtures (D50, no live VM/host-agent/
// Identity), with a recording controlplane.DigestPublisher wired via Deps.DigestPublisher:
//
//   - FLAG ON (armed) + wired publisher: exactly ONE digest batch is published per create and
//     the create reaches ATTACHED (the committed ack turns on Routable) — the install closes
//     the fail-closed-when-unwired gap.
//   - FLAG OFF (the wave default): the spine skips the digest-publish step, so the wired
//     publisher is NEVER driven (byte-identical to the pre-wire path, D50) and the create still
//     reaches ATTACHED.
//
// The spine-level fail-closed cases (armed + nil publisher, uncommitted ack) are covered at the
// coordinator/RPC surface in createspine_digest_test.go and digestpublishwire_test.go; this
// test owns the NewControlPlane wiring edge those two cannot reach (the fixture there leaves
// Deps.DigestPublisher nil).

import (
	"context"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// recordingDigestPublisher is a synthetic controlplane.DigestPublisher (D50): it counts the
// §6.1 publish calls the coordinator drives and returns a committed (Routable) ack so an armed
// create proceeds to ATTACHED. It records the session UUIDs it was asked to publish so the test
// can assert the seam saw exactly the create's session.
type recordingDigestPublisher struct {
	calls    int
	sessions []string
}

func (p *recordingDigestPublisher) PublishSessionDigests(_ context.Context, sessionUUID string) (sessions.DigestPublishOutcome, error) {
	p.calls++
	p.sessions = append(p.sessions, sessionUUID)
	return sessions.DigestPublishOutcome{ConsumerID: "host-consumer-1", BatchID: "batch-1", Routable: true}, nil
}

// newDigestInstallControlPlane builds a fully-wired ControlPlane over the synthetic fakes with
// the given §6.1 digest publisher threaded through Deps.DigestPublisher — the install this test
// exercises. It mirrors newFixture's synthetic wiring (fixtures_test.go) but injects the
// publisher, which newFixture does not expose.
func newDigestInstallControlPlane(t *testing.T, pub DigestPublisher) *ControlPlane {
	t.Helper()

	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := store.NewMemoryClock(clock)

	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref:     testEnvRef,
		RepoRef: testRepoID,
		ImageID: testImageID,
	}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}

	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))

	roleCatalog, rcErr := NewRoleCatalogServiceFromDir(testRolesDir, nil)
	if rcErr != nil {
		t.Fatalf("load role catalog: %v", rcErr)
	}

	deps := Deps{
		Store:           cpStore{st},
		Drivers:         fakeRegistry{host: testHostID, drv: newDriverFake()},
		Heartbeats:      heartbeats,
		Mint:            &fakeMint{},
		Digest:          &fakeDigest{acked: true},
		Inject:          &fakeInject{},
		Boot:            &fakeBoot{},
		Revoke:          &fakeRevoke{},
		Enrollment:      fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:           sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		RoleCatalog:     roleCatalog,
		DefaultOrg:      testOrg,
		StalenessBudget: 0,
		Clock:           clock,
		ResyncInterval:  time.Hour,
		DigestPublisher: pub,
	}
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	var n int
	cp.Sessions.SetSessionUUIDGen(func() string {
		n++
		return "sess-" + time.Unix(int64(n), 0).UTC().Format("0405")
	})
	return cp
}

// TestCreateSession_DigestPublish_InstalledPublishesOnce proves the ARMED install: with the
// flag on and a publisher threaded through Deps.DigestPublisher, a create drives the §6.1
// publish EXACTLY ONCE (keyed on the create's session UUID) and reaches ATTACHED — the coordinator
// install closes the armed-but-unwired fail-closed gap.
func TestCreateSession_DigestPublish_InstalledPublishesOnce(t *testing.T) {
	t.Setenv(sessions.DigestPublishWireFlag, "1")
	pub := &recordingDigestPublisher{}
	cp := newDigestInstallControlPlane(t, pub)

	resp, err := cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (armed, wired): unexpected error: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("CreateSession (armed, wired): state = %v, want ATTACHED (committed ack → routable)", got)
	}
	if pub.calls != 1 {
		t.Fatalf("digest publish calls = %d, want exactly 1 (one batch per create)", pub.calls)
	}
	if len(pub.sessions) != 1 || pub.sessions[0] != resp.GetSession().GetSessionUuid() {
		t.Fatalf("published sessions = %v, want [%q] (the create's session)", pub.sessions, resp.GetSession().GetSessionUuid())
	}
}

// TestCreateSession_DigestPublish_UnarmedPublishesNone proves the DEFAULT (disarmed) path stays
// byte-identical (D50): with the flag off, even though a publisher IS wired through
// Deps.DigestPublisher, the spine skips the digest-publish step so the publisher is NEVER driven,
// and the create still reaches ATTACHED.
func TestCreateSession_DigestPublish_UnarmedPublishesNone(t *testing.T) {
	t.Setenv(sessions.DigestPublishWireFlag, "0")
	pub := &recordingDigestPublisher{}
	cp := newDigestInstallControlPlane(t, pub)

	resp, err := cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (disarmed): unexpected error: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("CreateSession (disarmed): state = %v, want ATTACHED (byte-identical to pre-wire)", got)
	}
	if pub.calls != 0 {
		t.Fatalf("digest publish calls = %d, want 0 (disarmed spine skips the step)", pub.calls)
	}
}
