package controlplane

// fixtures_test.go holds the SYNTHETIC fixtures + fakes the control-plane capstone
// tests drive against (D50: NO live VM/host-agent/podman — the host driver is the
// generated hypervisor.v1 fake, the Identity/boundary seams are recording fakes, the
// store is *store.Memory). It builds a fully-wired ControlPlane (NewControlPlane) over
// these fakes so the three legs — the CreateSession handler, the reconcile loop, the
// scheduler adapter — are exercised exactly as production wires them, only the live
// network edges replaced by fakes.

import (
	"context"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1/hypervisorv1fake"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

const (
	testHostID       = "host-a"
	testRepoID       = "repo-acme"
	testEnvRef       = "env-acme-1"
	testImageID      = "img-sha256-deadbeef"
	testSubject      = "okta|ada"
	testOrg          = "acme"
	testRoleHashSeed = "default-role-hash-v0"
	// testRolesDir locates the checked-in roles/ catalog relative to this package's
	// test cwd (orchestrator/internal/controlplane → ../../../roles).
	testRolesDir = "../../../roles"
)

// fakeRegistry is a DriverRegistry returning ONE programmed host driver fake for every
// host (the single-host orchestrator-lite posture, D80). Hosts() reports the one host so
// the reconciler's fleet-broadcast path resolves it.
type fakeRegistry struct {
	host string
	drv  DriverClient
}

func (r fakeRegistry) DriverFor(_ context.Context, hostID string) (DriverClient, error) {
	if hostID == r.host {
		return r.drv, nil
	}
	// In the single-host posture every host resolves to the one driver (a placement
	// always picks r.host); a different host id is a wiring miss.
	return nil, ErrNoDriverForHost
}

func (r fakeRegistry) Hosts(_ context.Context) ([]string, error) { return []string{r.host}, nil }

// newDriverFake builds a host driver fake programmed to drive a create to a successful
// binding/attach and to ack a destroy/suspend. The CloneFromImage responder returns the
// never-recycled binding the §4.1 step-4 records; IssueAttachHandle/Suspend/Destroy ack.
func newDriverFake() *hypervisorv1fake.HypervisorDriverServiceFake {
	f := &hypervisorv1fake.HypervisorDriverServiceFake{}
	f.CloneFromImageResponder = func(_ context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
		return &hypervisorv1.CloneFromImageResponse{
			HostSessionIndex: 7,
			TapName:          "dstap-7",
			GuestIp: &hypervisorv1.GuestAddress{
				Family:  hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4,
				Address: []byte{10, 0, 0, 7},
			},
			OverlayPath: "/var/lib/ds/overlays/" + req.GetSpec().GetSessionUuid() + ".qcow2",
		}, nil
	}
	f.IssueAttachHandleResponder = func(_ context.Context, _ *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error) {
		return &hypervisorv1.IssueAttachHandleResponse{}, nil
	}
	f.SuspendResponder = func(_ context.Context, _ *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
		return &hypervisorv1.SuspendResponse{}, nil
	}
	f.DestroyResponder = func(_ context.Context, _ *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
		return &hypervisorv1.DestroyResponse{}, nil
	}
	return f
}

// fakeMint records mint calls and returns synthetic identity/CA refs.
type fakeMint struct {
	calls int
	err   error
}

func (m *fakeMint) Mint(_ context.Context, _ sessions.MintWorkloadIdentityClaims, _ string) (string, string, error) {
	m.calls++
	if m.err != nil {
		return "", "", m.err
	}
	return "id-ref-1", "ca-ref-1", nil
}

// fakeDigest records digest writes and acks by default (the routable gate's premise).
type fakeDigest struct {
	calls int
	acked bool
	err   error
}

func (d *fakeDigest) WriteAndAck(_ context.Context, _, _, _ string) (string, bool, error) {
	d.calls++
	if d.err != nil {
		return "", false, d.err
	}
	return "digest-ref-1", d.acked, nil
}

// fakeInject records CA injections; err drives the §4.1 step-7 fail-closed path.
type fakeInject struct {
	calls int
	err   error
}

func (i *fakeInject) InjectCA(_ context.Context, _, _, _ string) error {
	i.calls++
	return i.err
}

// fakeBoot records boots; err drives the §4.1 step-8 rollback path.
type fakeBoot struct {
	calls int
	err   error
}

func (b *fakeBoot) Boot(_ context.Context, _, _ string) error {
	b.calls++
	return b.err
}

// fakeRevoke records revocations (the §4.1 step-5/6 rollback compensation).
type fakeRevoke struct{ calls int }

func (r *fakeRevoke) Revoke(_ context.Context, _, _, _ string) error {
	r.calls++
	return nil
}

// fakeEnrollment is the §4.1 step-1 first-key resolver fake (D56): it reports the test
// repo enrolled by an org-admin (an enrollment authority under any posture).
type fakeEnrollment struct {
	repoID string
	ok     bool
}

func (e fakeEnrollment) ResolveEnrollment(_ context.Context, repoID string) (sessions.Enrollment, bool, error) {
	if !e.ok || repoID != e.repoID {
		return sessions.Enrollment{}, false, nil
	}
	return sessions.Enrollment{
		RepoID:              repoID,
		EnrolledByPrincipal: "admin-1",
		EnrolledByRole:      store.RoleOrgAdmin,
	}, true, nil
}

// fixture bundles the wired ControlPlane plus the fakes the tests assert against.
type fixture struct {
	cp     *ControlPlane
	st     *store.Memory
	drv    *hypervisorv1fake.HypervisorDriverServiceFake
	mint   *fakeMint
	digest *fakeDigest
	inject *fakeInject
	boot   *fakeBoot
	revoke *fakeRevoke
	clock  func() time.Time
}

// newFixture builds a fully-wired ControlPlane over the synthetic fakes. Knobs let a
// test inject a seam fault (inject/boot/digest) to exercise the rollback paths.
type fixtureOpts struct {
	injectErr     error
	bootErr       error
	digestUnacked bool
	schedConfig   scheduler.Config
	emptyFeed     bool // skip seeding the placement candidate heartbeat
}

// newFixtureEmptyFeed builds a fixture whose live heartbeat feed is empty (no placement
// candidate), so a create refuses at placement.
func newFixtureEmptyFeed(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, fixtureOpts{emptyFeed: true})
}

func newFixture(t *testing.T, opts fixtureOpts) *fixture {
	t.Helper()

	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := store.NewMemoryClock(clock)

	// Seed the §4.1 step-1 second key: a recorded env config for the repo, resolving the
	// content-addressed image (doc 15 §9).
	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref:     testEnvRef,
		RepoRef: testRepoID,
		ImageID: testImageID,
	}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}

	drv := newDriverFake()
	mint := &fakeMint{}
	digest := &fakeDigest{acked: !opts.digestUnacked}
	inject := &fakeInject{err: opts.injectErr}
	boot := &fakeBoot{err: opts.bootErr}
	revoke := &fakeRevoke{}

	heartbeats := NewHeartbeatStore(clock)
	if !opts.emptyFeed {
		// Seed a fresh heartbeat for the placement host so the scheduler has a candidate
		// with capacity (the §7 floors-fit + staleness filters pass: applied_seq 0 == the
		// empty-log policy head, capacity headroom present).
		heartbeats.Record(freshHeartbeat(testHostID, 0, 1))
	}

	// The roles.v1 RoleCatalogService READ-path server over the checked-in roles/
	// catalog (the built-in four, D50/D93) — so the wired ControlPlane registers the
	// catalog read API exactly as production does (doc 18 §6; D80). A load fault is a
	// fatal test error (the checked-in catalog must be present and parseable).
	roleCatalog, rcErr := NewRoleCatalogServiceFromDir(testRolesDir, nil)
	if rcErr != nil {
		t.Fatalf("load role catalog: %v", rcErr)
	}

	deps := Deps{
		Store:           cpStore{st},
		Drivers:         fakeRegistry{host: testHostID, drv: drv},
		Heartbeats:      heartbeats,
		Mint:            mint,
		Digest:          digest,
		Inject:          inject,
		Boot:            boot,
		Revoke:          revoke,
		Enrollment:      fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:           sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		RoleCatalog:     roleCatalog,
		DefaultOrg:      testOrg,
		SchedulerConfig: opts.schedConfig,
		StalenessBudget: 0,
		Clock:           clock,
		ResyncInterval:  time.Hour, // tests drive resync explicitly via resyncNow
	}
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	// Deterministic session UUIDs for the handler tests.
	var n int
	cp.Sessions.SetSessionUUIDGen(func() string {
		n++
		return "sess-" + time.Unix(int64(n), 0).UTC().Format("0405")
	})

	return &fixture{cp: cp, st: st, drv: drv, mint: mint, digest: digest, inject: inject, boot: boot, revoke: revoke, clock: clock}
}

// cpStore adapts *store.Memory onto the ControlPlaneStore method set (it satisfies every
// method; this named type pins the satisfaction at the test seam and documents that the
// concrete store is the single coherent backing store the wiring is cut from).
type cpStore struct{ *store.Memory }

// freshHeartbeat builds a synthetic heartbeat for a host with the given applied_seq and
// running-session count (capacity headroom present so floors-fit passes).
func freshHeartbeat(hostID string, appliedSeq uint64, running uint32) *hostagentv1.Heartbeat {
	return &hostagentv1.Heartbeat{
		HostId:     hostID,
		AppliedSeq: appliedSeq,
		Capacity: &hostagentv1.HostCapacity{
			RunningSessions: running,
		},
	}
}

// heartbeatWithObserved builds a synthetic heartbeat carrying an observed-session set
// (the reconciler's input) for a host.
func heartbeatWithObserved(hostID string, appliedSeq uint64, observed ...*hypervisorv1.ObservedSession) *hostagentv1.Heartbeat {
	hb := freshHeartbeat(hostID, appliedSeq, uint32(len(observed)))
	hb.Observed = observed
	return hb
}

// policyRow builds a minimal policy_log append row (actor required, D36) to advance the
// policy head in a placement-staleness test.
func policyRow(actor string) store.PolicyLogRow {
	return store.PolicyLogRow{
		Kind:        store.PolicyKindAppend,
		Actor:       actor,
		ContentHash: "hash-1",
		Payload:     []byte("{}"),
	}
}

// validCreateReq is the orchestrator.v1 request the happy-path handler test drives.
func validCreateReq() *orchestratorv1.CreateSessionRequest {
	return &orchestratorv1.CreateSessionRequest{
		RepoId:        testRepoID,
		EnvConfigRef:  testEnvRef,
		LaunchingUser: testSubject,
		RoleRef:       "",
	}
}
