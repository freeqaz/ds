package controlplane

// wiring_test.go proves the NewControlPlane assembly contract: a missing required dep is
// refused fail-closed at construction (never at the first create), the digest-not-acked
// routable gate (D73) refuses, and the single-store coherence the §4.1 spine requires
// holds end to end (a clean create's launching_user resolves back on the SAME store).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestNewControlPlane_RefusesMissingDep proves the construction-time fail-closed refusal:
// a wiring missing a required backend (here the host driver registry) is refused, never
// half-wired.
func TestNewControlPlane_RefusesMissingDep(t *testing.T) {
	st := store.NewMemory()
	_, err := NewControlPlane(Deps{
		Store: cpStore{st},
		// Drivers omitted — a required dep.
		Mint:       &fakeMint{},
		Digest:     &fakeDigest{acked: true},
		Inject:     &fakeInject{},
		Boot:       &fakeBoot{},
		Revoke:     &fakeRevoke{},
		Enrollment: fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:      sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
	})
	if err == nil {
		t.Fatal("NewControlPlane: expected a fail-closed refusal for a missing required dep")
	}
	if !strings.Contains(err.Error(), "Drivers") {
		t.Errorf("error should name the missing dep Drivers; got %v", err)
	}
}

// TestCreateSession_DigestNotAckedRefusesRoutable proves the §4.1 step-9 D73 routable gate:
// a digest write that is NOT acked blocks READY — the create rolls back and the handler
// maps ErrDigestNotAcked onto FailedPrecondition (not routable).
func TestCreateSession_DigestNotAckedRefusesRoutable(t *testing.T) {
	f := newFixture(t, fixtureOpts{digestUnacked: true})

	_, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatal("CreateSession: expected an ErrDigestNotAcked refusal (D73 routable gate)")
	}
	if st, _ := status.FromError(err); st.Code() != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}
	// The create rolled back (the digest was written but never acked → not routable).
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("digest-not-acked rollback destroy calls = %d, want 1", len(f.drv.DestroyRecorded()))
	}
}

// TestSingleStoreCoherence_LaunchingUserResolves proves the §4.1 single-store coherence
// holds end to end: a clean create links the launching principal (the gate's write) and
// the SAME store resolves the launching_user claim back (the step-5 read) — the
// StoreSeamsStrict accessor cut all three seams from one store, so the link the gate
// wrote is the link the resolver reads.
func TestSingleStoreCoherence_LaunchingUserResolves(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	resp, err := f.cp.Sessions.CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessionUUID := resp.GetSession().GetSessionUuid()

	// The launching_user resolves back on the SAME store (coherence): the gate linked the
	// principal, the resolver reads it — same store, so the claim is the IdP subject.
	claim, ok, rerr := f.st.ResolveLaunchingUserClaim(ctx, sessionUUID)
	if rerr != nil {
		t.Fatalf("ResolveLaunchingUserClaim: %v", rerr)
	}
	if !ok {
		t.Fatal("launching_user did not resolve back — the gate's link and the resolver crossed stores (coherence broken)")
	}
	if claim.Subject != testSubject {
		t.Errorf("resolved launching_user = %q, want %q", claim.Subject, testSubject)
	}
	if claim.Org != testOrg {
		t.Errorf("resolved org = %q, want %q", claim.Org, testOrg)
	}
}

// TestNewControlPlane_InstallsDigestReAckOnRedriver proves the production wiring installs
// withDigestReAck(d.Digest) on the §3 rule-b host-side re-create continuation (the
// SpineContinuationFunc the ConcreteRedriver drives). orch22 landed the digest re-write+
// re-ack seam on redrive.go behind the variadic option, but the production newHostReCreate
// construction in wiring.go never installed it, so a re-driven VM was declared converged
// WITHOUT re-acking its §4.1 step-6 digest — a HALF-CONVERGED, not-routable VM the step-9
// routable gate ({3,6} ≺ 9) would have refused (D73). Driving the production continuation
// (the one NewControlPlane built) over a missing-VM record asserts the seam is live: the
// digest is re-acked on the re-drive (the SAME Identity-owned digest face the create
// coordinator's step 6 drove), and only then is the VM converged (reCreate returns nil).
func TestNewControlPlane_InstallsDigestReAckOnRedriver(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	// Drive a clean create so the store holds a host-bound record with a LINKED launching
	// principal (the re-drive's premise, doc 16 §3.1) — the production re-create resolves
	// launching_user against the REAL store seam (d.Store), so the session must exist. The
	// create placed the session on testHostID (the single-host fixture posture).
	rec := createdRecord(t, f)
	callsBefore := f.digest.calls

	// Drive the PRODUCTION re-create continuation NewControlPlane built (the
	// SpineContinuationFunc target, carrying withDigestReAck(d.Digest)) over that record.
	// spineResult is the in-package re-asserted spine the SpineRunner would have produced
	// (D50 synthetic fixtures).
	if err := f.cp.reCreate.reCreate(ctx, rec, spineResult()); err != nil {
		t.Fatalf("production re-create (digest re-ack installed) should converge, got: %v", err)
	}

	// The digest seam was DRIVEN on the re-drive — withDigestReAck(d.Digest) is installed,
	// so a re-driven VM re-acks its step-6 digest before being declared converged (D73). An
	// uninstalled seam (the pre-fix wiring) would leave the count unchanged.
	if got := f.digest.calls - callsBefore; got != 1 {
		t.Fatalf("production re-drive must re-write+re-ack the digest exactly once (withDigestReAck installed), got %d re-acks", got)
	}
}

// TestNewControlPlane_DigestReAckRefusesNotRoutableOnReDrive proves the installed seam
// enforces the D73 routable invariant on the production continuation: a re-drive whose
// digest is written but NOT acked does NOT declare the VM converged — reCreate fails with
// sessions.ErrDigestNotAcked (the structural step-9 refusal), so the reconciler takes the
// §3 rule-b fail arm rather than declaring a not-routable VM converged. This is the
// behavior the missing withDigestReAck would have silently skipped (a re-create with no
// digest seam converges without ever re-acking).
func TestNewControlPlane_DigestReAckRefusesNotRoutableOnReDrive(t *testing.T) {
	// digestUnacked: the host writes but NEVER acks (the not-routable arm, D73). A clean
	// create would refuse at step-9, so seed a stored, host-bound, principal-linked record
	// directly (the re-drive's premise) and re-drive it through the production continuation.
	f := newFixture(t, fixtureOpts{digestUnacked: true})
	ctx := context.Background()
	rec := storeLinkedRecord(t, f, "sess-redrive-unacked")
	callsBefore := f.digest.calls

	err := f.cp.reCreate.reCreate(ctx, rec, spineResult())
	if err == nil {
		t.Fatal("an UNACKED digest on the production re-drive must NOT declare converged (D73)")
	}
	if !errors.Is(err, sessions.ErrDigestNotAcked) {
		t.Fatalf("expected the D73 structural refusal sessions.ErrDigestNotAcked, got: %v", err)
	}
	// The seam was driven (the write was attempted) — it is installed, it just did not ack.
	if got := f.digest.calls - callsBefore; got != 1 {
		t.Fatalf("expected one digest write attempt on the installed seam, got %d", got)
	}
}

// TestNewControlPlane_LiveFreshnessProbeUnderGate proves the §4.1 step-9 live-freshness
// probe (D72) is flipped from armed to LIVE by the placer-construction wiring under
// DS_ORCH_LIVE, and is UNCHANGED with the gate off:
//
//   - GATE ON (DS_ORCH_LIVE=1): NewControlPlane assigns placer.Freshness =
//     NewHostFreshness(<shared feed>), so Adapter.CurrentFreshness returns the placed
//     host's LIVE applied_seq (the value the step-9 routable gate re-validates against),
//     NOT sessions.ErrFreshnessUnknown — the window-close fires.
//   - GATE OFF (no DS_ORCH_LIVE): placer.Freshness stays nil, so CurrentFreshness returns
//     sessions.ErrFreshnessUnknown and the coordinator degrades to the recorded re-check —
//     the pre-orch25 behavior, unchanged (backwards-compatible, D50).
func TestNewControlPlane_LiveFreshnessProbeUnderGate(t *testing.T) {
	ctx := context.Background()

	// GATE ON: the shared feed (fixture seeds host testHostID at applied_seq 0). Under the
	// gate the placer's step-9 probe reads that live seq from the SAME feed the candidate
	// source places against — a placement and its step-9 re-check agree on the host's seq.
	t.Setenv("DS_ORCH_LIVE", "1")
	live := newFixture(t, fixtureOpts{})
	if live.cp.Placer == nil {
		t.Fatal("Placer was not exposed on the assembled control plane")
	}
	if live.cp.Placer.Freshness == nil {
		t.Fatal("DS_ORCH_LIVE: placer.Freshness must be the live HostFreshness seam (window-close armed)")
	}
	// The live probe returns the host's CURRENT applied_seq (0, the seeded fresh heartbeat)
	// — a LIVE seq, NOT ErrFreshnessUnknown: the residual placement->step-9 window closes.
	seq, err := live.cp.Placer.CurrentFreshness(ctx, testHostID)
	if err != nil {
		t.Fatalf("DS_ORCH_LIVE CurrentFreshness(%s) = err %v, want the live seq (not ErrFreshnessUnknown)", testHostID, err)
	}
	if seq != 0 {
		t.Fatalf("DS_ORCH_LIVE CurrentFreshness(%s) = %d, want the seeded live applied_seq 0", testHostID, seq)
	}

	// GATE OFF: a host the live feed never saw still resolves via the live seam under the
	// gate, degrading to ErrFreshnessUnknown (host-named) — the recorded re-check fallback.
	if _, ferr := live.cp.Placer.CurrentFreshness(ctx, "host-never-seen"); !errors.Is(ferr, sessions.ErrFreshnessUnknown) {
		t.Fatalf("DS_ORCH_LIVE CurrentFreshness(absent host) = %v, want a wrap of sessions.ErrFreshnessUnknown", ferr)
	}

	// GATE OFF (no DS_ORCH_LIVE): the probe stays inert — Freshness nil, CurrentFreshness
	// returns ErrFreshnessUnknown, the coordinator degrades to the recorded re-check
	// (unchanged, backwards-compatible).
	t.Setenv("DS_ORCH_LIVE", "0")
	off := newFixture(t, fixtureOpts{})
	if off.cp.Placer.Freshness != nil {
		t.Fatal("gate off: placer.Freshness must stay nil (the step-9 live probe inert)")
	}
	if _, ferr := off.cp.Placer.CurrentFreshness(ctx, testHostID); !errors.Is(ferr, sessions.ErrFreshnessUnknown) {
		t.Fatalf("gate off: CurrentFreshness = %v, want sessions.ErrFreshnessUnknown (inert probe, unchanged)", ferr)
	}
}

// TestNewControlPlane_FreshnessResolvesViaO1Accessor pins the PRODUCTION freshness wiring at
// the NewControlPlane level: under DS_ORCH_LIVE the placer.Freshness NewControlPlane builds
// must resolve a placed host's CurrentAppliedSeq through the live *HeartbeatStore's O(1)
// host-keyed SnapshotForHost accessor (a map hit, heartbeatstore.go), NOT the O(fleet)
// hostSnapshotIndex bridge (the fleet walk over the candidate-feed LatestSnapshots read
// surface). orch27 added the O(1) SnapshotForHost accessor and routed the §4.1 step-9
// freshness consumer to it for a *HeartbeatStore feed (with the hostSnapshotIndex fleet-walk
// as the candidate-feed-only fallback); orch26 wired placer.Freshness into NewControlPlane
// under the gate. This pin asserts that the production wiring takes the O(1) path so a
// refactor that accidentally drops it (reverting to the fleet walk on the hot create path at
// the ~500-host virtual-metal density D37 (sizing); D34 (virtual-metal fidelity env) sizes
// for) fails here — it mirrors the orch27
// seam-level TestHeartbeatFreshness_ResolvesViaO1Accessor but at the NewControlPlane wiring
// level, asserting through the exposed cp.Placer.Freshness the production construction built.
// Test-only (wiring.go FROZEN — it asserts production behavior); D50 synthetic feed, D72/D34.
func TestNewControlPlane_FreshnessResolvesViaO1Accessor(t *testing.T) {
	ctx := context.Background()

	// GATE ON: NewControlPlane assigns placer.Freshness = NewHostFreshness(heartbeats), the
	// production HostFreshness over the live *HeartbeatStore feed the fixture wired (the SAME
	// latest-per-host feed StoreCandidateSource places against). The fixture seeds testHostID
	// at applied_seq 0.
	t.Setenv("DS_ORCH_LIVE", "1")
	f := newFixture(t, fixtureOpts{})

	if f.cp.Placer == nil {
		t.Fatal("Placer was not exposed on the assembled control plane")
	}
	if f.cp.Placer.Freshness == nil {
		t.Fatal("DS_ORCH_LIVE: placer.Freshness must be the live HostFreshness seam (window-close armed)")
	}

	// The production placer.Freshness is the concrete heartbeatFreshness NewControlPlane built
	// (NewHostFreshness returns it). Reach the unexported appliedSeqSource() it drives the
	// O(1) store.HostAppliedSeq point read over — the path the production consumer takes.
	probe, ok := f.cp.Placer.Freshness.(heartbeatFreshness)
	if !ok {
		t.Fatalf("placer.Freshness = %T, want the production heartbeatFreshness (NewHostFreshness over the live feed)", f.cp.Placer.Freshness)
	}
	src := probe.appliedSeqSource()

	// REJECT the fleet-walk bridge: the production source must NOT be the O(fleet)
	// hostSnapshotIndex (a refactor that drops the O(1) path would route through it).
	if _, isBridge := src.(hostSnapshotIndex); isBridge {
		t.Fatal("production placer.Freshness resolved to the O(fleet) hostSnapshotIndex bridge; want the live *HeartbeatStore's O(1) SnapshotForHost accessor (the create hot path must not fleet-walk at ~500-host density, D37 sizing; D34 virtual-metal fidelity env)")
	}
	// ASSERT the O(1) direct path: the source IS the live *HeartbeatStore (its SnapshotForHost
	// is a map hit, heartbeatstore.go), the same store value the fixture wired as the feed.
	hbStore, isStore := src.(*HeartbeatStore)
	if !isStore {
		t.Fatalf("production placer.Freshness appliedSeqSource = %T, want the live *HeartbeatStore (the O(1) host-keyed SnapshotForHost accessor)", src)
	}
	if hbStore != f.cp.Heartbeats {
		t.Fatal("production placer.Freshness resolves over a DIFFERENT *HeartbeatStore than cp.Heartbeats; the step-9 probe and the candidate placement must share one live feed (D72)")
	}

	// End to end through the production seam: the O(1) accessor returns the placed host's LIVE
	// applied_seq (0, the seeded fresh heartbeat) — the value the step-9 routable gate
	// re-validates against (D72), resolved by a map hit, not a fleet walk.
	seq, ferr := f.cp.Placer.CurrentFreshness(ctx, testHostID)
	if ferr != nil {
		t.Fatalf("production CurrentFreshness(%s) = err %v, want the live seq via the O(1) accessor", testHostID, ferr)
	}
	if seq != 0 {
		t.Fatalf("production CurrentFreshness(%s) = %d, want the seeded live applied_seq 0", testHostID, seq)
	}
}

// createdRecord drives a clean CreateSession through the fixture handler (so the store
// holds a host-bound record with a LINKED launching principal — the re-drive's premise,
// doc 16 §3.1) and returns the persisted record. The create places the session on
// testHostID (the single-host fixture posture); the production re-create resolves
// launching_user against this real store, so a clean create is the faithful seed.
func createdRecord(t *testing.T, f *fixture) store.Session {
	t.Helper()
	ctx := context.Background()
	resp, err := f.cp.Sessions.CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	rec, err := f.st.GetSession(ctx, resp.GetSession().GetSessionUuid())
	if err != nil {
		t.Fatalf("seed get session: %v", err)
	}
	if rec.Ref.HostID == "" {
		t.Fatalf("seeded record has no bound host (the re-drive needs one): %+v", rec.Ref)
	}
	return rec
}

// storeLinkedRecord seeds the store directly with a host-bound session whose launching
// principal is LINKED (session + principal + the launching link) — the re-drive's premise
// without a clean create (used by the unacked-digest case, where a clean create would
// refuse at the step-9 routable gate before a record is fit to re-drive). It returns the
// record bound to testHostID so the production re-create has a host target.
func storeLinkedRecord(t *testing.T, f *fixture, sessionUUID string) store.Session {
	t.Helper()
	ctx := context.Background()
	ref := store.SessionRef{SessionUUID: sessionUUID, HostID: testHostID, HostSessionIndex: 42}
	if _, err := f.st.CreateSession(ctx, store.Session{
		Ref:          ref,
		EnvConfigRef: testEnvRef,
		ImageID:      testImageID,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	p, err := f.st.CreatePrincipal(ctx, store.Principal{
		ID:         "prin-redrive-1",
		IdPSubject: testSubject,
		Org:        testOrg,
	})
	if err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	if err := f.st.SetSessionLaunchingPrincipal(ctx, sessionUUID, p.ID); err != nil {
		t.Fatalf("link launching principal: %v", err)
	}
	rec, err := f.st.GetSession(ctx, sessionUUID)
	if err != nil {
		t.Fatalf("seed get session: %v", err)
	}
	return rec
}

// depsWithStalenessBudget builds a fully-wired, valid Deps over the synthetic fakes with the
// given §4.1 step-9 D72 staleness budget — the PRODUCTION wiring path (NewControlPlane threads
// Deps.StalenessBudget into sessions.NewSessionCreator, wiring.go). It mirrors newFixture's
// dep bundle but lets the test set a NON-DEFAULT budget (newFixture hardcodes 0), so the pin
// exercises the threading rather than the construction default. D50 synthetic fixtures only.
func depsWithStalenessBudget(t *testing.T, budget int64) Deps {
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
	return Deps{
		Store:           cpStore{st},
		Drivers:         fakeRegistry{host: testHostID, drv: newDriverFake()},
		Heartbeats:      NewHeartbeatStore(clock),
		Mint:            &fakeMint{},
		Digest:          &fakeDigest{acked: true},
		Inject:          &fakeInject{},
		Boot:            &fakeBoot{},
		Revoke:          &fakeRevoke{},
		Enrollment:      fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:           sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		DefaultOrg:      testOrg,
		StalenessBudget: budget,
		Clock:           clock,
		ResyncInterval:  time.Hour,
	}
}

// TestNewControlPlane_ThreadsStalenessBudgetToSelfReport pins the PRODUCTION wiring of the
// §4.1 step-9 D72 staleness budget at the NewControlPlane level: building the control plane
// with a NON-DEFAULT Deps.StalenessBudget must thread that value through to the coordinator's
// resolved re-check window — NOT silently fall back to the construction default (0). wiring.go
// currently passes d.StalenessBudget as NewSessionCreator's budget argument; a future regression
// that drops that threading (e.g. hardcodes 0, or wires the wrong Deps field) would leave the
// coordinator's resolved budget at the default and is CAUGHT here.
//
// The unit-level test (sessions.TestStep9StalenessBudgetSelfReport_PublishesResolvedBudget)
// pins the self-report at the sessions.NewSessionCreator seam; this is the controlplane-level
// production-wiring analogue, asserting that NewControlPlane — not a hand-built coordinator —
// threaded the wired budget. The assertion reads the resolved budget INSTANCE-SCOPED off
// cp.Creator.ResolvedStalenessBudget() (the orch45 accessor, sessioncreate.go), the same
// non-racy read the wave-1 enforcement pin uses (sessionservice_test.go), NOT the SET-last-wins
// process-global orchestrator_sessions_step9_staleness_budget expvar — so the observation is
// THIS coordinator's resolved window and is unaffected by any other constructor in the run.
// Test-only (wiring.go FROZEN — it asserts production behavior); D50 synthetic fixtures, D72.
func TestNewControlPlane_ThreadsStalenessBudgetToSelfReport(t *testing.T) {
	// A distinctive non-default budget unlikely to collide with the construction default (0)
	// or any other test's wiring — so a resolved budget at the default unambiguously means the
	// threading was dropped (not coincidentally equal).
	const wantBudget = int64(4096)

	cp, err := NewControlPlane(depsWithStalenessBudget(t, wantBudget))
	if err != nil {
		t.Fatalf("NewControlPlane(StalenessBudget=%d): %v", wantBudget, err)
	}
	if cp.Creator == nil {
		t.Fatal("NewControlPlane did not expose the §4.1 coordinator (Creator) the budget threads into")
	}

	// The production wiring threaded Deps.StalenessBudget into NewSessionCreator, which resolved
	// it to the coordinator's re-check window. Reading it instance-scoped off THIS control plane's
	// Creator observes the budget THIS NewControlPlane wired — independent of any other constructor.
	if got := cp.Creator.ResolvedStalenessBudget(); got != wantBudget {
		t.Fatalf("cp.Creator.ResolvedStalenessBudget() = %d, want %d — NewControlPlane must thread Deps.StalenessBudget into NewSessionCreator (a fallback to the construction default means the wiring dropped it)", got, wantBudget)
	}
}

// TestNewControlPlane_StalenessBudgetSelfReportTracksWiredValue strengthens the threading pin:
// two NewControlPlane builds with DIFFERENT non-default budgets each resolve THEIR wired value
// on their own coordinator. A wiring that ignored Deps.StalenessBudget (always 0, or a constant)
// would resolve the same value for both builds; requiring each coordinator's resolved budget to
// TRACK the wired budget across distinct values rules out a coincidental match and proves the
// value flows from Deps through NewControlPlane into the coordinator. Read instance-scoped off
// each build's own cp.Creator.ResolvedStalenessBudget() (the orch45 accessor), NOT the racy
// SET-last-wins process-global expvar — so each assertion is keyed on ITS build's coordinator,
// not whichever constructor ran last. D50 synthetic fixtures, D72.
func TestNewControlPlane_StalenessBudgetSelfReportTracksWiredValue(t *testing.T) {
	for _, want := range []int64{17, 9001} {
		cp, err := NewControlPlane(depsWithStalenessBudget(t, want))
		if err != nil {
			t.Fatalf("NewControlPlane(StalenessBudget=%d): %v", want, err)
		}
		if cp.Creator == nil {
			t.Fatal("NewControlPlane did not expose the §4.1 coordinator (Creator) the budget threads into")
		}
		if got := cp.Creator.ResolvedStalenessBudget(); got != want {
			t.Fatalf("cp.Creator.ResolvedStalenessBudget() = %d, want %d — the resolved budget must TRACK the wired budget through NewControlPlane", got, want)
		}
	}
}
