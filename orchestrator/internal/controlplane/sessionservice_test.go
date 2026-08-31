package controlplane

// sessionservice_test.go drives the CreateSession RPC handler (leg a) against the
// synthetic fixtures (D50): the handler drives the §4.1 ten-step spine to READY/ATTACHED
// on a valid request, and rolls back cleanly on a seam failure (the §4.1 step-7 CA
// injection fail-closed). All seams are fakes — no live VM/host-agent/podman.

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestCreateSession_DrivesSpineToAttached proves the handler builds a CreateRequest from
// the frozen CreateSessionRequest (role_ref → the coordinator) and drives the §4.1
// ten-step sequence all the way to ATTACHED, returning the persisted record's wire
// projection. It asserts the host driver was driven (CloneFromImage + IssueAttachHandle),
// the identity/digest/boot seams ran, and the response carries the §3 ATTACHED state.
func TestCreateSession_DrivesSpineToAttached(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}
	sess := resp.GetSession()
	if sess == nil {
		t.Fatal("CreateSession: nil session in response")
	}

	// The spine reached ATTACHED (the §4.1 step-10 terminal of a clean create).
	if got := sess.GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("CreateSession: state = %v, want ATTACHED", got)
	}
	// The §4.1 step-4 binding the host driver returned is recorded on the response quartet.
	if sess.GetHostId() != testHostID {
		t.Errorf("host_id = %q, want %q", sess.GetHostId(), testHostID)
	}
	if sess.GetHostSessionIndex() != 7 || sess.GetTapName() != "dstap-7" {
		t.Errorf("binding = (index %d, tap %q), want (7, dstap-7)", sess.GetHostSessionIndex(), sess.GetTapName())
	}
	if sess.GetImageId() != testImageID {
		t.Errorf("image_id = %q, want %q (resolved from the env config)", sess.GetImageId(), testImageID)
	}
	// The pinned default role triple is recorded (doc 18 §7: every session carries role
	// fields; absent role_ref ⇒ default@<current>).
	if sess.GetPinnedRoleName() != "default" {
		t.Errorf("pinned_role_name = %q, want default", sess.GetPinnedRoleName())
	}

	// The host driver was driven: CloneFromImage (step 4) + IssueAttachHandle (step 10).
	if len(f.drv.CloneFromImageRecorded()) != 1 {
		t.Errorf("CloneFromImage calls = %d, want 1", len(f.drv.CloneFromImageRecorded()))
	}
	if len(f.drv.IssueAttachHandleRecorded()) != 1 {
		t.Errorf("IssueAttachHandle calls = %d, want 1", len(f.drv.IssueAttachHandleRecorded()))
	}
	// The identity/digest/boot seams ran (steps 5/6/8).
	if f.mint.calls != 1 || f.digest.calls != 1 || f.boot.calls != 1 {
		t.Errorf("seam calls: mint=%d digest=%d boot=%d, want 1 each", f.mint.calls, f.digest.calls, f.boot.calls)
	}
	// A clean create never destroys / revokes.
	if len(f.drv.DestroyRecorded()) != 0 || f.revoke.calls != 0 {
		t.Errorf("clean create rolled back: destroy=%d revoke=%d, want 0", len(f.drv.DestroyRecorded()), f.revoke.calls)
	}

	// The persisted record agrees with the wire projection (ATTACHED, bound to the host).
	rec, gerr := f.st.GetSession(context.Background(), sess.GetSessionUuid())
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.State != store.SessionAttached {
		t.Errorf("record state = %q, want ATTACHED", rec.State)
	}
}

// TestCreateSession_RollsBackOnInjectFailure proves a §4.1 step-7 CA-injection failure
// (fail-closed, D17/D29) drives the compensating rollback: the host destroy runs, the
// identity/CA is revoked, the record is finalized DESTROYED, and the handler maps the
// failure onto a FailedPrecondition status (the create aborted before boot).
func TestCreateSession_RollsBackOnInjectFailure(t *testing.T) {
	f := newFixture(t, fixtureOpts{injectErr: errInjectBoom})

	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatalf("CreateSession: expected an error on inject failure, got session %v", resp.GetSession())
	}
	// The handler mapped the fail-closed CA-injection onto FailedPrecondition.
	if st, _ := status.FromError(err); st.Code() != codes.FailedPrecondition {
		t.Fatalf("CreateSession error code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}

	// The compensating rollback drove the host destroy (NFT-6 order + overlay disposal)
	// and the identity/CA revocation (the §4.1 step-7 rollback note).
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("rollback host destroy calls = %d, want 1", len(f.drv.DestroyRecorded()))
	}
	if f.revoke.calls != 1 {
		t.Errorf("rollback revoke calls = %d, want 1", f.revoke.calls)
	}
	// Boot never ran (7 ≺ 8: the create aborted at injection, before boot).
	if f.boot.calls != 0 {
		t.Errorf("boot calls = %d on an inject failure, want 0 (the create aborts before boot)", f.boot.calls)
	}

	// The record was finalized DESTROYED + retained (D66), never left half-created.
	recs, lerr := f.st.ListSessions(context.Background(), store.SessionFilter{IncludeDestroyed: true})
	if lerr != nil {
		t.Fatalf("ListSessions: %v", lerr)
	}
	if len(recs) != 1 {
		t.Fatalf("records after rollback = %d, want 1 (retained, finalized)", len(recs))
	}
	if recs[0].State != store.SessionDestroyed {
		t.Errorf("rolled-back record state = %q, want DESTROYED", recs[0].State)
	}
}

// TestCreateSession_RefusesUnauthenticatedLaunch proves a create with no launching_user
// is refused fail-closed at the launch gate (doc 16 §11.2) and mapped to PermissionDenied,
// with NO host-side work (no clone, no mint).
func TestCreateSession_RefusesUnauthenticatedLaunch(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	req := validCreateReq()
	req.LaunchingUser = "" // unauthenticated launch

	_, err := f.cp.Sessions.CreateSession(context.Background(), req)
	if err == nil {
		t.Fatal("CreateSession: expected a refusal for an unauthenticated launch")
	}
	if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied {
		t.Fatalf("CreateSession error code = %v, want PermissionDenied; err=%v", st.Code(), err)
	}
	// No host-side work happened (the gate refuses BEFORE placement/clone/mint).
	if len(f.drv.CloneFromImageRecorded()) != 0 || f.mint.calls != 0 {
		t.Errorf("unauthenticated launch did host work: clone=%d mint=%d, want 0",
			len(f.drv.CloneFromImageRecorded()), f.mint.calls)
	}
}

// TestCreateSession_RefusesUnenrolledRepo proves the §4.1 step-1 two-key refusal (D56):
// a create against a repo that is not enrolled is refused (FailedPrecondition), no record.
func TestCreateSession_RefusesUnenrolledRepo(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	req := validCreateReq()
	req.RepoId = "repo-not-enrolled"

	_, err := f.cp.Sessions.CreateSession(context.Background(), req)
	if err == nil {
		t.Fatal("CreateSession: expected a two-key refusal for an unenrolled repo")
	}
	if st, _ := status.FromError(err); st.Code() != codes.FailedPrecondition {
		t.Fatalf("CreateSession error code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}
}

// TestCreateSession_TwoKeyReasonNotEnrolled proves the create-path refusal carries the
// MACHINE-READABLE not-enrolled reason on the wire (D56 first key absent): a create
// against an unenrolled repo refuses FailedPrecondition with reason=not-enrolled in the
// status message, and does NO host work (the gate refuses at step 1, before placement).
func TestCreateSession_TwoKeyReasonNotEnrolled(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	req := validCreateReq()
	req.RepoId = "repo-not-enrolled"

	_, err := f.cp.Sessions.CreateSession(context.Background(), req)
	if err == nil {
		t.Fatal("CreateSession: expected a two-key refusal for an unenrolled repo")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}
	if !strings.Contains(st.Message(), "reason=not-enrolled") {
		t.Errorf("status message must carry reason=not-enrolled, got %q", st.Message())
	}
	if len(f.drv.CloneFromImageRecorded()) != 0 || f.mint.calls != 0 {
		t.Errorf("a two-key refusal did host work: clone=%d mint=%d, want 0",
			len(f.drv.CloneFromImageRecorded()), f.mint.calls)
	}
}

// TestCreateSession_TwoKeyReasonNoEnvSpec proves the create-path refusal carries the
// MACHINE-READABLE no-env-spec reason on the wire (D56 second key absent): a create
// against an enrolled repo with no resolvable env spec refuses FailedPrecondition with
// reason=no-env-spec, and does NO host work.
func TestCreateSession_TwoKeyReasonNoEnvSpec(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	req := validCreateReq()
	req.EnvConfigRef = "env-does-not-exist" // enrolled repo, but the second key is absent.

	_, err := f.cp.Sessions.CreateSession(context.Background(), req)
	if err == nil {
		t.Fatal("CreateSession: expected a two-key refusal for a missing env spec")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}
	if !strings.Contains(st.Message(), "reason=no-env-spec") {
		t.Errorf("status message must carry reason=no-env-spec, got %q", st.Message())
	}
	if len(f.drv.CloneFromImageRecorded()) != 0 || f.mint.calls != 0 {
		t.Errorf("a two-key refusal did host work: clone=%d mint=%d, want 0",
			len(f.drv.CloneFromImageRecorded()), f.mint.calls)
	}
}

var errInjectBoom = errStub("controlplane test: CA injection boom")

// errStub is a tiny error type for synthetic seam faults.
type errStub string

func (e errStub) Error() string { return string(e) }

// --- §4.1 step-9 freshness FAULT-vs-DEGRADE asymmetry over the wire (D72/D77) -------

// step9FreshnessDegradeTotalName is the published name of the §4.1 step-9 freshness-degrade
// FLEET-TOTAL expvar (sessions.step9FreshnessDegradeTotal). The sessions package owns the
// counter (and its package-private read helper); this controlplane-side e2e reads the SAME
// process-global expvar.Int through the standard /debug/vars surface so it can assert,
// over the wire, that the degrade branch did or did NOT fire for a CreateSession — without
// importing a sessions-internal seam. It is the exact metric an operator graphs (D72).
const step9FreshnessDegradeTotalName = "orchestrator_sessions_step9_freshness_degrade_total"

// step9DegradeTotal reads the current §4.1 step-9 freshness-degrade fleet-total from the
// global expvar registry (the sessions package publishes it under
// step9FreshnessDegradeTotalName). The counter is a PROCESS-GLOBAL monotone total, so a
// test asserts a DELTA across one create (snapshot before, snapshot after), never an
// absolute — other tests in the run bump the same total.
func step9DegradeTotal(t *testing.T) int64 {
	t.Helper()
	v := expvar.Get(step9FreshnessDegradeTotalName)
	if v == nil {
		t.Fatalf("expvar %q is not published — the sessions step-9 degrade counter must be registered", step9FreshnessDegradeTotalName)
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		t.Fatalf("expvar %q = %T, want *expvar.Int (the §4.1 step-9 degrade fleet-total)", step9FreshnessDegradeTotalName, v)
	}
	return iv.Value()
}

// faultFreshness is the §4.1 step-9 LIVE-freshness probe fake driving the asymmetry under
// test (D50 synthetic fixtures — no live feed). It satisfies scheduler.HostFreshness, the
// optional seam the production scheduler.Adapter (cp.Placer) probes per re-check. The same
// adapter the SessionCreator drives as its step-3 Placer EXPOSES this Freshness field, so a
// test assigns one of these to cp.Placer.Freshness to make the LIVE re-check (b) FAULT or
// report the placed host ABSENT — exactly the two outcomes scheduler.CurrentFreshness routes
// apart on the ErrFreshnessUnknown sentinel (orch27 pinned this at the adapter, orch30 at the
// sessions layer; this pins it END-TO-END over the CreateSession RPC).
//
//   - err != nil  → the probe ERRORS (a transport/feed fault — the host's freshness could
//     NOT be determined). scheduler.CurrentFreshness wraps it NOT-as-ErrFreshnessUnknown, so
//     recheckFreshness HARD-FAILS (return err) — the create rolls back fail-closed (D72/D77),
//     never degrades to READY.
//   - err == nil, ok == false → the host is ABSENT from the live feed (a clean "no current
//     report"). scheduler.CurrentFreshness returns a host-named wrap of ErrFreshnessUnknown,
//     so recheckFreshness DEGRADES to the recorded re-check (bumps the degrade counter) and
//     proceeds — the backwards-compatible admission.
type faultFreshness struct {
	seq uint64
	ok  bool
	err error
}

func (f faultFreshness) CurrentAppliedSeq(_ context.Context, _ string) (uint64, bool, error) {
	return f.seq, f.ok, f.err
}

var errFreshnessProbeBoom = errStub("controlplane test: step-9 freshness probe transport fault")

// serveSessions stands up the production-wired SessionService on an in-memory bufconn gRPC
// server and returns a SessionService client dialing it over the wire (D50: NO live socket /
// port bind / host-agent). It is the over-the-wire harness the asymmetry tests drive — a
// CreateSession round-trips the registered handler through the real gRPC transport, not an
// in-process call. dialBufconn (serve_test.go, same package) supplies the no-socket dial.
func serveSessions(t *testing.T, cp *ControlPlane) orchestratorv1.SessionServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	cp.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return orchestratorv1.NewSessionServiceClient(dialBufconn(t, lis))
}

// TestCreateSession_OverWire_Step9FreshnessFaultFailsClosed pins the §4.1 step-9 D72/D77
// fault-vs-degrade ASYMMETRY END-TO-END over the CreateSession RPC (bufconn): a LIVE
// freshness PROBE FAULT (the placed host's current freshness could NOT be determined — a
// transport/feed error, NOT a clean "absent") routes through the real gRPC handler and must
// surface as a FAIL-CLOSED gRPC status — never a degrade-to-READY. orch27 pinned this at the
// scheduler.Adapter, orch30 at the sessions recheckFreshness; this pins it at the WIRE.
//
// The fault wires into the SAME production scheduler.Adapter the SessionCreator drives as its
// step-3 Placer (cp.Placer): assigning cp.Placer.Freshness a faulting HostFreshness makes the
// coordinator's step-9 LIVE re-check (b) error. The error is NOT ErrFreshnessUnknown, so
// recheckFreshness hard-fails (return err) → rollback from StepRoutable → a *CreateError with
// no sentinel class → mapCreateError's default → codes.Internal (a fail-closed status the
// client reads, NOT a READY/ATTACHED session). The degrade counter is NOT bumped (the fault
// is not an admission). The host-side teardown ran (fail-closed: no half-trusted VM left
// routable, D77) — the create aborted, never waved through.
func TestCreateSession_OverWire_Step9FreshnessFaultFailsClosed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// The LIVE step-9 probe FAULTS: the placed host's current freshness is undeterminable.
	// This is the production scheduler.Adapter the coordinator already drives for placement
	// (step 3) — its exported Freshness seam is what step-9 (b) probes (D72).
	f.cp.Placer.Freshness = faultFreshness{err: errFreshnessProbeBoom}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatalf("CreateSession over the wire: a step-9 freshness PROBE FAULT must fail closed, got session %v", resp.GetSession())
	}
	// The fault surfaced as a fail-closed gRPC status (NOT a READY/ATTACHED session). A
	// generic probe fault is not one of mapCreateError's attributable sentinel classes, so
	// it maps to Internal — the create aborted on an undeterminable host, never degraded.
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("CreateSession error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("step-9 freshness fault over the wire mapped to %v, want Internal (fail-closed); err=%v", st.Code(), err)
	}
	if st.Code() == codes.OK {
		t.Fatal("a step-9 freshness fault must NOT return OK (a degrade-to-READY) over the wire")
	}
	// No READY session leaked back on the wire — the response carries no usable session.
	if resp.GetSession() != nil {
		t.Fatalf("a faulting step-9 probe returned a session %v, want none (fail-closed, no READY)", resp.GetSession())
	}

	// The degrade counter was NOT bumped: a PROBE FAULT is a fail-closed refusal, NOT the
	// recorded-re-check DEGRADE an ABSENT host gets. This is the asymmetry's load-bearing
	// half — a fault must never be silently admitted via the degrade path (D72).
	if delta := step9DegradeTotal(t) - before; delta != 0 {
		t.Fatalf("step-9 degrade counter advanced by %d on a PROBE FAULT, want 0 (a fault fails closed, it does NOT degrade)", delta)
	}

	// Fail-closed teardown (D77): the create aborted before READY and rolled back — the host
	// destroy ran (no half-created VM left bound) and the minted identity/CA was revoked. No
	// READY/ATTACHED record survives.
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("rollback host destroy calls = %d, want 1 (fail-closed teardown of the aborted create)", len(f.drv.DestroyRecorded()))
	}
	if f.revoke.calls != 1 {
		t.Errorf("rollback revoke calls = %d, want 1 (the step-5 mint is revoked on the abort)", f.revoke.calls)
	}
	recs, lerr := f.st.ListSessions(context.Background(), store.SessionFilter{})
	if lerr != nil {
		t.Fatalf("ListSessions: %v", lerr)
	}
	for _, rec := range recs {
		if rec.State == store.SessionReady || rec.State == store.SessionAttached {
			t.Fatalf("a faulting step-9 probe left a routable record (state %q), want none (fail-closed)", rec.State)
		}
	}
}

// TestCreateSession_OverWire_Step9HostAbsentDegradesAndProceeds is the ASYMMETRY's other
// half over the wire: a placed host that is ABSENT from the live freshness feed (a clean
// "no current report", NOT a probe fault) DEGRADES to the recorded re-check and PROCEEDS —
// the create reaches ATTACHED over the wire and the degrade counter IS bumped (the
// residual-D72-window admission is observable). Side by side with the fault case above this
// LOCKS the asymmetry at the RPC boundary: a fault fails closed (no degrade), an absent host
// degrades and proceeds (D72).
func TestCreateSession_OverWire_Step9HostAbsentDegradesAndProceeds(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// The LIVE step-9 probe answers cleanly that the placed host has NO current report
	// (ok == false, no error) — the host vanished from the live feed. scheduler.Adapter
	// surfaces this as a host-named ErrFreshnessUnknown, the degrade sentinel.
	f.cp.Placer.Freshness = faultFreshness{ok: false}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over the wire: an ABSENT host must DEGRADE and proceed, got error: %v", err)
	}
	// The create proceeded to ATTACHED on the recorded re-check (the §4.1 step-10 terminal):
	// an unprobeable host is admitted via the recorded freshness, NOT refused (D72).
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("over-the-wire create with an absent step-9 host state = %v, want ATTACHED (degrade-and-proceed)", got)
	}

	// The degrade counter advanced by exactly one: the recorded-re-check admission is the
	// observable residual-D72-window event an operator graphs. This is the OPPOSITE of the
	// fault case, which did NOT bump it — the asymmetry, pinned over the wire.
	if delta := step9DegradeTotal(t) - before; delta != 1 {
		t.Fatalf("step-9 degrade counter advanced by %d on an ABSENT host, want 1 (degrade-and-proceed)", delta)
	}

	// A clean degrade-and-proceed never tore the create down (no rollback): the host was
	// admitted, not refused.
	if len(f.drv.DestroyRecorded()) != 0 || f.revoke.calls != 0 {
		t.Errorf("degrade-and-proceed rolled back: destroy=%d revoke=%d, want 0 (the create proceeded)",
			len(f.drv.DestroyRecorded()), f.revoke.calls)
	}
}

// TestCreateSession_OverWire_Step9HostFellBehindFailsPrecondition is the THIRD step-9 live
// outcome over the wire, and the one that pins the SECOND asymmetry: a placed host that is
// PRESENT in the live freshness feed (a clean, error-free current report) but whose CURRENT
// applied_seq has FALLEN BEHIND the placement seq beyond the staleness budget. This is NOT a
// probe fault (the feed answered cleanly) and NOT an absent host (the host reports), so it is
// neither the fail-closed Internal of the fault case nor the degrade-and-proceed of the absent
// case: recheckFreshness's live (b) branch reads a present-but-lower seq, computes a positive
// drift past the budget, and fail-closes as sessions.ErrPolicyStale (NOT the ErrFreshnessUnknown
// degrade sentinel). mapCreateError routes ErrPolicyStale to codes.FailedPrecondition (the host
// is not placement-fresh; a retry may land elsewhere) — DISTINCT from the fault path's
// Internal. orch27/orch30 pinned the policy-stale class at the adapter / sessions layer; this
// pins the present-but-stale fell-behind catch END-TO-END over the CreateSession RPC (D72/D77).
//
// Setup: the budget is 0 (newFixture's StalenessBudget) so the host must be EXACTLY current.
// Re-record the placement candidate's heartbeat at applied_seq 5 (ahead of the empty-log policy
// head 0, so the §7 staleness filter still PLACES it — a host ahead of the reference is never
// penalized), making placement record AppliedSeq 5 (and the record's PolicyAppliedSeq 5, so the
// recorded re-check (a) passes with drift 0). The live probe then reports the host PRESENT
// (ok == true, no error) at a CURRENT seq of 3 — fell behind by 2 > budget 0 — so the live (b)
// re-check fail-closes as ErrPolicyStale.
func TestCreateSession_OverWire_Step9HostFellBehindFailsPrecondition(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// Place against applied_seq 5 (ahead of the empty-log head, so it places; the record's
	// PolicyAppliedSeq becomes 5, so the recorded re-check (a) passes with drift 0).
	f.cp.Heartbeats.Record(freshHeartbeat(testHostID, 5, 1))
	// The LIVE step-9 probe answers cleanly that the placed host is PRESENT (ok == true, no
	// error) but its CURRENT applied_seq is 3 — fallen behind placement seq 5 by 2 > budget 0.
	// This is a real present-but-stale report (the window-closing catch), NOT ErrFreshnessUnknown.
	f.cp.Placer.Freshness = faultFreshness{seq: 3, ok: true}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatalf("CreateSession over the wire: a present-but-stale (fell-behind) step-9 host must fail closed, got session %v", resp.GetSession())
	}
	// The fell-behind drift surfaced as ErrPolicyStale → FailedPrecondition (the host is not
	// placement-fresh), DISTINCT from the fault case's Internal: a present host that fell behind
	// is an attributable host-posture refusal, not an undeterminable-freshness fault (D72).
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("CreateSession error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("step-9 fell-behind over the wire mapped to %v, want FailedPrecondition (host policy stale, D72); err=%v", st.Code(), err)
	}
	// No READY session leaked back on the wire — the response carries no usable session.
	if resp.GetSession() != nil {
		t.Fatalf("a fell-behind step-9 host returned a session %v, want none (fail-closed, no READY)", resp.GetSession())
	}

	// The degrade counter was NOT bumped: a present-but-stale host is a fail-closed REFUSAL
	// (ErrPolicyStale), NOT the recorded-re-check DEGRADE an ABSENT (ErrFreshnessUnknown) host
	// gets. Only an UNPROBEABLE host degrades; a host that answered with a fell-behind seq is
	// refused. This is the load-bearing distinction from the absent case (D72).
	if delta := step9DegradeTotal(t) - before; delta != 0 {
		t.Fatalf("step-9 degrade counter advanced by %d on a present-but-stale host, want 0 (a fell-behind host fails closed, it does NOT degrade)", delta)
	}

	// Fail-closed teardown (D77): the create reached the routable gate (steps 4-8 ran) then
	// rolled back on the stale re-check — the host destroy ran (no half-trusted VM left bound)
	// and the minted identity/CA was revoked. No READY/ATTACHED record survives.
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("rollback host destroy calls = %d, want 1 (fail-closed teardown of the fell-behind create)", len(f.drv.DestroyRecorded()))
	}
	if f.revoke.calls != 1 {
		t.Errorf("rollback revoke calls = %d, want 1 (the step-5 mint is revoked on the abort)", f.revoke.calls)
	}
	recs, lerr := f.st.ListSessions(context.Background(), store.SessionFilter{})
	if lerr != nil {
		t.Fatalf("ListSessions: %v", lerr)
	}
	for _, rec := range recs {
		if rec.State == store.SessionReady || rec.State == store.SessionAttached {
			t.Fatalf("a fell-behind step-9 host left a routable record (state %q), want none (fail-closed)", rec.State)
		}
	}
}

// TestCreateSession_OverWire_Step9FaultAndAbsentRouteApart asserts the two outcomes SIDE BY
// SIDE through the SAME over-the-wire harness, so the asymmetry is locked as a single fact:
// the only difference between the requests is whether the placed host's step-9 freshness
// probe FAULTS (undeterminable) or reports the host ABSENT (clean no-report), and that single
// difference flips the RPC outcome from a fail-closed status (no degrade) to a degrade-and-
// proceed ATTACHED (counter bumped). A regression that collapsed a fault into the absent-
// degrade path (or vice versa) breaks exactly here (D72/D77).
func TestCreateSession_OverWire_Step9FaultAndAbsentRouteApart(t *testing.T) {
	// FAULT branch: undeterminable freshness → fail-closed, no degrade.
	ff := newFixture(t, fixtureOpts{})
	ff.cp.Placer.Freshness = faultFreshness{err: errFreshnessProbeBoom}
	faultClient := serveSessions(t, ff.cp)
	faultBefore := step9DegradeTotal(t)
	_, faultErr := faultClient.CreateSession(context.Background(), validCreateReq())
	faultDegrade := step9DegradeTotal(t) - faultBefore

	// ABSENT branch: clean no-report → degrade-and-proceed.
	af := newFixture(t, fixtureOpts{})
	af.cp.Placer.Freshness = faultFreshness{ok: false}
	absentClient := serveSessions(t, af.cp)
	absentBefore := step9DegradeTotal(t)
	absentResp, absentErr := absentClient.CreateSession(context.Background(), validCreateReq())
	absentDegrade := step9DegradeTotal(t) - absentBefore

	// The error OUTCOMES route apart: a fault fails closed, an absent host succeeds.
	if faultErr == nil {
		t.Fatal("FAULT branch: a step-9 probe fault must fail closed over the wire, got nil error")
	}
	if absentErr != nil {
		t.Fatalf("ABSENT branch: an absent step-9 host must degrade-and-proceed, got error: %v", absentErr)
	}
	if errors.Is(absentErr, faultErr) {
		t.Fatal("FAULT and ABSENT collapsed to the same outcome — the asymmetry regressed")
	}
	// The fail-closed branch is a real gRPC status (Internal), the absent branch reached READY.
	if st, _ := status.FromError(faultErr); st.Code() != codes.Internal {
		t.Fatalf("FAULT branch code = %v, want Internal (fail-closed)", st.Code())
	}
	if got := absentResp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("ABSENT branch state = %v, want ATTACHED (degrade-and-proceed)", got)
	}

	// The DEGRADE-counter outcomes route apart too: the fault did NOT bump it, the absent
	// host did (exactly once) — the asymmetry's metric half, side by side.
	if faultDegrade != 0 {
		t.Fatalf("FAULT branch bumped the degrade counter by %d, want 0 (a fault fails closed)", faultDegrade)
	}
	if absentDegrade != 1 {
		t.Fatalf("ABSENT branch bumped the degrade counter by %d, want 1 (degrade-and-proceed)", absentDegrade)
	}
}

// newFixtureBudget builds a fixture identical to newFixture but with a NON-ZERO §4.1
// step-9 staleness budget (Deps.StalenessBudget), the only knob fixtureOpts does not
// carry. newFixture hardcodes StalenessBudget 0 (the strictest budget — an EXACT
// applied_seq match is required), which pins the budget==0 boundary; the in-budget
// ADMITS case below needs a host that has fallen behind by a positive drift that the
// budget still TOLERATES, so it must construct the control plane with a budget > 0.
// The budget is sealed into the SessionCreator at construction (an unexported field,
// no setter, clamped negatives→0), so it can only be set through NewControlPlane —
// this helper wires the SAME synthetic seams/fakes newFixture does, changing only the
// budget, so the over-the-wire harness and assertions stay identical to the sibling
// cases (D50: no live VM/host-agent/podman; the budget is the lone variable under test).
func newFixtureBudget(t *testing.T, budget int64) *fixture {
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

	drv := newDriverFake()
	mint := &fakeMint{}
	digest := &fakeDigest{acked: true}
	inject := &fakeInject{}
	boot := &fakeBoot{}
	revoke := &fakeRevoke{}

	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))

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
		DefaultOrg:      testOrg,
		StalenessBudget: budget,
		Clock:           clock,
		ResyncInterval:  time.Hour,
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

	return &fixture{cp: cp, st: st, drv: drv, mint: mint, digest: digest, inject: inject, boot: boot, revoke: revoke, clock: clock}
}

// TestCreateSession_OverWire_Step9HostFellBehindWithinBudgetAdmits is the COMPLEMENT of
// TestCreateSession_OverWire_Step9HostFellBehindFailsPrecondition: it pins the OTHER side
// of the §4.1 step-9 D72 budget-comparison boundary over the wire. The fell-behind case
// above runs with budget 0 (drift 2 > 0 ⇒ ErrPolicyStale ⇒ FailedPrecondition); this case
// runs with a NON-ZERO budget and a positive drift that the budget STILL TOLERATES
// (drift ≤ budget), so recheckFreshness's live (b) branch does NOT fail-close — the host is
// present-but-slightly-behind yet WITHIN the routable window, so the create ADMITS and
// reaches ATTACHED over the wire. Side by side the two cases lock the comparison's STRICT
// boundary (`drift > budget`): a future off-by-one that flipped the test to `drift >= budget`
// would either wave through the beyond-budget case (the sibling catches it) OR refuse this
// at-budget case (THIS catches it). The recorded re-check (a) is unaffected — placement
// records PolicyAppliedSeq == placement seq, so (a) is always drift 0; only the live (b)
// branch governs (D72/D77).
//
// Setup: budget 3 (non-zero). Re-record the placement candidate's heartbeat at applied_seq 5
// (ahead of the empty-log policy head 0, so the §7 staleness filter still PLACES it — a host
// ahead of the reference is never penalized), making placement AppliedSeq 5 (and the record's
// PolicyAppliedSeq 5, so the recorded re-check (a) passes with drift 0). The live probe then
// reports the host PRESENT (ok == true, no error) at a CURRENT seq of 2 — fallen behind by 3,
// EXACTLY the budget (drift 3 ≤ budget 3) — so the live (b) re-check ADMITS, not refuses. This
// hits the at-budget boundary, not merely an interior point, so the strict-vs-non-strict
// comparison is locked.
func TestCreateSession_OverWire_Step9HostFellBehindWithinBudgetAdmits(t *testing.T) {
	const budget int64 = 3
	f := newFixtureBudget(t, budget)
	// Place against applied_seq 5 (ahead of the empty-log head, so it places; the record's
	// PolicyAppliedSeq becomes 5, so the recorded re-check (a) passes with drift 0).
	f.cp.Heartbeats.Record(freshHeartbeat(testHostID, 5, 1))
	// The LIVE step-9 probe answers cleanly that the placed host is PRESENT (ok == true, no
	// error) but its CURRENT applied_seq is 2 — fallen behind placement seq 5 by EXACTLY 3,
	// the budget. drift 3 ≤ budget 3, so the live (b) re-check does NOT fail-close: the host
	// is present-but-behind yet still within the routable window (the at-budget boundary).
	f.cp.Placer.Freshness = faultFreshness{seq: 2, ok: true}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over the wire: a fell-behind host WITHIN the non-zero budget (drift %d ≤ budget %d) must ADMIT, got error: %v", budget, budget, err)
	}
	// The create proceeded to ATTACHED (the §4.1 step-10 terminal): a host that fell behind
	// but stayed within the budget is admitted, NOT refused — the in-budget side of the
	// boundary the beyond-budget sibling refuses (D72).
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("over-the-wire create with an in-budget fell-behind step-9 host state = %v, want ATTACHED (admit)", got)
	}

	// The degrade counter was NOT bumped: an in-budget ADMIT is a clean live (b) PASS, not the
	// recorded-re-check DEGRADE an ABSENT (ErrFreshnessUnknown) host gets. A present host that
	// answered with an in-budget seq is admitted on the LIVE re-check itself — the live window
	// closed cleanly, it did not degrade to the recorded re-check (D72).
	if delta := step9DegradeTotal(t) - before; delta != 0 {
		t.Fatalf("step-9 degrade counter advanced by %d on an in-budget ADMIT, want 0 (a clean live re-check pass does NOT degrade)", delta)
	}

	// A clean in-budget admit never tore the create down (no rollback): the host was admitted
	// on the routable gate, not refused — DISTINCT from the beyond-budget sibling, which rolls
	// back fail-closed (D77).
	if len(f.drv.DestroyRecorded()) != 0 || f.revoke.calls != 0 {
		t.Errorf("in-budget admit rolled back: destroy=%d revoke=%d, want 0 (the create proceeded)",
			len(f.drv.DestroyRecorded()), f.revoke.calls)
	}
}

// TestCreateSession_OverWire_Step9HostFellBehindWithinBudgetInteriorAdmits documents the
// INTERIOR of the §4.1 step-9 D72 admit window — a host whose drift is STRICTLY LESS than a
// non-zero budget (drift 1 < budget 3), not the at-budget boundary the AtBudget sibling pins.
// The AtBudget case proves drift == budget admits (the inclusive `drift > budget` boundary);
// THIS case proves a drift well inside the window admits too, guarding against a regression
// that narrowed the comparison to an EXACT match (drift == budget only) while still passing
// the at-budget boundary by accident — an interior point would then be wrongly refused, and
// this catches it. Together the interior + at-budget cases bracket the inclusive routable
// window from inside, while the beyond-budget sibling pins it from outside (D72/D77).
//
// Setup: budget 3 (non-zero). Re-record the placement candidate's heartbeat at applied_seq 5
// (ahead of the empty-log policy head 0, so the §7 staleness filter still PLACES it), making
// placement AppliedSeq 5 (and the record's PolicyAppliedSeq 5, so the recorded re-check (a)
// passes with drift 0). The live probe then reports the host PRESENT (ok == true, no error)
// at a CURRENT seq of 4 — fallen behind by 1, STRICTLY INSIDE the budget (drift 1 < budget 3)
// — so the live (b) re-check ADMITS on a clean interior pass.
func TestCreateSession_OverWire_Step9HostFellBehindWithinBudgetInteriorAdmits(t *testing.T) {
	const budget int64 = 3
	f := newFixtureBudget(t, budget)
	// Place against applied_seq 5 (ahead of the empty-log head, so it places; the record's
	// PolicyAppliedSeq becomes 5, so the recorded re-check (a) passes with drift 0).
	f.cp.Heartbeats.Record(freshHeartbeat(testHostID, 5, 1))
	// The LIVE step-9 probe answers cleanly that the placed host is PRESENT (ok == true, no
	// error) but its CURRENT applied_seq is 4 — fallen behind placement seq 5 by 1, STRICTLY
	// inside the budget (drift 1 < budget 3) — the interior of the admit window, not its edge.
	f.cp.Placer.Freshness = faultFreshness{seq: 4, ok: true}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over the wire: a fell-behind host INSIDE the non-zero budget (drift 1 < budget %d) must ADMIT, got error: %v", budget, err)
	}
	// The create proceeded to ATTACHED: an interior-of-window host is admitted on the live (b)
	// re-check, NOT refused (D72) — the same admit verdict as the at-budget edge, from inside.
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("over-the-wire create with an interior-of-budget fell-behind step-9 host state = %v, want ATTACHED (admit)", got)
	}
	// The degrade counter was NOT bumped: an interior ADMIT is a clean live (b) PASS, not a
	// degrade — the live window closed cleanly (D72).
	if delta := step9DegradeTotal(t) - before; delta != 0 {
		t.Fatalf("step-9 degrade counter advanced by %d on an interior ADMIT, want 0 (a clean live re-check pass does NOT degrade)", delta)
	}
	// A clean interior admit never tore the create down (no rollback).
	if len(f.drv.DestroyRecorded()) != 0 || f.revoke.calls != 0 {
		t.Errorf("interior admit rolled back: destroy=%d revoke=%d, want 0 (the create proceeded)",
			len(f.drv.DestroyRecorded()), f.revoke.calls)
	}
}

// TestCreateSession_OverWire_Step9EnforcesWiredBudgetNotJustPublishes is the ENFORCEMENT pin
// (the gap the self-report-expvar publication tests CANNOT close). The wiring/self-report tests
// (TestNewControlPlane_ThreadsStalenessBudgetToSelfReport et al.) prove the wired budget reaches
// the PUBLISHED orchestrator_sessions_step9_staleness_budget expvar — that the operator-visible
// value tracks Deps.StalenessBudget. They do NOT prove the wired window is the one the §4.1
// step-9 routable RE-CHECK actually ENFORCES end to end. A coordinator could publish the right
// budget to the expvar yet enforce a different (or hardcoded) window in recheckFreshness, and
// every publication test would still pass. THIS test closes that gap over the CreateSession
// wire: with a NON-DEFAULT budget, a host placed JUST-OUTSIDE it (drift == budget+1, the first
// drift the window must refuse) drives a real RPC and MUST be rejected as codes.FailedPrecondition
// (ErrPolicyStale → the ENFORCED window), proving the budget the operator wired is the budget the
// step-9 gate enforces — not merely the budget it advertises.
//
// It reads the ENFORCED window through the NEW instance-scoped sessions.SessionCreator.
// ResolvedStalenessBudget() accessor (off cp.Creator), NOT the SET-last-wins process-global
// expvar: an instance-scoped, non-racy observation of THIS coordinator's resolved budget, so the
// assertion is about the window THIS create enforces, distinct from (and complementary to) the
// expvar publication the wiring tests pin.
//
// Setup: budget 2 (non-default). Re-record the placement candidate's heartbeat at applied_seq 5
// (ahead of the empty-log policy head 0, so the §7 staleness filter still PLACES it), making
// placement AppliedSeq 5 (and the record's PolicyAppliedSeq 5, so the recorded re-check (a)
// passes with drift 0). The live probe then reports the host PRESENT (ok == true, no error) at a
// CURRENT seq of 2 — fallen behind by 3 == budget 2 + 1, the FIRST drift JUST OUTSIDE the wired
// window (drift 3 > budget 2) — so the live (b) re-check fail-closes as ErrPolicyStale.
func TestCreateSession_OverWire_Step9EnforcesWiredBudgetNotJustPublishes(t *testing.T) {
	const budget int64 = 2
	f := newFixtureBudget(t, budget)

	// The ENFORCED window is THIS coordinator's resolved budget, read instance-scoped off
	// cp.Creator (not the racy SET-last-wins process-global expvar). Pin it equals the wired
	// budget BEFORE driving the create, so the FailedPrecondition below is provably keyed on
	// the budget+1 drift against the ENFORCED window — not a coincidental refusal.
	if got := f.cp.Creator.ResolvedStalenessBudget(); got != budget {
		t.Fatalf("ResolvedStalenessBudget() = %d, want the wired %d (the ENFORCED step-9 window — distinct from the published self-report expvar)", got, budget)
	}

	// Place against applied_seq 5 (ahead of the empty-log head, so it places; the record's
	// PolicyAppliedSeq becomes 5, so the recorded re-check (a) passes with drift 0).
	f.cp.Heartbeats.Record(freshHeartbeat(testHostID, 5, 1))
	// The LIVE step-9 probe answers cleanly that the placed host is PRESENT (ok == true, no
	// error) but its CURRENT applied_seq is 2 — fallen behind placement seq 5 by 3 == budget+1,
	// the FIRST drift JUST OUTSIDE the wired window (drift 3 > budget 2). The live (b) re-check
	// must fail-close as ErrPolicyStale: the enforced window refuses the budget+1 drift.
	outsideSeq := uint64(5) - uint64(budget) - 1 // 5 - 2 - 1 = 2; drift = 5 - 2 = 3 = budget+1
	f.cp.Placer.Freshness = faultFreshness{seq: outsideSeq, ok: true}

	client := serveSessions(t, f.cp)
	before := step9DegradeTotal(t)

	resp, err := client.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatalf("CreateSession over the wire: a host just-outside the wired budget (drift %d > budget %d) must be REJECTED by the ENFORCED window, got session %v", budget+1, budget, resp.GetSession())
	}
	// The just-outside-budget drift surfaced as ErrPolicyStale → FailedPrecondition: the budget
	// the operator WIRED is the budget the step-9 gate ENFORCES over the wire, not merely the
	// value PUBLISHED to the self-report expvar. A wiring that published the budget but enforced
	// a wider (or hardcoded) window would ADMIT here and this would fail (D72/D77).
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("CreateSession error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("just-outside-budget over the wire mapped to %v, want FailedPrecondition (the ENFORCED window refuses, D72); err=%v", st.Code(), err)
	}
	// No READY session leaked back on the wire — the enforced window refused, nothing usable.
	if resp.GetSession() != nil {
		t.Fatalf("a just-outside-budget host returned a session %v, want none (fail-closed, the enforced window refused)", resp.GetSession())
	}

	// The degrade counter was NOT bumped: a present-but-stale (just-outside-budget) host is a
	// fail-closed REFUSAL (ErrPolicyStale), NOT the recorded-re-check degrade an ABSENT host
	// gets — the same asymmetry the budget-0 fell-behind sibling pins, now keyed to a NON-DEFAULT
	// enforced window (D72).
	if delta := step9DegradeTotal(t) - before; delta != 0 {
		t.Fatalf("step-9 degrade counter advanced by %d on a just-outside-budget refusal, want 0 (the enforced window fails closed, it does NOT degrade)", delta)
	}

	// Fail-closed teardown (D77): the create reached the routable gate (steps 4-8 ran) then
	// rolled back on the enforced-window re-check — the host destroy ran (no half-trusted VM left
	// bound) and the minted identity/CA was revoked. No READY/ATTACHED record survives.
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("rollback host destroy calls = %d, want 1 (fail-closed teardown of the just-outside-budget create)", len(f.drv.DestroyRecorded()))
	}
	if f.revoke.calls != 1 {
		t.Errorf("rollback revoke calls = %d, want 1 (the step-5 mint is revoked on the abort)", f.revoke.calls)
	}
	recs, lerr := f.st.ListSessions(context.Background(), store.SessionFilter{})
	if lerr != nil {
		t.Fatalf("ListSessions: %v", lerr)
	}
	for _, rec := range recs {
		if rec.State == store.SessionReady || rec.State == store.SessionAttached {
			t.Fatalf("a just-outside-budget host left a routable record (state %q), want none (fail-closed, the enforced window refused)", rec.State)
		}
	}
}

// ---------------------------------------------------------------------------
// DestroySession (leg: the public §4.2 teardown surface). These pin that an
// operator tears a session down over the PUBLIC orchestrator.v1 handler (doc 15
// §4.2/§5.3) — the record flips desired=DESTROYING, the host-owned §4.2 ordering
// runs through the sessions.HostDestroyer seam, the retained record is finalized
// DESTROYED (D35/D72; doc 06 §3b clean-teardown). All seams are fakes (D50).
// ---------------------------------------------------------------------------

// recordingHostAgentDestroyer is a recording controlplane.HostAgentDestroyer (the
// in-process host-agent §4.2 orchestrator seam) for the single-binary posture: it
// captures every DestroyRequest the in-process adapter resolves + drives, so a test
// asserts the public DestroySession (and the create rollback) reached the IN-PROCESS
// §4.2 teardown with the record-resolved host-side state — no remote driver verb.
type recordingHostAgentDestroyer struct {
	mu       sync.Mutex
	requests []hostagent.DestroyRequest
}

func (r *recordingHostAgentDestroyer) Destroy(_ context.Context, req hostagent.DestroyRequest) (hostagent.DestroyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return hostagent.DestroyResult{DigestsFlushed: true, IdentityRevoked: true, Reported: true}, nil
}

func (r *recordingHostAgentDestroyer) recorded() []hostagent.DestroyRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]hostagent.DestroyRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

// newInProcDestroyFixture wires a ControlPlane whose §4.2 destroy seam is the
// IN-PROCESS adapter over a recording host-agent destroyer (Deps.HostAgent set, the
// orchestrator-lite single-binary posture, D80) — the SAME synthetic create seams
// newFixture wires, plus the in-process destroyer. It returns the fixture and the
// recorder so a test asserts the public DestroySession drove the in-process teardown.
func newInProcDestroyFixture(t *testing.T) (*fixture, *recordingHostAgentDestroyer) {
	t.Helper()

	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := store.NewMemoryClock(clock)
	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref: testEnvRef, RepoRef: testRepoID, ImageID: testImageID,
	}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}

	drv := newDriverFake()
	mint := &fakeMint{}
	digest := &fakeDigest{acked: true}
	inject := &fakeInject{}
	boot := &fakeBoot{}
	revoke := &fakeRevoke{}
	recorder := &recordingHostAgentDestroyer{}

	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))

	cp, err := NewControlPlane(Deps{
		Store:          cpStore{st},
		Drivers:        fakeRegistry{host: testHostID, drv: drv},
		HostAgent:      recorder, // wire the in-process §4.2 destroyer (single-binary posture)
		Heartbeats:     heartbeats,
		Mint:           mint,
		Digest:         digest,
		Inject:         inject,
		Boot:           boot,
		Revoke:         revoke,
		Enrollment:     fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:          sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		DefaultOrg:     testOrg,
		Clock:          clock,
		ResyncInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	var n int
	cp.Sessions.SetSessionUUIDGen(func() string {
		n++
		return "sess-" + time.Unix(int64(n), 0).UTC().Format("0405")
	})

	return &fixture{cp: cp, st: st, drv: drv, mint: mint, digest: digest, inject: inject, boot: boot, revoke: revoke, clock: clock}, recorder
}

// TestDestroySession_PublicSurface_DrivesTeardownToDestroyed proves the public
// DestroySession handler tears an ATTACHED session down through the §4.2 ordering: the
// record flips DESTROYING then is finalized DESTROYED (retained, D66) with DestroyedAt,
// and the host-owned teardown seam (here the remote driver verb, HostAgent nil) ran.
func TestDestroySession_PublicSurface_DrivesTeardownToDestroyed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	resp, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	if err != nil {
		t.Fatalf("DestroySession: unexpected error: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Fatalf("DestroySession: state = %v, want DESTROYED", got)
	}

	// The §4.2 teardown ran through the host seam (the remote driver verb, HostAgent nil).
	if len(f.drv.DestroyRecorded()) != 1 {
		t.Errorf("host destroy calls = %d, want 1 (the §4.2 teardown drove the host seam)", len(f.drv.DestroyRecorded()))
	}

	// The retained record (D66) is finalized DESTROYED with the teardown timestamp.
	rec, gerr := f.st.GetSession(context.Background(), uuid)
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.State != store.SessionDestroyed {
		t.Errorf("record state = %q, want DESTROYED", rec.State)
	}
	if rec.DestroyedAt == nil {
		t.Error("record DestroyedAt = nil, want the §4.2 step-6 teardown timestamp")
	}
}

// TestDestroySession_InProcess_ResolvesRecordedStateAndDrivesAdapter proves the
// single-binary posture (Deps.HostAgent set): the public DestroySession drives the
// IN-PROCESS §4.2 adapter (no remote driver verb), and the adapter resolves the recorded
// host-side state (the bound host + the current-epoch binding) from the session record.
func TestDestroySession_InProcess_ResolvesRecordedStateAndDrivesAdapter(t *testing.T) {
	f, recorder := newInProcDestroyFixture(t)

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	resp, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	if err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Fatalf("DestroySession: state = %v, want DESTROYED", got)
	}

	// The IN-PROCESS adapter drove the teardown — NOT the remote driver verb.
	if n := len(f.drv.DestroyRecorded()); n != 0 {
		t.Errorf("remote driver destroy calls = %d, want 0 (the in-process adapter owns the §4.2 teardown)", n)
	}
	got := recorder.recorded()
	if len(got) != 1 {
		t.Fatalf("in-process §4.2 destroyer calls = %d, want 1", len(got))
	}
	req := got[0]
	if req.SessionUUID != uuid {
		t.Errorf("in-process destroy session_uuid = %q, want %q", req.SessionUUID, uuid)
	}
	if req.HostID != testHostID {
		t.Errorf("in-process destroy host = %q, want %q (the record's bound host)", req.HostID, testHostID)
	}
	// The recorded host-side binding was resolved from the §5.6 record (the create's
	// step-4 binding: index 7 / dstap-7, per the driver fake's CloneFromImage).
	if !req.HasBinding {
		t.Error("in-process destroy HasBinding = false, want true (the create recorded a host binding)")
	}
	if req.Binding.HostSessionIndex != 7 || req.Binding.TapName != "dstap-7" {
		t.Errorf("resolved binding = (index %d, tap %q), want (7, dstap-7)", req.Binding.HostSessionIndex, req.Binding.TapName)
	}
}

// TestDestroySession_InProcess_RollbackUsesAdapter proves the in-process §4.2 destroyer is
// ALSO the create coordinator's compensating-rollback seam (the two armed-but-not-wired
// capstones converge on one seam): a §4.1 step-7 CA-injection failure drives the rollback
// through the SAME in-process adapter, never the remote driver verb.
func TestDestroySession_InProcess_RollbackUsesAdapter(t *testing.T) {
	t.Helper()
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := store.NewMemoryClock(clock)
	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{Ref: testEnvRef, RepoRef: testRepoID, ImageID: testImageID}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}
	drv := newDriverFake()
	recorder := &recordingHostAgentDestroyer{}
	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))
	cp, err := NewControlPlane(Deps{
		Store:          cpStore{st},
		Drivers:        fakeRegistry{host: testHostID, drv: drv},
		HostAgent:      recorder,
		Heartbeats:     heartbeats,
		Mint:           &fakeMint{},
		Digest:         &fakeDigest{acked: true},
		Inject:         &fakeInject{err: errInjectBoom}, // §4.1 step-7 fail-closed → rollback
		Boot:           &fakeBoot{},
		Revoke:         &fakeRevoke{},
		Enrollment:     fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:          sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		DefaultOrg:     testOrg,
		Clock:          clock,
		ResyncInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	cp.Sessions.SetSessionUUIDGen(func() string { return "sess-rollback-1" })

	if _, err := cp.Sessions.CreateSession(context.Background(), validCreateReq()); err == nil {
		t.Fatal("CreateSession: expected an inject failure")
	}
	// The compensating rollback drove the IN-PROCESS §4.2 adapter, not the remote verb.
	if n := len(drv.DestroyRecorded()); n != 0 {
		t.Errorf("remote driver destroy calls = %d on rollback, want 0 (in-process adapter owns it)", n)
	}
	if n := len(recorder.recorded()); n != 1 {
		t.Errorf("in-process rollback destroy calls = %d, want 1", n)
	}
}

// TestDestroySession_Idempotent proves a DestroySession of an already-DESTROYED session is
// a clean no-op success (the teardown already converged) — the retained record's projection
// is returned WITHOUT re-driving the host teardown (idempotent on session_uuid, doc 15 §4.2).
func TestDestroySession_Idempotent(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	if _, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}); err != nil {
		t.Fatalf("first DestroySession: %v", err)
	}
	// Second destroy: a clean no-op success, no additional host teardown.
	resp, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	if err != nil {
		t.Fatalf("re-DestroySession: unexpected error: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Errorf("re-DestroySession: state = %v, want DESTROYED", got)
	}
	if n := len(f.drv.DestroyRecorded()); n != 1 {
		t.Errorf("host destroy calls after re-destroy = %d, want 1 (the second destroy is a no-op)", n)
	}
}

// TestDestroySession_UnknownSession_NotFound proves destroying a session the store does not
// carry is a NotFound refusal (the operator named a session that does not exist) — no teardown.
func TestDestroySession_UnknownSession_NotFound(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	_, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: "sess-nope"})
	if err == nil {
		t.Fatal("DestroySession: expected NotFound for an unknown session")
	}
	if st, _ := status.FromError(err); st.Code() != codes.NotFound {
		t.Fatalf("DestroySession error code = %v, want NotFound; err=%v", st.Code(), err)
	}
	if n := len(f.drv.DestroyRecorded()); n != 0 {
		t.Errorf("host destroy calls = %d on an unknown session, want 0", n)
	}
}

// TestDestroySession_EmptyUUID_InvalidArgument proves an empty session_uuid is rejected
// InvalidArgument before any store read or host verb.
func TestDestroySession_EmptyUUID_InvalidArgument(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	_, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("DestroySession error code = %v, want InvalidArgument; err=%v", st.Code(), err)
	}
}

// TestDestroySession_Unwired_Unavailable proves a handler with no destroy leg installed
// (a test-narrowed SessionService) refuses Unavailable rather than half-tearing a session
// down (the clean-degrade posture, mirroring WatchSession/Attach when the legs are unwired).
func TestDestroySession_Unwired_Unavailable(t *testing.T) {
	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	_, err := svc.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: "sess-x"})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Fatalf("DestroySession error code = %v, want Unavailable (destroy leg unwired); err=%v", st.Code(), err)
	}
}

// TestDestroySession_OverWire proves the teardown closes END-TO-END over the gRPC
// DestroySession RPC (bufconn): an operator dials the public surface, names the session,
// and the handler drives it to DESTROYED — the M0 lifecycle closed through the wire.
func TestDestroySession_OverWire(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	client := serveSessions(t, f.cp)

	created, err := client.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over wire: %v", err)
	}
	resp, err := client.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: created.GetSession().GetSessionUuid()})
	if err != nil {
		t.Fatalf("DestroySession over wire: %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Fatalf("DestroySession over wire: state = %v, want DESTROYED", got)
	}
}

// TestDestroySession_FromSuspended_ClearsReason proves the public §4.2 teardown can
// destroy a SUSPENDED session (e.g. a D77 policy_breach suspension an operator then tears
// down). SUSPENDED is non-terminal, so the idempotent short-circuit does NOT catch it; the
// handler's DESTROYING flip must also CLEAR the §3 SUSPENDED(reason) invariant, else the
// store's "reason set iff SUSPENDED" CHECK (checkSuspend) rejects the DESTROYING write with
// ErrInvalid → FailedPrecondition and the session can never be destroyed over the wire.
func TestDestroySession_FromSuspended_ClearsReason(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	// Suspend the session with a reason (the SuspendSession handler is not wired this
	// capstone, so drive the record directly — a policy_breach suspension an operator
	// then destroys). The record now carries SUSPENDED(reason=policy_breach).
	suspended := store.SessionSuspended
	reason := store.SuspendReasonPolicyBreach
	if _, err := f.st.UpdateSession(context.Background(), uuid, store.SessionUpdate{State: &suspended, SuspendReason: &reason}); err != nil {
		t.Fatalf("suspend session: %v", err)
	}

	resp, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	if err != nil {
		t.Fatalf("DestroySession of a SUSPENDED session: unexpected error (the DESTROYING flip must clear the suspend reason): %v", err)
	}
	if got := resp.GetSession().GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Fatalf("DestroySession of a SUSPENDED session: state = %v, want DESTROYED", got)
	}

	// The retained record is finalized DESTROYED with no stale suspend reason.
	rec, gerr := f.st.GetSession(context.Background(), uuid)
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.State != store.SessionDestroyed {
		t.Errorf("record state = %q, want DESTROYED", rec.State)
	}
	if rec.SuspendReason != store.SuspendReasonNone {
		t.Errorf("record SuspendReason = %q, want cleared (only valid while SUSPENDED)", rec.SuspendReason)
	}
}
