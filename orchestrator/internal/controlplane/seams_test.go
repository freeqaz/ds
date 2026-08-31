package controlplane

// seams_test.go exercises the OPTIONAL host-hint targeting on the reconciler-facing
// quarantine/teardown verbs (registryDriver.Suspend/Destroy) WITHOUT a live VM
// (D50: the host drivers are recording fakes over a multi-host registry, no
// hostagent/podman/gRPC). The scenario the scope guards: at the ~500-host virtual-metal
// density the D37 v0 density model sizes for, an orphan-reap that broadcasts a
// Suspend/Destroy to every host driver is a fleet-wide fan-out; WithQuarantineHostHint
// lets the reconciler — which holds the reporting host_id from the heartbeat (doc 15
// §4.2) — collapse that to the one host that observed the orphan (D35 per-host driver
// contract, D66 host/index binding). These tests prove: (1) a hinted verb hits ONLY the
// named host's driver; (2) absent a hint the existing record/broadcast routing is
// unchanged (backwards-compatible); (3) a hint to an unregistered host surfaces
// ErrNoDriverForHost rather than silently broadcasting.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// recordingDriver is a per-host DriverClient fake (D50) that records the
// session_uuids it was asked to Suspend/Destroy, so a test can assert WHICH host
// drivers a verb reached (targeted vs. broadcast). Clone/IssueAttach are unused here
// and ack trivially.
type recordingDriver struct {
	host       string
	mu         sync.Mutex
	suspends   []string
	destroys   []string
	suspendErr error
	destroyErr error
}

func (d *recordingDriver) CloneFromImage(_ context.Context, _ *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	return &hypervisorv1.CloneFromImageResponse{}, nil
}

func (d *recordingDriver) IssueAttachHandle(_ context.Context, _ *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error) {
	return &hypervisorv1.IssueAttachHandleResponse{}, nil
}

func (d *recordingDriver) Suspend(_ context.Context, in *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	d.mu.Lock()
	d.suspends = append(d.suspends, in.GetSessionUuid())
	d.mu.Unlock()
	if d.suspendErr != nil {
		return nil, d.suspendErr
	}
	return &hypervisorv1.SuspendResponse{}, nil
}

func (d *recordingDriver) Destroy(_ context.Context, in *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	d.mu.Lock()
	d.destroys = append(d.destroys, in.GetSessionUuid())
	d.mu.Unlock()
	if d.destroyErr != nil {
		return nil, d.destroyErr
	}
	return &hypervisorv1.DestroyResponse{}, nil
}

func (d *recordingDriver) suspendCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.suspends)
}

func (d *recordingDriver) destroyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.destroys)
}

// multiHostRegistry is a DriverRegistry over several distinct per-host drivers (the
// fleet the broadcast path fans out over and the hint path targets one of). Hosts()
// reports every registered host in a stable order; DriverFor returns the named host's
// recording driver, or ErrNoDriverForHost for an unknown host.
type multiHostRegistry struct {
	drivers map[string]*recordingDriver
	order   []string
}

func newMultiHostRegistry(hosts ...string) *multiHostRegistry {
	r := &multiHostRegistry{drivers: make(map[string]*recordingDriver, len(hosts))}
	for _, h := range hosts {
		r.drivers[h] = &recordingDriver{host: h}
		r.order = append(r.order, h)
	}
	return r
}

func (r *multiHostRegistry) DriverFor(_ context.Context, hostID string) (DriverClient, error) {
	if d, ok := r.drivers[hostID]; ok {
		return d, nil
	}
	return nil, ErrNoDriverForHost
}

func (r *multiHostRegistry) Hosts(_ context.Context) ([]string, error) {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out, nil
}

// fixedSessionLookup is a sessionHostLookup that resolves a known session→host (the
// rule-b recorded-host path) and reports a miss (orphan) for any other UUID.
type fixedSessionLookup struct {
	sessions map[string]store.Session
}

func (l fixedSessionLookup) GetSession(_ context.Context, sessionUUID string) (store.Session, error) {
	if s, ok := l.sessions[sessionUUID]; ok {
		return s, nil
	}
	return store.Session{}, store.ErrNotFound
}

const (
	hostReporter = "host-reporter"
	hostOther1   = "host-other-1"
	hostOther2   = "host-other-2"
	orphanUUID   = "sess-orphan-1"
)

func newOrphanSuspendReq(sessionUUID string) *hypervisorv1.SuspendRequest {
	return &hypervisorv1.SuspendRequest{
		SessionUuid: sessionUUID,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		Provenance:  &boundaryv1.Provenance{RuleId: "test: orphan quarantine"},
	}
}

// TestQuarantineHostHintTargetsOneHost is the scope's core proof: an orphan
// quarantine (no record) carrying a host hint Suspends ONLY the named host's driver,
// never fanning out to the rest of the fleet (D35/D66 per-host driver + host/index
// binding — avoid the ~500-host broadcast the D37 v0 density model sizes for).
func TestQuarantineHostHintTargetsOneHost(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	// No record for the orphan: absent a hint this would broadcast to all three hosts.
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	ctx := WithQuarantineHostHint(context.Background(), hostReporter)
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("hinted Suspend: %v", err)
	}

	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("reporting host driver: want 1 Suspend, got %d", got)
	}
	if got := reg.drivers[hostOther1].suspendCount(); got != 0 {
		t.Fatalf("host-other-1 driver: want 0 Suspends (no broadcast), got %d", got)
	}
	if got := reg.drivers[hostOther2].suspendCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Suspends (no broadcast), got %d", got)
	}
	if got := reg.drivers[hostReporter].suspends[0]; got != orphanUUID {
		t.Fatalf("reporting host Suspend carried session %q, want %q", got, orphanUUID)
	}
}

// TestDestroyHostHintTargetsOneHost proves the Destroy verb honors the same hint —
// a teardown carrying a host hint targets only the named host's driver.
func TestDestroyHostHintTargetsOneHost(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	ctx := WithQuarantineHostHint(context.Background(), hostOther1)
	if _, err := d.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: orphanUUID}); err != nil {
		t.Fatalf("hinted Destroy: %v", err)
	}

	if got := reg.drivers[hostOther1].destroyCount(); got != 1 {
		t.Fatalf("hinted host driver: want 1 Destroy, got %d", got)
	}
	if got := reg.drivers[hostReporter].destroyCount(); got != 0 {
		t.Fatalf("host-reporter driver: want 0 Destroys (no broadcast), got %d", got)
	}
	if got := reg.drivers[hostOther2].destroyCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Destroys (no broadcast), got %d", got)
	}
}

// TestQuarantineWithoutHintBroadcasts is the backwards-compatibility proof: absent a
// host hint, an orphan (no record) keeps the EXISTING fleet-broadcast behavior — the
// idempotent Suspend reaches every registered host's driver, the running host
// servicing it and the rest no-opping (§3 rule a fallback unchanged).
func TestQuarantineWithoutHintBroadcasts(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// Plain context, no hint.
	if _, err := d.Suspend(context.Background(), newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("unhinted Suspend: %v", err)
	}

	// Broadcast returns on the FIRST success, so the first host in enumeration order
	// is the only one that must have been hit — but critically the targeting is NOT
	// the single named host of the hint path: the orphan has no record, so without a
	// hint the path is the broadcast fallback (proven by the first-host hit here, with
	// no host-hint plumbing involved). The first registered host services it.
	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("broadcast first host: want 1 Suspend, got %d", got)
	}
}

// TestQuarantineWithoutHintBroadcastsAllOnTransientFailure proves the broadcast
// fallback still fans out across the fleet when earlier hosts fail the idempotent
// verb: with no hint and no record, a Suspend that errors on the first host(s) is
// retried on the next until one succeeds (idempotent on session_uuid). This pins
// that the absent-hint path is the unchanged fleet broadcast, not an accidental
// single-host route.
func TestQuarantineWithoutHintBroadcastsAllOnTransientFailure(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	// First two hosts fail; the third succeeds — the broadcast must reach all three.
	reg.drivers[hostReporter].suspendErr = errors.New("driver unreachable")
	reg.drivers[hostOther1].suspendErr = errors.New("driver unreachable")
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	if _, err := d.Suspend(context.Background(), newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("broadcast Suspend (third host succeeds): %v", err)
	}

	for _, h := range []string{hostReporter, hostOther1, hostOther2} {
		if got := reg.drivers[h].suspendCount(); got != 1 {
			t.Fatalf("broadcast host %s: want 1 Suspend attempt, got %d", h, got)
		}
	}
}

// TestRecordedHostRoutesWithoutHint proves the recorded-host path (rule b / a
// regression) is unchanged when no hint is supplied: a session WITH a record routes
// to its recorded host's driver only, never a broadcast.
func TestRecordedHostRoutesWithoutHint(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	const recordedUUID = "sess-recorded-1"
	d := registryDriver{
		reg: reg,
		recs: fixedSessionLookup{sessions: map[string]store.Session{
			recordedUUID: {Ref: store.SessionRef{SessionUUID: recordedUUID, HostID: hostOther2}},
		}},
	}

	if _, err := d.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: recordedUUID}); err != nil {
		t.Fatalf("recorded-host Destroy: %v", err)
	}

	if got := reg.drivers[hostOther2].destroyCount(); got != 1 {
		t.Fatalf("recorded host driver: want 1 Destroy, got %d", got)
	}
	if got := reg.drivers[hostReporter].destroyCount(); got != 0 {
		t.Fatalf("host-reporter driver: want 0 Destroys, got %d", got)
	}
	if got := reg.drivers[hostOther1].destroyCount(); got != 0 {
		t.Fatalf("host-other-1 driver: want 0 Destroys, got %d", got)
	}
}

// TestHostHintOverridesRecordedHost proves the hint takes precedence over the
// recorded host (resolution order: hint first). A reconciler that names the
// reporting host targets it even if a record names a different host — the hint is the
// definite, caller-supplied target.
func TestHostHintOverridesRecordedHost(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	const recordedUUID = "sess-recorded-2"
	d := registryDriver{
		reg: reg,
		recs: fixedSessionLookup{sessions: map[string]store.Session{
			recordedUUID: {Ref: store.SessionRef{SessionUUID: recordedUUID, HostID: hostOther2}},
		}},
	}

	ctx := WithQuarantineHostHint(context.Background(), hostReporter)
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(recordedUUID)); err != nil {
		t.Fatalf("hinted Suspend over record: %v", err)
	}

	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("hinted host driver: want 1 Suspend, got %d", got)
	}
	if got := reg.drivers[hostOther2].suspendCount(); got != 0 {
		t.Fatalf("recorded host driver: want 0 Suspends (hint wins), got %d", got)
	}
}

// TestHostHintUnknownHostSurfacesError proves a hint to a host with no registered
// driver surfaces ErrNoDriverForHost rather than silently widening to a broadcast: a
// named target that cannot be reached is an error the reconciler absorbs into an
// alarm/retry. No other host's driver is touched.
func TestHostHintUnknownHostSurfacesError(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	ctx := WithQuarantineHostHint(context.Background(), "host-not-registered")
	_, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID))
	if !errors.Is(err, ErrNoDriverForHost) {
		t.Fatalf("hint to unknown host: want ErrNoDriverForHost, got %v", err)
	}
	for _, h := range []string{hostReporter, hostOther1} {
		if got := reg.drivers[h].suspendCount(); got != 0 {
			t.Fatalf("host %s driver: want 0 Suspends (no broadcast on a named miss), got %d", h, got)
		}
	}
}

// TestWithQuarantineHostHintEmptyIsNoHint proves WithQuarantineHostHint("") is a
// no-op: a caller can pass the reporting host unconditionally and, with no host to
// name, keep the absent-hint broadcast behavior. quarantineHostHint reads no hint
// from the unchanged context.
func TestWithQuarantineHostHintEmptyIsNoHint(t *testing.T) {
	ctx := context.Background()
	if got := WithQuarantineHostHint(ctx, ""); got != ctx {
		t.Fatalf("empty hint should return the context unchanged")
	}
	if _, ok := quarantineHostHint(WithQuarantineHostHint(context.Background(), "")); ok {
		t.Fatalf("empty hint should not register a host hint")
	}
	if _, ok := quarantineHostHint(context.Background()); ok {
		t.Fatalf("plain context should carry no host hint")
	}
	if host, ok := quarantineHostHint(WithQuarantineHostHint(context.Background(), hostReporter)); !ok || host != hostReporter {
		t.Fatalf("set hint: want (%q,true), got (%q,%v)", hostReporter, host, ok)
	}
}

// --------------------------------------------------------------------------
// The PRODUCTION BRIDGE (this unit's core proof): a ctx stamped by the RECONCILER
// (reconciler.WithQuarantineHostHint, a DIFFERENT package's unexported key than
// controlplane's own) is HONORED by registryDriver.runVerb, so the orphan-quarantine
// fast path is ON in prod. The real production caller (reconciler.quarantineOrphan,
// conflict.go) stamps reconciler.WithQuarantineHostHint with the reporting host_id the
// heartbeat carries (doc 15 §4.2); before the bridge runVerb consulted ONLY controlplane's
// own key, so that stamp NEVER reached prod and the quarantine still fleet-broadcast at the
// ~500-host D37 v0 density. These tests stamp via the RECONCILER seam and assert the verb
// host-targets the reporting host instead of broadcasting.
// --------------------------------------------------------------------------

// TestReconcilerStampedHintHonoredByRunVerb is the unit's acceptance proof: a Suspend on a
// ctx stamped by reconciler.WithQuarantineHostHint (the production reconciler's seam, a
// different package key than controlplane's) targets ONLY the named host's driver — the
// reporting-host hint reaches prod and collapses the fleet broadcast to one host.
//
// The hinted host is the LAST in enumeration order (hostOther2). This is load-bearing:
// the broadcast fallback returns on the FIRST host's success, so a hint that were NOT
// honored would have hit hostReporter (the first host) and never hostOther2. Asserting the
// first host got 0 and the last got 1 distinguishes "the hint targeted the named host" from
// "the broadcast happened to service the first host" — without it the test passes even when
// the reconciler-stamped hint is dropped (a tautology the first-host-coincidence hides).
func TestReconcilerStampedHintHonoredByRunVerb(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	// No record for the orphan: absent an honored hint this would broadcast, servicing the
	// FIRST host (hostReporter), never the last (hostOther2) we hint here.
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// Stamp via the RECONCILER seam, exactly as quarantineOrphan does in production.
	ctx := reconciler.WithQuarantineHostHint(context.Background(), hostOther2)
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("reconciler-stamped Suspend: %v", err)
	}

	if got := reg.drivers[hostOther2].suspendCount(); got != 1 {
		t.Fatalf("hinted (last-in-order) host driver: want 1 Suspend, got %d", got)
	}
	// The first host is what a dropped-hint broadcast would have serviced — it must be 0.
	if got := reg.drivers[hostReporter].suspendCount(); got != 0 {
		t.Fatalf("first-in-order host driver: want 0 Suspends (hint honored, not broadcast), got %d", got)
	}
	if got := reg.drivers[hostOther1].suspendCount(); got != 0 {
		t.Fatalf("host-other-1 driver: want 0 Suspends (no broadcast), got %d", got)
	}
	if got := reg.drivers[hostOther2].suspends[0]; got != orphanUUID {
		t.Fatalf("hinted host Suspend carried session %q, want %q", got, orphanUUID)
	}
}

// TestReconcilerStampedHintHonoredByDestroy proves the Destroy verb honors the
// reconciler-stamped hint too — a teardown on a reconciler-stamped ctx targets only the
// named host's driver.
func TestReconcilerStampedHintHonoredByDestroy(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	ctx := reconciler.WithQuarantineHostHint(context.Background(), hostOther1)
	if _, err := d.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: orphanUUID}); err != nil {
		t.Fatalf("reconciler-stamped Destroy: %v", err)
	}

	if got := reg.drivers[hostOther1].destroyCount(); got != 1 {
		t.Fatalf("hinted host driver: want 1 Destroy, got %d", got)
	}
	if got := reg.drivers[hostReporter].destroyCount(); got != 0 {
		t.Fatalf("host-reporter driver: want 0 Destroys (no broadcast), got %d", got)
	}
	if got := reg.drivers[hostOther2].destroyCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Destroys (no broadcast), got %d", got)
	}
}

// TestReconcilerStampedHintOverridesRecordedHost proves the reconciler-stamped hint wins
// over a recorded host (the hint is the definite, caller-supplied target), exactly as the
// controlplane-stamped hint does — the bridge preserves the hint-first resolution order.
func TestReconcilerStampedHintOverridesRecordedHost(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	const recordedUUID = "sess-recorded-bridge"
	d := registryDriver{
		reg: reg,
		recs: fixedSessionLookup{sessions: map[string]store.Session{
			recordedUUID: {Ref: store.SessionRef{SessionUUID: recordedUUID, HostID: hostOther2}},
		}},
	}

	ctx := reconciler.WithQuarantineHostHint(context.Background(), hostReporter)
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(recordedUUID)); err != nil {
		t.Fatalf("reconciler-stamped Suspend over record: %v", err)
	}

	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("hinted host driver: want 1 Suspend, got %d", got)
	}
	if got := reg.drivers[hostOther2].suspendCount(); got != 0 {
		t.Fatalf("recorded host driver: want 0 Suspends (hint wins), got %d", got)
	}
}

// TestControlplaneHintWinsOverReconcilerHint proves the precedence the bridge declares:
// when BOTH stamping seams name a host, controlplane's own WithQuarantineHostHint wins (a
// direct controlplane caller keeps precedence; the reconciler stamp is the prod fallback).
func TestControlplaneHintWinsOverReconcilerHint(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// controlplane names hostOther1; reconciler names hostReporter — controlplane wins.
	ctx := reconciler.WithQuarantineHostHint(context.Background(), hostReporter)
	ctx = WithQuarantineHostHint(ctx, hostOther1)
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("dual-stamped Suspend: %v", err)
	}

	if got := reg.drivers[hostOther1].suspendCount(); got != 1 {
		t.Fatalf("controlplane-named host driver: want 1 Suspend, got %d", got)
	}
	if got := reg.drivers[hostReporter].suspendCount(); got != 0 {
		t.Fatalf("reconciler-named host driver: want 0 Suspends (controlplane hint wins), got %d", got)
	}
	if got := reg.drivers[hostOther2].suspendCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Suspends, got %d", got)
	}
}

// TestReconcilerStampedHintUnknownHostSurfacesError proves a reconciler-stamped hint to a
// host with no registered driver surfaces ErrNoDriverForHost rather than silently widening
// to a broadcast — a named target that cannot be reached is an error the reconciler absorbs
// into an alarm/retry, the same posture as a controlplane-stamped miss.
func TestReconcilerStampedHintUnknownHostSurfacesError(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	ctx := reconciler.WithQuarantineHostHint(context.Background(), "host-not-registered")
	_, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID))
	if !errors.Is(err, ErrNoDriverForHost) {
		t.Fatalf("reconciler hint to unknown host: want ErrNoDriverForHost, got %v", err)
	}
	for _, h := range []string{hostReporter, hostOther1} {
		if got := reg.drivers[h].suspendCount(); got != 0 {
			t.Fatalf("host %s driver: want 0 Suspends (no broadcast on a named miss), got %d", h, got)
		}
	}
}

// TestReconcilerEmptyHintFallsThroughToBroadcast proves the bridge stays backwards-
// compatible: an empty reconciler stamp registers no hint (the reconciler seam returns the
// context unchanged), so an orphan with no record keeps the EXISTING fleet-broadcast
// behavior — the absent-hint path is unchanged.
func TestReconcilerEmptyHintFallsThroughToBroadcast(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1, hostOther2)
	d := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// reconciler.WithQuarantineHostHint("") is a no-op → no hint on the context.
	ctx := reconciler.WithQuarantineHostHint(context.Background(), "")
	if _, err := d.Suspend(ctx, newOrphanSuspendReq(orphanUUID)); err != nil {
		t.Fatalf("empty-reconciler-hint Suspend: %v", err)
	}
	// Broadcast services on the first registered host (no single-host hint route taken).
	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("broadcast first host: want 1 Suspend, got %d", got)
	}
}

// TestEffectiveQuarantineHostHintBridgesBothSeams unit-tests the bridge resolver directly:
// it reads controlplane's own hint first, falls back to the reconciler-stamped hint, and
// reports absent when neither seam stamped — the exact precedence runVerb relies on.
func TestEffectiveQuarantineHostHintBridgesBothSeams(t *testing.T) {
	// Neither seam → no hint.
	if host, ok := effectiveQuarantineHostHint(context.Background()); ok || host != "" {
		t.Fatalf("no stamp: want (\"\",false), got (%q,%v)", host, ok)
	}
	// Reconciler-only stamp → the reconciler host (the production prod-path fallback).
	rctx := reconciler.WithQuarantineHostHint(context.Background(), hostReporter)
	if host, ok := effectiveQuarantineHostHint(rctx); !ok || host != hostReporter {
		t.Fatalf("reconciler-only stamp: want (%q,true), got (%q,%v)", hostReporter, host, ok)
	}
	// Controlplane-only stamp → the controlplane host.
	cctx := WithQuarantineHostHint(context.Background(), hostOther1)
	if host, ok := effectiveQuarantineHostHint(cctx); !ok || host != hostOther1 {
		t.Fatalf("controlplane-only stamp: want (%q,true), got (%q,%v)", hostOther1, host, ok)
	}
	// Both stamps → controlplane wins.
	bctx := WithQuarantineHostHint(reconciler.WithQuarantineHostHint(context.Background(), hostReporter), hostOther1)
	if host, ok := effectiveQuarantineHostHint(bctx); !ok || host != hostOther1 {
		t.Fatalf("both stamps: want controlplane (%q,true), got (%q,%v)", hostOther1, host, ok)
	}
}

// --------------------------------------------------------------------------
// THE PRODUCTION-PATH INTEGRATION (this unit's core proof). The bridge is proven in
// two HALVES elsewhere: reconciler/conflict_test.go proves quarantineOrphan STAMPS the
// reconciler key, and the TestReconcilerStamped* tests above prove registryDriver.runVerb
// HONORS a reconciler-stamped ctx. But NEITHER half wires the PRODUCTION reconciler.Driver
// = controlplane.registryDriver end-to-end, so a future refactor that drops the stamp
// (conflict.go) OR the bridge clause (effectiveQuarantineHostHint, seams.go) could pass
// both half-tests while prod silently reverts to a fleet broadcast. The test below closes
// that gap: it constructs the REAL registryDriver AS the reconciler's Driver, drives an
// actual reconcile of an orphan heartbeat through the production reconciler, and asserts
// the resulting quarantine Suspend targets ONLY the reporting host's driver — never the
// fleet. Removing EITHER the stamp OR the bridge clause makes it fail.
//
// controlplane is the ONLY tree that may import BOTH controlplane and reconciler (the
// controlplane → reconciler → controlplane cycle direction the reconciler seam header calls
// out), so this whole-spine integration legally lives here and nowhere else.
// --------------------------------------------------------------------------

// orphanObserved builds a synthetic ObservedSession with no matching record — the §3
// rule-a orphan the production reconciler quarantines. No live VM/host-agent (D50): it is
// a frozen hypervisor.v1 message the reconciler diffs against an EMPTY record store.
func orphanObserved(sessionUUID string) *hypervisorv1.ObservedSession {
	return &hypervisorv1.ObservedSession{
		SessionUuid: sessionUUID,
		DomainUuid:  "dom-" + sessionUUID,
	}
}

// TestProductionReconcilerDriverQuarantineTargetsReportingHost is the unit's acceptance
// proof: it wires the REAL controlplane.registryDriver AS the reconciler's Driver (the exact
// production assembly main.go makes) and drives a real reconcile. The heartbeat reports an
// orphan VM (no record) from hostReporter, so the production reconciler's quarantineOrphan
// stamps reconciler.WithQuarantineHostHint(ctx, hostReporter) and calls driver.Suspend. With
// the bridge clause live, registryDriver.runVerb resolves that ONE host's driver and targets
// it; the rest of the fleet is never touched — the ~500-host D37 v0 density broadcast is
// collapsed to one host. This is the END-TO-END proof the two half-tests can't give:
//
//   - drop the STAMP in conflict.go (quarantineOrphan no longer stamps the reporting host) →
//     no hint reaches runVerb → the orphan with no record BROADCASTS, servicing the FIRST
//     host (hostOther1), so hostReporter's count is 0 → this test FAILS;
//   - drop the BRIDGE clause in seams.go (effectiveQuarantineHostHint no longer consults the
//     reconciler key) → the reconciler-stamped hint is ignored → same broadcast → FAILS.
//
// hostReporter is registered LAST in enumeration order; this is load-bearing exactly as in
// TestReconcilerStampedHintHonoredByRunVerb — a dropped-hint broadcast returns on the FIRST
// host's success (hostOther1), never the last, so asserting the reporting host (last) got the
// Suspend and the first host got 0 distinguishes "the production stamp+bridge targeted the
// reporting host" from "a broadcast happened to service the first host".
func TestProductionReconcilerDriverQuarantineTargetsReportingHost(t *testing.T) {
	// hostReporter LAST so a dropped-stamp/dropped-bridge broadcast would service hostOther1
	// (first), never hostReporter — the assertions below catch the silent revert.
	reg := newMultiHostRegistry(hostOther1, hostOther2, hostReporter)

	// The real production driver: registryDriver over the multi-host registry, resolving the
	// recorded host from the control-plane store. An EMPTY store makes every observed session
	// an orphan (no record) — the §3 rule-a path. *store.Memory satisfies sessionHostLookup
	// via GetSession (the same narrow read production wires).
	st := store.NewMemory()
	prodDriver := registryDriver{reg: reg, recs: st}

	// Construct the PRODUCTION reconciler with the real registryDriver as its Driver — the
	// exact reconciler.Driver = controlplane.registryDriver assembly. No redriver/alarm
	// needed for the rule-a quarantine path (a nil alarm drops alarms; the orphan still
	// suspends). A fixed clock keeps the reconcile deterministic.
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	rec, err := reconciler.New(st, prodDriver, nil, nil, clock, reconciler.Config{})
	if err != nil {
		t.Fatalf("reconciler.New over production registryDriver: %v", err)
	}

	// Drive a real heartbeat from hostReporter carrying ONE orphan VM (no record). Observe
	// runs the full §3 conflict diff: the orphan has no record, so quarantineOrphan stamps
	// the reporting host (hostReporter) and Suspends through the production driver.
	hb := heartbeatWithObserved(hostReporter, 1, orphanObserved(orphanUUID))
	if err := rec.Observe(context.Background(), hb); err != nil {
		t.Fatalf("production reconcile Observe: %v", err)
	}

	// The reporting host (LAST in order) must have received exactly the orphan's Suspend —
	// the stamp reached prod and the bridge honored it.
	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("reporting host driver: want 1 quarantine Suspend (stamp+bridge targeted it), got %d", got)
	}
	if got := reg.drivers[hostReporter].suspends[0]; got != orphanUUID {
		t.Fatalf("reporting host Suspend carried session %q, want the orphan %q", got, orphanUUID)
	}
	// The FIRST host is what a dropped-stamp / dropped-bridge broadcast would have serviced —
	// it MUST be 0, the assertion that distinguishes a targeted quarantine from a broadcast.
	if got := reg.drivers[hostOther1].suspendCount(); got != 0 {
		t.Fatalf("first-in-order host driver: want 0 Suspends (no fleet broadcast — stamp+bridge collapsed it), got %d", got)
	}
	if got := reg.drivers[hostOther2].suspendCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Suspends (no fleet broadcast), got %d", got)
	}
	// INVARIANT (§3 rule a): an orphan is quarantined, NEVER auto-destroyed.
	for _, h := range []string{hostReporter, hostOther1, hostOther2} {
		if got := reg.drivers[h].destroyCount(); got != 0 {
			t.Fatalf("host %s driver: orphan must NEVER be auto-destroyed (§3 rule a), got %d Destroys", h, got)
		}
	}
}

// TestProductionReconcilerDriverRecordedSessionNotABroadcast guards the backwards-compatible
// recorded-host path through the SAME production assembly: a session WITH a record (a §3
// rule-c regression, not an orphan) still routes by its recorded host, never broadcasting and
// never mis-firing the orphan host-hint. This pins that wiring the real registryDriver as the
// reconciler Driver leaves the non-orphan routing unchanged — the integration is purely
// additive over the existing record-resolve behavior.
func TestProductionReconcilerDriverRecordedSessionNotABroadcast(t *testing.T) {
	reg := newMultiHostRegistry(hostOther1, hostOther2, hostReporter)
	st := store.NewMemory()
	prodDriver := registryDriver{reg: reg, recs: st}

	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	rec, err := reconciler.New(st, prodDriver, nil, nil, clock, reconciler.Config{})
	if err != nil {
		t.Fatalf("reconciler.New over production registryDriver: %v", err)
	}

	// Seed a record on hostReporter in a non-terminal state, then observe it in a REGRESSED
	// state (PARKED < READY) so the §3 rule-c path runs WITHOUT a destroy/suspend driver hit —
	// the recorded-host routing here is exercised purely to prove an orphan from a DIFFERENT
	// reporting host does not entangle with a recorded session. A recorded session is NOT an
	// orphan: it must not trigger the quarantine broadcast.
	const recordedUUID = "sess-recorded-prod"
	if _, err := st.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: recordedUUID, HostID: hostReporter, HostSessionIndex: 3, TapName: "dstap-3"},
		State: store.SessionReady,
	}); err != nil {
		t.Fatalf("seed recorded session: %v", err)
	}

	// Heartbeat from hostReporter observing ONLY the recorded session: the §3 join finds the
	// record (NOT an orphan), so quarantineOrphan never fires and the reconcile drives NO
	// Suspend/Destroy on ANY host — the production driver never broadcasts for a recorded
	// session. (The observed element carries no pin-downable state, so rule-c regression is a
	// no-op too: a recorded in-flight session is exercised purely to prove it does not entangle
	// with the orphan host-hint broadcast.)
	hb := heartbeatWithObserved(hostReporter, 1, orphanObserved(recordedUUID))
	if err := rec.Observe(context.Background(), hb); err != nil {
		t.Fatalf("production reconcile Observe (recorded): %v", err)
	}

	for _, h := range []string{hostReporter, hostOther1, hostOther2} {
		if got := reg.drivers[h].suspendCount(); got != 0 {
			t.Fatalf("host %s driver: a recorded session must drive NO Suspend, got %d", h, got)
		}
		if got := reg.drivers[h].destroyCount(); got != 0 {
			t.Fatalf("host %s driver: a recorded session must drive NO Destroy, got %d", h, got)
		}
	}
}

// --------------------------------------------------------------------------
// THE PRODUCTION-PATH INTEGRATION FOR THE §3 RULE-b DESTROY REAP (this unit's core
// proof). orchid4 closed the orphan-quarantine SUSPEND bridge end-to-end
// (TestProductionReconcilerDriverQuarantineTargetsReportingHost above), but the sibling
// §4.2 DESTROY verb's host-hint path is proven only at the registryDriver UNIT level
// (TestDestroyHostHintTargetsOneHost / TestReconcilerStampedHintHonoredByDestroy) — never
// through the production reconciler.Driver=registryDriver assembly driven from a §3 rule-b
// reconcileMissingVM reap. The two unit halves are the SAME gap the Suspend integration
// closed: reconciler/conflict.go STAMPS the reporting host (reconciler.WithQuarantineHostHint),
// and registryDriver.runVerb HONORS a reconciler-stamped ctx (the effectiveQuarantineHostHint
// bridge clause, seams.go) — but neither half wires the production registryDriver AS the
// reconciler's Driver and drives a real rule-b reap through it. A future refactor that dropped
// the Destroy-side stamp OR the bridge clause could pass both Destroy half-tests while prod
// silently reverted to a fleet Destroy broadcast on the reap path. The tests below close that
// gap for the Destroy verb exactly as the Suspend integration does for Suspend.
//
// HOW A §3 RULE-b REAP YIELDS A registryDriver.Destroy. reconcileMissingVM (conflict.go)
// reaps a host-resident record whose VM is absent from the observed set: with a Redriver
// wired it hands the record to RedriveSession. The reconciler.Driver CONTRACT
// (reconciler.go) sanctions a §4.2 Destroy on this rule-b arm "to fail a no-VM non-terminal
// record to DESTROYED after re-drive is exhausted" — so a Redriver MAY reap the record by
// tearing the missing domain down through the §4.2 Destroy verb on the SAME reconciler.Driver
// the production assembly injects (registryDriver). The reporting host the heartbeat carries
// (doc 15 §4.2) is stamped onto the Destroy context (reconciler.WithQuarantineHostHint) so
// the idempotent teardown targets the ONE host that observed the missing VM, never
// broadcasting across the fleet at the ~500-host D37 v0 density — the identical host-targeting
// contract quarantineOrphan applies to the Suspend.
//
// FIDELITY NOTE (what this models vs. what prod does TODAY). This is the contract-sanctioned
// host-Destroy path on the rule-b arm, guarded so the stamp+bridge survive a refactor that
// routes a rule-b Destroy through reconciler.Driver. It is more synthetic than the orphan
// Suspend integration, which drives a REAL quarantineOrphan: the production ConcreteRedriver
// re-asserts the CREATE spine, and the current failToDestroyed arm finalizes the RECORD via a
// store write — NEITHER drives reconciler.Driver.Destroy today, and the live §4.2 teardown
// (DestroyRedriver, DESTROYING sweep) routes over a host-KEYED DestroyDriver seam, not this
// context hint. reapRedriver is the synthetic (D50) re-driver that models the contract's
// host-Destroying reap arm over the REAL production registryDriver — no live
// VM/host-agent/podman, just the frozen DestroyRequest — so the bridge that WOULD carry it is
// proven end-to-end. See conflict.go's reconcileMissingVM cross-ref.
// --------------------------------------------------------------------------

// reapRedriver is a synthetic reconciler.Redriver (D50) modeling the contract-sanctioned §3
// rule-b reap arm that tears a missing-VM record's domain down through the §4.2 Destroy verb on
// the PRODUCTION reconciler.Driver (the real registryDriver), stamping the record's host as the
// reporting-host hint (reconciler.WithQuarantineHostHint) exactly as quarantineOrphan stamps it
// for the Suspend. It holds the same reconciler.Driver the production assembly injects, so the
// Destroy flows through the real runVerb host-targeting (hint → recorded host → broadcast)
// end-to-end. (The production ConcreteRedriver re-asserts the CREATE spine instead; see the
// FIDELITY NOTE above — this models the Driver-contract host-Destroy arm to guard the bridge.)
type reapRedriver struct {
	driver reconciler.Driver
}

// RedriveSession reaps the missing-VM record via the §4.2 Destroy verb on the production driver,
// stamping the record's host so the idempotent teardown targets that ONE host (the reporting host
// reconcileHost threads from the heartbeat). It returns nil — the Destroy IS the reap (the §3
// rule-b "the record's VM is gone; tear it down on its host" action), so reconcileMissingVM does
// not also take the fail-to-DESTROYED arm.
func (rd reapRedriver) RedriveSession(ctx context.Context, rec store.Session) error {
	ctx = reconciler.WithQuarantineHostHint(ctx, rec.Ref.HostID)
	_, err := rd.driver.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: rec.Ref.SessionUUID})
	return err
}

// Compile-time proof the synthetic reap re-driver satisfies the reconciler.Redriver seam, so
// reconciler.New drives it through the §3 rule-b reconcileMissingVM arm exactly as it would the
// production ConcreteRedriver.
var _ reconciler.Redriver = reapRedriver{}

// TestProductionReconcilerDriverRuleBReapDestroyTargetsReportingHost is the unit's acceptance
// proof for the DESTROY verb: it wires the REAL controlplane.registryDriver AS the reconciler's
// Driver (the exact production assembly, wiring.go: registryDriver{reg, recs} passed to
// reconciler.New) and drives a real §3 rule-b reap. A host-resident record (WORKING) on
// hostReporter is observed with its VM MISSING from the heartbeat's observed set, so the
// production reconciler's reconcileMissingVM hands it to the reap re-driver, which stamps
// reconciler.WithQuarantineHostHint(ctx, hostReporter) and Destroys through the production
// driver. With the bridge clause live, registryDriver.runVerb resolves that ONE host's driver
// and targets it; the rest of the fleet is never touched — the ~500-host D37 v0 density
// Destroy broadcast is collapsed to one host. This is the END-TO-END proof the two Destroy
// half-tests can't give:
//
//   - drop the STAMP (reapRedriver / quarantineOrphan no longer stamps the reporting host) →
//     no hint reaches runVerb → the reap Destroy (no record in the driver's recs lookup)
//     BROADCASTS, servicing the FIRST host (hostOther1), so hostReporter's count is 0 → FAILS;
//   - drop the BRIDGE clause in seams.go (effectiveQuarantineHostHint no longer consults the
//     reconciler key) → the reconciler-stamped hint is ignored → same broadcast → FAILS.
//
// hostReporter is registered LAST in enumeration order; this is load-bearing exactly as in the
// Suspend integration — a dropped-hint broadcast returns on the FIRST host's success
// (hostOther1), never the last, so asserting the reporting host (last) got the Destroy and the
// first host got 0 distinguishes "the production stamp+bridge targeted the reporting host" from
// "a broadcast happened to service the first host". The driver's recs lookup is EMPTY (the §3
// rule-b record lives in the RECONCILER's store, a distinct read) so a dropped stamp/bridge
// falls to the broadcast fallback — never silently to the recorded-host route (which, being the
// same reporting host, would hide the regression).
func TestProductionReconcilerDriverRuleBReapDestroyTargetsReportingHost(t *testing.T) {
	// hostReporter LAST so a dropped-stamp/dropped-bridge broadcast would service hostOther1
	// (first), never hostReporter — the assertions below catch the silent revert.
	reg := newMultiHostRegistry(hostOther1, hostOther2, hostReporter)

	// The reconciler's desired-state store holds the §3 rule-b record (a host-resident WORKING
	// session on hostReporter). The production registryDriver's recs lookup is EMPTY so the reap
	// Destroy resolves via the HINT (or, if the stamp/bridge is dropped, the broadcast fallback —
	// NOT the recorded-host route, which would mask a dropped hint). This is the exact mirror of
	// the orphan Suspend integration, where the orphan likewise has no record in the driver's recs.
	recStore := store.NewMemory()
	const reapUUID = "sess-ruleb-reap"
	if _, err := recStore.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: reapUUID, HostID: hostReporter, HostSessionIndex: 7, TapName: "dstap-7"},
		State: store.SessionWorking,
	}); err != nil {
		t.Fatalf("seed rule-b record: %v", err)
	}

	// The PRODUCTION driver: registryDriver over the multi-host registry with an EMPTY recs
	// lookup (fixedSessionLookup with no sessions) — so the reap Destroy is hint-routed, exactly
	// as the orphan Suspend is. *store.Memory satisfies sessionHostLookup via GetSession; here the
	// distinct empty lookup keeps the reap's host-targeting on the hint, the mutation-sensitive path.
	prodDriver := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// Construct the PRODUCTION reconciler with the real registryDriver as its Driver and the reap
	// re-driver as its Redriver — the exact reconciler.New(store, registryDriver, redriver, …)
	// assembly. The §3 rule-b reconcileMissingVM hands the missing-VM record to the re-driver,
	// which Destroys through the production driver. A nil alarm drops alarms; a fixed clock keeps
	// the reconcile deterministic.
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	rec, err := reconciler.New(recStore, prodDriver, reapRedriver{driver: prodDriver}, nil, clock, reconciler.Config{})
	if err != nil {
		t.Fatalf("reconciler.New over production registryDriver: %v", err)
	}

	// Drive a real heartbeat from hostReporter whose observed set is EMPTY: the recorded session's
	// VM is absent, so the §3 rule-b reap (reconcileMissingVM) fires and Destroys through the
	// production driver with the reporting host stamped. An empty observed set introduces no
	// orphan (so rule a never fires and the assertion below that the reap drives NO Suspend is a
	// genuine invariant on the reap path, not masked by a spurious orphan quarantine).
	hb := heartbeatWithObserved(hostReporter, 1)
	if err := rec.Observe(context.Background(), hb); err != nil {
		t.Fatalf("production reconcile Observe: %v", err)
	}

	// The reporting host (LAST in order) must have received exactly the reap's Destroy — the
	// stamp reached prod and the bridge honored it.
	if got := reg.drivers[hostReporter].destroyCount(); got != 1 {
		t.Fatalf("reporting host driver: want 1 rule-b reap Destroy (stamp+bridge targeted it), got %d", got)
	}
	if got := reg.drivers[hostReporter].destroys[0]; got != reapUUID {
		t.Fatalf("reporting host Destroy carried session %q, want the reaped record %q", got, reapUUID)
	}
	// The FIRST host is what a dropped-stamp / dropped-bridge broadcast would have serviced — it
	// MUST be 0, the assertion that distinguishes a targeted reap from a broadcast.
	if got := reg.drivers[hostOther1].destroyCount(); got != 0 {
		t.Fatalf("first-in-order host driver: want 0 Destroys (no fleet broadcast — stamp+bridge collapsed it), got %d", got)
	}
	if got := reg.drivers[hostOther2].destroyCount(); got != 0 {
		t.Fatalf("host-other-2 driver: want 0 Destroys (no fleet broadcast), got %d", got)
	}
	// INVARIANT (§3 rule b is a Destroy reap, not a quarantine): the reap drives NO Suspend on
	// ANY host — the orphan-quarantine path must not entangle with the missing-VM reap.
	for _, h := range []string{hostReporter, hostOther1, hostOther2} {
		if got := reg.drivers[h].suspendCount(); got != 0 {
			t.Fatalf("host %s driver: a rule-b reap must drive NO Suspend, got %d", h, got)
		}
	}
}

// TestProductionReconcilerDriverRuleBNonHostResidentNotReaped guards the backwards-compatible
// rule-b predicate through the SAME production assembly: a record in a state that legitimately
// need NOT show a VM (PARKED — host slot released, §3 refinement 2) is NOT a missing-VM fault, so
// reconcileMissingVM skips it (expectsHostVM is false) and NO Destroy reaches ANY host's driver.
// This pins that wiring the real registryDriver as the reconciler Driver with the reap re-driver
// leaves the §3 rule-b host-resident predicate unchanged — the integration is purely additive
// over the existing reap gating, never widening the set of records the Destroy verb reaps.
func TestProductionReconcilerDriverRuleBNonHostResidentNotReaped(t *testing.T) {
	reg := newMultiHostRegistry(hostOther1, hostOther2, hostReporter)
	recStore := store.NewMemory()
	prodDriver := registryDriver{reg: reg, recs: fixedSessionLookup{sessions: map[string]store.Session{}}}

	// A PARKED record (host slot released) legitimately has no VM — its absence from the observed
	// set is NOT a missing-VM fault, so the §3 rule-b reap must skip it.
	const parkedUUID = "sess-ruleb-parked"
	if _, err := recStore.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: parkedUUID, HostID: hostReporter, HostSessionIndex: 9, TapName: "dstap-9"},
		State: store.SessionParked,
	}); err != nil {
		t.Fatalf("seed PARKED record: %v", err)
	}

	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	rec, err := reconciler.New(recStore, prodDriver, reapRedriver{driver: prodDriver}, nil, clock, reconciler.Config{})
	if err != nil {
		t.Fatalf("reconciler.New over production registryDriver: %v", err)
	}

	// Heartbeat from hostReporter with an EMPTY observed set: a host-resident record absent here
	// would be reaped, but PARKED is not host-resident, so reconcileMissingVM skips it. The empty
	// set also introduces no orphan, so the no-Suspend assertion below is a genuine invariant.
	hb := heartbeatWithObserved(hostReporter, 1)
	if err := rec.Observe(context.Background(), hb); err != nil {
		t.Fatalf("production reconcile Observe (parked): %v", err)
	}

	for _, h := range []string{hostReporter, hostOther1, hostOther2} {
		if got := reg.drivers[h].destroyCount(); got != 0 {
			t.Fatalf("host %s driver: a non-host-resident (PARKED) record must drive NO Destroy, got %d", h, got)
		}
		if got := reg.drivers[h].suspendCount(); got != 0 {
			t.Fatalf("host %s driver: a non-host-resident (PARKED) record must drive NO Suspend, got %d", h, got)
		}
	}
}

// errFeed is a hostSnapshotFeed fake whose LatestSnapshots fails, so a test can assert
// heartbeatFreshness surfaces a feed-read fault rather than reporting the host absent.
type errFeed struct{ err error }

func (e errFeed) LatestSnapshots(context.Context, string) ([]store.HeartbeatSnapshot, error) {
	return nil, e.err
}

// TestHostFreshnessResolvesLiveAppliedSeq proves the production §4.1 step-9 live-freshness
// seam (D72): the HostFreshness adapter resolves a placed host's CURRENT applied_seq O(1)
// from the SAME latest-per-host HeartbeatStore feed StoreCandidateSource places against,
// so the step-9 routable gate re-validates against the host's present freshness — closing
// the residual placement->step-9 window the recorded-only re-check misses. The four
// branches the step-9 degrade depends on:
//
//   - a host PRESENT in the live feed returns its current applied_seq + true (the live seq,
//     NOT ErrFreshnessUnknown — the gate re-validates against it);
//   - a host ABSENT from the live feed (it vanished) returns (0, false) so the placer maps
//     it to sessions.ErrFreshnessUnknown and the coordinator degrades to the recorded
//     re-check (gate-off / host-absent behavior unchanged, backwards-compatible);
//   - the LATEST snapshot wins (a host that re-emitted a higher applied_seq is read at its
//     current value, the freshness the D72 re-check assumes);
//   - a feed-read fault is surfaced verbatim (never swallowed into a false).
func TestHostFreshnessResolvesLiveAppliedSeq(t *testing.T) {
	ctx := context.Background()

	// Drive the seam against the production scheduler.Adapter so the test exercises the
	// REAL step-9 entrypoint (Adapter.CurrentFreshness over the optional Freshness seam),
	// not just the adapter in isolation — under a wired seam the probe returns the live
	// seq, with the host absent it degrades to ErrFreshnessUnknown.
	feed := NewHeartbeatStore(nil)
	feed.Record(freshHeartbeat("host-fresh", 5, 1))

	probe := NewHostFreshness(feed)

	// PRESENT host → its current applied_seq + true (the live seq the step-9 gate re-checks).
	seq, ok, err := probe.CurrentAppliedSeq(ctx, "host-fresh")
	if err != nil {
		t.Fatalf("CurrentAppliedSeq(host-fresh): %v", err)
	}
	if !ok || seq != 5 {
		t.Fatalf("CurrentAppliedSeq(host-fresh) = (%d, %v), want (5, true)", seq, ok)
	}

	// LATEST wins: the host re-emits a higher applied_seq; the probe reads the current value.
	feed.Record(freshHeartbeat("host-fresh", 9, 1))
	seq, ok, err = probe.CurrentAppliedSeq(ctx, "host-fresh")
	if err != nil {
		t.Fatalf("CurrentAppliedSeq(host-fresh, re-emitted): %v", err)
	}
	if !ok || seq != 9 {
		t.Fatalf("CurrentAppliedSeq(host-fresh, re-emitted) = (%d, %v), want (9, true)", seq, ok)
	}

	// ABSENT host → (0, false): the host has no current report; the placer maps this to
	// ErrFreshnessUnknown and the coordinator degrades to the recorded re-check.
	seq, ok, err = probe.CurrentAppliedSeq(ctx, "host-gone")
	if err != nil {
		t.Fatalf("CurrentAppliedSeq(host-gone): %v", err)
	}
	if ok || seq != 0 {
		t.Fatalf("CurrentAppliedSeq(host-gone) = (%d, %v), want (0, false)", seq, ok)
	}

	// A feed-read fault is surfaced verbatim (never a silent false).
	wantErr := errors.New("feed down")
	faulty := heartbeatFreshness{feed: errFeed{err: wantErr}}
	if _, _, ferr := faulty.CurrentAppliedSeq(ctx, "host-fresh"); !errors.Is(ferr, wantErr) {
		t.Fatalf("CurrentAppliedSeq (feed fault) err = %v, want wrap of %v", ferr, wantErr)
	}

	// A nil feed reports the host absent (false) — a half-wired probe fail-closes to the
	// recorded re-check rather than panicking.
	nilFeed := heartbeatFreshness{}
	if _, ok, err := nilFeed.CurrentAppliedSeq(ctx, "host-fresh"); err != nil || ok {
		t.Fatalf("CurrentAppliedSeq (nil feed) = (_, %v, %v), want (_, false, nil)", ok, err)
	}
}

// TestAdapterCurrentFreshnessOverProductionSeam drives the REAL sessions.Placer step-9
// entrypoint (scheduler.Adapter.CurrentFreshness) over the production HostFreshness seam,
// proving the wiring closes the residual D72 window end-to-end:
//
//   - WIRED + host present: CurrentFreshness returns the host's LIVE applied_seq (the value
//     the step-9 routable gate re-validates against), NOT sessions.ErrFreshnessUnknown — so
//     the window-closing path actually fires (the "under DS_ORCH_LIVE the probe returns the
//     live seq" acceptance);
//   - WIRED + host absent: CurrentFreshness returns sessions.ErrFreshnessUnknown (host-named),
//     so recheckFreshness takes the degrade branch and returns nil (the recorded re-check),
//     unchanged — a host that vanished is not hard-failed;
//   - UNWIRED (gate off / no Freshness seam): CurrentFreshness returns ErrFreshnessUnknown,
//     the pre-probe behavior, so a non-live run is unchanged (backwards-compatible).
func TestAdapterCurrentFreshnessOverProductionSeam(t *testing.T) {
	ctx := context.Background()

	feed := NewHeartbeatStore(nil)
	feed.Record(freshHeartbeat("host-a", 11, 1))

	// WIRED: assign the production HostFreshness seam to the Adapter's optional Freshness
	// field (the additive step-9 live probe) — the same assignment the capstone placer-
	// construction site makes under DS_ORCH_LIVE.
	wired := scheduler.NewAdapter(nil, nil, nil)
	wired.Freshness = NewHostFreshness(feed)

	gotSeq, err := wired.CurrentFreshness(ctx, "host-a")
	if err != nil {
		t.Fatalf("wired CurrentFreshness(host-a): %v (want the live seq, not ErrFreshnessUnknown)", err)
	}
	if gotSeq != 11 {
		t.Fatalf("wired CurrentFreshness(host-a) = %d, want the live applied_seq 11", gotSeq)
	}

	// WIRED + host absent: degrades to ErrFreshnessUnknown (host-named) — the coordinator
	// falls back to the recorded re-check, unchanged.
	if _, err := wired.CurrentFreshness(ctx, "host-gone"); !errors.Is(err, sessions.ErrFreshnessUnknown) {
		t.Fatalf("wired CurrentFreshness(host-gone) err = %v, want a wrap of sessions.ErrFreshnessUnknown", err)
	}

	// UNWIRED (no Freshness seam — gate off / placement-only wiring): ErrFreshnessUnknown,
	// the pre-probe behavior, so the residual window stays as it was (backwards-compatible).
	unwired := scheduler.NewAdapter(nil, nil, nil)
	if _, err := unwired.CurrentFreshness(ctx, "host-a"); !errors.Is(err, sessions.ErrFreshnessUnknown) {
		t.Fatalf("unwired CurrentFreshness err = %v, want sessions.ErrFreshnessUnknown (inert probe)", err)
	}
}

// ---------------------------------------------------------------------------
// §11.2 grant-suspend sink: the injected seam that carries the MAPPED eviction
// cause to the grant-service on a routed Suspend (doc 16 §11.2 / §5.4). These
// tests pin the EXHAUSTIVE hypervisor.v1 → attach.v1 SuspendReason mapping, prove
// the sink fires exactly once per routed Suspend with the mapped reason, and prove
// a nil sink is a byte-unchanged no-op — all WITHOUT importing the identity tree
// (D80: proto/gen/go types only) and WITHOUT a live VM (D50 recording fakes).
// ---------------------------------------------------------------------------

// sinkCall records one SuspendWithReason invocation so a test can assert the
// session_uuid and the MAPPED attach.v1 cause the routing handed the grant sink.
type sinkCall struct {
	sessionUUID string
	reason      attachv1.SuspendReason
}

// recordingGrantSink is a GrantSuspendSink fake (D50) that records every
// SuspendWithReason call — the composition-side grant-service surface is satisfied
// natively by this proto-only interface (no identity import).
type recordingGrantSink struct {
	mu    sync.Mutex
	calls []sinkCall
}

func (s *recordingGrantSink) SuspendWithReason(sessionUUID string, reason attachv1.SuspendReason) {
	s.mu.Lock()
	s.calls = append(s.calls, sinkCall{sessionUUID: sessionUUID, reason: reason})
	s.mu.Unlock()
}

func (s *recordingGrantSink) snapshot() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sinkCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// TestSuspendReasonMapsIntoGrantSink is the scope's core proof: an EXHAUSTIVE
// table over all four frozen hypervisor.v1 SuspendReason values asserts the routed
// Suspend hands the grant sink the correctly MAPPED attach.v1 cause exactly once
// (USER→USER, POLICY_BREACH→POLICY_BREACH, REBALANCE→REBALANCE, UNSPECIFIED→USER —
// the bare-shim posture), while the hypervisor verb still routes to the recorded
// host's driver exactly once (the verb routing is untouched, the sink is additive).
func TestSuspendReasonMapsIntoGrantSink(t *testing.T) {
	cases := []struct {
		name string
		in   hypervisorv1.SuspendReason
		want attachv1.SuspendReason
	}{
		{"user", hypervisorv1.SuspendReason_SUSPEND_REASON_USER, attachv1.SuspendReason_SUSPEND_REASON_USER},
		{"policy_breach", hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH},
		{"rebalance", hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE, attachv1.SuspendReason_SUSPEND_REASON_REBALANCE},
		{"unspecified", hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED, attachv1.SuspendReason_SUSPEND_REASON_USER},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := newMultiHostRegistry(hostReporter, hostOther1)
			sink := &recordingGrantSink{}
			const sess = "sess-grant-1"
			d := registryDriver{
				reg: reg,
				recs: fixedSessionLookup{sessions: map[string]store.Session{
					sess: {Ref: store.SessionRef{SessionUUID: sess, HostID: hostReporter}},
				}},
				grantSink: sink,
			}

			req := &hypervisorv1.SuspendRequest{SessionUuid: sess, Reason: tc.in}
			if _, err := d.Suspend(context.Background(), req); err != nil {
				t.Fatalf("routed Suspend: %v", err)
			}

			calls := sink.snapshot()
			if len(calls) != 1 {
				t.Fatalf("grant sink invoked %d times, want exactly 1 per routed Suspend", len(calls))
			}
			if calls[0].sessionUUID != sess {
				t.Errorf("sink session_uuid = %q, want %q", calls[0].sessionUUID, sess)
			}
			if calls[0].reason != tc.want {
				t.Errorf("mapped reason = %v, want %v (%s→attach)", calls[0].reason, tc.want, tc.name)
			}
			// The hypervisor verb still routed to exactly the recorded host, untouched.
			if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
				t.Errorf("recorded host driver Suspend count = %d, want 1", got)
			}
			if got := reg.drivers[hostOther1].suspendCount(); got != 0 {
				t.Errorf("other host driver Suspend count = %d, want 0 (verb routing untouched)", got)
			}
		})
	}
}

// TestSuspendReasonToAttachExhaustive pins the pure mapping helper directly over all
// four frozen values, guarding the read-only projection against a future enum drift
// (a regression here would surface as a POLICY_BREACH recording as USER, the exact
// gap this unit closes).
func TestSuspendReasonToAttachExhaustive(t *testing.T) {
	cases := []struct {
		in   hypervisorv1.SuspendReason
		want attachv1.SuspendReason
	}{
		{hypervisorv1.SuspendReason_SUSPEND_REASON_USER, attachv1.SuspendReason_SUSPEND_REASON_USER},
		{hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH},
		{hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE, attachv1.SuspendReason_SUSPEND_REASON_REBALANCE},
		{hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED, attachv1.SuspendReason_SUSPEND_REASON_USER},
	}
	for _, tc := range cases {
		if got := suspendReasonToAttach(tc.in); got != tc.want {
			t.Errorf("suspendReasonToAttach(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestNilGrantSinkIsNoOp proves default construction (registryDriver{reg,recs} with no
// grantSink) is a byte-unchanged no-op: a routed Suspend never panics and still routes
// the hypervisor verb to the recorded host exactly as before — the injected §11.2
// signal is purely additive and opt-in at composition.
func TestNilGrantSinkIsNoOp(t *testing.T) {
	reg := newMultiHostRegistry(hostReporter, hostOther1)
	const sess = "sess-grant-nil"
	d := registryDriver{
		reg: reg,
		recs: fixedSessionLookup{sessions: map[string]store.Session{
			sess: {Ref: store.SessionRef{SessionUUID: sess, HostID: hostReporter}},
		}},
		// grantSink deliberately unset (nil) — the default-construction posture.
	}

	req := &hypervisorv1.SuspendRequest{
		SessionUuid: sess,
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
	}
	if _, err := d.Suspend(context.Background(), req); err != nil {
		t.Fatalf("nil-sink Suspend: %v", err)
	}
	if got := reg.drivers[hostReporter].suspendCount(); got != 1 {
		t.Fatalf("nil-sink: recorded host Suspend count = %d, want 1 (routing unchanged)", got)
	}
	if got := reg.drivers[hostOther1].suspendCount(); got != 0 {
		t.Fatalf("nil-sink: other host Suspend count = %d, want 0", got)
	}
}

// Compile-time proof the recording fake satisfies the injected sink seam (the same
// shape the grant-service's SuspendWithReason(sessionUUID, reason) surface satisfies at
// composition, OUTSIDE this binary — D80: proto/gen/go types only, no identity import).
var _ GrantSuspendSink = (*recordingGrantSink)(nil)
