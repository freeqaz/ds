// SPDX-License-Identifier: Apache-2.0

// The orchestrator-side suspend / park / resume control-plane driver (doc 15 §3 +
// §4.3): it drives the FROZEN §3 transitions — WORKING→SUSPENDED, the
// SUSPENDED→RESUMING→WORKING resume, and the >15-min SNAPSHOTTING→PARKED escalation
// then the PARKED→CREATING@host' scheduler re-place — reconciler-driven, idempotent
// on session_uuid, and rollback-safe. It is the orchestrator counterpart of the
// SessionCreator (sessioncreate.go): a CONSTRUCTIBLE coordinator with its seams
// injected, unit-tested against synthetic fixtures + the generated hypervisor.v1
// fake (D50, no live VM/host-agent/podman) and NOT wired into main.go (the RPC /
// reconciler wiring is a separate task).
//
// THE FROZEN CONTRACT (consume, never re-declare):
//   - Every state edge is validated through sessions.IsTransition against the
//     FROZEN transition_table.go — the driver traverses no edge the §3 graph does
//     not contain. The state VOCABULARY (StateSuspended/StateResuming/...) is the
//     transition table's, never re-declared.
//   - The SUSPENDED→RESUMING edge is gated by sessions.AuthorizeResume
//     (resumeauthority.go) BEFORE traversal: the split authorities (user→user;
//     policy_breach→human-approval w/ a LANDED ask-grant; rebalance→scheduler). A
//     DENIED resume stays at §3 SUSPENDED — no edge traversed, no host verb driven.
//   - PARKED (D46) releases the host slot and makes NO transparency claim; resume
//     from PARKED re-places through the NORMAL scheduler with the SAME session UUID
//     but a NEW host index/tap on the target (the record keeps index history), and
//     re-mints through MintIdentity (an expired credential re-mints on resume, doc
//     16 §5.4). The >15-min escalation tier comes from the D46 escalation clock
//     (escalationclock.go); this driver consumes the verdict, never re-derives it.
//
// SEAMS. The host verbs cross as the FROZEN hypervisor.v1 proto MESSAGES (DATA),
// satisfied by the generated fake + synthetic fixtures (D50). The driver reuses the
// sessioncreate.go seams where they already exist — Placer (re-place), HostAllocator
// (the new index/tap on the target), Minter (re-mint on resume) — and adds the
// narrow suspend/resume host verbs (Suspender/Resumer/Snapshotter) plus a narrow
// ParkResumeStore the *store.Memory/*store.Postgres value satisfies natively. The
// resume-authority gate's ApprovalPresence read seam (resumeauthority.go) is injected
// for the policy_breach arm; a synthetic fake wires it in tests.
//
// IDEMPOTENCY. Every operation is idempotent on session_uuid against the current
// record state: a re-delivered Suspend for a session already SUSPENDED under the same
// reason is a no-op; a Resume for a session already RESUMING/WORKING is a no-op; a
// re-driven park for a session already PARKED is a no-op. The driver reads the
// current record, computes the target edge, and short-circuits when the record is
// already at (or past) the target — the level-triggered reconcile contract (D35).
//
// EMIT, NEVER GATE A RELEASE (D81/D32). The driver records timing and the escalation
// verdict; it arms no M2 release budget. Instant-start / create-to-attach budgets are
// instrumentation-only until dogfood data arms them.
//
// ADDITIVE / NEW FILE ONLY. No §3 state/edge/reason added; transition_table.go and
// resumeauthority.go are consumed verbatim, not edited.

package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// --- errors ---

// ErrParkResumeNoSession is returned when the record the driver was asked to act on
// does not exist (the reconciler should not drive a verb for an unknown session).
var ErrParkResumeNoSession = errors.New("sessions: park/resume: no such session record")

// ErrIllegalTransition wraps an attempt to drive a §3 edge the FROZEN transition
// table does not contain (a defensive guard — the driver computes the edge from the
// current state, so this fires only on an unexpected record state, e.g. a Resume
// driven from DESTROYED). It names the rejected From→To.
type ErrIllegalTransition struct {
	From store.SessionState
	To   store.SessionState
}

func (e *ErrIllegalTransition) Error() string {
	return fmt.Sprintf("sessions: park/resume: illegal §3 transition %s→%s (not in the frozen transition table)", e.From, e.To)
}

// ErrResumeDenied wraps a resume refused by the AuthorizeResume gate (the split
// authorities; a policy_breach with no landed approval). The session stays at §3
// SUSPENDED. The wrapped decision carries the human-readable reason.
type ErrResumeDenied struct {
	Decision ResumeDecision
}

func (e *ErrResumeDenied) Error() string {
	return "sessions: park/resume: resume denied by authority gate: " + e.Decision.Reason
}

// --- host-verb seams (the frozen hypervisor.v1 verbs as DATA) ---

// Suspender drives the FROZEN hypervisor.v1 Suspend verb on the session's placed
// host (the WORKING→SUSPENDED edge). The request is the SuspendRequest the
// suspendsignal.go terminator built (reason + POL-3 provenance); it is idempotent on
// session_uuid (the boundary dedup key collapses retransmits upstream). The
// host-agent gRPC client and the generated fake both satisfy it; a test fake
// satisfies it identically.
type Suspender interface {
	Suspend(ctx context.Context, hostID string, req *hypervisorv1.SuspendRequest) error
}

// Resumer drives the FROZEN hypervisor.v1 Resume verb on the (in-place) host (the
// SUSPENDED→RESUMING→WORKING resume for a session whose VM is still resident — the
// transparent/best-effort tiers; NOT the PARKED re-place, which goes through the
// scheduler). Idempotent on session_uuid.
type Resumer interface {
	Resume(ctx context.Context, hostID, sessionUUID string) error
}

// Snapshotter drives the FROZEN hypervisor.v1 Snapshot verb on the placed host (the
// WORKING/SUSPENDED→SNAPSHOTTING step of the >15-min escalation, before PARKED). It
// captures the per-session overlay so the session can be re-placed later. Idempotent
// on session_uuid.
type Snapshotter interface {
	Snapshot(ctx context.Context, hostID, sessionUUID string) error
}

// --- store seam ---

// ParkResumeStore is the NARROW persistence seam the driver depends on — a
// read-modify-advance over the §5.6 record plus the index-epoch append the park
// re-place needs. It is a slice of the store.Repository surface (GetSession,
// UpdateSession, AppendIndexEpoch), declared here so the driver adds NO method to any
// store interface (the storeseams / PolicyHead discipline). *store.Memory and
// *store.Postgres satisfy it natively; tests wire a synthetic fake (D50).
type ParkResumeStore interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
	AppendIndexEpoch(ctx context.Context, sessionUUID string, e store.IndexEpoch) (store.Session, error)
}

// --- seams bundle + coordinator ---

// ParkResumeSeams bundles the injected seams. Store is always required. The host
// verbs and the re-place seams are required only for the operations that reach them
// (a test-narrowed coordinator that only exercises the suspend path need not wire the
// re-place seams); a production wiring supplies them all. Approvals backs the
// policy_breach resume arm (resumeauthority.go) — required only when a policy_breach
// resume can be driven.
type ParkResumeSeams struct {
	// Store backs every record read/advance. Required.
	Store ParkResumeStore
	// Suspender drives WORKING→SUSPENDED. Required for Suspend.
	Suspender Suspender
	// Resumer drives the in-place SUSPENDED→RESUMING→WORKING resume. Required for
	// Resume of a still-resident session.
	Resumer Resumer
	// Snapshotter drives the SNAPSHOTTING step of the >15-min escalation. Required for
	// EscalateToPark.
	Snapshotter Snapshotter
	// Placer re-places a PARKED session through the normal scheduler (PARKED→
	// CREATING@host'). Required for ResumeFromPark. Reuses the sessioncreate.go seam.
	Placer Placer
	// HostAllocator allocates the NEW index/tap on the re-place target. Required for
	// ResumeFromPark. Reuses the sessioncreate.go seam.
	HostAllocator HostAllocator
	// Minter re-mints identity + interception CA on resume (an expired credential
	// re-mints on resume, doc 16 §5.4). Required for ResumeFromPark. ALSO required by
	// the in-place Resume when the persisted MintExpiry horizon has already PASSED (a
	// credential that expired while the session was SUSPENDED re-mints before the host
	// Resume verb); a still-future/zero horizon resumes with no Minter call, so a Resume
	// path that never expires a credential need not wire it. Reuses the sessioncreate.go
	// seam.
	Minter Minter
	// Approvals backs the policy_breach resume arm's landed-approval read
	// (resumeauthority.go). Required only when a policy_breach resume can be driven;
	// the other arms admit on authority match alone, so a nil reader is safe for them.
	Approvals ApprovalPresence
}

// ParkResumeDriver is the constructible suspend/park/resume coordinator. It holds
// the seams + an injected clock (now func() time.Time) for park/resume timing
// records. It is PURE w.r.t. its seams (no global state); concurrency is the seams'
// concern (the store serializes record mutation). Construct via NewParkResumeDriver.
type ParkResumeDriver struct {
	seams ParkResumeSeams
	now   func() time.Time
}

// NewParkResumeDriver constructs the driver. A nil Store is a construction error
// (every operation reads the record). A nil now defaults to time.Now. The host /
// re-place seams are validated lazily at the operation that needs them (so a
// test-narrowed driver is constructible), surfacing a clear error if absent.
func NewParkResumeDriver(seams ParkResumeSeams, now func() time.Time) (*ParkResumeDriver, error) {
	if seams.Store == nil {
		return nil, errors.New("sessions: NewParkResumeDriver: Store seam is required")
	}
	if now == nil {
		now = time.Now
	}
	return &ParkResumeDriver{seams: seams, now: now}, nil
}

// Suspend drives the §3 WORKING→SUSPENDED edge for the session named by req (the
// hypervisor.v1.SuspendRequest the suspendsignal.go terminator built). It is
// idempotent: a session already SUSPENDED under the SAME reason is a no-op (the
// boundary's redelivered signal, already deduped upstream, is safe here too). It
// validates the edge through IsTransition, drives the host Suspend verb, and advances
// the record to SUSPENDED(reason). The reason and provenance ride the request; the
// record's SuspendReason is mapped from the hypervisor reason.
//
// Returns the updated record. A session in a non-WORKING, non-SUSPENDED state (e.g.
// DESTROYING) is an ErrIllegalTransition — the reconciler should not suspend a
// teardown.
func (d *ParkResumeDriver) Suspend(ctx context.Context, req *hypervisorv1.SuspendRequest) (store.Session, error) {
	if req == nil || req.GetSessionUuid() == "" {
		return store.Session{}, errors.New("sessions: park/resume Suspend: nil request / empty session_uuid")
	}
	sessionUUID := req.GetSessionUuid()
	rec, err := d.getSession(ctx, sessionUUID)
	if err != nil {
		return store.Session{}, err
	}

	storeReason := mapHypervisorReasonToStore(req.GetReason())

	// Idempotency: already SUSPENDED under the same reason → no-op (return current).
	if rec.State == store.SessionSuspended {
		if rec.SuspendReason == storeReason {
			return rec, nil
		}
		// A different reason on an already-SUSPENDED session is a conflict the driver
		// does not silently overwrite (the first suspension reason is authoritative for
		// resume authority); surface it.
		return store.Session{}, fmt.Errorf("sessions: park/resume Suspend: session %s already SUSPENDED under reason %q, refusing to overwrite with %q", sessionUUID, rec.SuspendReason, storeReason)
	}

	if !IsTransition(toState(rec.State), StateSuspended) {
		return store.Session{}, &ErrIllegalTransition{From: rec.State, To: store.SessionSuspended}
	}

	if d.seams.Suspender == nil {
		return store.Session{}, errors.New("sessions: park/resume Suspend: no Suspender seam wired")
	}
	if err := d.seams.Suspender.Suspend(ctx, rec.Ref.HostID, req); err != nil {
		// Host verb failed — the record stays WORKING (no edge traversed); the
		// reconciler re-drives. Surface the fault.
		return store.Session{}, fmt.Errorf("sessions: park/resume Suspend: host Suspend verb failed for session %s on host %s: %w", sessionUUID, rec.Ref.HostID, err)
	}

	suspended := store.SessionSuspended
	updated, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:         &suspended,
		SuspendReason: &storeReason,
	})
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume Suspend: record advance to SUSPENDED failed for session %s: %w", sessionUUID, err)
	}
	return updated, nil
}

// Resume drives the in-place §3 SUSPENDED→RESUMING→WORKING resume for a session whose
// VM is STILL RESIDENT on its host (the transparent / best-effort tiers — NOT a PARKED
// session, which re-places through ResumeFromPark). It CALLS AuthorizeResume BEFORE
// traversing SUSPENDED→RESUMING: a denied resume stays at SUSPENDED with no host verb
// driven. On a permit it validates the edge, advances to RESUMING, drives the host
// Resume verb, and advances RESUMING→WORKING.
//
// presented is the authority the resume requestor presents (user / human-approval /
// scheduler); the required authority is DERIVED from the suspension reason on the
// record (never carried separately — resumeauthority.go's discipline). Idempotent: a
// session already RESUMING or WORKING is a no-op.
//
// HORIZON CHECK (doc 16 §5.4 — an expired credential re-mints on resume). A session can
// sit SUSPENDED past its minted-credential / interception-CA TTL, so before the host
// Resume verb is driven this checks the PERSISTED MintExpiry: when the horizon is
// NON-ZERO and ALREADY PAST (vs d.now()) the stale credential is RE-MINTED via the
// Minter and the fresh {IdentityRef,CARef,MintExpiry} are persisted on the RESUMING
// UpdateSession, so the session never resumes onto a dead credential. A ZERO horizon
// (no TTL tracked) or a still-FUTURE horizon resumes UNCHANGED — no needless mint
// churn. The re-mint requires the Minter seam; an expired horizon with no Minter wired
// is a clear error (the session stays SUSPENDED).
func (d *ParkResumeDriver) Resume(ctx context.Context, sessionUUID string, presented ResumeAuthority) (store.Session, error) {
	rec, err := d.getSession(ctx, sessionUUID)
	if err != nil {
		return store.Session{}, err
	}

	// Idempotency: already past SUSPENDED on the resume path → no-op.
	if rec.State == store.SessionResuming || rec.State == store.SessionWorking {
		return rec, nil
	}
	if rec.State != store.SessionSuspended {
		return store.Session{}, &ErrIllegalTransition{From: rec.State, To: store.SessionResuming}
	}

	// THE GATE: authorize the SUSPENDED→RESUMING traversal BEFORE touching state.
	dec, err := AuthorizeResume(ctx, ResumeRequest{
		Reason:             attachv1Reason(mapStoreReasonToAttach(rec.SuspendReason)),
		PresentedAuthority: presented,
		SessionUUID:        sessionUUID,
	}, d.seams.Approvals)
	if err != nil {
		// A landed-approval read fault is a fail-closed denial; surface it so the driver
		// can distinguish a fault from a policy refusal (the session stays SUSPENDED).
		return store.Session{}, err
	}
	if !dec.Permitted {
		return store.Session{}, &ErrResumeDenied{Decision: dec}
	}

	if d.seams.Resumer == nil {
		return store.Session{}, errors.New("sessions: park/resume Resume: no Resumer seam wired")
	}

	// HORIZON CHECK (doc 16 §5.4): a credential that EXPIRED while the session was
	// suspended must be re-minted BEFORE the host Resume verb is driven — the session
	// must never resume onto a dead credential. The horizon is the PERSISTED MintExpiry
	// on the record; it is in scope to re-mint only when NON-ZERO (a TTL is tracked) AND
	// already PAST (vs the injected clock). A zero/future horizon resumes unchanged (no
	// mint churn).
	resuming := store.SessionResuming
	noneReason := store.SuspendReasonNone
	resumingUpdate := store.SessionUpdate{
		State:         &resuming,
		SuspendReason: &noneReason, // clear the reason as we leave SUSPENDED
	}
	if !rec.MintExpiry.IsZero() && rec.MintExpiry.Before(d.now()) {
		if d.seams.Minter == nil {
			// The credential is stale but no Minter is wired to refresh it — fail closed
			// rather than resume onto a dead credential. The session stays SUSPENDED.
			return store.Session{}, fmt.Errorf("sessions: park/resume Resume: session %s credential expired at %s (now %s) but no Minter seam is wired to re-mint on resume", sessionUUID, rec.MintExpiry, d.now())
		}
		mint, err := d.seams.Minter.Mint(ctx, MintWorkloadIdentityClaims{SessionUUID: sessionUUID}, rec.RolePin.Name)
		if err != nil {
			// Re-mint failed — the session stays SUSPENDED for the reconciler to re-drive.
			return store.Session{}, fmt.Errorf("sessions: park/resume Resume: re-mint of expired credential failed for session %s: %w", sessionUUID, err)
		}
		// Persist the fresh identity/CA + advanced horizon on the SAME RESUMING advance
		// (the create-time persist precedent, sessioncreate.go step 5). A bare Minter that
		// surfaces no expiry yields the zero value, which persists as the NULL not-set
		// posture.
		resumingUpdate.IdentityRef = &mint.IdentityRef
		resumingUpdate.CARef = &mint.CARef
		resumingUpdate.MintExpiry = &mint.Expiry
	}

	// SUSPENDED→RESUMING (validated).
	if !IsTransition(StateSuspended, StateResuming) {
		return store.Session{}, &ErrIllegalTransition{From: store.SessionSuspended, To: store.SessionResuming}
	}
	if _, err := d.seams.Store.UpdateSession(ctx, sessionUUID, resumingUpdate); err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume Resume: record advance to RESUMING failed for session %s: %w", sessionUUID, err)
	}

	if err := d.seams.Resumer.Resume(ctx, rec.Ref.HostID, sessionUUID); err != nil {
		// Host Resume failed mid-resume; the record stays RESUMING for the reconciler to
		// re-drive (RESUMING→WORKING is re-attempted on the next observe). Surface it.
		return store.Session{}, fmt.Errorf("sessions: park/resume Resume: host Resume verb failed for session %s on host %s: %w", sessionUUID, rec.Ref.HostID, err)
	}

	// RESUMING→WORKING (validated).
	if !IsTransition(StateResuming, StateWorking) {
		return store.Session{}, &ErrIllegalTransition{From: store.SessionResuming, To: store.SessionWorking}
	}
	working := store.SessionWorking
	updated, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{State: &working})
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume Resume: record advance to WORKING failed for session %s: %w", sessionUUID, err)
	}
	return updated, nil
}

// EscalateToPark drives the >15-min D46 escalation: the §3 SNAPSHOTTING→PARKED edge
// (preceded by the host Snapshot). It is called when the escalation clock
// (escalationclock.go) has classified the pause as TierEscalate. It snapshots the
// session, advances to SNAPSHOTTING, then PARKED — releasing the host slot (the
// record's PARKED state IS the slot-release signal; no further host residency is
// claimed). It makes NO transparency claim.
//
// The session may be at WORKING (a direct snapshot+park), at SNAPSHOTTING (a re-drive
// mid-escalation), or at SUSPENDED (the common D46 path — a suspension that outran the
// 15-min tier, INCLUDING the unanswered genuine rung-2 ask that MUST park, never time
// out, per D53/D77). SNAPSHOTTING's only in-edge in the FROZEN §3 graph is
// WORKING→SNAPSHOTTING, so a SUSPENDED origin cannot snapshot directly. Rather than
// fail-close that case (which left the genuine rung-2 ask with NO path to PARKED), the
// driver RE-CONVERGES the SUSPENDED session through the legal frozen edges
// SUSPENDED→RESUMING→WORKING (escalateReconverge) before snapshotting — every hop a
// legal §3 transition, NO new edge added to transition_table.go. Idempotent: a session
// already PARKED is a no-op.
func (d *ParkResumeDriver) EscalateToPark(ctx context.Context, sessionUUID string) (store.Session, error) {
	rec, err := d.getSession(ctx, sessionUUID)
	if err != nil {
		return store.Session{}, err
	}

	// Idempotency: already PARKED → no-op.
	if rec.State == store.SessionParked {
		return rec, nil
	}

	// SUSPENDED-ORIGIN ESCALATION (the D46 >15-min tier on a still-suspended session —
	// the case that MUST park, never time out). SNAPSHOTTING has no SUSPENDED in-edge in
	// the FROZEN graph, so re-converge through the legal SUSPENDED→RESUMING→WORKING path
	// to a WORKING-equivalent origin first. This is a FORCED escalation park, NOT a
	// user/approval-authorized resume: it never returns the session to active work — it
	// transits RESUMING/WORKING only as legal §3 waypoints en route to SNAPSHOTTING→
	// PARKED — so it does NOT consult the resume-authority gate (AuthorizeResume, which
	// governs restoring a session to WORK; the unanswered genuine rung-2 ask parks WITHOUT
	// a landed approval, per doc 15 §3 note 2 / D53/D77). No new §3 edge is traversed.
	//
	// RESUMING is also routed here so a re-drive after a PARTIAL re-converge (a crash
	// between the SUSPENDED→RESUMING and RESUMING→WORKING hops) continues from where it
	// stalled rather than fail-closing — the level-triggered reconcile contract (D35).
	if rec.State == store.SessionSuspended || rec.State == store.SessionResuming {
		rec, err = d.escalateReconverge(ctx, sessionUUID, rec)
		if err != nil {
			return store.Session{}, err
		}
	}

	// After any re-converge the session is at WORKING (the legal SNAPSHOTTING in-edge) or
	// already mid-SNAPSHOTTING (a re-drive). Reject any other origin (PARKED handled above,
	// DESTROYING never escalates).
	if rec.State != store.SessionWorking && rec.State != store.SessionSnapshotting {
		return store.Session{}, &ErrIllegalTransition{From: rec.State, To: store.SessionSnapshotting}
	}

	if d.seams.Snapshotter == nil {
		return store.Session{}, errors.New("sessions: park/resume EscalateToPark: no Snapshotter seam wired")
	}

	// WORKING→SNAPSHOTTING (validated) when not already snapshotting.
	if rec.State == store.SessionWorking {
		if !IsTransition(StateWorking, StateSnapshotting) {
			return store.Session{}, &ErrIllegalTransition{From: store.SessionWorking, To: store.SessionSnapshotting}
		}
		snapshotting := store.SessionSnapshotting
		if _, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{State: &snapshotting}); err != nil {
			return store.Session{}, fmt.Errorf("sessions: park/resume EscalateToPark: record advance to SNAPSHOTTING failed for session %s: %w", sessionUUID, err)
		}
	}

	if err := d.seams.Snapshotter.Snapshot(ctx, rec.Ref.HostID, sessionUUID); err != nil {
		// Snapshot failed; the record stays SNAPSHOTTING for the reconciler to re-drive.
		return store.Session{}, fmt.Errorf("sessions: park/resume EscalateToPark: host Snapshot verb failed for session %s on host %s: %w", sessionUUID, rec.Ref.HostID, err)
	}

	// SNAPSHOTTING→PARKED (validated). PARKED releases the host slot — the record's
	// PARKED state is the release signal; the host agent reaps the slot on the next
	// reconcile (no transparency claim).
	if !IsTransition(StateSnapshotting, StateParked) {
		return store.Session{}, &ErrIllegalTransition{From: store.SessionSnapshotting, To: store.SessionParked}
	}
	parked := store.SessionParked
	noneReason := store.SuspendReasonNone
	updated, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:         &parked,
		SuspendReason: &noneReason, // PARKED carries no suspend reason
	})
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume EscalateToPark: record advance to PARKED failed for session %s: %w", sessionUUID, err)
	}
	return updated, nil
}

// escalateReconverge walks a still-SUSPENDED session to a WORKING-equivalent origin via
// the LEGAL FROZEN §3 edges SUSPENDED→RESUMING→WORKING, so the >15-min D46 escalation can
// then drive WORKING→SNAPSHOTTING→PARKED — the full legal re-converge being
// SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED with NO new edge added to
// transition_table.go (the §3 freeze, 01KTWJ3PG0, stays intact). Each hop is validated
// through IsTransition against the frozen table; the driver traverses no edge the graph
// does not contain.
//
// THE AUTHORITY DISTINCTION (load-bearing). The in-place Resume (above) gates
// SUSPENDED→RESUMING through AuthorizeResume because it is restoring the session to active
// WORK — a policy_breach session may not return to work without a landed human approval
// (doc 16 §8.2). This re-converge is the OPPOSITE: a FORCED escalation park (doc 15 §3
// note 2 / D46 / D53 / D77 — the unanswered genuine rung-2 ask MUST park and never time
// out into allow or kill). It does NOT return the session to work; it transits RESUMING and
// WORKING only as legal §3 waypoints and immediately snapshots+parks (releasing the host
// slot, no transparency claim). Gating it on a landed approval would be semantically wrong
// (the genuine rung-2 ask parks precisely BECAUSE no human answered), so this path does NOT
// consult AuthorizeResume. No host Resume verb is driven either — the session is not being
// resumed for use, only walked to a snapshot-able state; the host slot is released at PARKED.
//
// It is idempotent on the record state (the level-triggered reconcile contract, D35): a
// session already at RESUMING or WORKING short-circuits the hop it has already taken, so a
// re-driven escalation after a partial advance re-converges from wherever it stalled. It
// returns the record at WORKING (the legal SNAPSHOTTING in-edge) for EscalateToPark to
// continue.
func (d *ParkResumeDriver) escalateReconverge(ctx context.Context, sessionUUID string, rec store.Session) (store.Session, error) {
	// SUSPENDED→RESUMING (validated). Clear the suspend reason as we leave SUSPENDED (the
	// store's checkSuspend invariant: only a SUSPENDED record carries a reason). This is the
	// FORCED escalation transit — NO AuthorizeResume gate (see method doc), NO host Resume
	// verb (the session is walked to a snapshot-able state, not resumed for use).
	if rec.State == store.SessionSuspended {
		if !IsTransition(StateSuspended, StateResuming) {
			return store.Session{}, &ErrIllegalTransition{From: store.SessionSuspended, To: store.SessionResuming}
		}
		resuming := store.SessionResuming
		noneReason := store.SuspendReasonNone
		advanced, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
			State:         &resuming,
			SuspendReason: &noneReason,
		})
		if err != nil {
			return store.Session{}, fmt.Errorf("sessions: park/resume EscalateToPark: re-converge advance SUSPENDED→RESUMING failed for session %s: %w", sessionUUID, err)
		}
		rec = advanced
	}

	// RESUMING→WORKING (validated). The record now sits at WORKING — the legal in-edge for
	// the SNAPSHOTTING step EscalateToPark drives next.
	if rec.State == store.SessionResuming {
		if !IsTransition(StateResuming, StateWorking) {
			return store.Session{}, &ErrIllegalTransition{From: store.SessionResuming, To: store.SessionWorking}
		}
		working := store.SessionWorking
		advanced, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{State: &working})
		if err != nil {
			return store.Session{}, fmt.Errorf("sessions: park/resume EscalateToPark: re-converge advance RESUMING→WORKING failed for session %s: %w", sessionUUID, err)
		}
		rec = advanced
	}

	return rec, nil
}

// ResumeFromPark re-places a PARKED session through the NORMAL scheduler: the §3
// PARKED→CREATING@host' edge, the SAME session UUID, a NEW host index/tap on the
// target (the record keeps the prior epoch in IndexHistory), and a re-mint of the
// per-session identity + interception CA (an expired credential re-mints on resume,
// doc 16 §5.4).
//
// It CALLS AuthorizeResume FIRST (the same split-authority gate the in-place Resume
// uses) — a denied resume leaves the session PARKED. On a permit it re-places via the
// Placer, allocates the new binding via the HostAllocator on the target host, appends
// the new index epoch (which advances Ref and burns the new index), re-mints via the
// Minter, and advances PARKED→CREATING@host'. The subsequent CREATING→READY→ATTACHED
// choreography is the SessionCreator's job (sessioncreate.go) — this driver hands the
// re-placed session off at CREATING@host', it does not re-run the full ten-step spine.
//
// presented is the resume authority; the required authority derives from the reason
// the session was PARKED under. NOTE: a PARKED record carries SuspendReasonNone (park
// cleared it), so the required authority for a parked-from-policy_breach resume is
// carried by the caller — the reconciler passes the original reason. To keep the gate
// honest, ResumeFromPark takes the parkReason explicitly (the reason the session was
// suspended under before it escalated to park), so the human-approval gate still
// applies to a policy_breach park that escalated past 15 min (the unanswered genuine
// rung-2 ask parks and resumes ONLY on a landed answer, never times out).
func (d *ParkResumeDriver) ResumeFromPark(ctx context.Context, sessionUUID string, presented ResumeAuthority, parkReason attachReasonOrUnset) (store.Session, error) {
	rec, err := d.getSession(ctx, sessionUUID)
	if err != nil {
		return store.Session{}, err
	}

	// Idempotency: already re-placing (CREATING) or past it → no-op.
	if rec.State == store.SessionCreating {
		return rec, nil
	}
	if rec.State != store.SessionParked {
		return store.Session{}, &ErrIllegalTransition{From: rec.State, To: store.SessionCreating}
	}

	// THE GATE: a policy_breach park resumes ONLY on a landed human approval (doc 16
	// §8.2 resume-on-answer); user/scheduler arms admit on authority match. The reason
	// is the caller-supplied park reason (PARKED itself carries none).
	dec, err := AuthorizeResume(ctx, ResumeRequest{
		Reason:             attachv1Reason(parkReason),
		PresentedAuthority: presented,
		SessionUUID:        sessionUUID,
	}, d.seams.Approvals)
	if err != nil {
		return store.Session{}, err
	}
	if !dec.Permitted {
		return store.Session{}, &ErrResumeDenied{Decision: dec}
	}

	if d.seams.Placer == nil || d.seams.HostAllocator == nil || d.seams.Minter == nil {
		return store.Session{}, errors.New("sessions: park/resume ResumeFromPark: re-place seams (Placer/HostAllocator/Minter) not all wired")
	}

	// Re-place through the normal scheduler (D72 policy-fresh placement). Reuse the
	// frozen image/floors the record already carries — placement keys on image-cache
	// locality + floors-fit + freshness (§7).
	placement, err := d.seams.Placer.Place(ctx, sessionUUID, PlacementRequest{
		ImageID:      rec.ImageID,
		EnvConfigRef: rec.EnvConfigRef,
	})
	if err != nil {
		// No fresh host placeable — the session stays PARKED for a later re-place.
		return store.Session{}, fmt.Errorf("sessions: park/resume ResumeFromPark: re-place failed for session %s: %w", sessionUUID, err)
	}

	// Allocate the NEW index/tap on the target host (VmSpec carried as DATA; the host
	// agent derives the new dstap-<idx> + guest IP). The session UUID is the continuity
	// key — the spec names it so the host binds the new index to the SAME session.
	alloc, err := d.seams.HostAllocator.AllocateAndDefine(ctx, placement.HostID, &hypervisorv1.VmSpec{SessionUuid: sessionUUID})
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume ResumeFromPark: host allocate on re-place target %s failed for session %s: %w", placement.HostID, sessionUUID, err)
	}

	// Append the NEW index epoch: closes the prior (PARKED) epoch, opens the new
	// binding on the target, advances Ref, and burns the new index (never recycled).
	if _, err := d.seams.Store.AppendIndexEpoch(ctx, sessionUUID, store.IndexEpoch{
		HostID:           placement.HostID,
		HostSessionIndex: alloc.HostSessionIndex,
		TapName:          alloc.TapName,
		GuestIP:          alloc.GuestIP,
		GuestIPFamily:    alloc.GuestIPFamily,
		StartedAt:        d.now(),
	}); err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume ResumeFromPark: index-epoch append on re-place failed for session %s: %w", sessionUUID, err)
	}

	// Re-mint identity + interception CA on resume (doc 16 §5.4). The claims are the
	// session-scoped re-mint; the role_ref rides the pinned triple on the record.
	mint, err := d.seams.Minter.Mint(ctx, MintWorkloadIdentityClaims{SessionUUID: sessionUUID}, rec.RolePin.Name)
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume ResumeFromPark: re-mint failed for session %s: %w", sessionUUID, err)
	}

	// PARKED→CREATING@host' (validated). Record the re-placed identity/CA + the
	// placement applied_seq; the SessionCreator drives CREATING→READY→ATTACHED next.
	if !IsTransition(StateParked, StateCreating) {
		return store.Session{}, &ErrIllegalTransition{From: store.SessionParked, To: store.SessionCreating}
	}
	creating := store.SessionCreating
	appliedSeq := placement.AppliedSeq
	// Advance the durable MintExpiry horizon (doc 15 §5.6 / doc 16 §5.4): the re-place
	// re-mint produced a fresh credential, so the persisted horizon must track the NEW
	// MintResult.Expiry alongside IdentityRef/CARef (the create-time persist precedent,
	// sessioncreate.go step 5). A bare Minter that surfaces NO expiry yields the zero
	// value, which persists as the NULL not-set posture — no spurious TTL appears.
	updated, err := d.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:            &creating,
		IdentityRef:      &mint.IdentityRef,
		CARef:            &mint.CARef,
		MintExpiry:       &mint.Expiry,
		PolicyAppliedSeq: &appliedSeq,
	})
	if err != nil {
		return store.Session{}, fmt.Errorf("sessions: park/resume ResumeFromPark: record advance to CREATING@host' failed for session %s: %w", sessionUUID, err)
	}
	return updated, nil
}

// --- helpers ---

func (d *ParkResumeDriver) getSession(ctx context.Context, sessionUUID string) (store.Session, error) {
	rec, err := d.seams.Store.GetSession(ctx, sessionUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Session{}, fmt.Errorf("%w: %s", ErrParkResumeNoSession, sessionUUID)
		}
		return store.Session{}, err
	}
	return rec, nil
}

// toState bridges a store.SessionState string to a sessions.State for IsTransition
// (the two share the verbatim §3 token values; this is a typed re-tag, never a
// re-declaration of the vocabulary).
func toState(s store.SessionState) State { return State(s) }

// mapHypervisorReasonToStore maps the hypervisor.v1.SuspendReason (the driver's
// authoritative reason) onto the store's persisted SuspendReason token. USER→user,
// POLICY_BREACH→policy_breach, REBALANCE→rebalance; UNSPECIFIED→none (which the store
// rejects for a SUSPENDED record, fail-closed).
func mapHypervisorReasonToStore(r hypervisorv1.SuspendReason) store.SuspendReason {
	switch r {
	case hypervisorv1.SuspendReason_SUSPEND_REASON_USER:
		return store.SuspendReasonUser
	case hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH:
		return store.SuspendReasonPolicyBreach
	case hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE:
		return store.SuspendReasonRebalance
	default:
		return store.SuspendReasonNone
	}
}

// mapStoreReasonToAttach maps the store's persisted SuspendReason onto the FROZEN
// attach.v1.SuspendReason the resume-authority gate (resumeauthority.go) keys on. It
// is the inverse projection of mapHypervisorReasonToStore onto the §3 read-only
// projection enum AuthorizeResume consumes.
func mapStoreReasonToAttach(r store.SuspendReason) attachReasonOrUnset {
	switch r {
	case store.SuspendReasonUser:
		return attachReasonUser
	case store.SuspendReasonPolicyBreach:
		return attachReasonPolicyBreach
	case store.SuspendReasonRebalance:
		return attachReasonRebalance
	default:
		return attachReasonUnset
	}
}

// attachReasonOrUnset is a tiny internal enum bridging the store reason to the
// attach.v1.SuspendReason without importing the attach proto into the store layer.
// It is converted to the FROZEN attach.v1.SuspendReason by attachv1Reason at the gate
// boundary — never a re-declaration of the proto enum, just a local carrier.
type attachReasonOrUnset int

const (
	attachReasonUnset attachReasonOrUnset = iota
	attachReasonUser
	attachReasonPolicyBreach
	attachReasonRebalance
)

// SuspendReasonForResume maps a store.SuspendReason to the carrier ResumeFromPark
// takes for parkReason — exported so the reconciler can supply the original park
// reason when it re-places a session whose record cleared the reason at PARK.
func SuspendReasonForResume(r store.SuspendReason) attachReasonOrUnset {
	return mapStoreReasonToAttach(r)
}

// attachv1Reason converts the local carrier to the FROZEN attach.v1.SuspendReason the
// resume-authority gate (resumeauthority.go) consumes. The UNSET carrier maps to the
// proto UNSPECIFIED zero value, which AuthorizeResume fail-closes (no authority can
// resume an unspecified reason).
func attachv1Reason(r attachReasonOrUnset) attachv1.SuspendReason {
	switch r {
	case attachReasonUser:
		return attachv1.SuspendReason_SUSPEND_REASON_USER
	case attachReasonPolicyBreach:
		return attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH
	case attachReasonRebalance:
		return attachv1.SuspendReason_SUSPEND_REASON_REBALANCE
	default:
		return attachv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED
	}
}
