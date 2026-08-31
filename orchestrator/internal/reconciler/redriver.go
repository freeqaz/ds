package reconciler

// redriver.go is the CONCRETE Redriver — the §3 rule-b/rule-c convergence-loop
// CLOSER. The package-core reconciler (reconciler.go) defines the Redriver SEAM
// and runs with it nil: a nil Redriver makes a missing-VM record (rule b) go
// STRAIGHT to fail-to-DESTROYED and a state regression (rule c) downgrade to
// audit-only — neither RE-ASSERTS the record's desired state, so the convergence
// loop never closes. This file supplies the concrete Redriver that DOES re-assert
// desired state, by routing the re-drive through the SAME create spine the
// CreateSession RPC runs (sessions.RedriveSpine → sessions.RunCreateSpine) — never
// a re-implementation of the create choreography inside the reconciler.
//
// WHY THROUGH THE SPINE (the seam the task pins). The §4.1 create choreography is
// owned ONCE, in internal/sessions: the launch-gate → role-pin → step-5-mint
// cluster (RunCreateSpine) and the full ten-step coordinator (SessionCreator) that
// wraps it. The reconciler must NOT grow a second copy of that ordering — a drift
// between "create via the RPC" and "re-create via the reconciler" is exactly the
// convergence bug the level-triggered model exists to avoid. So the concrete
// Redriver holds the SAME spine seams the create path holds and calls
// sessions.RedriveSpine, which reconstructs the create request from the PERSISTED
// record (its already-linked launching principal + its pinned role) and re-runs
// RunCreateSpine. Both the create RPC and the reconciler re-drive thus flow through
// ONE spine (the task's "the Redriver calls the SAME RunCreateSpine, not a copy").
//
// IMPORT DIRECTION (acyclic, the reason this lives reconciler-side). sessions does
// NOT import reconciler (the spine is create-choreography, ignorant of
// convergence); reconciler imports sessions (states.go already reads the frozen §3
// transition table from it). So the concrete Redriver belongs HERE — it depends on
// sessions (RedriveSpine), satisfies the Redriver seam reconciler.go declares, and
// is wired into the loop by passing it as the redriver argument to New.
//
// HOST-SIDE RE-CREATE (the continuation seam). RedriveSpine closes the steps-1–2 +
// step-5 cluster — the part the reconciler must not re-implement. A full re-create
// then drives the host-side steps (3–4, 6–10), which the §4.1 ten-step coordinator
// (sessions.SessionCreator) owns. The concrete Redriver carries an OPTIONAL
// continuation seam (SpineContinuation) the wiring site fills with a thin adapter
// over that coordinator's host-side re-create — so the re-drive can complete the
// VM re-create through the SAME coordinator, not a copy. When the continuation is
// nil (the convergence-only wiring), the re-drive re-asserts the spine cluster and
// requests the host re-create be picked up on the next observed cycle; the record's
// desired state is unchanged and the next heartbeat confirms convergence. Either
// way the reconciler never re-implements the create spine.
//
// D50 (synthetic fixtures only): every collaborator is an injected interface this
// package (or sessions) owns, so the whole re-drive is unit-tested against
// synthetic record fixtures + a spy spine — zero live VM/host-agent/podman.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// SpineRunner is the narrow seam the concrete Redriver re-asserts a record's
// desired state through: it re-runs the §4.1 steps-1–2 + step-5 create cluster for
// a persisted record (re-authorize the already-linked launch, re-resolve the
// pinned role, re-assemble the step-5 mint claims). It is satisfied IN PRODUCTION
// by a thin adapter over sessions.RedriveSpine (which calls the SAME
// sessions.RunCreateSpine the CreateSession RPC runs — never a copy), and IN TESTS
// by a spy that records every re-drive and asserts the record routed through the
// spine. Keeping it an interface (not a direct sessions.RedriveSpine call inside
// RedriveSession) is what lets the unit tests prove "the redriver routes through
// RunCreateSpine" with a fake spine — the task's "assert via a spy/fake spine".
//
// ReassertDesired returns the re-asserted spine cluster output on success. A
// sessions.ErrRedriveNoLaunchingUser error is the NULLABLE / system-session case
// (the record has no linked launching principal, so it cannot be honestly
// re-asserted through the user-launch spine) — the concrete Redriver surfaces it so
// the reconciler takes the §3 rule-b fail-to-DESTROYED-with-audit arm rather than
// re-driving a fabricated launch. Any other error is a transient (resolver/store
// fault) the reconciler retries on the next tick.
type SpineRunner interface {
	ReassertDesired(ctx context.Context, rec store.Session) (sessions.CreateSpineResult, error)
}

// SpineContinuation drives the HOST-SIDE re-create steps (§4.1 steps 3–4, 6–10)
// after the spine cluster re-asserts (steps-1–2 + 5). It is satisfied at the wiring
// site by a thin adapter over the §4.1 ten-step coordinator (sessions.SessionCreator)
// so the re-drive completes the VM re-create through the SAME coordinator the
// create RPC uses — never a reconciler-side copy of the host-side ordering. It is
// OPTIONAL: a nil continuation makes the concrete Redriver re-assert ONLY the spine
// cluster and leave the host re-create to be picked up on the next observed cycle
// (the convergence-only wiring) — the record's desired state is unchanged and the
// next heartbeat re-converges. Carried as a record-typed seam (no proto, no host
// handle here) so the reconciler stays host-mechanics-ignorant.
type SpineContinuation interface {
	ContinueHostReCreate(ctx context.Context, rec store.Session, spine sessions.CreateSpineResult) error
}

// ConcreteRedriver re-asserts a record's desired state through the SAME create
// spine the CreateSession RPC runs — the §3 rule-b/rule-c convergence-loop closer
// the reconciler's Redriver seam expects. Construct it with NewConcreteRedriver and
// pass it as the redriver argument to reconciler.New; the conflict rules then
// re-drive (not audit-only) and re-converge (not downgrade) through this.
//
// It holds the spine runner (required) and the optional host-side continuation. It
// is concurrency-safe by construction (it holds no mutable state — every
// RedriveSession threads its own locals), so it is safe under the reconciler's
// single-goroutine drive AND under a future N-replica drive (the level-triggered
// model: a re-drive is idempotent on session_uuid, so a re-issued one on the next
// tick is a no-op).
type ConcreteRedriver struct {
	spine        SpineRunner
	continuation SpineContinuation
	logger       *slog.Logger
}

// NewConcreteRedriver builds the concrete Redriver. spine is REQUIRED (it is the
// route into the shared create spine — without it there is no re-assert and the
// caller should pass a nil Redriver to reconciler.New instead). continuation MAY be
// nil (the convergence-only wiring: re-assert the spine cluster and let the host
// re-create be picked up next observed cycle). logger nil → slog.Default.
func NewConcreteRedriver(spine SpineRunner, continuation SpineContinuation, logger *slog.Logger) (*ConcreteRedriver, error) {
	if spine == nil {
		return nil, errors.New("reconciler: NewConcreteRedriver: nil spine runner (a redriver with no spine cannot re-assert desired state — pass a nil Redriver to New for the fail-to-DESTROYED posture)")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ConcreteRedriver{spine: spine, continuation: continuation, logger: logger}, nil
}

// RedriveSession satisfies the reconciler.Redriver seam: it re-asserts the
// persisted record's desired state by routing through the SAME create spine the
// CreateSession RPC runs (the SpineRunner → sessions.RedriveSpine →
// sessions.RunCreateSpine). It is called by §3 rule b (a host-resident record whose
// VM is missing → re-drive) and §3 rule c (a state regression → re-converge toward
// desired); in BOTH the contract is "re-assert desired", and re-asserting through
// the spine is what closes the convergence loop.
//
// Returns:
//   - nil — the spine cluster re-asserted (and, when a continuation is wired, the
//     host re-create was driven). The reconciler leaves the record's desired state
//     intact; the next observed cycle confirms the VM is back. (Rule b's re-drive
//     succeeded; rule c re-converged.)
//   - a non-nil error — the re-drive could not be honestly completed. The
//     reconciler takes the §3 rule-b fail-to-DESTROYED-with-audit arm (for rule b)
//     or records the regression audit and retries (rule c). A
//     sessions.ErrRedriveNoLaunchingUser error is the nullable/system-session case
//     (the record cannot be re-asserted through the user-launch spine); it is
//     surfaced so the reconciler classifies it rather than minting a placeholder.
//
// The re-drive is idempotent on session_uuid (the spine's gate re-link, role pin,
// and mint assembly are all idempotent, and a host-side re-create verb is too), so
// a re-issued re-drive on the next tick is a no-op — never a double-create.
func (cr *ConcreteRedriver) RedriveSession(ctx context.Context, rec store.Session) error {
	sessionUUID := rec.Ref.SessionUUID
	if sessionUUID == "" {
		return errors.New("reconciler: redrive: record has empty session UUID")
	}

	// (1) RE-ASSERT the §4.1 steps-1–2 + step-5 cluster through the SHARED spine. This
	// re-authorizes the record's already-linked launch (idempotent), re-resolves its
	// PINNED role, and re-assembles the step-5 mint claims — the create-choreography
	// part the reconciler must NOT re-implement. A spine error is surfaced to the
	// caller's §3 arm (nullable/system-session = the classified sentinel; otherwise a
	// transient).
	spine, err := cr.spine.ReassertDesired(ctx, rec)
	if err != nil {
		if sessions.ErrIsRedriveNoLaunchingUser(err) {
			// The record has no linked launching principal — it cannot be re-asserted
			// through the user-launch spine without fabricating a subject (§3.1 forbids).
			// Surface it so the reconciler takes the rule-b fail-to-DESTROYED-with-audit
			// arm; log it here so the un-re-drivable record is attributable.
			cr.logger.Warn("reconciler: redrive: record has no linked launching principal; cannot re-assert through the spine",
				slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID))
			return fmt.Errorf("reconciler: redrive session %s: %w", sessionUUID, err)
		}
		return fmt.Errorf("reconciler: redrive session %s: re-assert spine: %w", sessionUUID, err)
	}

	// (2) HOST-SIDE RE-CREATE (steps 3–4, 6–10) via the OPTIONAL continuation over the
	// SAME ten-step coordinator. When unwired (convergence-only), the re-assert of the
	// spine cluster is the re-drive's effect and the host re-create is picked up on the
	// next observed cycle (the record's desired state is unchanged). When wired, the
	// continuation drives the host re-create through the shared coordinator — never a
	// reconciler-side copy.
	if cr.continuation == nil {
		cr.logger.Info("reconciler: redrive re-asserted the create spine cluster (host re-create deferred to next observed cycle — no continuation wired)",
			slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID))
		return nil
	}
	if err := cr.continuation.ContinueHostReCreate(ctx, rec, spine); err != nil {
		return fmt.Errorf("reconciler: redrive session %s: host re-create: %w", sessionUUID, err)
	}
	cr.logger.Info("reconciler: redrive re-asserted desired state through the shared create spine (host re-create driven)",
		slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID))
	return nil
}

// SpineRunnerFunc adapts a plain function to the SpineRunner seam — the wiring site
// installs `SpineRunnerFunc(func(ctx, rec) { return sessions.RedriveSpine(ctx,
// gate, roleResolver, mintResolver, pinWriter, rec, logger) })` so the concrete
// Redriver routes through the SAME sessions.RunCreateSpine the create RPC uses,
// with the spine's store-backed seams (gate linker, launching_user resolver, pin
// writer) supplied from the ONE coherent store value (the create path's). Keeping
// the adapter here lets the reconciler depend only on the SpineRunner DATA seam,
// never on the spine's internal seam types.
type SpineRunnerFunc func(ctx context.Context, rec store.Session) (sessions.CreateSpineResult, error)

// ReassertDesired calls the wrapped function.
func (f SpineRunnerFunc) ReassertDesired(ctx context.Context, rec store.Session) (sessions.CreateSpineResult, error) {
	return f(ctx, rec)
}

// SpineContinuationFunc adapts a plain function to the SpineContinuation seam — the
// wiring site installs a closure over the §4.1 ten-step coordinator's host-side
// re-create so the host steps run through the SAME coordinator. Keeping it here
// mirrors SpineRunnerFunc so both halves of the re-drive are wired by closures at
// one site, the reconciler depending only on the DATA seams.
type SpineContinuationFunc func(ctx context.Context, rec store.Session, spine sessions.CreateSpineResult) error

// ContinueHostReCreate calls the wrapped function.
func (f SpineContinuationFunc) ContinueHostReCreate(ctx context.Context, rec store.Session, spine sessions.CreateSpineResult) error {
	return f(ctx, rec, spine)
}

// Compile-time proof that the concrete Redriver satisfies the reconciler.Redriver
// seam reconciler.go declares — so passing *ConcreteRedriver as the redriver
// argument to New is type-correct, and the conflict rules re-drive/re-converge
// through the shared spine instead of degrading to audit-only / fail-to-DESTROYED.
var _ Redriver = (*ConcreteRedriver)(nil)

// ---------------------------------------------------------------------------
// DestroyRedriver — the §4.2 teardown convergence closer for a session STUCK in
// DESTROYING (the destroy-path durability gap this unit closes).
// ---------------------------------------------------------------------------
//
// WHY A SEPARATE RE-DRIVER (not the rule-b missing-VM arm). The §3 conflict rules
// (conflict.go) deliberately EXCLUDE DESTROYING from the host-resident set
// (states.go: a teardown-in-flight record is not expected to show a VM), so the
// rule-b missing-VM arm NEVER reaps a DESTROYING record — and it must not, because
// a freshly-flipped DESTROYING record IS mid-teardown, not a no-VM fault (the
// TestRuleB_NonHostResidentStates_NotReaped invariant). But DestroySession
// (sessionservice.go) flips desired→DESTROYING, drives the §4.2 teardown, and
// finalizes→DESTROYED — and on a TRANSIENT host-teardown FAULT it leaves the record
// DESTROYING with the comment "reconciler will re-drive". Today nothing does: the
// ConcreteRedriver above only re-asserts toward the CREATE spine, so a transient
// fault STRANDS the session in DESTROYING forever. This re-driver is the missing
// backstop: it re-drives a stuck DESTROYING record FORWARD through the SAME §4.2
// teardown (the host-folded Destroy verb, idempotent on session_uuid — doc 15 §4.2)
// and, on a clean teardown, finalizes the record to DESTROYED (the §3-terminal move,
// stamping DestroyedAt; the row is RETAINED, never deleted — D66).
//
// IDEMPOTENT + RE-DRIVEABLE (the level-triggered contract). The §4.2 Destroy verb is
// idempotent on session_uuid (a re-run over an already-torn-down host is a no-op /
// convergence to a no-op, D68), so re-driving a DESTROYING record whose host-side
// teardown ALREADY completed (only the DESTROYED finalize was lost) simply re-runs the
// no-op teardown and lands the finalize. A persistent teardown fault leaves the record
// DESTROYING (the destroy is not yet clean) for the NEXT sweep — never a spurious
// DESTROYED on an un-torn-down session, and never a fail-to-DESTROYED that would claim
// a clean teardown that did not happen.
//
// D50: every collaborator is an injected interface this package owns (the DESTROYING
// lister, the §4.2 destroyer, the finalize writer), so the whole re-drive is unit-tested
// against synthetic record fixtures + a fake destroyer — zero live VM/host-agent/podman.

// DestroyingLister lists the records currently STUCK in DESTROYING (desired = the
// in-flight teardown marker). It is satisfied by the control-plane store's ListSessions
// (filtered to State=DESTROYING) — the store adds no method; this seam is the narrow
// READ the sweep needs. A store.ErrUnavailable (Postgres-DOWN degraded mode) is surfaced
// so the sweep STALLS rather than fabricating an empty DESTROYING set (it never finalizes
// a record it cannot confirm is stuck).
type DestroyingLister interface {
	ListDestroying(ctx context.Context) ([]store.Session, error)
}

// DestroyDriver drives the host-folded §4.2 teardown for a session keyed on
// (hostID, sessionUUID) — idempotent and re-driveable (doc 15 §4.2). It is the SAME
// sessions.HostDestroyer seam the create coordinator's compensating rollback and the
// public DestroySession handler drive (the in-process adapter in orchestrator-lite, the
// remote driver in the fleet), declared narrow here so the reconciler depends only on the
// destroy verb, never the controlplane wiring (acyclic — controlplane imports reconciler).
type DestroyDriver interface {
	Destroy(ctx context.Context, hostID, sessionUUID string) error
}

// DestroyFinalizer writes the §3-terminal DESTROYING→DESTROYED transition (stamping
// DestroyedAt) once the §4.2 teardown is clean. It is satisfied by the control-plane
// store's UpdateSession; declared narrow so the re-driver depends only on the one write.
type DestroyFinalizer interface {
	FinalizeDestroyed(ctx context.Context, sessionUUID string) (store.Session, error)
}

// DestroyRedriver re-drives sessions stuck in DESTROYING forward to DESTROYED via the
// §4.2 teardown — the destroy-path convergence backstop a transient teardown fault needs
// (it left the record DESTROYING; DestroySession's own comment promises the reconciler
// re-drives it, and this is that re-drive). Construct with NewDestroyRedriver and drive it
// with Sweep (the wiring runs it on a cadence alongside the reconcile loop). It holds no
// mutable state, so it is concurrency-safe and a re-issued sweep is a no-op on an
// already-converged record (the §4.2 verb is idempotent on session_uuid).
type DestroyRedriver struct {
	lister    DestroyingLister
	destroyer DestroyDriver
	finalizer DestroyFinalizer
	logger    *slog.Logger
}

// NewDestroyRedriver builds the DESTROYING→DESTROYED re-driver. lister, destroyer, and
// finalizer are REQUIRED (a re-driver missing any of them cannot honestly converge a
// stuck teardown); logger nil → slog.Default.
func NewDestroyRedriver(lister DestroyingLister, destroyer DestroyDriver, finalizer DestroyFinalizer, logger *slog.Logger) (*DestroyRedriver, error) {
	if lister == nil {
		return nil, errors.New("reconciler: NewDestroyRedriver: nil DESTROYING lister")
	}
	if destroyer == nil {
		return nil, errors.New("reconciler: NewDestroyRedriver: nil §4.2 destroyer")
	}
	if finalizer == nil {
		return nil, errors.New("reconciler: NewDestroyRedriver: nil destroy finalizer")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DestroyRedriver{lister: lister, destroyer: destroyer, finalizer: finalizer, logger: logger}, nil
}

// Sweep re-drives every record stuck in DESTROYING forward to DESTROYED via the §4.2
// teardown. For each stuck record it drives the idempotent host-folded Destroy verb and,
// on a clean teardown, finalizes the record to DESTROYED (the §3-terminal move). A teardown
// or finalize FAULT on one record is logged and the record is LEFT DESTROYING for the next
// sweep (never finalized to DESTROYED on an un-torn-down session) — one bad teardown never
// stalls the rest of the sweep. A store.ErrUnavailable from the list (Postgres-DOWN degraded
// mode) STALLS the whole sweep (returned to the caller), so the sweep never fabricates an
// empty DESTROYING set and never converges a record it cannot confirm.
//
// It is idempotent + re-driveable: a record whose host-side teardown already completed (only
// the DESTROYED finalize was lost) re-runs the no-op §4.2 verb and lands the finalize; a
// record whose teardown is genuinely still faulting stays DESTROYING for the next sweep. It
// returns the number of records FINALIZED this sweep (for the wiring's observability/tests).
func (dr *DestroyRedriver) Sweep(ctx context.Context) (int, error) {
	recs, err := dr.lister.ListDestroying(ctx)
	if err != nil {
		return 0, fmt.Errorf("reconciler: destroy re-drive: list DESTROYING: %w", err)
	}
	finalized := 0
	for _, rec := range recs {
		if dr.redriveOne(ctx, rec) {
			finalized++
		}
	}
	return finalized, nil
}

// redriveOne re-drives a single stuck DESTROYING record forward to DESTROYED. It returns
// true iff the record was finalized to DESTROYED this call (a clean §4.2 teardown followed
// by a clean finalize). A fault at either step is logged and returns false — the record is
// left DESTROYING for the next sweep, never finalized on an un-torn-down session.
func (dr *DestroyRedriver) redriveOne(ctx context.Context, rec store.Session) bool {
	sessionUUID := rec.Ref.SessionUUID
	if sessionUUID == "" {
		dr.logger.Warn("reconciler: destroy re-drive: skipping DESTROYING record with empty session UUID")
		return false
	}
	// Guard against a non-DESTROYING record sneaking through a mis-filtered lister: only a
	// DESTROYING record is re-drive-eligible (a terminal DESTROYED is already converged; any
	// other state is not this re-driver's concern — the §3 conflict rules own those).
	if rec.State != store.SessionDestroying {
		return false
	}
	// (1) Re-drive the §4.2 teardown (host-folded Destroy, idempotent on session_uuid). On a
	// transient/persistent fault the record stays DESTROYING (the teardown is not yet clean) —
	// log and leave it for the next sweep, never finalize a session whose host-side teardown
	// did not complete.
	if err := dr.destroyer.Destroy(ctx, rec.Ref.HostID, sessionUUID); err != nil {
		dr.logger.Warn("reconciler: destroy re-drive: §4.2 teardown of stuck DESTROYING record faulted; left DESTROYING for next sweep",
			slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID), slog.Any("err", err))
		return false
	}
	// (2) Teardown clean → finalize the §3-terminal DESTROYING→DESTROYED transition (DestroyedAt
	// stamped; the row is RETAINED — D66). A finalize fault leaves the record DESTROYING; the next
	// sweep re-runs the (now no-op) teardown and re-attempts the finalize.
	if _, err := dr.finalizer.FinalizeDestroyed(ctx, sessionUUID); err != nil {
		dr.logger.Warn("reconciler: destroy re-drive: §4.2 teardown succeeded but DESTROYED finalize faulted; left DESTROYING for next sweep",
			slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID), slog.Any("err", err))
		return false
	}
	dr.logger.Info("reconciler: destroy re-drive: re-drove a stuck DESTROYING session forward to DESTROYED via the §4.2 teardown",
		slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID))
	return true
}
