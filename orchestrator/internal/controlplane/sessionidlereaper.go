package controlplane

// sessionidlereaper.go is the SESSION IDLE-TTL REAPER (the writer-less-RUNNING leak
// closer). Nothing else reaps a RUNNING session once its writer DETACHES: the §3
// reconcile loop's escalation leg only sweeps SUSPENDED sessions (reconcileloop.go
// escalateSweep), and the §4.2 destroy re-driver only re-drives records already STUCK
// in DESTROYING (wiring.go RunDestroyReDrive). A session whose human writer detaches
// but is never re-attached therefore stays RUNNING — and its per-session KVM VM (≈8 GB)
// stays resident — FOREVER. This reaper closes that leak.
//
// THE POLICY (conservative by construction; D61 sessions are persistent + re-attachable).
// A session is reaped ONLY when it is BOTH:
//
//   - RUNNING — one of the live, booted, attachable states {READY, ATTACHED, WORKING}
//     (isReapableRunning). NEVER a SUSPENDED / PARKED / SNAPSHOTTING / MIGRATING /
//     RESUMING / PENDING / CREATING / DESTROYING / DESTROYED record: a transient or
//     parked or terminal record is owned by another convergence leg (the escalation
//     sweep, the destroy re-driver, the create coordinator) and must never be raced by
//     this reaper, and a SUSPENDED/PARKED session holds no live VM to leak.
//   - WRITER-LESS for longer than the TTL — no human holds the one writer seat
//     (attendedness.Compute over the AUTHORITATIVE record seat, the SAME writer-
//     attached-only verdict the W2 steal gate reads, writerrelay.go), continuously for
//     more than the configured TTL. The TTL is conservative (default 30m) so a brief
//     detach-and-reattach is never reaped; only a session left writer-less past the
//     whole window is.
//
// THE "WRITER-LESS SINCE" CLOCK (in-memory, level-triggered). There is no persisted
// "writer detached at" column, so the reaper tracks the writer-less-since instant
// ITSELF: the FIRST sweep that observes a RUNNING session writer-less stamps now as its
// writer-less-since; each later sweep that still sees it RUNNING + writer-less keeps that
// stamp; a sweep that sees a writer back (attended) OR the session no longer reapable-
// RUNNING CLEARS the stamp. A session is reaped only once its CONTINUOUS writer-less
// span (now − since) exceeds the TTL. The map is the reaper's own state, touched only on
// its single sweep goroutine (Run), so it needs no lock; on a control-plane RESTART the
// clock resets (a freshly-observed writer-less session is given a full new TTL window —
// the conservative direction: a restart never prematurely reaps).
//
// REAP-EXACTLY-ONCE. When the span exceeds the TTL the reaper drives the EXISTING §4.2
// destroyer (sessions.HostDestroyer — the SAME path DestroySession and the create
// rollback drive, idempotent on session_uuid) and DROPS the session from its tracking
// map, so a single observed leak drives exactly one Destroy call (the destroyer flips the
// record toward DESTROYED; the next sweep no longer sees it RUNNING, so it is not
// re-considered). A Destroy fault is logged and the stamp is RETAINED so the next tick
// re-drives (the level-triggered property; Destroy is idempotent on session_uuid).
//
// DISABLED BY DEFAULT-OVERRIDE. TTL ≤ 0 disables the reaper entirely (newSessionIdleReaper
// returns nil; Run is a no-op): a deployment opts OUT by setting DS_ORCH_SESSION_IDLE_TTL=0.
// The wiring (wiring.go) parses the env, defaults to DefaultSessionIdleTTL (30m), and only
// starts the Run goroutine when a reaper was constructed.
//
// D50 / NO LIVE RUN. The reaper is driven by a fake clock + a fake destroyer + a fake
// lister in tests (sessionidlereaper_test.go); the destroyer it drives is the same
// constructible seam the rest of the §4.2 path is tested against. No live VM/host-agent.

import (
	"context"
	"log/slog"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attendedness"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// DefaultSessionIdleTTL is the default writer-less-RUNNING reap horizon (the strawman the
// wiring takes when DS_ORCH_SESSION_IDLE_TTL is unset, doc 15 §10 cadence values are free).
// It is CONSERVATIVE: long enough that a human stepping away (a brief detach, a refresh, a
// network blip then re-attach) is never reaped, short enough that an abandoned session's
// per-session VM does not leak indefinitely. A deployment tunes it via the env (0 disables).
const DefaultSessionIdleTTL = 30 * time.Minute

// idleReaperSessionLister is the narrow read the reaper needs: the session records to scan
// each sweep. The single ControlPlaneStore satisfies it via ListSessions (the SAME read the
// escalation sweep and the destroy re-driver use), so backing the reaper with the real store
// adds no store method (the storeseams discipline). It is declared narrow so the reaper is
// unit-testable against a fake lister with no full store.
type idleReaperSessionLister interface {
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
}

// sessionIdleReaper destroys a RUNNING session that has had NO writer for longer than the
// TTL, via the EXISTING §4.2 destroyer. Construct with newSessionIdleReaper; drive it with
// Run (the ticker goroutine, mirroring RunDestroyReDrive) or Sweep (one pass — the test
// seam). Its writerlessSince map is touched ONLY on the Run/Sweep goroutine, so it needs no
// lock (the same single-goroutine discipline the reconcile loop holds for its lastBeat map).
type sessionIdleReaper struct {
	lister    idleReaperSessionLister
	destroyer sessions.HostDestroyer
	ttl       time.Duration
	clock     func() time.Time
	logger    *slog.Logger

	// writerlessSince is the in-memory "writer-less since" clock: session UUID → the FIRST
	// instant this reaper observed the session RUNNING + writer-less. A session is reaped
	// once now − writerlessSince[uuid] exceeds ttl. An attended or no-longer-running session
	// is deleted from the map (its writer-less span resets), so a re-attach-then-detach
	// starts a FRESH window. Touched only on the sweep goroutine — no lock needed.
	writerlessSince map[string]time.Time
}

// newSessionIdleReaper builds the reaper over the session lister, the §4.2 destroyer, the
// TTL, the clock, and the logger. A TTL ≤ 0 DISABLES the reaper: it returns nil so the
// wiring simply never starts the Run goroutine (the env-driven opt-out). A nil lister or
// destroyer is a programming error surfaced as a nil reaper too (an un-runnable reaper is
// never half-wired into the run loop) — but the wiring always passes the required store +
// the §4.2 destroyer, so this guards only a misconstruction. A nil clock defaults to
// time.Now; a nil logger to slog.Default.
func newSessionIdleReaper(lister idleReaperSessionLister, destroyer sessions.HostDestroyer, ttl time.Duration, clock func() time.Time, logger *slog.Logger) *sessionIdleReaper {
	if ttl <= 0 || lister == nil || destroyer == nil {
		return nil
	}
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &sessionIdleReaper{
		lister:          lister,
		destroyer:       destroyer,
		ttl:             ttl,
		clock:           clock,
		logger:          logger,
		writerlessSince: make(map[string]time.Time),
	}
}

// Run drives the reaper on a cadence until ctx is cancelled: every interval it runs one
// Sweep (list → stamp/clear the writer-less clock → reap the over-TTL writer-less RUNNING
// sessions). It mirrors RunDestroyReDrive's ticker idiom (wiring.go) — a single goroutine,
// no second writer of the writerlessSince map. A non-positive interval takes the reaper's
// TTL as the cadence (a session is then re-checked at least once per TTL window). It returns
// ctx.Err() on a clean shutdown; a nil reaper Run is a no-op (the disabled case). main.go /
// the wiring starts this in its own goroutine alongside cp.Reconcile.Run.
func (r *sessionIdleReaper) Run(ctx context.Context, interval time.Duration) error {
	if r == nil {
		// Disabled (TTL ≤ 0): nothing to run. Block until ctx is cancelled so a caller that
		// unconditionally starts Run in a goroutine has a uniform lifecycle either way.
		<-ctx.Done()
		return ctx.Err()
	}
	if interval <= 0 {
		interval = r.ttl
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.Sweep(ctx)
		}
	}
}

// Sweep runs ONE reaper pass synchronously on the calling goroutine (the Run goroutine, or a
// test driving it deterministically): it lists the session records, advances the in-memory
// writer-less clock for every RUNNING + writer-less session (stamping a first observation,
// clearing an attended / no-longer-running one), and reaps — via the §4.2 destroyer — every
// session whose CONTINUOUS writer-less span has exceeded the TTL. It is best-effort and
// idempotent: a list fault is logged and the sweep returns (the next tick re-sweeps); a
// per-session Destroy fault is logged and the session is left in the clock (the next tick
// re-drives — Destroy is idempotent on session_uuid). It must NOT be called concurrently with
// Run (the writerlessSince map is single-goroutine state).
func (r *sessionIdleReaper) Sweep(ctx context.Context) {
	if r == nil {
		return
	}
	recs, err := r.lister.ListSessions(ctx, store.SessionFilter{})
	if err != nil {
		r.logger.WarnContext(ctx, "session idle reaper: list failed (continuing; next tick re-sweeps)", slog.Any("err", err))
		return
	}

	now := r.clock()
	// seen collects the UUIDs still RUNNING + writer-less this sweep, so we can GC any stale
	// clock entry for a session that is gone / attended / no longer running (its span resets).
	seen := make(map[string]struct{}, len(recs))

	for i := range recs {
		rec := recs[i]
		if !isReapableRunning(rec.State) {
			continue // not a live RUNNING session — never this reaper's to touch.
		}
		if hasWriter(rec, now) {
			// A human holds the seat: the session is ATTENDED, not a leak. Clear any prior
			// writer-less stamp so a LATER detach starts a fresh full-TTL window (the
			// re-attach-then-detach case is given the whole window again, never reaped early).
			delete(r.writerlessSince, rec.Ref.SessionUUID)
			continue
		}

		// RUNNING + writer-less. Stamp the first observation, or read the existing stamp.
		uuid := rec.Ref.SessionUUID
		seen[uuid] = struct{}{}
		since, ok := r.writerlessSince[uuid]
		if !ok {
			// First sweep that saw this session writer-less: start its clock. It is NOT reaped
			// this pass (a just-observed writer-less session — possibly just detached — gets a
			// full TTL window before any reap; the conservative direction).
			r.writerlessSince[uuid] = now
			continue
		}

		if now.Sub(since) <= r.ttl {
			continue // writer-less, but not yet for longer than the TTL — leave it be.
		}

		// Writer-less for longer than the TTL: reap via the EXISTING §4.2 destroyer (the SAME
		// path DestroySession drives, idempotent on session_uuid). On success drop the clock
		// entry so this leak drives exactly one Destroy (the next sweep no longer sees it
		// RUNNING). On a fault keep the stamp and log: the next tick re-drives (level-triggered;
		// Destroy is idempotent), so a transient host fault never strands the leak un-reaped.
		if derr := r.destroyer.Destroy(ctx, rec.Ref.HostID, uuid); derr != nil {
			r.logger.WarnContext(ctx, "session idle reaper: §4.2 destroy failed (leaving clock stamp; next tick re-drives — Destroy idempotent on session_uuid)",
				slog.String("session", uuid), slog.String("host", rec.Ref.HostID), slog.Duration("writerless_for", now.Sub(since)), slog.Any("err", derr))
			continue
		}
		delete(r.writerlessSince, uuid)
		r.logger.InfoContext(ctx, "session idle reaper: destroyed writer-less RUNNING session past idle TTL (§4.2 teardown via the existing destroyer)",
			slog.String("session", uuid), slog.String("host", rec.Ref.HostID), slog.Duration("writerless_for", now.Sub(since)), slog.Duration("ttl", r.ttl))
	}

	// GC stale clock entries: any session whose stamp we hold but did NOT re-observe RUNNING +
	// writer-less this sweep (it was destroyed, attended, suspended, parked, …) is dropped so
	// the map never grows with dead sessions and a later writer-less span starts fresh.
	for uuid := range r.writerlessSince {
		if _, still := seen[uuid]; !still {
			delete(r.writerlessSince, uuid)
		}
	}
}

// isReapableRunning reports whether a session state is a live, booted, attachable RUNNING
// state this reaper may reap a writer-less occupant of — exactly {READY, ATTACHED, WORKING}.
// Every OTHER state is excluded by design:
//
//   - PENDING / CREATING — not yet booted (no live VM to leak) and mid-create (reaping would
//     race the create coordinator).
//   - SNAPSHOTTING / MIGRATING / RESUMING — transient in-flight transitions owned by another
//     convergence leg; never raced.
//   - SUSPENDED / PARKED — not running (the escalation sweep owns SUSPENDED; a PARKED session
//     holds no live VM); explicitly out of scope.
//   - DESTROYING / DESTROYED — terminal / in-flight teardown (the destroy re-driver owns it).
//
// This is the conservative RUNNING set the unit specifies ("only RUNNING + writer-less; never
// SUSPENDED/PARKED/SNAPSHOTTING"); widening it reopens that scope.
func isReapableRunning(s store.SessionState) bool {
	switch s {
	case store.SessionReady, store.SessionAttached, store.SessionWorking:
		return true
	default:
		return false
	}
}

// hasWriter reports whether a human holds the session's one writer seat (the session is
// ATTENDED), computed via the SAME attendedness verdict the W2 steal gate reads
// (writerrelay.go writerSeatAttendedness): the AUTHORITATIVE record writer-seat fields
// (attendedness.SeatViewFromRecord) under the writer-attached-only interim (zero Input, zero
// Policy — the recent-input gate is off until input-activity events land, exactly the M0/M1
// behavior). A session with no writer (RoleNone, or a half-cleared WriterRole=WRITER with an
// empty holder) reads as NOT attended → writer-less. now stamps the (interim-unused) freshness
// clock so the call is total.
func hasWriter(rec store.Session, now time.Time) bool {
	sig := attendedness.Compute(
		attendedness.SeatViewFromRecord(rec),
		attendedness.Input{},
		attendedness.Policy{},
		now,
	)
	return sig.Attended
}

// sessionHasWriter is the now-free writer-seat verdict the wire projection
// (sessionToProto, Session.has_writer) carries. It reuses the SAME attendedness
// verdict as the idle reaper and the W2 steal gate (hasWriter). In the
// writer-attached-only interim the verdict is independent of the clock (the
// recent-input gate is off, §5.5), so the projection stays a PURE function of the
// record — the zero time only stamps the unread AttendedAt inside Compute. When
// input-activity events land and the recent-input gate turns on, this is where the
// projection threads a real clock.
func sessionHasWriter(rec store.Session) bool {
	return hasWriter(rec, time.Time{})
}
