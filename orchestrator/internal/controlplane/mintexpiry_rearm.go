package controlplane

// mintexpiry_rearm.go — the BOOT RE-ARM SWEEP that makes the durable §5.6 MintExpiry
// column (migration 0010) the SYSTEM OF RECORD for minted-credential expiry across an
// orchestrator restart (doc 16 §5.4).
//
// THE PROBLEM IT CLOSES. The mintExpiryScheduler's per-session timers (wiring.go) are
// IN-PROCESS only (time.AfterFunc). An orchestrator restart loses every armed timer — but
// the DURABLE MintExpiry horizon each live session carries on its record SURVIVES (it is a
// persisted column, written by the §4.1 step-5 create and the §4.2/§5.4 re-mint). Without a
// boot re-arm, a session whose credential horizon falls in a restart window would never be
// re-minted by the scheduler (the reconciler is only a coarse backstop — it converges VM
// presence, not credential TTL), so the credential would silently expire.
//
// THE FIX (doc 16 §5.4 — the durable record is the system of record, the in-process timer
// merely its scheduler). On control-plane assembly (NewControlPlane, right after the
// scheduler is constructed) we LIST the live (non-terminal) sessions and, for every one
// carrying a non-zero persisted MintExpiry, re-arm the scheduler by calling OnMintExpiry
// with the PERSISTED horizon. OnMintExpiry already handles every edge:
//
//   - a horizon already in the PAST arms delay=0, so the re-mint fires PROMPTLY (an
//     already-expired credential re-mints on the next tick — doc 16 §5.4);
//   - the fire path re-reads the persisted horizon and re-mints or, if the horizon moved
//     forward in the meantime, re-arms — so a re-arm of a still-fresh horizon is harmless;
//   - the fire path DROPS idempotently for a terminal/DESTROYING session, so even a
//     to-be-torn-down session re-armed here churns no identity.
//
// This is purely additive to the boot path: it lists, re-arms, and returns. It never
// blocks (OnMintExpiry is non-blocking — it swaps a timer and returns; the re-mint runs
// later on the timer goroutine), never mutates a record, and a store read fault is logged
// and tolerated (the sweep is best-effort; the reconciler remains the backstop). It depends
// ONLY on ListSessions + the scheduler's OnMintExpiry — no new method on any store seam.

import (
	"context"
	"log/slog"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// mintExpiryRearmLister is the NARROW read seam the boot sweep depends on: list the live
// session set so the sweep can re-arm each one's persisted horizon. It is a slice of the
// ControlPlaneStore surface (ListSessions) — *store.Memory / *store.Postgres satisfy it
// natively and tests wire a synthetic fake — so the sweep adds NO method to any store
// interface (the storeseams discipline).
type mintExpiryRearmLister interface {
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
}

// mintExpiryRearmSink is the narrow arm seam the boot sweep drives: re-arm a per-session
// timer at a persisted horizon. *mintExpiryScheduler satisfies it via OnMintExpiry; a test
// wires a recording fake to assert the sweep re-arms exactly the live-with-horizon set.
type mintExpiryRearmSink interface {
	OnMintExpiry(sessionUUID string, expiry time.Time)
}

// reArmMintExpiry is the boot re-arm sweep (doc 16 §5.4). It lists the live (non-terminal)
// sessions and, for every one carrying a non-zero persisted MintExpiry horizon, calls
// sink.OnMintExpiry(uuid, horizon) to re-arm the in-process timer the restart lost — making
// the durable record the system of record across restarts. It returns the number of
// sessions re-armed (for the caller's boot log + the test's assertion).
//
// LIVE SET. It lists with IncludeDestroyed=false so DESTROYED records are omitted at the
// source (no re-arm for a terminal session). A DESTROYING (mid-teardown) session is still
// returned by the list (it is non-terminal in the §3 machine), so the sweep may re-arm it;
// that is SAFE — fire()'s tightened idempotent drop (wiring.go) covers SessionDestroying, so
// a re-armed DESTROYING session re-mints nothing and churns no identity during teardown.
//
// A zero/not-set MintExpiry (the no-TTL posture, MintExpiry.IsZero()) is SKIPPED — there is
// no horizon to track, mirroring the coordinator's no-track guard. A store read fault is
// logged and tolerated (best-effort boot bookkeeping; the reconciler is the backstop), and
// the sweep returns the count re-armed before the fault.
func reArmMintExpiry(ctx context.Context, lister mintExpiryRearmLister, sink mintExpiryRearmSink, logger *slog.Logger) int {
	if logger == nil {
		logger = slog.Default()
	}
	if lister == nil || sink == nil {
		return 0
	}

	live, err := lister.ListSessions(ctx, store.SessionFilter{IncludeDestroyed: false})
	if err != nil {
		// Best-effort: a boot-time store fault leaves the in-process timers unarmed for
		// this cycle; the reconciler remains the backstop and the next assembly (or a
		// create/resume re-mint) re-establishes the horizon. Never fail the boot on it.
		logger.Warn("controlplane: mint-expiry boot re-arm: list live sessions failed — timers not re-armed this cycle (reconciler backstop)",
			slog.Any("err", err))
		return 0
	}

	rearmed := 0
	for _, rec := range live {
		// Defense in depth: skip any terminal record the filter did not omit (it should
		// not return DESTROYED with IncludeDestroyed=false, but the sweep must never
		// re-arm a terminal session). A DESTROYING session is intentionally NOT skipped
		// here — fire()'s tightened drop handles it (no re-mint mid-teardown).
		if rec.State.IsTerminal() {
			continue
		}
		// SKIP the no-TTL posture: a zero MintExpiry means the record tracks no horizon
		// (the coordinator's no-track guard mirrored here).
		if rec.MintExpiry.IsZero() {
			continue
		}
		// RE-ARM at the PERSISTED horizon. A past horizon arms delay=0 (the credential
		// re-mints promptly on the next tick — doc 16 §5.4); a future one arms to it.
		sink.OnMintExpiry(rec.Ref.SessionUUID, rec.MintExpiry)
		rearmed++
	}

	if rearmed > 0 {
		logger.Info("controlplane: mint-expiry boot re-arm: re-armed persisted horizons across restart (doc 16 §5.4)",
			slog.Int("rearmed", rearmed))
	}
	return rearmed
}
