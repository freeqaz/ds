// SPDX-License-Identifier: Apache-2.0

package reconciler

// reconcileloop.go — the CREDENTIAL-TTL BACKSTOP CADENCE DRIVER: the periodic loop
// that runs the credttl.go ReconcileMintExpiry pass on the SAME rhythm as the §3
// VM-presence Resync (doc 15 §3 periodic full resync / doc 16 §5.4).
//
// WHY A SEPARATE PASS ON THE SAME CADENCE. credttl.go's ReconcileMintExpiry is a
// SEPARATE convergence from Observe/Resync: those diff a host's observed VM set
// against its desired records off a heartbeat; this converges credential TTL off the
// DURABLE record alone (the persisted §5.6 MintExpiry column), needing no observed
// set. It is therefore not folded into Resync's per-host diff — it is its own list +
// re-arm pass. But it runs on the SAME periodic cadence as the full resync (the
// coarse level-triggered backstop behind the in-process mintExpiryScheduler timers):
// once per cadence the backstop re-checks the durable horizons and re-arms any the
// in-process timer / boot sweep is not driving (the two miss windows credttl.go
// documents). This file is that cadence driver, mirroring the control-plane's sibling
// sweeps (RunDestroyReDrive / RunSessionIdleReap) so the credential-TTL backstop joins
// the convergence loop with one uniform start-in-a-goroutine lifecycle.
//
// SINGLE-GOROUTINE SAFETY. ReconcileMintExpiry touches NO mutable reconciler state (it
// reads the store and drives the narrow re-arm seam — it never touches the lastBeat
// map), so it does NOT participate in the lastBeat single-goroutine contract the
// Observe/Resync owner enforces. It is therefore safe to run on its OWN goroutine
// alongside the reconcile loop (unlike Observe/Resync, which must be serialized). The
// control-plane wiring (wiring.go) starts RunMintExpiry in its own goroutine next to
// the reconcile loop's Run and the §4.2 destroy re-drive sweep.
//
// NO-SEAM / NIL POSTURE. With no MintReconverger installed (WithMintReconverger never
// called), ReconcileMintExpiry no-ops (credttl.go) — so this loop ticks but drives
// nothing, leaving the in-process timer / boot sweep as the sole credential-TTL
// mechanism (fully backwards-compatible). A degraded-mode store outage STALLS one pass
// (ReconcileMintExpiry returns the degraded error after raising AlarmDegraded) and the
// loop logs it and retries on the next tick — it never crashes the convergence loop on
// a store outage (the same posture as the reconcile loop's Resync fault handling).
//
// D50 / OFFLINE. The loop is driven by a cancellable context + a synthetic clock-free
// ticker in tests; ReconcileMintExpiry runs against the synthetic store + re-arm fake
// (no live mint, no VM/host-agent/podman).

import (
	"context"
	"log/slog"
	"time"
)

// DefaultMintExpiryBackstopInterval is the cadence the credential-TTL backstop sweeps
// at (RunMintExpiry) when the caller passes a non-positive interval — a strawman (doc
// 15 §10 cadence values are free): often enough that a horizon the in-process timer is
// not driving re-converges promptly, infrequent enough that the list-live read is
// cheap. It mirrors the reconcile loop's periodic full-resync cadence so the §3
// VM-presence convergence and the credential-TTL backstop run on aligned rhythms (doc
// 16 §5.4 "the reconciler runs it on the same periodic cadence as Resync").
const DefaultMintExpiryBackstopInterval = 30 * time.Second

// RunMintExpiry runs the credential-TTL backstop (ReconcileMintExpiry, credttl.go) on a
// cadence until ctx is cancelled: every interval it runs one ReconcileMintExpiry pass —
// list the live records and re-arm / re-mint every one whose persisted MintExpiry
// horizon is already past, through the installed MintReconverger (WithMintReconverger).
// It is the periodic-cadence arm of the credential-TTL backstop, DISTINCT from the boot
// re-arm sweep (controlplane/mintexpiry_rearm.go, single-shot at assembly) and from the
// in-process mintExpiryScheduler timers (per-session time.AfterFunc): this is the coarse
// level-triggered backstop that re-converges a horizon BOTH of those missed.
//
// A non-positive interval takes DefaultMintExpiryBackstopInterval. With no
// MintReconverger installed each pass is a no-op (credttl.go), so a backstop-less wiring
// still has a uniform start-in-a-goroutine lifecycle. A pass fault (a store outage
// raising AlarmDegraded, or any other list/seam error) is logged and the loop continues
// — the next tick re-sweeps (the level-triggered property; ReconcileMintExpiry's re-arm
// is idempotent on session_uuid + horizon). It returns ctx.Err() on a clean shutdown.
// main.go / the control-plane wiring start it in its own goroutine alongside the
// reconcile loop's Run; it is safe to run concurrently because ReconcileMintExpiry
// touches no mutable reconciler state (it never reads/writes lastBeat).
func (r *Reconciler) RunMintExpiry(ctx context.Context, interval time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = DefaultMintExpiryBackstopInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.ReconcileMintExpiry(ctx); err != nil {
				// A degraded-mode store outage (or any pass fault) STALLS this pass only:
				// ReconcileMintExpiry already raised AlarmDegraded and re-converged nothing
				// (sessions ride cached grants to expiry, D39). Log and retry next tick — never
				// crash the convergence loop on a store outage (the reconcile loop's Resync
				// fault posture, mirrored).
				logger.WarnContext(ctx, "reconciler: credential-TTL backstop pass faulted; will retry next tick (level-triggered re-converges)",
					slog.Any("err", err))
			}
		}
	}
}

// reconcileMintExpiryNow runs one ReconcileMintExpiry pass synchronously — a test seam so
// a test can force a credential-TTL backstop pass without waiting for the ticker, mirroring
// the control-plane loop's resyncNow/escalateNow idiom. It is NOT called from RunMintExpiry
// (which owns the ticker); a test calls it directly to drive the backstop deterministically.
func (r *Reconciler) reconcileMintExpiryNow(ctx context.Context) error {
	return r.ReconcileMintExpiry(ctx)
}
