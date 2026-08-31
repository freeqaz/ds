package reconciler

// The three frozen §3 conflict rules and the missed-beat sweep — the heart of
// the level-triggered reconcile. reconcileHost runs the full diff for ONE host:
// observed set (from a heartbeat / re-adoption) vs. that host's desired records.
//
//   rule (a) observed VM with no record        → QUARANTINE (suspend) + alarm,
//                                                 NEVER auto-destroy.
//   rule (b) record with no VM, non-terminal    → re-drive, else fail to
//                                                 DESTROYED with an audit event.
//   rule (c) state regression                   → re-converge toward desired.
//
// markMissedBeats is the crash-matrix cell "3 missed heartbeats → UNKNOWN, never
// auto-destroyed". Orphan reaping (rule a/b) diffs every observed set against the
// records, so it runs on every Observe and every Resync — exactly the §4.2
// "every heartbeat carries observed sessions; the reconciler diffs against
// records" contract.

import (
	"context"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// quarantineReason is the suspend annotation the reconciler stamps when it
// quarantines an orphan VM (§3 rule a). It is a free diagnostic label on the
// SuspendRequest provenance, never a §3 state — the state is SUSPENDED, the
// reason class is POLICY_BREACH (the D77 "genuine-threat / operator-driven
// suspend" class an unrecorded VM falls under: an unaccounted-for domain is
// quarantined pending operator triage, never silently torn down).
const quarantineReason = "reconciler: observed VM has no session record (orphan); quarantined pending operator triage (§3 rule a)"

// reconcileHost runs the full conflict-rule diff for one host: the observed
// session set against that host's desired records. It is the single code path
// both the event-driven (Observe) and periodic (Resync) legs converge through.
//
// A store.ErrUnavailable from the record read is the Postgres-DOWN degraded mode
// (doc 15 §3): the reconcile STALLS (returns the degraded error) — it does not
// quarantine the host's VMs as orphans just because the records are unreadable,
// and it does not destroy records it cannot confirm. Running sessions continue;
// host agents stay autonomous on their last verified snapshot.
func (r *Reconciler) reconcileHost(ctx context.Context, hostID string, observed []*hypervisorv1.ObservedSession) error {
	recs, err := r.store.ListSessions(ctx, store.SessionFilter{HostID: hostID, IncludeDestroyed: false})
	if err != nil {
		if degraded(err) {
			r.raise(ctx, AlarmDegraded, "", hostID, "reconcile: store unavailable; running sessions continue on last verified snapshot")
		}
		return fail("reconcile host "+hostID, err)
	}

	// Index records by UUID for the observed→record join, and the observed set by
	// UUID for the record→observed join. Both diffs run off these two maps so the
	// orphan reap (rule a) and the no-VM reap (rule b) see the same snapshot.
	recByUUID := make(map[string]store.Session, len(recs))
	for _, s := range recs {
		recByUUID[s.Ref.SessionUUID] = s
	}
	obsByUUID := make(map[string]*hypervisorv1.ObservedSession, len(observed))
	for _, o := range observed {
		if uuid := o.GetSessionUuid(); uuid != "" {
			obsByUUID[uuid] = o
		}
	}

	// Rule (a) + rule (c): walk the observed set.
	for _, o := range observed {
		uuid := o.GetSessionUuid()
		if uuid == "" {
			// An observed element with no session UUID cannot be joined to a record
			// — treat it as an orphan VM (rule a): quarantine, never destroy. The
			// domain UUID still scopes the quarantine alarm.
			r.quarantineOrphan(ctx, hostID, o)
			continue
		}
		rec, found := recByUUID[uuid]
		if !found {
			// Rule (a): observed VM with no record → quarantine, never auto-destroy.
			r.quarantineOrphan(ctx, hostID, o)
			continue
		}
		// Record exists — check for a state regression (rule c).
		r.reconcileRegression(ctx, rec, o)
	}

	// Rule (b): walk the host-resident records, reap those with no observed VM.
	for _, rec := range recs {
		if _, seen := obsByUUID[rec.Ref.SessionUUID]; seen {
			continue // VM is present; rules a/c handled it.
		}
		r.reconcileMissingVM(ctx, rec)
	}
	return nil
}

// quarantineOrphan implements §3 rule (a): an observed VM with no record is
// SUSPENDED into quarantine (POLICY_BREACH reason class, with provenance noting
// the orphan), NEVER auto-destroyed, and an alarm is raised for operator triage.
// Suspend is idempotent on session_uuid, so re-quarantining the same orphan on
// the next tick is a no-op.
func (r *Reconciler) quarantineOrphan(ctx context.Context, hostID string, o *hypervisorv1.ObservedSession) {
	req := &hypervisorv1.SuspendRequest{
		SessionUuid: o.GetSessionUuid(),
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		// Provenance is REQUIRED for POLICY_BREACH (§5.1). The orphan has no policy
		// rule that fired — the RuleId carries the reconciler's quarantine reason so
		// the "why was this suspended?" answer (doc 15 §4.3) names the orphan-reap
		// origin, not a fabricated policy match.
		Provenance: &boundaryv1.Provenance{
			RuleId: quarantineReason,
		},
	}
	// HOST-TARGETING FAST PATH (doc 15 §4.2; D35 per-host driver, D66 host/index
	// binding). The orphan has NO record, so the SuspendRequest names only a session
	// — the host is unknown to the frozen reconciler.Driver verb. But reconcileHost
	// HOLDS the host that REPORTED the orphan: the heartbeat that surfaced it carries
	// the host_id (§4.2), threaded here as hostID. Stamp it onto the context the
	// driver receives (WithQuarantineHostHint, seams.go) so a host-targeting Driver
	// routes the idempotent Suspend to that ONE host's driver instead of BROADCASTING
	// across every registered host at the ~500-host density the D37 v0 density model
	// sizes for. The hint is OPTIONAL + ADDITIVE: an empty hostID is a no-op (the
	// context is unchanged), and a Driver that does not read the hint keeps its
	// record-resolve / broadcast routing — fully backwards-compatible. The frozen
	// Driver.Suspend signature and the frozen hypervisor.v1 SuspendRequest are
	// untouched; the host rides the context only.
	ctx = WithQuarantineHostHint(ctx, hostID)
	if _, err := r.driver.Suspend(ctx, req); err != nil {
		// The quarantine drive failed; raise the alarm anyway so the orphan is
		// never silently left running un-flagged, and let the next tick retry
		// (Suspend is idempotent). Critically we DO NOT escalate to Destroy — §3
		// rule a is "never auto-destroy".
		r.raise(ctx, AlarmQuarantine, o.GetSessionUuid(), hostID,
			"orphan VM quarantine suspend FAILED (will retry next tick; never auto-destroyed): "+err.Error())
		return
	}
	r.raise(ctx, AlarmQuarantine, o.GetSessionUuid(), hostID,
		"orphan VM (domain "+o.GetDomainUuid()+") suspended into quarantine; never auto-destroyed (§3 rule a)")
}

// reconcileRegression implements §3 rule (c): when the observed state is a
// BACKWARD move from the record's desired state (isRegression), re-converge the
// record toward desired. The reconciler's "desired" is the record's persisted
// state — convergence means driving the observed VM back toward it. At this layer
// the re-converge is signalled by re-asserting the desired record (a Redrive
// of the desired state — idempotent) and an audit alarm; the actual forward
// driver verbs belong to the create/resume choreography, not re-implemented here.
//
// An un-pin-downable observed state (UNSPECIFIED / off-vocabulary) is NOT treated
// as a regression — the host could not report it, so the reconciler leaves the
// record's desired state intact and waits for a pin-downable observation (a
// genuinely stuck VM is reaped by rule b once it stops being observed). This
// avoids thrashing a record on a transient un-observable beat.
func (r *Reconciler) reconcileRegression(ctx context.Context, rec store.Session, o *hypervisorv1.ObservedSession) {
	obs, ok := observedState(o.GetObservedState())
	if !ok {
		return // un-pin-downable observation; not a regression.
	}
	if !isRegression(rec.State, obs) {
		return // observed == desired, a legal in-flight transition, or forward.
	}
	// Re-converge toward desired: re-assert the desired record. If no redriver is
	// wired, the audit alarm still records the regression so an operator sees it;
	// the record's desired state is unchanged (the reconciler never REGRESSES the
	// record to match a slipped VM — that would invert the level-triggered model).
	detail := "state regression observed=" + string(obs) + " desired=" + string(rec.State) + "; re-converging toward desired (§3 rule c)"
	if r.redriver != nil {
		if err := r.redriver.RedriveSession(ctx, rec); err != nil {
			detail += "; redrive request failed (will retry next tick): " + err.Error()
		}
	}
	r.raise(ctx, AlarmReconverge, rec.Ref.SessionUUID, rec.Ref.HostID, detail)
}

// reconcileMissingVM implements §3 rule (b): a record whose VM is absent from the
// host's observed set. If the record is in a state that should NOT have a host VM
// (PARKED — slot released; SUSPENDED — paused but normally still reported;
// PENDING — not placed; DESTROYING/DESTROYED — teardown), absence is expected and
// the reconciler does nothing. Otherwise the record is host-resident with a
// missing VM:
//
//   - re-drive it toward desired via the Redriver (re-create the VM), OR
//   - if re-drive is unavailable or fails, FAIL it to DESTROYED with an audit
//     event (§3 rule b's alternative arm) — a clean, audited finalize, never a
//     silent orphan-record.
//
// The reconciler never auto-destroys a VM here (there is no VM to destroy); it
// finalizes the RECORD to DESTROYED, which the destroy choreography (§4.2) and
// metering then settle. The state write is the §3-sanctioned terminal move.
//
// HOST-TARGETING (cross-ref). The §3 rule-b re-drive arm (reconcileMissingVM →
// Redriver.RedriveSession) is the seam through which a missing-VM record is reaped:
// the Driver contract (reconciler.go) sanctions a §4.2 Destroy on this arm "to fail a
// no-VM non-terminal record to DESTROYED after re-drive is exhausted." When a Redriver
// drives that Destroy through the frozen reconciler.Driver verb, the reporting host this
// reconcile holds (the heartbeat that surfaced the absence, doc 15 §4.2) is the host to
// target: stamping it onto the Destroy context exactly as quarantineOrphan stamps it for
// the Suspend (WithQuarantineHostHint) lets a host-targeting Driver route the idempotent
// teardown to that ONE host's driver instead of broadcasting across the fleet (D35/D66).
// (NB the production ConcreteRedriver re-asserts the CREATE spine and the current
// failToDestroyed arm finalizes the RECORD via a store write — neither drives the Driver
// Destroy verb today; the DESTROYING-sweep DestroyRedriver drives §4.2 over a host-keyed
// DestroyDriver seam, not this context hint. So this is the contract-sanctioned path a
// host-Destroying Redriver WOULD take, guarded so the bridge survives a refactor that
// routes a rule-b Destroy through reconciler.Driver.) The proof the stamp+bridge reach
// prod for the Destroy verb — the real registryDriver wired AS reconciler.Driver, driven
// through this rule-b reap arm — is
// controlplane.TestProductionReconcilerDriverRuleBReapDestroyTargetsReportingHost (the
// Destroy sibling of the orphan-Suspend TestProductionReconcilerDriverQuarantineTargetsReportingHost).
func (r *Reconciler) reconcileMissingVM(ctx context.Context, rec store.Session) {
	if !expectsHostVM(rec.State) {
		return // PARKED/SUSPENDED/PENDING/terminal — no VM expected, not a fault.
	}
	if r.redriver != nil {
		if err := r.redriver.RedriveSession(ctx, rec); err == nil {
			// Re-drive requested; the create choreography re-creates the VM. The
			// record stays in its desired state; next observed cycle confirms it.
			return
		}
		// Re-drive failed → fall through to the fail-to-DESTROYED arm.
	}
	r.failToDestroyed(ctx, rec)
}

// failToDestroyed finalizes a no-VM record to DESTROYED with an audit event (§3
// rule b alternative arm / §4.2). It writes the §3-terminal state through the
// store; a store.ErrUnavailable stalls the finalize (degraded mode — the record
// is left as-is, to be retried when Postgres returns), it never fakes the write.
func (r *Reconciler) failToDestroyed(ctx context.Context, rec store.Session) {
	dest := store.SessionDestroyed
	now := r.now()
	_, err := r.store.UpdateSession(ctx, rec.Ref.SessionUUID, store.SessionUpdate{
		State:       &dest,
		DestroyedAt: store.SetTime(now),
	})
	if err != nil {
		if degraded(err) {
			r.raise(ctx, AlarmDegraded, rec.Ref.SessionUUID, rec.Ref.HostID,
				"fail-to-DESTROYED stalled: store unavailable; record left intact for retry")
			return
		}
		// A non-degraded write fault: alarm so the stuck record is visible; the
		// next tick retries the finalize.
		r.raise(ctx, AlarmFailedToDestroyed, rec.Ref.SessionUUID, rec.Ref.HostID,
			"fail-to-DESTROYED write FAILED (will retry): "+err.Error())
		return
	}
	r.raise(ctx, AlarmFailedToDestroyed, rec.Ref.SessionUUID, rec.Ref.HostID,
		"record had no VM on host and was failed to DESTROYED with audit (§3 rule b); re-drive unavailable/exhausted")
}
