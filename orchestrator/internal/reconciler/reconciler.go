package reconciler

// Package-core: the constructible level-triggered Reconciler (D35).
//
// Desired state lives in Postgres (the control-plane store, internal/store);
// observed state arrives as host-agent heartbeats (the frozen hostagent.v1
// Heartbeat, carrying hypervisor.v1.ObservedSession elements, §5.1/§5.2). The
// reconciler converges the two by DIFFING the observed set against the records —
// it never replays an RPC chain, so a crash recovers purely by re-observing
// (internal/reconciler/doc.go; the hostagent RecoverSessions re-adoption seeds
// the first post-restart observed set).
//
// Two triggers (doc 15 §3, both required): EVENT-DRIVEN reconcile on each
// heartbeat (Observe), PLUS periodic full resync over every host (Resync). The
// conflict rules and crash-matrix cells are the same code on both paths — the
// only difference is the trigger.
//
// This is a CONSTRUCTIBLE component (New + methods), NOT wired into main.go (a
// separate task owns that wiring). Every collaborator is an injected interface
// this package owns, so the whole convergence is unit-testable against synthetic
// heartbeat/record fixtures with zero live VM/host-agent/podman (D50).

import (
	"context"
	"errors"
	"fmt"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// RecordStore is the narrow desired-state read/write seam the reconciler needs,
// satisfied by *store.Memory and *store.Postgres via their existing Repository
// methods (this package adds NO method to the Repository interface — it depends
// only on the three calls below). Keeping the seam narrow is what lets the unit
// tests drive convergence against a tiny in-memory fake or the real *store.Memory
// interchangeably.
//
// A store call returning store.ErrUnavailable is the documented Postgres-DOWN
// DEGRADED mode (doc 15 §3): the reconciler STALLS that work (it neither drives
// the driver nor pretends durability), surfaces a degraded-mode audit, and lets
// running sessions continue on the host's last verified snapshot. It never
// destroys or quarantines on a store outage.
type RecordStore interface {
	// ListSessions returns desired records matching the filter (the host's
	// non-destroyed records when filtered by HostID). The reconciler diffs the
	// host-resident subset of these against the heartbeat's observed set, and joins
	// observed VMs back to records by UUID off this same set — so the
	// "observed VM with no record" quarantine path (rule a) reads the list, never a
	// per-UUID get.
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
	// UpdateSession finalizes a no-VM record to DESTROYED (rule b alternative arm).
	// The reconciler only ever writes states the §3 machine sanctions.
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// Driver is the convergence-action seam — the hypervisor.v1 verbs the reconciler
// drives to move observed toward desired. It is satisfied in production by the
// generated hypervisor.v1 driver client (per host) and in tests by a recording
// fake. The reconciler drives ONLY these verbs and ONLY the §3-sanctioned ones:
//
//   - Suspend with POLICY_BREACH provenance to QUARANTINE an observed VM that has
//     no record (§3 rule a — quarantine, never auto-destroy);
//   - Destroy to fail a no-VM non-terminal record to DESTROYED after re-drive is
//     exhausted (§3 rule b), and to teardown a DESTROYING record (§4.2);
//   - the re-drive of a missing-VM record is a desired-state assertion the
//     create/destroy choreography owns; the reconciler signals it via the
//     RedriveSession hook so this package never re-implements the create spine.
//
// Every verb is idempotent on session_uuid (§5.1), so a re-issued convergence
// action on the next tick is a no-op, never a double-drive.
type Driver interface {
	// Suspend pauses a VM with a reason (the §3 quarantine uses POLICY_BREACH with
	// provenance). Idempotent on session_uuid.
	Suspend(ctx context.Context, req *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error)
	// Destroy drives the §4.2 teardown for a session. Idempotent on session_uuid.
	Destroy(ctx context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error)
}

// Redriver re-asserts a desired record whose VM is missing (the §3 rule-b
// re-drive arm). The reconciler does NOT re-implement the §4.1 create spine; it
// hands the record back to whatever owns re-creation. A nil Redriver means
// "re-drive is unavailable in this wiring" — a missing-VM record then takes the
// fail-to-DESTROYED arm directly (the §3 rule-b alternative), with an audit
// event, never a silent drop.
type Redriver interface {
	// RedriveSession requests re-convergence of a record toward its desired state
	// (re-create the missing VM). It returns nil on a successfully requested
	// re-drive; an error makes the reconciler take the fail-to-DESTROYED arm.
	RedriveSession(ctx context.Context, s store.Session) error
}

// Alarmer raises the §3 operator alarms / audit events the conflict rules and
// crash matrix demand: the quarantine alarm (rule a), the fail-to-DESTROYED audit
// (rule b), the UNKNOWN-on-missed-beats notice, and the Postgres-DOWN degraded
// notice. It is a pure side-channel — the reconciler's convergence decisions do
// not depend on its return, so a noisy or slow alarm sink never stalls
// convergence (a nil Alarmer drops the alarms, used only in tests that assert
// convergence and not alarming).
type Alarmer interface {
	Alarm(ctx context.Context, a Alarm)
}

// AlarmKind enumerates the operator-visible events the reconciler raises. They
// are the §3 audit/alarm surface, not state vocabulary.
type AlarmKind string

const (
	// AlarmQuarantine is raised when an observed VM has no record and is suspended
	// into quarantine (§3 rule a — never auto-destroyed).
	AlarmQuarantine AlarmKind = "quarantine_orphan_vm"
	// AlarmFailedToDestroyed is the audit event when a no-VM non-terminal record is
	// failed to DESTROYED after re-drive is exhausted/unavailable (§3 rule b).
	AlarmFailedToDestroyed AlarmKind = "record_failed_to_destroyed"
	// AlarmReconverge is raised when a state regression is re-converged toward
	// desired (§3 rule c).
	AlarmReconverge AlarmKind = "state_regression_reconverged"
	// AlarmHostUnknown is raised when a host misses the missed-beat threshold and
	// its sessions are marked UNKNOWN — NEVER auto-destroyed (§3 / §5.2).
	AlarmHostUnknown AlarmKind = "host_unknown_missed_heartbeats"
	// AlarmDegraded is raised when a store call returns ErrUnavailable — the
	// Postgres-DOWN degraded mode; new converging writes stall, running sessions
	// continue (§3).
	AlarmDegraded AlarmKind = "store_degraded_postgres_down"
)

// Alarm is one operator-visible event. SessionUUID/HostID scope it; Detail is a
// human string. The reconciler stamps these; the sink (LOG-1 / paging) is the
// Alarmer impl's concern.
type Alarm struct {
	Kind        AlarmKind
	SessionUUID string
	HostID      string
	Detail      string
	At          time.Time
}

// Config tunes the reconciler. The cadence/threshold VALUES are rig-tuned and
// free (doc 15 §10) — only the conflict rules and crash matrix they drive are
// frozen. Zero values take the documented strawman defaults.
type Config struct {
	// MissedBeatThreshold is the number of consecutive heartbeat cadences a host
	// may miss before its sessions are marked UNKNOWN (doc 15 §5.2: 3 missed beats;
	// strawman, free). <=0 takes DefaultMissedBeatThreshold.
	MissedBeatThreshold int

	// Cadence is the heartbeat cadence the missed-beat math is measured against
	// (doc 15 §5.2: 5 s strawman, free). <=0 takes DefaultCadence. The threshold is
	// applied as MissedBeatThreshold*Cadence of silence.
	Cadence time.Duration
}

// errEmptyHostID guards convergence paths that need a host key — a re-adoption or
// reconcile with no host id cannot scope the record diff.
var errEmptyHostID = errors.New("empty host_id")

// DefaultMissedBeatThreshold is the doc 15 §5.2 strawman: 3 missed beats →
// sessions UNKNOWN, never auto-destroyed. A rig-tuned VALUE, free (doc 15 §10).
const DefaultMissedBeatThreshold = 3

// DefaultCadence mirrors the host-agent heartbeat strawman cadence (doc 15 §5.2:
// 5 s, free). Named here so the missed-beat window has a default without the
// reconciler importing the hostagent package.
const DefaultCadence = 5 * time.Second

// Reconciler is the constructible level-triggered convergence component (D35).
// Construct with New; drive it with Observe (event-driven, per heartbeat) and
// Resync (periodic full resync). It is safe to call from one goroutine; the
// driving loop (a separate wiring task) owns concurrency.
type Reconciler struct {
	store    RecordStore
	driver   Driver
	redriver Redriver
	alarm    Alarmer
	now      func() time.Time
	cfg      Config

	// mintReconverger is the OPTIONAL credential-TTL backstop seam (credttl.go),
	// installed additively via WithMintReconverger AFTER New so New's frozen/shared
	// signature (wiring.go constructs the Reconciler) stays untouched. Nil = the
	// credential-TTL backstop is disabled and ReconcileMintExpiry no-ops; the
	// in-process mintExpiryScheduler timer / boot-sweep remains the sole credential-TTL
	// mechanism (the pre-backstop behavior). It is NOT mutable reconcile state — it is
	// set once at wiring and only READ on the ReconcileMintExpiry pass, so it does not
	// participate in the lastBeat single-goroutine contract.
	mintReconverger MintReconverger

	// lastBeat tracks the last time each host's heartbeat was observed, so a
	// missed-beat sweep (markMissedBeats) can find hosts gone silent past the
	// threshold. It is the reconciler's only mutable state — and it is REBUILDABLE
	// purely by re-observing (a fresh reconciler with an empty map converges
	// identically once heartbeats resume), which is the level-triggered /
	// stateless-replica crash-matrix property (a replica crash is a no-op).
	lastBeat map[string]time.Time
}

// New constructs a Reconciler. store and driver are required; redriver and alarm
// may be nil (nil redriver makes a missing-VM record fail to DESTROYED directly;
// nil alarm drops alarms). now defaults to time.Now when nil.
func New(recStore RecordStore, driver Driver, redriver Redriver, alarm Alarmer, now func() time.Time, cfg Config) (*Reconciler, error) {
	if recStore == nil {
		return nil, errors.New("reconciler: nil store")
	}
	if driver == nil {
		return nil, errors.New("reconciler: nil driver")
	}
	if now == nil {
		now = time.Now
	}
	if cfg.MissedBeatThreshold <= 0 {
		cfg.MissedBeatThreshold = DefaultMissedBeatThreshold
	}
	if cfg.Cadence <= 0 {
		cfg.Cadence = DefaultCadence
	}
	return &Reconciler{
		store:    recStore,
		driver:   driver,
		redriver: redriver,
		alarm:    alarm,
		now:      now,
		cfg:      cfg,
		lastBeat: make(map[string]time.Time),
	}, nil
}

// silenceWindow is how long a host may go without a heartbeat before its sessions
// are marked UNKNOWN: MissedBeatThreshold cadences of silence (doc 15 §5.2).
func (r *Reconciler) silenceWindow() time.Duration {
	return time.Duration(r.cfg.MissedBeatThreshold) * r.cfg.Cadence
}

// raise emits an alarm if an Alarmer is wired; it stamps At from the reconciler
// clock so tests get a deterministic timestamp.
func (r *Reconciler) raise(ctx context.Context, kind AlarmKind, sessionUUID, hostID, detail string) {
	if r.alarm == nil {
		return
	}
	r.alarm.Alarm(ctx, Alarm{
		Kind:        kind,
		SessionUUID: sessionUUID,
		HostID:      hostID,
		Detail:      detail,
		At:          r.now(),
	})
}

// degraded reports whether err is the Postgres-DOWN degraded-mode signal
// (store.ErrUnavailable). On it the reconciler stalls converging writes and
// raises AlarmDegraded — running sessions continue, host agents stay autonomous
// on their last verified snapshot (doc 15 §3).
func degraded(err error) bool { return errors.Is(err, store.ErrUnavailable) }

// Observe is the EVENT-DRIVEN reconcile leg (doc 15 §3): one heartbeat in, the
// host's observed set diffed against its desired records. It records the
// heartbeat time (feeding the missed-beat sweep), then runs the three conflict
// rules over this host. Returns a degraded error only when the store is down
// (the caller logs/backs off); other per-session faults are absorbed into alarms
// so one bad session never stalls the host's reconcile.
func (r *Reconciler) Observe(ctx context.Context, hb *hostagentv1.Heartbeat) error {
	if hb == nil {
		return errors.New("reconciler: nil heartbeat")
	}
	hostID := hb.GetHostId()
	if hostID == "" {
		return errors.New("reconciler: heartbeat with empty host_id")
	}
	r.lastBeat[hostID] = r.now()
	return r.reconcileHost(ctx, hostID, hb.GetObserved())
}

// Resync is the PERIODIC FULL RESYNC leg (doc 15 §3): it re-runs the conflict
// rules over EVERY host the records know about, using the supplied per-host
// observed snapshot (the latest heartbeat-observed set per host, the same
// ObservedSession shape RecoverSessions produces). A host present in the records
// but ABSENT from observedByHost is a host that has reported nothing this cycle —
// the missed-beat sweep (run here) handles it; resync never invents an empty
// observed set for it and so never spuriously destroys its sessions.
//
// observedByHost maps host_id → that host's currently-observed sessions. Hosts in
// the map are reconciled against their records; hosts only in the records get the
// missed-beat treatment via markMissedBeats.
func (r *Reconciler) Resync(ctx context.Context, observedByHost map[string][]*hypervisorv1.ObservedSession) error {
	hosts, err := r.knownHosts(ctx)
	if err != nil {
		if degraded(err) {
			r.raise(ctx, AlarmDegraded, "", "", "resync: store unavailable; running sessions continue on last verified snapshot")
			return err
		}
		return err
	}
	// Reconcile every host that reported an observed set this cycle. A
	// resync-carried observed set IS a fresh observation (the latest
	// heartbeat-observed set per host, the §3 contract) — stamp lastBeat so the
	// missed-beat sweep below does NOT spuriously mark a host that just reported
	// a live set UNKNOWN (a host in observedByHost is by definition not silent;
	// the sweep is for hosts that reported NOTHING this cycle).
	now := r.now()
	for hostID, observed := range observedByHost {
		hosts[hostID] = true
		r.lastBeat[hostID] = now
		if err := r.reconcileHost(ctx, hostID, observed); err != nil {
			if degraded(err) {
				return err
			}
			// non-degraded per-host fault already absorbed into alarms by
			// reconcileHost; keep resyncing the rest of the fleet.
		}
	}
	// Sweep for hosts gone silent past the threshold (no observed set this cycle,
	// or never reporting) → their sessions go UNKNOWN, never auto-destroyed.
	r.markMissedBeats(ctx, hosts)
	return nil
}

// knownHosts returns the set of host_ids that appear on any non-destroyed record
// (the hosts the reconciler is responsible for). Used by Resync to bound the
// fleet sweep.
func (r *Reconciler) knownHosts(ctx context.Context) (map[string]bool, error) {
	recs, err := r.store.ListSessions(ctx, store.SessionFilter{IncludeDestroyed: false})
	if err != nil {
		return nil, err
	}
	hosts := make(map[string]bool)
	for _, s := range recs {
		if s.Ref.HostID != "" {
			hosts[s.Ref.HostID] = true
		}
	}
	return hosts, nil
}

// fail wraps a non-degraded store/driver error for return paths that propagate
// one (currently only the degraded path returns up; this keeps the wrapping in
// one spot if that changes).
func fail(op string, err error) error { return fmt.Errorf("reconciler: %s: %w", op, err) }

// Compile-time proof that the real control-plane stores satisfy the reconciler's
// narrow desired-state seam via their existing Repository methods — the
// reconciler adds NO method to the Repository interface, and the in-memory and
// Postgres impls are interchangeable behind RecordStore exactly as they are
// behind Repository.
var (
	_ RecordStore = (*store.Memory)(nil)
	_ RecordStore = (*store.Postgres)(nil)
)
