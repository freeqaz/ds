// SPDX-License-Identifier: Apache-2.0

// policy.go — the daemon's POL-4 WatchPolicies consumer + heartbeat reporter
// wiring, plus the supporting M0 offline bindings (the persistent index counter,
// the offline two-phase consumer barriers, and the snapshot persister). These are
// the orchestrator-dialing legs: they reuse the ALREADY-LANDED internal/hostagent
// units (Subscribe -> SnapshotStore -> ApplyCoordinator for POL-4, Stream for the
// heartbeat) — this file only COMPOSES them into the daemon and supplies the M0
// offline seam impls; it does NOT reimplement any of them.
//
// They come up only when -orchestrator-addr is configured; the offline default
// (the M0 smoke path) serves the HypervisorDriverService without them.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// ── newOfflineApplyCoordinator: the landed POL-4 two-phase barrier, M0-wired ──

// offlineBarrier is an M0 offline ConsumerBarrier (hostagent.ConsumerBarrier): it
// stands in for a host-local boundary-service integration (ds-tlsproxy /
// nft-writer / ds-dnsgate) so the landed ApplyCoordinator (the D72 two-phase
// barrier) is constructible and drives end to end offline. Prepare accepts the
// snapshot (staging is a no-op offline — nothing real to stage), Commit is the
// non-fallible flip (a no-op offline). The REAL barriers are the host-local UDS
// gRPC clients to the three consumers (apply.go's seam); they land with those
// integrations.
//
// TODO(host-side): replace with the real per-consumer UDS gRPC ConsumerBarriers.
type offlineBarrier struct {
	name string
}

func (b offlineBarrier) Name() string { return b.name }

func (b offlineBarrier) Prepare(_ context.Context, snap *boundaryv1.PolicySnapshot) (hostagent.PreparedSnapshot, error) {
	// Stage = no-op offline; carry the snapshot through as the opaque prepared
	// handle the coordinator hands back to this same barrier's Commit.
	return snap, nil
}

func (b offlineBarrier) Commit(_ context.Context, _ hostagent.PreparedSnapshot) error {
	// Atomic flip = no-op offline (nothing real to swap).
	return nil
}

// newOfflineApplyCoordinator builds the landed ApplyCoordinator over the three M0
// offline barriers in FIXED admitter-last commit order (ds-tlsproxy + nft-writer
// before ds-dnsgate, D72) with no post-commit sweeper (the host advances its
// applied seq through the coordinator's own commit on the M0 offline path; the
// real revocation sweep wires the SweepRunner when the consumer integrations land).
//
// TODO(host-side): wire the real SweepRunner (the post-commit revocation sweep,
// D72) once the per-consumer integrations land, so apply_seq advances post-sweep.
func newOfflineApplyCoordinator() (*hostagent.ApplyCoordinator, error) {
	order := []hostagent.ConsumerBarrier{
		offlineBarrier{name: hostagent.BoundaryTLSProxy},
		offlineBarrier{name: hostagent.BoundaryNFTWriter},
		offlineBarrier{name: hostagent.BoundaryDNSGate}, // admitter LAST (D72)
	}
	return hostagent.NewApplyCoordinator(order, nil)
}

// ── buildFeedProducers: the live POL-4 fan-out PRODUCERS + the real revocation engine ──
//
// buildFeedProducers is the daemon's SINGLE composition point for the POL-4 host-local
// committed-snapshot fan-out PRODUCERS (doc 11 §5.3, doc 13 §5): the always-bound on-disk
// FeedWriter, the live WatchPolicies(from_seq) carrier (behind DS_DNSGATE_HOST_AGENT_FEED
// =uds:), and — composed FIRST as the revocation leg behind DS_REVOCATION_FEED_LIVE — the
// REAL post-commit RevocationProducer over the vN→vN+1 RevokedSetDiffEngine. It returns the
// bound hostagent.FeedProducers; run() hands fp.Sweeper() to the ApplyCoordinator (so each
// producer fans out EXACTLY behind the prepare/commit barrier, D72) and calls fp.Start(ctx)
// to bring up the live carrier's serve loop when its gate selected it.
//
// THE TWO GATES (single-sourced with the dataplane consumers; default-OFF byte-identical):
//
//   - DS_REVOCATION_FEED_LIVE — arms the REAL revocation producer leg. UNSET (the default,
//     and the only path in the sandbox / CI / unit tests) → NO revocation producer is
//     composed: BindFeedProducers receives a nil revocation arg, so the post-commit chain
//     is EXACTLY [FeedWriter] (behaviorally identical to the prior bare-FeedWriter sweeper —
//     a single-member SweeperChain is a pass-through). The diff engine is NOT even
//     constructed, so the offline apply path never decodes a document. SET → the
//     RevocationProducer (over the diff engine) is composed FIRST so the host is swept onto
//     vN+1 before any version is fanned out (apply_seq advances post-sweep, D72), and behind
//     this gate it DIALS the ds-tlsproxy subscriber's UDS with each vN→vN+1 revoked delta.
//   - DS_DNSGATE_HOST_AGENT_FEED — selects the live host-local WatchPolicies carrier (a
//     "uds:" value). UNSET / non-"uds:" → only the file feed (and the revocation leg if its
//     own gate is set); no carrier UDS is bound, no serve loop spawned (fp.Start is a no-op).
//
// THE DIFF ENGINE'S DOCUMENT DECODER IS THE DEFERRED-MANUAL SEAM. The RevokedSetDiffEngine
// computes the revoked set by diffing successive versions' ADMITTED SETS, which it reads
// through an injected hostagent.AdmittedSetDecoder (the document schema is free
// implementation behind the opaque payload, policy_stream.pb.go). The REAL POL-1 v0 document
// decoder is owner-landed (the analog of the other host-side "owner-landed" seams); the
// daemon scaffolds the engine behind DS_REVOCATION_FEED_LIVE with the deferred decoder
// (deferredAdmittedSetDecoder) so the live producer leg is REACHABLE + fail-closed today, and
// an operator who has wired the real decoder swaps it in. Until then the deferred decoder
// fail-closes the post-commit revocation sweep on the live path (apply_seq HOLDS — the
// fail-closed posture: a version whose revoked-set cannot be computed must not advance). With
// the gate UNSET (every default path) none of this runs.
func buildFeedProducers(feedDir string) (*hostagent.FeedProducers, error) {
	// The REAL revocation producer leg is composed ONLY behind DS_REVOCATION_FEED_LIVE so the
	// default-OFF chain stays EXACTLY [FeedWriter] (byte-identical). The diff engine is built
	// only on the live path — the offline apply never decodes a document.
	var revocation hostagent.Sweeper
	if hostagent.RevocationFeedLiveEnabled() {
		engine, err := hostagent.NewRevokedSetDiffEngine(deferredAdmittedSetDecoder{})
		if err != nil {
			return nil, fmt.Errorf("new revoked-set diff engine: %w", err)
		}
		producer, err := hostagent.NewRevocationProducer(engine)
		if err != nil {
			return nil, fmt.Errorf("new revocation producer: %w", err)
		}
		revocation = producer
	}
	// The D78 attendedness-fact forward leg is armed ALONGSIDE the revocation leg, behind
	// its OWN presence-only gate (DS_ATTENDEDNESS_FEED_LIVE). It is NOT a post-commit Sweeper
	// (it forwards a session-lifecycle fact, not a policy version), so it does not join the
	// SweeperChain; armAttendednessForwardLeg constructs + logs the gated producer's posture.
	// With the gate UNSET (every default / CI / unit-test path) it is a clean no-op — nothing
	// is constructed, nothing dialed — so the default-OFF buildFeedProducers is byte-identical.
	armAttendednessForwardLeg()
	// The D77 grant-return forward leg is armed ALONGSIDE the attendedness leg, behind its
	// OWN presence-only gate (DS_GRANT_RETURN_FEED_LIVE). Like the attendedness leg it is NOT
	// a post-commit Sweeper (it forwards an approved ask-grant, not a policy version), so it
	// does not join the SweeperChain; armGrantReturnForwardLeg constructs + logs the gated
	// producer's posture. With the gate UNSET (every default / CI / unit-test path) it is a
	// clean no-op — nothing is constructed, nothing dialed — so the default-OFF
	// buildFeedProducers is byte-identical.
	armGrantReturnForwardLeg()
	// BindFeedProducers composes the chain in fan-out order: revocation (if armed) FIRST,
	// then the always-bound file feed, then — behind the "uds:" gate — the live carrier. The
	// nft-writer live ingest fan-out (WithNftProgrammer) is the owner-landed leg; the daemon
	// has no real NftProgrammer transport here, so it is not appended (the gate-unset /
	// no-transport path stays byte-identical).
	return hostagent.BindFeedProducers(feedDir, revocation), nil
}

// armAttendednessForwardLeg composes the D78 attendedness-fact producer (the cross-process
// WRITE leg into the ds-tlsproxy AttendednessFeed, attendedness_producer.go) behind its
// presence-only gate DS_ATTENDEDNESS_FEED_LIVE. With the gate UNSET (the default) it is a
// clean no-op — no producer is constructed, no socket is dialed, and the daemon is
// byte-identical to the pre-producer build. SET, it constructs the producer and logs its
// armed posture (the resolved endpoint the operator must single-source with the ds-tlsproxy
// subscriber's DS_TLSPROXY_ATTENDEDNESS_LISTEN).
//
// DEFERRED-MANUAL (the live driver). The producer's Forward is driven by a host-ward
// SessionLifecycleUpdate the host agent decodes (attended=4 / attended_at=5); but no RPC
// carries SessionLifecycleUpdate host-ward today (the orchestrator->host-agent leg is a
// follow-up rider on the frozen hostagent.v1, OUT of scope here). So this leg is ARMED +
// reachable behind the gate, its encode + delivery unit-proven (attendedness_producer_test.go),
// and an operator wiring the live feed end to end swaps in the real lifecycle-update source
// — the analog of the revocation leg's deferred admitted-set decoder. NEVER-LOG-THE-SECRET
// (D73): the log names only the endpoint, never a fact byte.
func armAttendednessForwardLeg() {
	if !hostagent.AttendednessFeedLiveEnabled() {
		return
	}
	producer := hostagent.NewAttendednessProducer()
	slog.Default().Info(
		"D78 attendedness-fact forward leg ARMED (DS_ATTENDEDNESS_FEED_LIVE) — deferred-manual: no host-ward SessionLifecycleUpdate source wired yet (follow-up rider)",
		"endpoint", producer.Endpoint(),
		"live", producer.Live(),
	)
}

// armGrantReturnForwardLeg composes the D77 grant-return producer (the cross-process WRITE
// leg into the ds-tlsproxy GrantReturnFeed, grantreturn_producer.go) behind its presence-only
// gate DS_GRANT_RETURN_FEED_LIVE. With the gate UNSET (the default) it is a clean no-op — no
// producer is constructed, no socket is dialed, and the daemon is byte-identical to the
// pre-producer build. SET, it constructs the producer and logs its armed posture (the
// resolved endpoint the operator must single-source with the ds-tlsproxy subscriber's
// DS_TLSPROXY_GRANT_LISTEN).
//
// DEFERRED-MANUAL (the live driver). The producer's Forward is driven by an approved POL-5
// ask-grant the host agent decodes off the policy stream (orchestrator.v1 ApproveAskRequest
// → a POLICY_ROW_KIND_ASK_GRANT PolicyLogRow); but no live carrier emits that grant
// host-ward here (the orchestrator→host-agent leg is a follow-up rider, OUT of scope). So
// this leg is ARMED + reachable behind the gate, its encode + delivery unit-proven
// (grantreturn_producer_test.go), and an operator wiring the live feed end to end swaps in
// the real ask-grant source — the analog of the attendedness leg's deferred lifecycle-update
// source and the revocation leg's deferred admitted-set decoder. NEVER-LOG-THE-SECRET (D73):
// the log names only the endpoint, never a grant byte.
func armGrantReturnForwardLeg() {
	if !hostagent.GrantFeedLiveEnabled() {
		return
	}
	producer := hostagent.NewGrantReturnProducer()
	slog.Default().Info(
		"D77 grant-return forward leg ARMED (DS_GRANT_RETURN_FEED_LIVE) — deferred-manual: no host-ward ask-grant source wired yet (follow-up rider)",
		"endpoint", producer.Endpoint(),
		"live", producer.Live(),
	)
}

// deferredAdmittedSetDecoder is the DEFERRED-MANUAL stand-in for the real POL-1 v0 document
// decoder the vN→vN+1 diff engine reads its admitted set through. The document's internal
// schema is free implementation behind the frozen (seq, content_hash, document) identity
// (policy_stream.pb.go), and no real decoder has landed host-side, so this seam FAILS CLOSED:
// it returns an error so the diff engine HOLDS apply_seq (the post-commit revocation sweep
// does not advance past a version whose admitted set — and therefore whose revoked set —
// cannot be computed). It is reached ONLY behind DS_REVOCATION_FEED_LIVE; off the gate the
// diff engine is never constructed. NEVER-LOG-THE-SECRET (D73): it names no document byte.
//
// DEFERRED-MANUAL: an operator wiring the live revocation feed end to end swaps this for the
// real document decoder (the analog of the other host-side owner-landed seams). The engine's
// diff logic is unit-proven against a synthetic decoder (revocation_diff_test.go); this stand-in
// keeps the live producer leg reachable + fail-closed until the real decoder lands.
type deferredAdmittedSetDecoder struct{}

func (deferredAdmittedSetDecoder) Decode(_ context.Context, snap *boundaryv1.PolicySnapshot) (hostagent.AdmittedSet, error) {
	return nil, fmt.Errorf(
		"hostagent: admitted-set decoder DEFERRED (no POL-1 v0 document decoder wired host-side); seq %d revoked-set held fail-closed",
		snap.GetSeq(),
	)
}

// RESERVED (host-side): the POL-4 SnapshotStore verify/persist/ack leg. The landed
// hostagent.SnapshotStore (verify content_hash -> persist -> fan out -> ack) sits
// BETWEEN Subscribe and the ApplyCoordinator in the full flow (e2e_test.go), but it
// requires a host-LOCAL durable SnapshotPersister (NOT control-plane Postgres, D6)
// and a boundary.v1 AckPolicySender — both host-side integrations. M0 drives the
// coordinator directly off the verified subscription so the daemon's POL-4 freshness
// gate is exercised today; the store leg wires in when the persister + ack sink land.
//
// TODO(host-side, D6/D36): insert hostagent.NewSnapshotStore(persister, acker, nil)
// between Subscribe and the coordinator so the host persists + acks each applied seq.

// ── reasonTracker: the host-ward FeedWriter drop-reason → heartbeat Detail router ──

// reasonTracker holds the MOST-RECENT per-fed-consumer FeedWriter SnapshotReason (and
// the seq it bit on), the host-side half of the reason-routing seam
// (hostagent.ReasonHook / FeedProducers.SetReasonHook). The bound producer set's file
// feed calls Record on EVERY committed version it classifies (SchemaFailure /
// ContentHashMismatch / ReasonNone), and coordStateSource.Snapshot reads DetailFor(seq)
// off the tracker onto the matching consumer's free-text ServiceHealth.Detail
// (heartbeat.go) an operator queries end to end. It is the last-writer-wins latch a
// clean version CLEARS (ReasonNone → empty Detail), so a stale token never lingers past
// a good apply. State stays HEALTHY throughout — the Detail is a DIAGNOSTIC (doc 13
// §5.1), NOT a health-state transition; a withheld version is a producer-side drop the
// operator must SEE, not a boundary-service outage.
//
// No proto enum is widened (freeze-gated): the token rides the existing free-text
// ServiceHealth.Detail. Guarded by a mutex — the reason hook fires on the post-commit
// sweep goroutine while the heartbeat cadence reads on its own.
type reasonTracker struct {
	mu     sync.Mutex
	latest map[string]reasonAt // consumer name → its most-recent (reason, seq)
}

// reasonAt is one consumer's most-recent classified version: the SnapshotReason and the
// seq it bit on, so Detail renders "<token> at seq <seq>" (or clears on ReasonNone).
type reasonAt struct {
	reason hostagent.SnapshotReason
	seq    uint64
}

// newReasonTracker builds an empty tracker (no consumer has a reason yet → every
// Detail is empty, the prior behavior). Returned as a value the daemon installs onto the
// bound producer set (SetReasonHook) AND hands to coordStateSource so the two share the
// SAME latch.
func newReasonTracker() *reasonTracker {
	return &reasonTracker{latest: make(map[string]reasonAt)}
}

// Record latches consumer's most-recent (reason, seq). It is the hostagent.ReasonHook
// the file feed invokes post-commit; last-writer-wins, so a ReasonNone clean apply
// overwrites (and thereby CLEARS the Detail of) a prior withheld version's token.
func (t *reasonTracker) Record(consumer string, reason hostagent.SnapshotReason, seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.latest[consumer] = reasonAt{reason: reason, seq: seq}
}

// DetailFor renders consumer's most-recent ServiceHealth.Detail: the SnapshotReason's
// DetailFor(seq) ("<token> at seq <seq>" on a withheld version, "" on a clean one — a
// clean apply clears any stale token). A consumer with no recorded reason yet returns
// "" (its prior empty-Detail behavior). Never touches the health STATE.
func (t *reasonTracker) DetailFor(consumer string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.latest[consumer]
	if !ok {
		return ""
	}
	return at.reason.DetailFor(at.seq)
}

// ── startPolicyAndHeartbeat: the orchestrator-dialing legs ────────────────────

// startPolicyAndHeartbeat brings up the two orchestrator-dialing legs of the host
// agent (doc 15 §5.2/§5.3) on background goroutines tracked by wg, each draining on
// ctx (the graceful-shutdown signal):
//
//   - the POL-4 WatchPolicies CONSUMER: hostagent.Subscribe opens the single
//     per-host WatchPolicies subscription, and a pump drives each verified snapshot
//     through the SnapshotStore (verify/persist/ack) and the ApplyCoordinator (the
//     D72 two-phase commit) — the SAME coordinator the RoutabilityGate reads its
//     freshness from, so applying a snapshot makes the host routable;
//   - the HEARTBEAT reporter: hostagent.Stream emits a frame per cadence carrying
//     the host's applied_seq + observed state until ctx drains.
//
// It dials the orchestrator over the configured endpoint. Both legs reuse the
// landed units verbatim; this is pure composition.
//
// SCOPE NOTE (M0): the SnapshotStore here acks through a NIL acker would fail
// construction, so this leg is wired only when an orchestrator endpoint is present;
// the ack sink + the per-consumer sweep are reserved for the host-side integration
// (see newOfflineApplyCoordinator / memPersister TODOs).
//
// observed is the host's self-observation seam (nil offline): the heartbeat
// StateSource calls it each cadence to report the resident sessions in the §3
// observed set, so the reconciler joins each record to its running VM instead of
// re-driving it as a missing VM (the live-attach-stream-teardown fix). A nil
// observer reports no sessions (the prior behavior).
func startPolicyAndHeartbeat(ctx context.Context, wg *sync.WaitGroup, cfg config, coord *hostagent.ApplyCoordinator, observed observedSessionsFunc, logger *slog.Logger) {
	// SEPARATE connections per leg. The two legs MUST NOT share one gRPC conn: the POL-4
	// consumer's runPolicyConsumer returns immediately when the orchestrator does not serve
	// PolicyService.WatchPolicies (the MVP control plane registers SessionService + the
	// heartbeat ingest, NOT PolicyService — so WatchPolicies is Unimplemented and the
	// subscription closes at once). If both legs shared one conn, the POL-4 goroutine's
	// deferred conn.Close() would tear down the SAME conn the heartbeat rides, killing it
	// after a single frame — which then makes the orchestrator's reconciler treat the host as
	// stale and churn redrive (re-creating the placed session every cadence, tearing down the
	// live WatchSession/attach). Each leg owning its own conn isolates that teardown.
	policyConn, err := grpc.NewClient(cfg.orchestratorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Error("orchestrator dial failed; POL-4 consumer + heartbeat NOT started", "addr", cfg.orchestratorAddr, "err", err)
		return
	}
	hbConn, err := grpc.NewClient(cfg.orchestratorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = policyConn.Close()
		logger.Error("orchestrator dial failed; POL-4 consumer + heartbeat NOT started", "addr", cfg.orchestratorAddr, "err", err)
		return
	}

	// POL-4 WatchPolicies consumer leg (its own conn — closing it never touches the heartbeat).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = policyConn.Close() }()
		runPolicyConsumer(ctx, policyConn, coord, logger)
	}()

	// Heartbeat reporter leg (its own conn) with a RECONNECT loop: hostagent.Stream returns
	// on any stream drop (its documented contract — "the caller re-dials"), so the daemon must
	// re-open the stream rather than report a single host beat and go silent forever. Without
	// this the orchestrator stops hearing from the host on the first transient drop and churns
	// redrive. The loop backs off briefly between attempts and exits cleanly on ctx cancel
	// (daemon drain). One Stream call sends a frame per cadence until the stream breaks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = hbConn.Close() }()
		src := &coordStateSource{hostID: cfg.hostID, coord: coord, observed: observed, reasons: cfg.reasonTracker, logger: logger}
		const reconnectBackoff = 2 * time.Second
		for {
			if ctx.Err() != nil {
				return
			}
			dialer := hostagent.NewClientDialer(hostagentv1.NewHostAgentServiceClient(hbConn))
			if _, err := hostagent.Stream(ctx, dialer, src, hostagent.StreamConfig{}); err != nil {
				if ctx.Err() != nil {
					return // daemon drain — not an error worth logging
				}
				logger.Warn("heartbeat stream dropped; reconnecting", "err", err, "backoff", reconnectBackoff.String())
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectBackoff):
			}
		}
	}()
}

// observedSessionsFunc reports the sessions the host is running right now, as the
// SHARED hypervisor.v1.ObservedSession list the heartbeat carries (doc 15 §5.2) —
// the reconciler's observed-state input (§3). It is the host's honest
// self-observation: on the live path it enumerates the resident ds-domains
// (virsh) and joins them to their persisted session records. A nil func (offline,
// or no observer wired) reports NO observed sessions, exactly as before.
type observedSessionsFunc func(context.Context) ([]*hypervisorv1.ObservedSession, error)

// coordStateSource is the heartbeat StateSource (hostagent.StateSource) the daemon
// sources each cadence tick: it reports this host's identity, the host-ward
// applied_seq derived from the POL-4 ApplyCoordinator's committed version (marking
// all three named consumers HEALTHY at that seq so the frozen min-over-three,
// hostagent.AppliedSeq, reflects the host's applied policy version, D72), AND —
// when an observer is wired (the live path) — the OBSERVED-SESSION list the
// reconciler diffs against the desired records (§3).
//
// THE OBSERVED-SESSION LEG (why it is REQUIRED for a live-driven session). The §3
// reconciler runs rule (b) "record with no observed VM → re-drive (re-create the
// VM)" on EVERY heartbeat (and every resync). With the observed list EMPTY, every
// host-resident record (READY/ATTACHED/WORKING) looks like a missing VM, so the
// reconciler re-drives — re-mint + re-clone + re-inject + re-BOOT the domain — every
// cadence, which tears down a live WatchSession/attach stream mid-drive (the
// interactive CC round-trip never completes; the attach seq stays 0). Reporting the
// host's actual resident sessions in the observed set is what makes the reconciler
// JOIN the record to its VM and leave the converged, attached session ALONE. The
// observed element carries a nil ObservedState (un-pin-downable): the reconciler
// treats it as "present, state unknown" — neither a missing-VM re-drive (rule b) nor
// a regression re-converge (rule c, which short-circuits on an un-pin-downable
// observation) — exactly the no-touch convergence a healthy attached session needs.
//
// SCOPE NOTE (M0): the per-consumer health is sourced from the coordinator's
// host-applied seq, not from a live SweepNotifier (the post-commit revocation sweep
// is reserved with the consumer integrations — see newOfflineApplyCoordinator).
// Capacity and samples remain reserved for a richer host-side self-observation
// StateSource; this leg reports the observed-session list (the convergence input)
// and the policy version the reconciler needs to schedule onto the host (the
// unschedulable-floor input, D36). A nil observer (offline) reports no sessions,
// fully backwards-compatible.
type coordStateSource struct {
	hostID   string
	coord    *hostagent.ApplyCoordinator
	observed observedSessionsFunc // nil => report no observed sessions (offline)
	// reasons routes the FeedWriter's most-recent per-consumer drop reason onto the
	// matching ServiceHealth.Detail (the reason-routing seam). nil => no reason routing
	// (every Detail empty, the prior behavior) — the field is nil-safe.
	reasons *reasonTracker
	logger  *slog.Logger
}

func (s *coordStateSource) Snapshot(ctx context.Context) (hostagent.HostState, error) {
	seq := s.coord.AppliedSeq()
	// healthy stamps a consumer HEALTHY at the host-applied seq AND carries its
	// most-recent FeedWriter drop reason on the free-text Detail (the reason-routing
	// seam): DetailFor(name) renders "<token> at seq <seq>" on a withheld version and ""
	// on a clean one (a clean apply clears any stale token). State stays HEALTHY — the
	// Detail is a DIAGNOSTIC (doc 13 §5.1), never a health-state transition. A nil
	// tracker (no reason routing wired) leaves Detail empty, the prior behavior.
	detailFor := func(name string) string {
		if s.reasons == nil {
			return ""
		}
		return s.reasons.DetailFor(name)
	}
	healthy := func(name string) *hostagentv1.ServiceHealth {
		return &hostagentv1.ServiceHealth{
			Name:       name,
			State:      hostagentv1.HealthState_HEALTH_STATE_HEALTHY,
			AppliedSeq: seq,
			Detail:     detailFor(name),
		}
	}
	// The host's honest observed-session list (the §3 convergence input). A nil
	// observer (offline) reports nothing. An observer fault is logged and reported as
	// an EMPTY observed set this beat — NOT a heartbeat error: a failed self-probe must
	// not silence the whole heartbeat (which would mark the host UNKNOWN). The
	// reconciler's level-triggered model re-converges on the next beat that probes
	// cleanly; reporting empty risks ONE spurious re-drive, far less harmful than going
	// silent.
	var observed []*hypervisorv1.ObservedSession
	if s.observed != nil {
		obs, err := s.observed(ctx)
		if err != nil {
			if s.logger != nil {
				s.logger.WarnContext(ctx, "heartbeat: observed-session probe failed; reporting empty observed set this beat (level-triggered re-converges next beat)",
					"host", s.hostID, "err", err)
			}
		} else {
			observed = obs
		}
	}
	return hostagent.HostState{
		HostID:   s.hostID,
		Observed: observed,
		Boundary: []*hostagentv1.ServiceHealth{
			healthy(hostagent.BoundaryTLSProxy),
			healthy(hostagent.BoundaryNFTWriter),
			healthy(hostagent.BoundaryDNSGate),
		},
	}, nil
}

// runPolicyConsumer drives the POL-4 WatchPolicies consumer: it subscribes from
// seq 0, then for each delivered snapshot runs the two-phase apply through the
// coordinator (the SnapshotStore verify/persist/ack is reserved for the host-side
// ack-sink integration — see the SCOPE NOTE). The subscription channel closing is
// the sole end-of-stream signal (graceful drain on ctx, or a stream fault the
// caller's reconnect policy re-drives).
func runPolicyConsumer(ctx context.Context, conn grpc.ClientConnInterface, coord *hostagent.ApplyCoordinator, logger *slog.Logger) {
	ch, err := hostagent.Subscribe(ctx, conn, 0)
	if err != nil {
		logger.Error("POL-4 WatchPolicies subscribe failed", "err", err)
		return
	}
	for snap := range ch {
		out, err := coord.Apply(ctx, snap)
		if err != nil {
			logger.Error("POL-4 apply failed; host stays on prior version", "seq", snap.GetSeq(), "err", err)
			continue
		}
		logger.Info("POL-4 snapshot applied", "seq", snap.GetSeq(), "committed", out.Committed, "applied_seq", out.AppliedSeq)
	}
	logger.Info("POL-4 WatchPolicies subscription closed (drain or reconnect)")
}
