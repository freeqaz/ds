// Package controlplane is the CONTROL-PLANE CAPSTONE (doc 15 §2/§3/§4.1): the one
// place the three constructible components shipped deliberately un-wired — the §4.1
// session-create coordinator (internal/sessions.SessionCreator), the level-triggered
// reconciler (internal/reconciler), and the §7 scheduler (internal/scheduler) — are
// assembled, together with the orch18 scheduler.Adapter and the concrete Redriver,
// into ONE runnable control plane. NewControlPlane is the constructor; cmd/orchestrator's
// main.go is a thin bootstrap that builds the backends and calls it.
//
// THE THREE LEGS (the task's wiring surface, doc 15):
//
//   - (a) CreateSession RPC — SessionService implements the frozen orchestrator.v1
//     SessionService.CreateSession over the §4.1 ten-step coordinator, built with the
//     production hypervisor.v1 gRPC-backed host seams + the Identity/boundary
//     mint/digest/inject/boot/revoke seams, and the single-store coherence accessor
//     (StoreSeamsStrict) so the launch-gate linker, the launching_user resolver, and
//     the role-pin writer provably share one store (D95/D106).
//
//   - (b) reconciler driving loop — reconcileLoop is the single-goroutine owner that
//     Observes per inbound hostagent.v1.Heartbeat (recording the live HeartbeatStore
//     feed) and Resyncs on cadence, honoring the lastBeat single-goroutine contract;
//     the ConcreteRedriver is wired with SpineRunnerFunc(RedriveSpine) + a host-side
//     re-create continuation and passed as reconciler.New's redriver argument (§3
//     rule b), with an Alarmer relay to LOG-1.
//
//   - (c) scheduler placement — scheduler.Adapter is injected as the coordinator's
//     Placer (§4.1 step 3), over a StoreCandidateSource (the live feed, the tenancy
//     scope, and the store lister) and a policy_log-head PolicySeqSource
//     (store.PolicyHead).
//
// CONSTRAINTS (binding). The only legal cross-tree import is proto/gen/go — the host
// agent / Identity / boundary services are reached ONLY through the frozen generated
// clients (the per-host driver client) or narrow seams this package declares (the
// Identity/boundary verbs), carried as DATA. The whole assembly is unit-tested against
// the generated hypervisor.v1 fake + synthetic fixtures with NO live VM/host-agent/
// podman (D50); main.go env-gates the live network edges behind DS_ORCH_LIVE=1. The
// package adds NO proto edit and NO shared-store-file edit — the one additive store
// query (the policy_log-head PolicyHead) lives in internal/store/controlplane_wiring_queries.go.
//
// Governing decisions: D35 (the two-service shape + reconciliation), D72 (policy-fresh
// placement / applied_seq), D73 (digest-ack routable gate), D82 (mint), D95/D106
// (CreateSessionRequest.role_ref), D17/D29 (CA injection), D50 (synthetic fixtures).
package controlplane
