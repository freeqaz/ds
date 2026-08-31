// SPDX-License-Identifier: Apache-2.0

// Package hostredeployconverge is the env-gated live conformance harness for the
// D26/D51 re-key-on-host-redeploy claim (doc 16 §6.3): when a boundary host is
// redeployed, the live re-key "re-pushes every live digest under the new key
// without violating mint-before-attach". It is the (c) guardrail-assurance
// member that discharges that claim against a LIVE deployment — the deferred
// manual conformance pass owned by the boundary rig.
//
// # The claim, made executable
//
// doc 16 §6.3 adopts as a default: per-host per-epoch keys, rotation at
// golden-image cadence, re-key on host redeploy, and — the load-bearing
// invariant this harness proves — "live re-key re-pushes every live digest under
// the new key without violating mint-before-attach". The orchestrator-side
// production driver is RunHostRedeploy (orchestrator/internal/sessions/
// hostredeploy.go): the freshly redeployed host's digest-feed client starts
// EMPTY and must be loaded + ACKED with the new-key digest set for EVERY live
// session BEFORE the retiring host is revoked. That ordering IS mint-before-
// attach for the re-key: a session is never routable through a host whose new-key
// digest set has not committed, and the old host's old-key digests are revoked
// ONLY after the new host's ack confirms the full set landed. A re-key that drops
// any live digest, or revokes the old key before the new-key set is acked, opens
// a window where a live secret's digest is absent from the keyed plane — a
// fail-OPEN gap the §6.3 default forbids.
//
// # The harness split — offline verdict logic + env-gated live driver
//
// Mirroring quic-canary and pol2reachability, the verdict logic (Evaluate and
// the named Err* sentinels) is PURE and offline-evaluable:
// convergence_test.go drives it against SYNTHETIC re-key observations (no live
// host, no KVM, no boundary), exactly as resolverlock/quic-canary assert their
// shapes offline before the live tier lands. The LIVE half (env-gated behind
// LiveEnvVar, default SKIPPED) drives a REAL host redeploy on a real KVM boundary
// host and feeds the observed re-key into Evaluate; until an operator wires the
// real driver RunLive fails LOUDLY (ErrLiveDriverNotWired),
// so DS_HOST_REDEPLOY_LIVE=1 never reports a false green over an unimplemented
// driver. There is NO live KVM/host/boundary in-wave (D50): the synthetic offline
// half is the in-wave proof; the live drive is the deferred manual step.
//
// # No live secrets, no recorded traffic (D50)
//
// This package carries NO live secrets and NO recorded traffic: every fixture is
// a synthetic, clearly-labeled re-key observation constructed in-test from the
// doc 16 §6.3 spec — it is the spec made executable, not a copy of any shipped
// artifact. The shipped suite runs offline with zero data egress, which keeps
// the on-prem tier safe by construction (D50). The live half stays gated and
// never runs in CI.
//
// Governing decisions: D73/D84 (the secret-digest feed + §6.3 HMAC key
// lifecycle), D26/D51 (the guardrail-conformance suite ships runnable against any
// data-plane deployment), D50 (synthetic-in-git fixtures; live legs env-gated +
// default-skipped), D109 (the host agent acks on behalf of the host-side
// fan-out). Network prose uses egress-gateway / TLS-termination vocabulary.
package hostredeployconverge
