// SPDX-License-Identifier: Apache-2.0

// boundaryreadiness — the host-WIDE pre-step-4 boundary admission precondition
// (the BoundaryReadiness seam, seams.go): before HostAgent.CreateSession mutates
// any host-side state it PROBES that the three host-boundary nft tables of the
// unit-v3 install set are present AND the two boundary services answer. A
// not-ready / uncertain probe refuses the create at StepNone — fail-closed,
// nothing host-side exists to unwind (doc 15 §4.1 "failure at 1–3").
//
// This file is the ALL-PLATFORMS half: the offline always-ready stand-in
// (deferredReadiness), the live config (LiveReadinessConfig), the single-sourced
// required-table constants, and the gate-aware NewBoundaryReadiness factory. The
// LIVE body (a read-only `nft list table inet <name>` shell-out + service dials)
// is Linux-only and lives behind //go:build linux (boundaryreadiness_linux.go),
// with a non-Linux compile stub (boundaryreadiness_stub.go) returning the
// deferred always-ready impl — mirroring the admissionshm _linux/_stub split.
//
// LIVE-GATING (additive, default-path-unchanged): the real probe is reachable
// ONLY under DS_HOSTAGENT_LIVE (the SAME single source of truth — LiveEnabled —
// every other live seam rides) AND, in the daemon composition root, a `ds-nethelper`
// privileged-helper client having been constructed (D148 — the re-key off the old
// nftbridge.Built key, which is permanently false now that the host agent builds
// untagged; cmd/host-agent/seams.go). The nft-list shell-out itself needs no
// privilege, but gating selection on the helper keeps the live boundary-readiness
// choice coherent with the rest of the live composition (newAttachPrimitive).
// With the gate unset (the default, and the only path in the sandbox / CI / unit
// tests) NewBoundaryReadiness returns the no-touch deferredReadiness — byte-identical
// to today (no kernel / socket touch on the create path).
//
// READ-ONLY / FLOOR-INDEPENDENT: the probe mutates NOTHING (a read-only `nft list`
// + TCP dials) and is NOT a runtime input the floor's drop depends on — the kernel
// `ds_boundary` default-deny + QUIC-reject keeps dropping regardless of this probe
// (doc 09 §3). It only gates ADDING a session; removing NFT-4/NFT-3b at runtime
// makes the probe REFUSE new sessions (correct), it never opens the floor.

package libvirt

import (
	"context"
	"time"
)

// The three required host-boundary nft table names (the unit-v3 install set,
// doc 09 §3, ds-nft-bootstrap.service). Single-sourced HERE so the probe agrees
// with the bootstrap unit + the NFT-4 / NFT-3b artifacts; a future drift would
// show up as a probe that refuses a correctly-fenced host (loud, not silent).
const (
	// tableDsBoundary is the NFT-1 default-deny floor table (incl. the QUIC reject,
	// D70). Self-sufficient: the kernel ruleset keeps dropping independent of this
	// probe (doc 09 §3) — its PRESENCE is what the probe admits a session against.
	tableDsBoundary = "ds_boundary"
	// tableDsResolverClosure is the NFT-4 resolver-bypass closure table (D69/D70).
	tableDsResolverClosure = "ds_resolver_closure"
	// tableDsProxyOut is the NFT-3b Stage-3 OUTPUT containment table (D76).
	tableDsProxyOut = "ds_proxy_out"
)

// DefaultProbeTimeout bounds each nft-list shell-out and each service dial so a
// hung nft binary or a wedged listener cannot stall a CreateSession indefinitely.
// CreateSession is per-session / orchestrator-paced (not a hot path), so a short
// per-op bound is correct; a non-clean result inside it is treated as not-ready
// (fail-closed). Overridable per host via LiveReadinessConfig.ProbeTimeout.
const DefaultProbeTimeout = 2 * time.Second

// RequiredBoundaryTables is the single-sourced list of the three host-boundary nft
// tables the live readiness probe requires present (the unit-v3 install set). The
// daemon composition root threads it into LiveReadinessConfig.TablesRequired so the
// probe and the bootstrap unit never drift on a hand-edited literal. Returned as a
// fresh slice each call so a caller cannot mutate the canonical set.
func RequiredBoundaryTables() []string {
	return []string{tableDsBoundary, tableDsResolverClosure, tableDsProxyOut}
}

// LiveReadinessConfig carries the host facts the LIVE BoundaryReadiness probe needs:
// the required table set (RequiredBoundaryTables by default), the two boundary-service
// endpoints to dial, and the per-op timeout. These are host-bring-up FACTS (doc 13
// §4) supplied by the daemon composition root on the operator host; the offline
// module never hardcodes them.
type LiveReadinessConfig struct {
	// TablesRequired is the set of host-boundary nft table names that must ALL be
	// present for the host to be ready (RequiredBoundaryTables()). An empty set is
	// rejected at construction (newLiveReadiness) — never a vacuously-passing table
	// half. The list is the single overridable source for the NFT-3b-optional knob
	// (a host deliberately running the NFT-1 baseline without ds_proxy_out would
	// drop that entry here — Boundary-owner's call, doc 09 §3).
	TablesRequired []string
	// DNSGateAddr is the TCP address the probe dials to prove ds-dnsgate answers
	// (prefer tcp/53 — a UDP "dial" never refuses, so it cannot prove liveness).
	// Empty is rejected at construction — never a vacuously-passing service half.
	DNSGateAddr string
	// TLSProxyAddr is the TCP address the probe dials to prove ds-tlsproxy answers
	// (the ds-tlsproxy redirect/proxy address). Empty is rejected at construction.
	TLSProxyAddr string
	// TableRunner, when non-nil, REPLACES the default in-process
	// `nft list table inet <table>` shell-out. It must return nil exactly when
	// the table is present.
	//
	// This is the D148 seam: under the ROOT-HELPER model the agent runs
	// unprivileged, and `nft list` needs CAP_NET_ADMIN merely to initialise its
	// netlink cache — so the in-process default reports EVERY table absent and
	// fails readiness closed for a floor that is actually installed. The live
	// path injects a runner that asks ds-nethelper (which holds the capability)
	// instead. Left nil the default is unchanged, so the root/dev path and the
	// unit tests behave exactly as before.
	TableRunner func(ctx context.Context, table string) error
	// ProbeTimeout bounds each nft-list shell-out and each service dial. <=0 takes
	// DefaultProbeTimeout (newLiveReadiness fills it) so the live gate is never
	// unbounded.
	ProbeTimeout time.Duration
}

// deferredReadiness is the offline / gate-off BoundaryReadiness stand-in: Probe is
// ALWAYS ready, touching no kernel object and no socket, so the daemon's create path
// off DS_HOSTAGENT_LIVE is byte-identical to today. It is also the non-Linux compile
// target's real type (boundaryreadiness_stub.go returns it under the gate too, since
// the nft-list/dial probe is Linux-only here). Symmetric with deferredAttach.
type deferredReadiness struct{}

// Probe is always-ready off the gate — the host boundary is assumed present (the
// offline/CI/fake path never fences a host). The detail names the offline posture so
// an operator reading a log can tell the gate was deferred, not actually probed.
func (deferredReadiness) Probe(_ context.Context) (bool, string, error) {
	return true, "deferred (offline)", nil
}

// NewBoundaryReadiness returns the gate-aware BoundaryReadiness: the real live probe
// (boundaryreadiness_linux.go newLiveReadiness) when DS_HOSTAGENT_LIVE=1 AND the
// platform supports the nft-list/dial probe (Linux), the no-touch deferredReadiness
// otherwise. The live/offline choice rides the single EnvHostAgentLive source of
// truth (LiveEnabled), matching every other gate-aware seam (NewOverlayStore /
// NewBooter / NewAdmissionSegment). A construction error under the gate (an empty
// dnsgate/tlsproxy addr or empty table set) is surfaced to the caller — the daemon
// root maps it to a FATAL bring-up refusal rather than serving with a vacuous gate
// (fail-closed; never a silently always-ready live gate).
func NewBoundaryReadiness(cfg LiveReadinessConfig) (BoundaryReadiness, error) {
	if !LiveEnabled() {
		return deferredReadiness{}, nil
	}
	return newLiveReadiness(cfg)
}
