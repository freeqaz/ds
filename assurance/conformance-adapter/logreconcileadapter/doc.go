// SPDX-License-Identifier: Apache-2.0

// Package logreconcileadapter is the env-gated LIVE conformance driver for the
// doc 06 §3c per-session stream-reconciliation (c)-row — suite member LOG-4
// (doc 09 §7). It is the LIVE dual-run leg the guardrail-conformance README
// assigns to assurance/conformance-adapter/ (the published claims package
// assurance/guardrail-conformance/logreconcile states the SAME contract over
// SYNTHETIC Go-literal fixtures with zero egress; D50). This package is where the
// claim goes green against a REAL deployment: it reconciles a real ds-flowlog
// proxy system-of-record (SoR) stream against the independent kernel conntrack
// ledger for ONE live session, behind a DS_LOG4_LIVE env gate, default-skipped.
//
// # The claim, made executable against the live plane
//
// LOG-4 (doc 09 §7) asserts the boundary continuously RECONCILES the two
// independent egress accounting streams for a session: the ds-flowlog proxy
// system-of-record (the per-flow record only the proxy sees — admitting DNS name,
// identity, byte/duration accounting, policy versions; D43) and the kernel
// conntrack ledger (the L3/4 destroy-event record covering DENIED and
// ESCAPE-HATCH flows the proxy never sees; D43). Every byte that left a VM
// interface must be explained by the other stream, the D44 three keys (guest IP /
// tap name / ct mark) must AGREE on every joined pair, no flow is double-counted,
// every TLS/HTTP decision enforced a policy version >= the version of the DNS
// event that admitted it (D72), and any unexplained divergence (or a non-zero
// conntrack-drop counter) is an ALARM, not a log line (doc 12 §2.3 boundary-hole
// alarm). LOG-4 is the per-session accounting identity that catches a redirect
// hole the moment one stream loses a flow the other recorded.
//
// # The reconciliation taxonomy is single-sourced from logreconcile
//
// The offline claims package assurance/guardrail-conformance/logreconcile owns
// the canonical LOG-4 verdict — CheckReconciliation over a SessionReconciliation
// fixture, returning a typed []Violation drawn from its SIX named ViolationClass
// values. This live driver REUSES that taxonomy rather than duplicating it: a
// live run reconciles the real two streams into the same SessionReconciliation
// shape and runs the SAME CheckReconciliation, so the wire pass and the offline
// spec can never disagree on a verdict. The taxonomy is mirrored here as the
// LiveViolationClass enum (the six class STRINGS verbatim) so a SCAFFOLDED runner
// can record the documented expected verdict and so this package compiles in the
// conformance-adapter module AS-IS — assurance/guardrail-conformance is a
// standalone module (GOWORK=off, not in go.work, not in this module's go.mod), so
// importing logreconcile requires a require+replace this in-wave unit does not own
// (the conformance-adapter go.mod + go.work edit). The mirror is the wave-safe
// single-sourcing seam: when the operator wires the deferred manual pass (and the
// one-line go.mod require+replace lands), CheckReconciliation is imported
// directly from logreconcile and LiveViolationClass collapses to a type alias of
// logreconcile.ViolationClass — a mechanical swap, asserted byte-for-byte stable
// by TestLiveViolationClassesMatchLogreconcile against the documented class
// strings so a rename in either half fails LOUDLY here.
//
// # The harness split — env-gated live driver, scaffolded runner body
//
// Mirroring the in-tree siblings (pol2reachability/live_test.go,
// hostredeployconverge/live_test.go, tlsproxyinspect/live_test.go): a single
// const LiveEnvVar gate, a default-skip requireLive(t) -> t.Skip when unset, and
// a SCAFFOLDED runner body. Per the wave rules we never run live claude / cia run
// / podman, and never stand up a real ds-flowlog / conntrack / nft / KVM here
// (D50). RunLive records the documented wire shape and the expected verdict, then
// fails with ErrLiveDriverNotWired so DS_LOG4_LIVE=1 fails LOUDLY rather than
// reporting a false green over an unimplemented driver — a half-configured live
// run can never look like a pass (HONEST STATUS). The deferred manual operator
// step is: stand up a real session through the real boundary, capture its
// ds-flowlog SoR stream + the kernel conntrack ledger for the reconciliation
// window, join them into a SessionReconciliation, and run CheckReconciliation;
// convergence is an empty []Violation. The synthetic offline half
// (logreconcile_test.go) is the in-wave proof.
//
// # No live secrets, no recorded traffic (D50)
//
// This package carries NO live secrets and NO recorded traffic: the only data it
// touches in the default (gate-unset) path is the documented LOG-4 taxonomy
// strings, constructed in-source from the doc 09 §7 spec. The shipped suite runs
// offline with zero data egress; the live half stays gated and never runs in CI.
//
// Governing decisions: D43 (the two independent egress-accounting streams —
// proxy SoR + conntrack ledger), D44 (the three-keys by-construction attribution
// tuple), D72/LOG-4 (continuous version(decision) >= version(admitting DNS)),
// D26/D51 (the guardrail-conformance suite ships runnable against any data-plane
// deployment), D50 (synthetic-in-git fixtures; live legs env-gated +
// default-skipped). Anchors: doc 06 §3c, doc 09 §7 LOG-4, doc 12 §2.3. Network
// prose uses egress-gateway / TLS-termination vocabulary.
package logreconcileadapter

import (
	"errors"
	"fmt"
	"os"
)

// LiveViolationClass mirrors assurance/guardrail-conformance/logreconcile's
// ViolationClass — the named LOG-4 reconciliation failure modes — so this live
// driver can name the expected verdict of a reconciliation WITHOUT duplicating
// the offline package's Check logic and WITHOUT requiring a cross-module import
// the in-wave go.mod does not yet carry (see the package doc). The string values
// are the canonical class names verbatim; TestLiveViolationClassesMatchLogreconcile
// pins them so a rename in either half fails here. When the operator wires the
// deferred pass and the go.mod require+replace lands, replace this with
//
//	type LiveViolationClass = logreconcile.ViolationClass
//
// and the six consts below become references to logreconcile's — a mechanical
// swap that leaves every call site unchanged.
type LiveViolationClass string

// The SIX named LOG-4 reconciliation violation classes (verbatim from
// logreconcile; doc 09 §7). A clean live reconciliation reports NONE of these —
// an empty verdict means the per-session accounting identity held.
const (
	// ViolationProxyFlowUnreconciled — a proxy system-of-record flow has no joining
	// conntrack ledger entry; the kernel accounting lost a flow the proxy recorded.
	ViolationProxyFlowUnreconciled LiveViolationClass = "proxy-flow-unreconciled-in-conntrack"
	// ViolationConntrackFlowUnexplained — a conntrack ledger flow has no joining
	// proxy record and no explicit escape-hatch/denied allowance; a redirect hole.
	ViolationConntrackFlowUnexplained LiveViolationClass = "conntrack-flow-unexplained"
	// ViolationThreeKeysDisagreeNotDropped — the D44 three keys disagreed across the
	// streams but the flow was reconciled rather than dropped (a kernel drop at
	// runtime, never an honored reconciled flow; D44).
	ViolationThreeKeysDisagreeNotDropped LiveViolationClass = "three-keys-disagree-not-dropped"
	// ViolationFlowDoubleCounted — the same flow appears more than once in a single
	// stream; reconciliation is a per-session accounting identity, so a duplicate
	// corrupts the ledger join.
	ViolationFlowDoubleCounted LiveViolationClass = "flow-double-counted"
	// ViolationDecisionVersionOlderThanDNS — the TLS/HTTP decision enforced a policy
	// version OLDER than the DNS event that admitted the flow (D72/LOG-4).
	ViolationDecisionVersionOlderThanDNS LiveViolationClass = "decision-version-older-than-admitting-dns"
	// ViolationDivergenceNotAlarmed — an unexplained divergence (or a conntrack-drop
	// counter) surfaced as a LOG LINE rather than an ALARM (doc 09 §7 / doc 12 §2.3).
	ViolationDivergenceNotAlarmed LiveViolationClass = "divergence-not-alarmed"
)

// LiveViolationClasses is the ordered set of the six classes, for any tooling
// (and the coverage guard) that enumerates the taxonomy uniformly. The order is
// the documented enumeration order of doc 09 §7 / the logreconcile package.
func LiveViolationClasses() []LiveViolationClass {
	return []LiveViolationClass{
		ViolationProxyFlowUnreconciled,
		ViolationConntrackFlowUnexplained,
		ViolationThreeKeysDisagreeNotDropped,
		ViolationFlowDoubleCounted,
		ViolationDecisionVersionOlderThanDNS,
		ViolationDivergenceNotAlarmed,
	}
}

// LiveEnvVar is the single switch for the live half. UNSET (or any value other
// than "1") keeps the live half disabled — LiveEnabled() returns false and the
// live runner SKIPs naming this var, so the default `go test ./...` is offline
// and deterministic. CI never sets it. Set to "1" to opt into the live run (which
// fails LOUDLY until the real ds-flowlog↔conntrack reconciliation driver is
// wired). The name matches the sibling gates (DS_POL2_LIVE, DS_TLS3_LIVE,
// DS_HOST_REDEPLOY_LIVE) and the doc 09 §7 LOG-4 suite member.
const LiveEnvVar = "DS_LOG4_LIVE"

// SessionEnvVar names the live session whose two streams the live half
// reconciles. It only resolves WHICH session the live driver would reconcile —
// it does not by itself enable the live half; LiveEnvVar still governs. LOG-4 is
// a PER-SESSION accounting identity (D43/D44), so the live run is scoped to one
// session at a time.
const SessionEnvVar = "DS_LOG4_SESSION"

// LiveEnabled reports whether the operator opted into the live half via
// LiveEnvVar=1. The default (unset) is false — CI is offline and deterministic.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// LiveSession returns the session id the live run would reconcile (SessionEnvVar
// override, empty default). It does not enable the live half.
func LiveSession() string { return os.Getenv(SessionEnvVar) }

// ErrLiveDriverNotWired fires from the env-gated live half until an operator
// wires the real ds-flowlog↔conntrack reconciliation driver — so DS_LOG4_LIVE=1
// fails LOUDLY rather than reporting a false green over an unimplemented driver.
// There is no live ds-flowlog / conntrack / nft / KVM / boundary in-wave (D50);
// this is a DEFERRED MANUAL step (doc 09 §7 LOG-4, D26/D51 per-session
// stream-reconciliation conformance).
var ErrLiveDriverNotWired = errors.New("logreconcileadapter: live LOG-4 reconciliation driver not wired — DS_LOG4_LIVE=1 requires a real ds-flowlog proxy SoR stream + the kernel conntrack ledger for a live session, which the wave sandbox lacks; this is a DEFERRED MANUAL step (doc 09 §7 LOG-4, doc 06 §3c, D43/D44/D72; reconcile the captured streams into a logreconcile.SessionReconciliation and run CheckReconciliation — an empty verdict is convergence)")

// LiveVerdict is the outcome of a live LOG-4 reconciliation: the named violation
// classes CheckReconciliation reported over the real session's two streams, in
// the documented enumeration order. Reconciled=true iff Violations is empty — the
// per-session accounting identity held with no proxy-flow gap, no unexplained
// conntrack flow, no three-keys disagreement, no double-count, no version
// inversion, and every divergence (none) alarmed. It mirrors the SHAPE of
// logreconcile's []Violation result as a verdict the live driver returns.
type LiveVerdict struct {
	// Session is the live session this verdict reconciled (the per-session scope).
	Session string
	// Violations is every named LOG-4 violation class observed over the real
	// streams (empty iff Reconciled). Drawn from LiveViolationClasses().
	Violations []LiveViolationClass
	// Reconciled reports whether the live reconciliation converged (no violations).
	Reconciled bool
}

// RunLive is the env-gated live driver entry point. It would drive a REAL
// per-session LOG-4 reconciliation: capture the live ds-flowlog proxy
// system-of-record stream and the independent kernel conntrack ledger for
// LiveSession() over a reconciliation window, join them into a
// logreconcile.SessionReconciliation (proxy flows ↔ conntrack flows by flow id,
// carrying the D44 three keys + the D72 policy versions), run
// logreconcile.CheckReconciliation, and return the named violations as a
// LiveVerdict (Reconciled iff empty).
//
// Until an operator wires the real driver it returns ErrLiveDriverNotWired so
// DS_LOG4_LIVE=1 never reports a false green. There is NO live ds-flowlog /
// conntrack / boundary in-wave (D50): the live half is a DEFERRED MANUAL step;
// the synthetic offline half (logreconcile_test.go) is the in-wave proof. The
// verdict taxonomy (LiveViolationClass, mirroring logreconcile.ViolationClass) is
// unchanged when the real driver lands — the operator replaces only this body
// (and swaps the mirror for the direct import; see the package doc).
func RunLive() (LiveVerdict, error) {
	if !LiveEnabled() {
		// Callers gate on LiveEnabled() (requireLive). Returning the sentinel here
		// keeps a misuse from silently producing an empty (vacuously-reconciled) run.
		return LiveVerdict{}, fmt.Errorf("%w: live half not enabled (%s != 1)", ErrLiveDriverNotWired, LiveEnvVar)
	}
	return LiveVerdict{}, ErrLiveDriverNotWired
}
