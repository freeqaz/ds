// SPDX-License-Identifier: Apache-2.0

// Package quictrigger is the conformance adapter for the D70 STANDING
// trigger-evaluation check (doc 12 §7, doc 14 §10/§9) — the weekly/nightly
// scheduled decision that combines all three flip-to-inspect triggers into a
// single, timestamped, queryable, NON-JUDGMENT-CALL boolean: flip QUIC posture
// from "block-with-fallback" to "must-inspect"?
//
// # Where this sits relative to the canary (u1)
//
// The sibling quic-canary package (u1) owns the FIRST and standing-est trigger:
// the nightly pinned-client conformance canary that measures first-contact +
// p95 latency and produces a quiccanary.Report whose FlipToInspect() captures
// trigger 1 (canary first-contact failure OR p95 latency regression). This
// package (u3) is the STANDING WEEKLY trigger-evaluation runner that CONSUMES
// that canary Report and joins it with the other two doc 12 §7 triggers into one
// audit-grade flip decision. It does not re-implement the canary verdict — it
// imports quiccanary.Report verbatim so the two halves never disagree on what
// trigger 1 means.
//
// # The three triggers (doc 12 §7, D70 — frozen contract)
//
// The flip from block to must-inspect fires on ANY of:
//
//	(1) NIGHTLY CANARY: the pinned latest-stable client set fails first-contact
//	    to a baseline domain OR regresses p95 first-contact latency beyond budget
//	    vs a TCP-direct control. Owned by quic-canary (u1); consumed here as a
//	    quiccanary.Report. Reasons: ReasonCanaryFailure, ReasonLatencyRegression.
//
//	(2) BASELINE-ENDPOINT POSTURE: a D64 baseline endpoint becomes H3-ONLY (it
//	    no longer answers over TCP 443 at all) OR measurably DEGRADES its TCP 443
//	    service. Reasons: ReasonBaselineH3Only, ReasonBaselineTCPDegraded.
//
//	(3) H3-BOUND WORKLOAD FEATURE: a required workload feature is H3-bound
//	    (WebTransport, MASQUE/connect-udp, an H3-only gRPC API), EVIDENCED BY task
//	    failures JOINED TO udp/443 reject events. Reason: ReasonH3BoundFeature.
//
// "Trigger evaluation is a standing weekly/nightly check, NOT a judgment call"
// (doc 12 §7). This package makes "should we flip?" a pure, deterministic,
// testable function (Evaluate → FlipDecision.Flip) over three planted inputs.
//
// # The LOG-1 reject-counter join (D70 telemetry, doc 14 §2)
//
// Trigger 3's evidence is the WHOLE reason the LOG-1 FlowRecord carries a
// reject-reason code distinguishing QUIC_BLOCKED from generic default-deny
// (boundaryv1.RejectReason_REJECT_REASON_QUIC_BLOCKED, frozen at the Stage-0
// proto freeze, doc 14 §2). The reject rule is counted PER SESSION (D70); the
// reason code is "what makes the D70 flip-to-inspect trigger queryable off-box"
// (doc 14 §2). This package consumes the previous week's FlowRecords, counts
// QUIC_BLOCKED rejects per session (SessionRef join key, never the
// mark_session_index disambiguator, doc 14 §4), and joins those per-session
// counts to the reported task failures: a workload that FAILED while the SAME
// session was racking up udp/443 QUIC_BLOCKED rejects is the evidence trail that
// a required feature is H3-bound. A task failure with NO co-session QUIC reject
// is NOT evidence (it failed for some other reason) and never trips trigger 3 —
// the join is what turns a raw failure count into a flip signal.
//
// # The audit record (doc 12 §7: "logged with timestamp and evidence")
//
// A FlipDecision is the queryable audit artifact the standing check emits each
// run: the boolean Flip, the set of Reasons that fired (each a stable
// FlipReason code), a human-readable Evidence summary per reason with the
// supporting metrics, and a UTC RFC3339Nano Timestamp. When Flip is true the
// entry is timestamped and queryable for audit (FlipDecision.AuditLine produces
// the single canonical log line; FlipDecision.Query* accessors let an auditor
// ask "did we ever flip, when, and on what evidence"). A no-flip run is ALSO
// recorded (Flip=false) so the audit trail is continuous, not just the
// exceptions — a standing check proves it ran AND found nothing as much as it
// proves it found something.
//
// # Two halves, one verdict logic (the quic-canary precedent)
//
//   - OFFLINE (default, always runs; no network): evaluator_test.go drives the
//     PURE Evaluate verdict against PLANTED scenarios — each trigger fires in
//     isolation, combinations fire together, and the all-clear baseline does not
//     flip — exactly as quic-canary asserts its verdict logic offline before the
//     live tier. It also reconciles the FlipReason universe against source (the
//     go/ast self-check the canary and tlsproxyinspect use) so a new reason
//     can't be added without a planted scenario.
//   - SCHEDULED (the standing run): RunWeekly is the runner entry point a
//     nightly/weekly CI job (.github/workflows) invokes — it collects the
//     previous week's inputs (canary Report, baseline posture, the LOG-1
//     FlowRecord stream + reported task failures) and feeds them to the same
//     Evaluate. Until an operator wires the real input collectors against a
//     running deployment it fails LOUDLY with ErrRunnerNotWired (never a vacuous
//     green over an unimplemented collector), the same env-gate posture as
//     quic-canary's RunLive.
//
// # The env-gate + schedule contract (doc 14 §10: NFT-4 at Stage 2)
//
// This is the doc 06 (c)/(d) rig extension that lands WITH NFT-4 at Stage 2: a
// WEEKLY scheduled runner (the cron half of the nightly canary job) that gates
// the D70 flip.
//
//   - DS_QUIC_TRIGGER_LIVE unset or != "1" (default, the CI posture):
//     LiveEnabled() is false; the scheduled runner SKIPS and the offline verdict
//     tests run deterministically with no network.
//   - "1": the operator opts into the scheduled run; RunWeekly fails loudly until
//     the real collectors are wired (ErrRunnerNotWired).
//
// # What this package does NOT own
//
// The canary measurement itself (trigger 1's first-contact + p95 verdict) is
// owned by quic-canary (u1). The udp/443 REJECT itself (the on-box NFT-4
// reject-not-drop + ICMP port-unreachable + per-session counter) is owned by the
// ds-nft ruleset and asserted by the resolverlock NFT-4 closure driver. The
// LOG-1 FlowRecord schema (the QUIC_BLOCKED reject-reason code) is frozen in
// proto/ at Stage 0. This package is the standing JOIN over those frozen
// artifacts that turns three independent signals into one audit-grade flip
// decision.
//
// # Egress-gateway / TLS-termination vocabulary
//
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-terminating boundary service on the
// egress path. The flip-to-inspect this check gates is the D70 carveout: if QUIC
// is ever inspected it would be a SEPARATE non-pingora UDP terminator slotting in
// behind the same mechanism-agnostic recovery interface (doc 12 §7 clean seam) —
// no roadmap commitment, only a measured, queryable, standing trigger.
package quictrigger
