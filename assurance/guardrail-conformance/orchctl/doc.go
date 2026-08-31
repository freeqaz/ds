// SPDX-License-Identifier: Apache-2.0

// Package orchctl holds the executable form of the orchestrator-owned and
// co-owned (c)-tier guardrail-conformance rows from doc 15 §11 ("Assurance
// hooks", the "(c) rows owned or co-owned" bullet). It is part of the D51 public
// claims package ([../README.md]): every guardrail the docs promise becomes a
// test that tries to make the guardrail FAIL and asserts it doesn't (doc 06
// §3c). These rows live in their OWN subpackage, distinct from the boundary
// nftgate/ rows and the goldenfreshness/ rotation row, because the guarantees are
// orchestrator-side (the session state machine, the create/placement choreography,
// the policy distribution clock, and the control-plane log sink), contributed by
// the workstream that owns each guarantee (README.md).
//
// VOCABULARY (doc 06 §3c, binding). Never attack / redteam / intrusion. These are
// **assurance tests for properties we advertise** — the same way a database ships
// tests that prove it doesn't lose committed writes. Each row is named for the
// property it proves and the NAMED way a regression would let it slip; a fixture
// that models a defeat attempt is named for the property it probes (a
// stale-applied_seq host, an unswept eviction), never for an attacker.
//
// THE FIVE ROWS (doc 15 §11; cross-anchored to §3, §4.1, §4.3, §7, doc 13 §5/§7,
// doc 06 §3c):
//
//	(1) suspend-on-breach execution — a boundary→orchestrator suspend signal
//	    (§4.3) drives Suspend(reason) under the D77 taxonomy: a genuine-threat
//	    class (blocklist hit / a rule configured action: suspend) suspends the VM,
//	    while an ordinary action: block behavioral cap (the D77 default,
//	    self-healed in-band) does NOT escalate; the reason stays inside the frozen
//	    §3 SUSPENDED(reason) enum, and a POLICY_BREACH suspend carries POL-3
//	    provenance (§5.1). This is the doc 06 §3c "Suspend-on-breach fires" row's
//	    orchestrator-execution half (D77/D35; NOT the original D53).
//
//	(2) ask-grant atomicity (doc 13 §7) — a session-scoped TTL'd grant travels
//	    stream → barrier → sweep; the FIRST post-apply retry SUCCEEDS, while a
//	    retry during the commit window fails cleanly at DNS (REFUSED), never as
//	    resolve-success-then-TLS-refusal, and never enforces ahead of the
//	    two-phase admitter-last barrier (doc 13 §5/§7, doc 15 §4.3, D72/D36).
//
//	(3) skew-widening / scheduler-refusal — the scheduler places ONLY on hosts
//	    whose heartbeat applied_seq is within the staleness budget of the swept
//	    policy head; a stale-applied_seq host is UNSCHEDULABLE (a widening cannot
//	    take effect there), and the §4.1 step-9 re-check re-refuses a host that
//	    fell behind after placement (doc 15 §7 filter 1 / §4.1 step 3+9, doc 13 §7
//	    "Skew-widening test", D36/D72).
//
//	(4) revocation-of-derived-state clock — doc 15 §11 says "this doc owns both
//	    ends": the clock runs from policy_log commit (the orchestrator write path,
//	    §4.3) to the last consumer's post-sweep-plus-flush applied_seq (the
//	    readiness report, §5.2). A severing-rung block EVICTS derived state within
//	    the sweep (not left to ride the TTL clamp), a non-severing change leaves
//	    established flows alone (D53), and applied_seq advances to the committed
//	    version only post-sweep-plus-flush (doc 13 §5/§7, doc 15 §11, D72/D68/D53).
//
//	(5) D74 pack-staleness canary evidence feed — CO-OWNED for its evidence feed
//	    only: the control-plane log sink supplies the enforcing-mode hit data
//	    behind the zero-hits retirement rule ("30 days of zero enforcing-mode hits
//	    opens a removal-review PR", doc 13 §7). This row asserts the evidence-feed
//	    obligation: the zero-hits judgment is made ONLY against ENFORCING-mode hits
//	    over a COMPLETE window — a shadow/observe-mode hit is not evidence of use,
//	    and a telemetry gap is not a clean zero (doc 15 §11, doc 13 §7, D74).
//
// THE CHECK. Each row is a pure Decide/Check function over a SYNTHETIC fixture
// (D50): a Go-literal state-machine input the test builds, exercised with a
// CONFORMING control (the guardrail holds clean) and one fixture per NAMED
// violation class. The shape mirrors the goldenfreshness sibling — a typed
// fixture, a typed ViolationClass taxonomy, and a Check returning every NAMED
// violation in a stable order — so the row "fails NAMED" rather than with a bare
// boolean. The anchor constants the docs fix (the DefaultCanaryWindowDays = 30
// retirement window) are restated here with a guard test pinning them to the
// documented value, so a silent constant drift fails in the test, not in
// production (the goldenfreshness anchor-guard discipline).
//
// SYNTHETIC ONLY (D50). There is NO live policy stream, no live VM, no host
// agent, no KVM, no podman, and no live `claude` / `cia run` anywhere in this
// package. The suspend signals, grant-pipeline phases, host applied_seq values,
// revocation sweeps, and canary hit counts are all hand-authored DATA built in
// the test; nothing here dials a control plane, drives a driver verb, runs a
// sweep, or reads telemetry. No DS_*_LIVE token is read or set. The module is
// deliberately OFF the repo go.work `use` list and runs standalone under
// GOWORK=off (../go.mod), so the claims package stays independent of production
// build state.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). All five rows are
// oss-runnable: each is a static fixture-vs-reference decision with no data-plane,
// VM, or image dependency, so they execute on any checkout via `go test ./...`
// from any cwd (the fixtures are in-code Go literals, so there is no fixture-path
// or working-directory dependency).
//
// REGISTRATION (claim metadata — pending the guardrail-map's first per-claim
// seeding). These rows REGISTER pending the repo-root guardrail-map.yaml's first
// per-claim seeding (doc 06 TODO "Translate every guardrail claim … (c) assertion"
// / doc SUMMARY next-action 4), the seeding the sibling guardrailmap-seed-claim
// -rows unit installs. The guardrail tags below are single-sourced here so the
// package's claim metadata and the map row name the SAME rows when that seeding
// lands; until then the rows are registered via this metadata only (the
// goldenfreshness/doc.go FOLLOW-UP discipline — a row ships with its tag name
// fixed so the §3c table, this package, and the guardrail-map stay single-sourced).
// The tags follow the doc 06 §3c <domain>-conformance / <property> shape, never
// attack/redteam naming:
//
//	guardrail tag                                row
//	orch-suspend-on-breach                       (1) suspend-on-breach execution (D77)
//	orch-ask-grant-atomicity                     (2) ask-grant atomicity (doc 13 §7)
//	orch-skew-widening-scheduler-refusal         (3) skew-widening / scheduler-refusal (D72)
//	orch-revocation-of-derived-state-clock       (4) revocation-of-derived-state clock (D72/D68)
//	orch-pack-staleness-canary-evidence-feed     (5) D74 pack-staleness canary evidence feed (co-owned)
//
//	runnability: oss-runnable (see RUNNABILITY above)
//	anchors:     doc 15 §11 (§3, §4.1, §4.3, §7); doc 13 §5/§7; doc 06 §3c
//	decisions:   D77 (suspend taxonomy), D72 (distribution / readiness / placement),
//	             D74 (pack staleness), D68/D53 (rung-conditional revocation),
//	             D35/D36 (state + unschedulable), D50 (synthetic fixtures), D51 (public package)
//
// [../README.md]: ../README.md
package orchctl
