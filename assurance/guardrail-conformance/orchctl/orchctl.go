// SPDX-License-Identifier: Apache-2.0

package orchctl

import (
	"fmt"
	"sort"
)

// orchctl holds the executable form of the doc 15 §11 orchestrator-owned /
// co-owned (c)-tier guardrail-conformance rows (doc.go states the claims and
// their anchors). Each row below is modeled as a small, deterministic check over
// SYNTHETIC fixtures (D50) — Go-literal inputs built by the test, never a live
// policy stream, VM, host-agent, KVM, or podman run. The shape mirrors the
// goldenfreshness sibling: a typed fixture + a typed violation taxonomy + a pure
// Diff/Decide function the test exercises with a CONFORMING control and one
// fixture per NAMED violation class.
//
// The doc 06 §3c language note is binding here: nothing in this package is named
// attack / redteam / intrusion. Every check is phrased as "the guardrail HOLDS,
// and this is the named way a regression would let it slip." A fixture that
// models a defeat attempt is named for the property it probes (a stale-applied_seq
// host, an unswept eviction), never for an attacker.

// ── Single-sourced guardrail tags (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// The five doc 06 §3c <domain>-conformance tags this package's rows carry, in the
// doc.go REGISTRATION order. Tags is the SINGLE SOURCE for the row names: the
// repo-root guardrail-map.yaml's orchctl glob row and this slice must name the
// SAME rows, and TestTagsStable pins the slice so a silent drift fails HERE rather
// than against a differently-named map row (the goldenfreshness/suspendbreach
// const Tag discipline, extended to a multi-row package — an honest map row names
// real, single-sourced tag values, never a placeholder string).
const (
	// TagSuspendOnBreach — row (1) suspend-on-breach execution (D77).
	TagSuspendOnBreach = "orch-suspend-on-breach"
	// TagAskGrantAtomicity — row (2) ask-grant atomicity (doc 13 §7).
	TagAskGrantAtomicity = "orch-ask-grant-atomicity"
	// TagSkewWideningSchedulerRefusal — row (3) skew-widening / scheduler-refusal (D72).
	TagSkewWideningSchedulerRefusal = "orch-skew-widening-scheduler-refusal"
	// TagRevocationOfDerivedStateClock — row (4) revocation-of-derived-state clock (D72/D68).
	TagRevocationOfDerivedStateClock = "orch-revocation-of-derived-state-clock"
	// TagPackStalenessCanaryEvidenceFeed — row (5) D74 pack-staleness canary evidence
	// feed (co-owned for its evidence feed only).
	TagPackStalenessCanaryEvidenceFeed = "orch-pack-staleness-canary-evidence-feed"
)

// Tags is the ordered set of single-sourced guardrail tags this package owns or
// co-owns, for the guardrail-map.yaml orchctl row to name the SAME rows.
var Tags = []string{
	TagSuspendOnBreach,
	TagAskGrantAtomicity,
	TagSkewWideningSchedulerRefusal,
	TagRevocationOfDerivedStateClock,
	TagPackStalenessCanaryEvidenceFeed,
}

// ── Shared violation type ───────────────────────────────────────────────────

// ViolationClass names a single failure mode one of the five rows enumerates, so
// every violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// constants are grouped per row below.
type ViolationClass string

// Violation is a single guardrail breach: which rule, which subject (the session
// / host / domain the check ran against), and a human-readable reason citing the
// governing anchor.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// sortViolations orders a slice by (class, subject) so failure messages and
// class-set comparisons are stable across runs.
func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 1 — suspend-on-breach execution (doc 15 §11; §3 SUSPENDED(reason); §4.3;
//         doc 06 §3c "Suspend-on-breach fires"; D77 taxonomy, D35 state).
//
// THE CLAIM: a boundary→orchestrator suspend signal (doc 15 §4.3) drives
// Suspend(reason) on the driver, where the reason is the SUSPENDED(reason) enum
// {user, policy_breach, rebalance} (§3) with policy_breach NARROWED to D77's
// genuine-threat classes — a blocklist hit, or a rule explicitly configured
// action: suspend. Ordinary behavioral caps default action: block and are
// in-band failures the agent self-heals from — they MUST NOT escalate to a VM
// suspend (D77's "suspension as last resort"). A POLICY_BREACH suspend is valid
// only with POL-3 provenance attached (§4.3 / §5.1 SuspendRequest.provenance
// REQUIRED for POLICY_BREACH).
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationSuspendNotFired — a genuine-threat signal (blocklist hit / a rule
	// configured action: suspend) did NOT drive Suspend(reason); the VM kept
	// running through a breach the docs promise suspends it.
	ViolationSuspendNotFired ViolationClass = "suspend-on-breach-not-fired"
	// ViolationSuspendOverEscalated — an ordinary block-default cap was escalated
	// to a VM suspend; D77 narrows policy_breach to genuine threats, so a
	// self-healing in-band failure must NOT suspend the VM.
	ViolationSuspendOverEscalated ViolationClass = "suspend-on-breach-over-escalated"
	// ViolationSuspendReasonUnmapped — the suspend fired but under a reason class
	// outside the frozen §3 {user, policy_breach, rebalance} enum.
	ViolationSuspendReasonUnmapped ViolationClass = "suspend-reason-outside-d77-taxonomy"
	// ViolationSuspendProvenanceMissing — a POLICY_BREACH suspend carried no POL-3
	// provenance; §5.1 makes provenance REQUIRED for POLICY_BREACH.
	ViolationSuspendProvenanceMissing ViolationClass = "suspend-policy-breach-provenance-missing"
)

// SuspendReason is the frozen §3 SUSPENDED(reason) enum (the §5.1
// SuspendReason proto mirror, D35/D77). The zero value is intentionally the
// invalid "unset" marker so an unmapped signal surfaces rather than defaulting
// to a real class.
type SuspendReason string

const (
	ReasonUnset     SuspendReason = ""     // not a legal driven reason; an unmapped signal
	ReasonUser      SuspendReason = "user" // user-requested pause (resume authority: user)
	ReasonPolicy    SuspendReason = "policy_breach"
	ReasonRebalance SuspendReason = "rebalance" // scheduler rebalance (resume authority: scheduler)
)

// validReasons is the frozen §3 enum; any driven reason outside it is unmapped.
var validReasons = map[SuspendReason]bool{
	ReasonUser:      true,
	ReasonPolicy:    true,
	ReasonRebalance: true,
}

// CapAction is the D52 `action`/`rung` value a tripped guardrail rule carries.
// D77 default for behavioral caps is block; only `suspend` (or a blocklist hit)
// is a genuine threat.
type CapAction string

const (
	ActionBlock   CapAction = "block"   // D77 default for behavioral caps: in-band, self-healed, NEVER suspends the VM
	ActionSuspend CapAction = "suspend" // a rule explicitly configured to suspend — a genuine-threat class
)

// SuspendSignal is a synthetic boundary→orchestrator suspend signal (doc 15
// §4.3): the tripped rule's disposition plus its POL-3 provenance.
type SuspendSignal struct {
	Session string
	// Blocklist is true iff the trip is a blocklist hit (the other genuine-threat
	// class besides an explicit action: suspend rule).
	Blocklist bool
	// RuleAction is the tripped rule's D52 action (block | suspend). Meaningful
	// only when Blocklist is false.
	RuleAction CapAction
	// Provenance is the POL-3 (matched rule, layer, version) string; empty means
	// no provenance was attached.
	Provenance string
}

// SuspendOutcome is what the orchestrator drove for a signal: whether
// Suspend(reason) fired, and under which §3 reason.
type SuspendOutcome struct {
	SuspendFired bool
	Reason       SuspendReason
}

// genuineThreat reports whether the signal is a D77 genuine-threat class: a
// blocklist hit OR a rule explicitly configured action: suspend.
func (s SuspendSignal) genuineThreat() bool {
	return s.Blocklist || s.RuleAction == ActionSuspend
}

// DriveSuspend is the executable model of doc 15 §4.3: it maps a synthetic
// suspend signal to the outcome the orchestrator MUST drive on the driver. A
// genuine-threat class drives Suspend(POLICY_BREACH); an ordinary block-default
// cap is an in-band failure and drives NO suspend. (User/rebalance suspends arrive
// on other paths and are modeled by their own signals — DriveSuspend is the
// breach path.) This is the reference behavior the conformance check compares the
// fixture's recorded outcome against.
func DriveSuspend(s SuspendSignal) SuspendOutcome {
	if !s.genuineThreat() {
		return SuspendOutcome{SuspendFired: false}
	}
	return SuspendOutcome{SuspendFired: true, Reason: ReasonPolicy}
}

// CheckSuspendOnBreach asserts the recorded outcome conforms to the D77 taxonomy
// for the given signal and returns every NAMED violation. An empty result means
// the row holds: the genuine threat suspended, the in-band cap did not, the
// reason is in-enum, and a POLICY_BREACH suspend carried provenance.
func CheckSuspendOnBreach(s SuspendSignal, got SuspendOutcome) []Violation {
	var vs []Violation
	want := DriveSuspend(s)

	switch {
	case want.SuspendFired && !got.SuspendFired:
		vs = append(vs, Violation{
			Class:   ViolationSuspendNotFired,
			Subject: s.Session,
			Reason: "a D77 genuine-threat signal (blocklist hit or a rule configured " +
				"action: suspend) did not drive Suspend(reason); the VM kept running " +
				"through a breach the suspend-on-breach claim promises suspends it (doc 15 " +
				"§4.3, doc 06 §3c, D77)",
		})
	case !want.SuspendFired && got.SuspendFired:
		vs = append(vs, Violation{
			Class:   ViolationSuspendOverEscalated,
			Subject: s.Session,
			Reason: "an ordinary action: block behavioral cap (the D77 default, an in-band " +
				"failure the agent self-heals from) was escalated to a VM suspend; D77 " +
				"narrows policy_breach to genuine threats — suspension is the last resort, " +
				"never the response to a self-healing cap (doc 15 §3 refinement 3, D77)",
		})
	}

	// Reason + provenance are only meaningful when a suspend actually fired.
	if got.SuspendFired {
		if !validReasons[got.Reason] {
			vs = append(vs, Violation{
				Class:   ViolationSuspendReasonUnmapped,
				Subject: s.Session,
				Reason: fmt.Sprintf("suspend fired under reason %q, outside the frozen §3 "+
					"SUSPENDED(reason) enum {user, policy_breach, rebalance}; adding a reason "+
					"is a contract-set change, not a runtime value (doc 15 §3, D35/D77)",
					string(got.Reason)),
			})
		}
		if got.Reason == ReasonPolicy && s.Provenance == "" {
			vs = append(vs, Violation{
				Class:   ViolationSuspendProvenanceMissing,
				Subject: s.Session,
				Reason: "a POLICY_BREACH suspend carried no POL-3 provenance (matched rule, " +
					"layer, version); §5.1 makes provenance REQUIRED for POLICY_BREACH so the " +
					"suspend is auditable to the rule that fired it (doc 15 §4.3/§5.1, D77)",
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 2 — ask-grant atomicity (doc 15 §11; §4.3 ask-grant write path; doc 13 §7
//         "Ask-grant atomicity"; D72 stream→barrier→sweep, D36 policy_log).
//
// THE CLAIM (doc 13 §7): a grant travels stream → barrier → sweep; the FIRST
// post-apply retry succeeds; and DURING the commit window a retry fails at DNS
// (REFUSED), NEVER as resolve-success-then-TLS-refusal. The orchestrator owns the
// write path (§4.3): an approval appends a session-scoped TTL'd allow grant to
// policy_log under the policy_log seq; approval→enforced rides the distribution
// barrier (doc 13 §5 two-phase admitter-last) and is "applied" only post-sweep.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationGrantNotEnforcedPostApply — the first retry AFTER the grant reached
	// applied (post-sweep) did NOT succeed; an applied grant must enforce.
	ViolationGrantNotEnforcedPostApply ViolationClass = "ask-grant-not-enforced-post-apply"
	// ViolationGrantEnforcedPreApply — a retry succeeded BEFORE the grant reached
	// applied (during stream/barrier, pre-sweep); the grant leaked enforcement
	// ahead of the commit barrier (a fail-OPEN window the admitter-last order forbids).
	ViolationGrantEnforcedPreApply ViolationClass = "ask-grant-enforced-before-apply"
	// ViolationGrantMidWindowNotDnsRefused — a retry during the commit window did
	// not fail cleanly at DNS (REFUSED): it either resolved-then-refused-at-TLS
	// (the split-brain doc 13 §7 forbids) or leaked through.
	ViolationGrantMidWindowNotDnsRefused ViolationClass = "ask-grant-mid-window-not-dns-refused"
)

// GrantPhase is where in the stream→barrier→sweep pipeline a grant sits when a
// retry is attempted. The pipeline is ordered: Streamed (appended to policy_log,
// not yet committed) → Barriered (prepare staged, commit window OPEN, not yet
// swept) → Applied (post-sweep: derived state reconciled, applied_seq advanced).
type GrantPhase string

const (
	PhaseStreamed  GrantPhase = "streamed"  // appended under the policy_log seq; not committed
	PhaseBarriered GrantPhase = "barriered" // inside the two-phase commit window; not yet swept
	PhaseApplied   GrantPhase = "applied"   // post-sweep; enforced
)

// RetryResult is the observable outcome of a retry against the boundary. The
// distinction the row exists to catch is DnsRefused (clean, fail-closed at the
// resolver) vs ResolveThenTlsRefuse (the split-brain doc 13 §7 forbids).
type RetryResult string

const (
	RetrySucceeded         RetryResult = "succeeded"            // flow allowed end to end
	RetryDnsRefused        RetryResult = "dns-refused"          // clean fail-closed at DNS (REFUSED)
	RetryResolveThenTlsRej RetryResult = "resolve-then-tls-rej" // resolved at DNS, refused at TLS — FORBIDDEN
)

// ExpectedRetry is the reference RetryResult doc 13 §7 mandates for a retry at a
// given pipeline phase: post-apply succeeds; pre-apply (streamed or inside the
// commit window) fails cleanly at DNS with REFUSED.
func ExpectedRetry(phase GrantPhase) RetryResult {
	if phase == PhaseApplied {
		return RetrySucceeded
	}
	return RetryDnsRefused
}

// GrantRetry is a synthetic fixture: a session-scoped grant at a pipeline phase
// and the observed result of a retry attempted there.
type GrantRetry struct {
	Session string
	Phase   GrantPhase
	Got     RetryResult
}

// CheckAskGrantAtomicity asserts the stream→barrier→sweep atomicity claim for one
// retry fixture: the first post-apply retry succeeds, and no retry enforces ahead
// of apply or exhibits the resolve-then-TLS-refuse split-brain.
func CheckAskGrantAtomicity(g GrantRetry) []Violation {
	var vs []Violation
	switch g.Phase {
	case PhaseApplied:
		if g.Got != RetrySucceeded {
			vs = append(vs, Violation{
				Class:   ViolationGrantNotEnforcedPostApply,
				Subject: g.Session,
				Reason: fmt.Sprintf("the first retry after the grant reached APPLIED "+
					"(post-sweep) returned %q, not success; an applied ask-grant must enforce "+
					"— approval→enforced is complete only post-sweep-plus-flush (doc 13 §5/§7, "+
					"doc 15 §4.3, D72)", string(g.Got)),
			})
		}
	default: // streamed or barriered: pre-apply
		switch g.Got {
		case RetrySucceeded:
			vs = append(vs, Violation{
				Class:   ViolationGrantEnforcedPreApply,
				Subject: g.Session,
				Reason: fmt.Sprintf("a retry succeeded while the grant was still %q (pre-sweep); "+
					"enforcement leaked ahead of the two-phase admitter-last commit barrier — "+
					"every transient mixed-version window must be fail-CLOSED (doc 13 §5/§7, D72)",
					string(g.Phase)),
			})
		case RetryResolveThenTlsRej:
			vs = append(vs, Violation{
				Class:   ViolationGrantMidWindowNotDnsRefused,
				Subject: g.Session,
				Reason: "a retry during the commit window resolved at DNS then was refused at " +
					"TLS; doc 13 §7 forbids this split-brain — a mid-window retry must fail at " +
					"DNS (REFUSED), never as resolve-success-then-TLS-refusal (doc 13 §7, D72)",
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 3 — skew-widening / scheduler-refusal (doc 15 §11; §4.1 step 3 + step 9;
//         §7 filter 1; doc 13 §7 "Skew-widening test"; D72 unschedulable rule).
//
// THE CLAIM (doc 13 §7 / doc 15 §7 filter 1): the scheduler places ONLY on hosts
// whose heartbeat applied_seq is within the staleness budget of the swept policy
// head; a host whose applied_seq has fallen behind (a slow enforcer not yet
// post-sweep on the current version) is UNSCHEDULABLE (D36/D72). A widening that
// must not take effect on a stale host therefore cannot be placed there. The §4.1
// step-9 re-check re-validates freshness at routable time, closing the
// placement→routable window.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationStalePlacementAdmitted — a session was PLACED on a host whose
	// applied_seq is outside the staleness budget; D72 makes such a host
	// unschedulable, so admitting a placement there widens on a stale enforcer.
	ViolationStalePlacementAdmitted ViolationClass = "skew-widening-stale-placement-admitted"
	// ViolationFreshPlacementRefused — a host within the budget was refused; the
	// staleness rule must not over-refuse a fresh host (that would make every
	// create fail and is the inverse regression).
	ViolationFreshPlacementRefused ViolationClass = "skew-widening-fresh-placement-refused"
	// ViolationStaleRoutableAdmitted — a placed session reached ROUTABLE while its
	// host's applied_seq had since fallen behind; the §4.1 step-9 re-check must
	// re-refuse, closing the placement→routable window.
	ViolationStaleRoutableAdmitted ViolationClass = "skew-widening-stale-routable-admitted"
)

// HostFreshness is a synthetic fixture: a host's heartbeat applied_seq versus the
// current swept policy head, the staleness budget N (in seq units), and whether
// the scheduler ADMITTED a placement on it (Placed) and whether the §4.1 step-9
// re-check then let it reach routable (Routable). applied_seq is the D72
// min-over-three, post-sweep value (doc 15 §5.2).
type HostFreshness struct {
	Host string
	// PolicyHead is the current swept policy_log seq (the moving D72 reference).
	PolicyHead uint64
	// AppliedSeq is the host's reported applied_seq (min-over-three, post-sweep).
	AppliedSeq uint64
	// BudgetN is the staleness budget in seq units; a host is fresh iff it is
	// within N of the head (PolicyHead-AppliedSeq <= BudgetN).
	BudgetN uint64
	// Placed records whether the scheduler admitted a placement on this host.
	Placed bool
	// Routable records whether the placed session then reached routable (the §4.1
	// step-9 re-check let it through). Meaningful only when Placed is true.
	Routable bool
}

// fresh reports whether the host's applied_seq is within the staleness budget of
// the current swept head. A head ahead of applied by more than N is STALE
// (D36/D72 unschedulable). An applied_seq somehow AHEAD of the head is impossible
// under the post-sweep contract but is treated as fresh (it is not behind).
func (h HostFreshness) fresh() bool {
	if h.AppliedSeq >= h.PolicyHead {
		return true
	}
	return h.PolicyHead-h.AppliedSeq <= h.BudgetN
}

// CheckSkewWidening asserts the D72 unschedulable rule and the §4.1 step-9
// re-check for one host fixture: a stale host is never placed nor reaches
// routable, and a fresh host is never spuriously refused.
func CheckSkewWidening(h HostFreshness) []Violation {
	var vs []Violation
	isFresh := h.fresh()
	switch {
	case !isFresh && h.Placed:
		vs = append(vs, Violation{
			Class:   ViolationStalePlacementAdmitted,
			Subject: h.Host,
			Reason: fmt.Sprintf("placement admitted on host with applied_seq=%d, %d behind the "+
				"swept policy head=%d (budget N=%d); D72 makes a host outside the staleness "+
				"budget UNSCHEDULABLE — placing there would widen on an enforcer not yet "+
				"post-sweep on the current version (doc 15 §7 filter 1 / §4.1 step 3, D36/D72)",
				h.AppliedSeq, h.PolicyHead-h.AppliedSeq, h.PolicyHead, h.BudgetN),
		})
	case isFresh && !h.Placed:
		vs = append(vs, Violation{
			Class:   ViolationFreshPlacementRefused,
			Subject: h.Host,
			Reason: fmt.Sprintf("placement refused on host with applied_seq=%d, within the "+
				"staleness budget N=%d of the swept head=%d; a fresh host must be schedulable "+
				"— over-refusing one would fail every create on a healthy fleet (doc 15 §7 "+
				"filter 1, D36/D72)", h.AppliedSeq, h.BudgetN, h.PolicyHead),
		})
	}
	// §4.1 step-9: even a host fresh AT placement must be re-refused at routable if
	// it has since fallen behind. A placed-but-stale host that reached routable is
	// the residual placement→routable window the step-9 re-check exists to close.
	if h.Placed && !isFresh && h.Routable {
		vs = append(vs, Violation{
			Class:   ViolationStaleRoutableAdmitted,
			Subject: h.Host,
			Reason: fmt.Sprintf("placed session reached ROUTABLE while host applied_seq=%d had "+
				"fallen %d behind the swept head=%d (budget N=%d); the §4.1 step-9 freshness "+
				"re-check must re-refuse, closing the placement→routable window (doc 15 §4.1 "+
				"step 9, D72)", h.AppliedSeq, h.PolicyHead-h.AppliedSeq, h.PolicyHead, h.BudgetN),
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 4 — revocation-of-derived-state clock (doc 15 §11 "this doc owns both ends";
//         doc 13 §5 revocation sweep / §7 "Revocation-of-derived-state"; §4.3;
//         D72/D68/D53).
//
// THE CLAIM (doc 13 §5/§7, doc 15 §11): the push-to-enforced clock runs from
// policy_log commit (one end, orchestrator-owned, the write path §4.3) to the
// last consumer's post-sweep-plus-flush applied_seq (the other end, the readiness
// report §5.2) — doc 15 §11 says "this doc owns both ends." A block(X) pushed at
// a SEVERING rung (block-or-higher, D53) must EVICT derived state (allow-set
// entries, DNS-2b map, live TTL'd grants) within the sweep — not leave it to ride
// the TTL clamp — and applied_seq advances only AFTER that sweep-plus-flush. A
// non-severing change (allow+log rung) leaves established flows alone (D53).
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationDerivedStateNotEvicted — a severing-rung revocation committed but
	// derived state survived the sweep (left to ride the TTL clamp).
	ViolationDerivedStateNotEvicted ViolationClass = "revocation-derived-state-not-evicted"
	// ViolationAppliedSeqAdvancedPreSweep — applied_seq advanced to the new version
	// BEFORE the sweep-plus-flush completed; readiness must lag the sweep (the
	// orchestrator-owned far end of the clock), or a stale host reads fresh.
	ViolationAppliedSeqAdvancedPreSweep ViolationClass = "revocation-applied-seq-advanced-pre-sweep"
	// ViolationNonSeveringFlowSevered — a non-severing (allow+log rung) change
	// severed an established flow; D53 makes the flush rung-conditional, so a
	// non-severing change must leave the stream alone.
	ViolationNonSeveringFlowSevered ViolationClass = "revocation-non-severing-flow-severed"
)

// Revocation is a synthetic fixture modeling one policy_log-committed revocation
// and its observed effect on derived state and the readiness clock.
type Revocation struct {
	// Domain is the subject of the revocation (e.g. a blocked domain X).
	Domain string
	// Severing is true iff the rule's rung is block-or-higher (D53): the flush
	// must fire and established flows are severed. A non-severing (allow+log)
	// change leaves established flows alone.
	Severing bool
	// CommitSeq is the policy_log seq the revocation committed at (the near end of
	// the clock).
	CommitSeq uint64
	// DerivedStateEvicted records whether the sweep evicted the domain's derived
	// state (allow-set + DNS-2b entries + live grants). Meaningful for a severing
	// revocation.
	DerivedStateEvicted bool
	// EstablishedFlowSevered records whether an established flow to the domain was
	// torn down by the flush.
	EstablishedFlowSevered bool
	// SweepCompleted records whether the post-commit revocation sweep finished.
	SweepCompleted bool
	// AppliedSeq is the readiness applied_seq the host reported. The clock's far
	// end is "post-sweep-plus-flush": applied_seq may reach CommitSeq only after
	// SweepCompleted.
	AppliedSeq uint64
}

// CheckRevocationClock asserts the revocation-of-derived-state clock for one
// fixture: a severing revocation evicts derived state within the sweep, a
// non-severing one leaves established flows alone, and applied_seq advances to
// the committed version only post-sweep-plus-flush.
func CheckRevocationClock(r Revocation) []Violation {
	var vs []Violation
	if r.Severing && r.SweepCompleted && !r.DerivedStateEvicted {
		vs = append(vs, Violation{
			Class:   ViolationDerivedStateNotEvicted,
			Subject: r.Domain,
			Reason: "a severing-rung (block-or-higher) revocation completed its sweep but the " +
				"domain's derived state (allow-set / DNS-2b entries / live TTL'd grants) " +
				"survived; the sweep must EVICT it, not leave it to ride the TTL clamp (doc 13 " +
				"§5/§7, D72/D68/D53)",
		})
	}
	if !r.Severing && r.EstablishedFlowSevered {
		vs = append(vs, Violation{
			Class:   ViolationNonSeveringFlowSevered,
			Subject: r.Domain,
			Reason: "a non-severing (allow+log rung) change severed an established flow; D53 " +
				"makes the flush rung-conditional — a non-severing change must leave the " +
				"established stream alone (doc 13 §5/§7, D53)",
		})
	}
	// The readiness clock's far end: applied_seq reaches the committed version only
	// post-sweep-plus-flush. applied_seq >= CommitSeq with the sweep NOT completed
	// means readiness advanced ahead of enforcement — a stale host reading fresh.
	if r.AppliedSeq >= r.CommitSeq && !r.SweepCompleted {
		vs = append(vs, Violation{
			Class:   ViolationAppliedSeqAdvancedPreSweep,
			Subject: r.Domain,
			Reason: fmt.Sprintf("applied_seq=%d reached the committed version %d before the "+
				"sweep-plus-flush completed; readiness is reported only post-sweep (doc 15 §5.2, "+
				"doc 13 §5 readiness row) — advancing it pre-sweep lets a not-yet-enforcing host "+
				"read fresh and stay schedulable (doc 15 §11 owns both ends of this clock, D72)",
				r.AppliedSeq, r.CommitSeq),
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 5 — D74 pack-staleness canary evidence feed (doc 15 §11 "co-owned for its
//         evidence feed only"; doc 13 §7 "Staleness canary"; §2 D74 pack;
//         D74/D72).
//
// THE CLAIM (doc 15 §11, doc 13 §7): the pack-staleness canary's retirement rule
// — "30 days of zero ENFORCING-MODE hits opens a removal-review PR" — is gated on
// the control-plane log sink's enforcing-mode hit data. doc 15 §11 co-owns this
// row "for its evidence feed only": the orchestrator-side log sink supplies the
// enforcing-mode hit counts. The evidence-feed obligation this row asserts is
// that the zero-hits judgment is made ONLY against ENFORCING-mode hits over a
// COMPLETE window — a shadow/observe-mode hit is not evidence of use, and a window
// with missing days is not a clean zero (a gap must not be read as zero use, or a
// still-used pack entry gets retired on absent telemetry).
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationCanaryShadowCountedAsHit — a shadow/observe-mode hit was counted as
	// an enforcing-mode hit, so a still-evidenced entry that only saw observe-mode
	// traffic was NOT retired (the retirement is suppressed by non-evidence).
	ViolationCanaryShadowCountedAsHit ViolationClass = "canary-shadow-hit-counted-as-enforcing"
	// ViolationCanaryGapReadAsZero — the window had missing days (incomplete
	// telemetry) but was judged a clean zero, so a possibly-still-used entry was
	// retired on absent evidence.
	ViolationCanaryGapReadAsZero ViolationClass = "canary-window-gap-read-as-zero"
	// ViolationCanaryRetiredWithEnforcingHits — an entry with >0 enforcing-mode
	// hits over the window was retired; the rule retires ONLY on zero enforcing hits.
	ViolationCanaryRetiredWithEnforcingHits ViolationClass = "canary-retired-despite-enforcing-hits"
)

// DefaultCanaryWindowDays is the documented retirement window: 30 days of zero
// enforcing-mode hits opens a removal-review PR (doc 13 §7 "Staleness canary").
// A guard test pins this to the documented cadence so a silent constant drift
// fails HERE, not against a different window than the doc promises (the same
// anchor-guard pattern goldenfreshness uses for its rotation window).
const DefaultCanaryWindowDays = 30

// CanaryEvidence is a synthetic fixture: the control-plane log sink's
// enforcing-mode hit evidence for one pack entry over a retirement window, plus
// the retirement decision that was taken.
type CanaryEvidence struct {
	// Entry is the pack FQDN under review.
	Entry string
	// WindowDays is the retirement window the judgment was made over.
	WindowDays int
	// EnforcingHits is the count of ENFORCING-mode hits the orchestrator log sink
	// recorded over the window (the evidence-feed half doc 15 §11 co-owns).
	EnforcingHits int
	// ShadowHits is the count of shadow/observe-mode hits over the window. These
	// are NOT evidence of use for the retirement rule and must not be folded into
	// the enforcing-mode count.
	ShadowHits int
	// DaysWithTelemetry is how many of WindowDays actually reported. A window with
	// missing days is incomplete: a gap must not be read as zero use.
	DaysWithTelemetry int
	// Retired records whether the entry was actually retired (removal-review PR
	// opened).
	Retired bool
}

// windowComplete reports whether the canary saw telemetry on every day of the
// window. A window cannot be judged a clean zero unless it is complete.
func (e CanaryEvidence) windowComplete() bool {
	return e.DaysWithTelemetry >= e.WindowDays
}

// CheckCanaryEvidenceFeed asserts the evidence-feed half of the D74 pack-staleness
// canary retirement rule for one fixture: retirement happens iff there were zero
// ENFORCING-mode hits over a COMPLETE window, shadow-mode hits are never counted
// as enforcing, and a telemetry gap is never read as a clean zero.
func CheckCanaryEvidenceFeed(e CanaryEvidence) []Violation {
	var vs []Violation

	// Whether the rule SHOULD retire: zero enforcing-mode hits over a complete
	// window. Shadow hits are irrelevant to the judgment (not evidence of use).
	shouldRetire := e.EnforcingHits == 0 && e.windowComplete()

	if e.Retired && e.EnforcingHits > 0 {
		vs = append(vs, Violation{
			Class:   ViolationCanaryRetiredWithEnforcingHits,
			Subject: e.Entry,
			Reason: fmt.Sprintf("entry retired despite %d enforcing-mode hit(s) over the "+
				"window; the staleness-canary rule opens a removal-review PR ONLY on 30 days "+
				"of ZERO enforcing-mode hits (doc 13 §7, doc 15 §11 evidence feed, D74)",
				e.EnforcingHits),
		})
	}
	if e.Retired && !e.windowComplete() {
		vs = append(vs, Violation{
			Class:   ViolationCanaryGapReadAsZero,
			Subject: e.Entry,
			Reason: fmt.Sprintf("entry retired on a window with only %d/%d days of telemetry; "+
				"an incomplete window must NOT be read as a clean zero — a still-used entry "+
				"would be retired on absent evidence (doc 13 §7, doc 15 §11 evidence feed, D74)",
				e.DaysWithTelemetry, e.WindowDays),
		})
	}
	// The shadow-fold regression: a complete window with zero enforcing hits but
	// some shadow hits SHOULD retire (shadow is not evidence of use). If it was NOT
	// retired, the shadow hits were wrongly folded into the enforcing judgment.
	if shouldRetire && !e.Retired && e.ShadowHits > 0 {
		vs = append(vs, Violation{
			Class:   ViolationCanaryShadowCountedAsHit,
			Subject: e.Entry,
			Reason: fmt.Sprintf("entry NOT retired though it had zero enforcing-mode hits over "+
				"a complete window — its %d shadow/observe-mode hit(s) were wrongly counted as "+
				"enforcing-mode evidence; only ENFORCING-mode hits gate retirement (doc 13 §7, "+
				"doc 15 §11 evidence feed, D74)", e.ShadowHits),
		})
	}
	sortViolations(vs)
	return vs
}
