// SPDX-License-Identifier: Apache-2.0

package logreconcile

import (
	"fmt"
	"sort"
)

// logreconcile models the doc 06 §3c per-session stream-reconciliation (c) row —
// suite member LOG-4 (doc 09 §7) — as a single, deterministic Check over a
// SYNTHETIC fixture (D50): Go-literal inputs the test builds, never a live
// ds-flowlog, conntrack stream, proxy, VM, KVM, or podman run. The shape mirrors
// the netisolation / orchctl siblings: a typed fixture + a typed violation taxonomy
// + a pure Check returning every NAMED violation. doc.go states the claim and its
// anchors (D43/D44/D72; doc 09 §7; doc 12 §2.3).
//
// The doc 06 §3c language note is binding here: nothing is named attack / redteam /
// intrusion. Every check is phrased as "the guardrail HOLDS, and this is the named
// way a regression would let it slip." A fixture that models a defeat attempt is
// named for the property it probes (a proxy flow with no joining conntrack entry, a
// three-keys disagreement), never for an attacker.

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION;
// guardrail-map.yaml). Tag is the SINGLE SOURCE for the row name: the repo-root
// guardrail-map.yaml's logreconcile glob row (at the first per-claim seeding) and
// this constant must name the SAME row, and TestTagStable pins it so a silent drift
// fails HERE rather than against a differently-named map row (the
// suspendbreach/goldenfreshness const-Tag discipline). guardrail-map.yaml is never
// edited from this package — a new unmapped subdir self-gates fail-closed (D47; the
// map is Boundary-owned).
const Tag = "per-session-stream-reconciliation"

// Tags exposes the single-sourced tag as an ordered slice, for parity with the
// multi-row sibling packages (netisolation/orchctl) and for any tooling that
// enumerates a package's row tags uniformly.
var Tags = []string{Tag}

// ── Shared violation type ───────────────────────────────────────────────────

// ViolationClass names a single failure mode this row enumerates, so every
// violation reports WHICH rule it tripped (the "fails NAMED" bar).
type ViolationClass string

// Violation is a single reconciliation breach: which rule, which subject (the flow
// key / session the check ran against), and a human-readable reason citing the
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

// ── The six named violation classes (doc.go THE SIX NAMED VIOLATION CLASSES) ──

const (
	// ViolationProxyFlowUnreconciled — a proxy system-of-record flow has no joining
	// conntrack ledger entry; the kernel accounting lost a flow the proxy recorded.
	// Every byte that left a VM interface must be explained by the other stream
	// (doc 09 §7).
	ViolationProxyFlowUnreconciled ViolationClass = "proxy-flow-unreconciled-in-conntrack"
	// ViolationConntrackFlowUnexplained — a conntrack ledger flow (including a DENIED
	// or ESCAPE-HATCH flow) has no joining proxy record and no explicit escape-hatch
	// allowance; an unexplained flow means the redirect has a hole (doc 09 §7 /
	// doc 12 §2.3 boundary-hole alarm).
	ViolationConntrackFlowUnexplained ViolationClass = "conntrack-flow-unexplained"
	// ViolationThreeKeysDisagreeNotDropped — the D44 three keys (guest IP / tap name /
	// ct mark) disagreed across the streams but the flow was reconciled rather than
	// dropped; a disagreement is a kernel drop at runtime and a suite failure, never
	// an honored claim (D44).
	ViolationThreeKeysDisagreeNotDropped ViolationClass = "three-keys-disagree-not-dropped"
	// ViolationFlowDoubleCounted — the same flow appears more than once in a single
	// stream (duplicated); reconciliation is a per-session accounting identity, so a
	// double-counted flow corrupts the ledger join.
	ViolationFlowDoubleCounted ViolationClass = "flow-double-counted"
	// ViolationDecisionVersionOlderThanDNS — the TLS/HTTP decision enforced a policy
	// version OLDER than the DNS event that admitted the flow; D72/LOG-4 continuously
	// assert version(decision) >= version(admitting DNS event).
	ViolationDecisionVersionOlderThanDNS ViolationClass = "decision-version-older-than-admitting-dns"
	// ViolationDivergenceNotAlarmed — an unexplained divergence (or a conntrack-drop
	// counter) surfaced as a LOG LINE rather than an ALARM; doc 09 §7 / doc 12 §2.3
	// make divergence an alarm class, not an audit line.
	ViolationDivergenceNotAlarmed ViolationClass = "divergence-not-alarmed"
)

// ── The D44 three-keys attribution tuple ────────────────────────────────────

// FlowKey is the D44 by-construction attribution tuple: the orchestrator-assigned
// per-session guest IP, the deterministic tap name (`dstap-<idx>`), and the
// interface-keyed ct mark. The three keys must AGREE across both streams; a
// disagreement is a kernel drop at runtime and a suite failure (D44).
type FlowKey struct {
	// GuestIP is the orchestrator-assigned unique per-session guest IP.
	GuestIP string
	// Tap is the deterministic per-session tap name (`dstap-<idx>`), the
	// authoritative NFT-2 join key.
	Tap string
	// CtMark is the interface-keyed composite ct mark (the D76 layout's session
	// index nibble); rendered as a string so a fixture can model an honest value or
	// a disagreement plainly.
	CtMark string
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.Tap, k.GuestIP, k.CtMark)
}

// agrees reports whether two flow keys agree on all three D44 keys.
func (k FlowKey) agrees(o FlowKey) bool {
	return k.GuestIP == o.GuestIP && k.Tap == o.Tap && k.CtMark == o.CtMark
}

// ── The two streams ─────────────────────────────────────────────────────────

// ProxyFlow is one entry in the proxy system-of-record stream (D43): the per-flow
// record the proxy alone can see (DNS name, identity, byte/duration accounting),
// plus the D44 attribution key and the policy versions LOG-4 orders.
type ProxyFlow struct {
	// ID is a synthetic flow identifier the conntrack ledger joins on (a stand-in
	// for the 5-tuple+session join key; reconciliation matches a proxy flow to a
	// conntrack flow by ID).
	ID string
	// Key is the D44 attribution tuple as the PROXY recorded it.
	Key FlowKey
	// Domain is the admitting domain (the proxy is system of record for the DNS-name
	// join); informational for messages.
	Domain string
	// AdmittingDNSVersion is the policy_log version of the DNS event that admitted
	// this flow (D72).
	AdmittingDNSVersion uint64
	// DecisionVersion is the policy_log version the TLS/HTTP decision enforced under
	// (D72). LOG-4 asserts DecisionVersion >= AdmittingDNSVersion.
	DecisionVersion uint64
}

// ConntrackFlow is one entry in the independent kernel conntrack ledger (D43): the
// L3/4 destroy-event record the host daemon emits, covering DENIED and
// ESCAPE-HATCH flows the proxy never sees. It carries the same D44 attribution key
// so the two streams join by construction.
type ConntrackFlow struct {
	// ID is the synthetic flow identifier the proxy stream joins on. For a denied or
	// escape-hatch flow there is no proxy record, so a conntrack-only ID is expected
	// — but only when the flow is explicitly explained (Denied || EscapeHatch).
	ID string
	// Key is the D44 attribution tuple as the KERNEL recorded it (the conntrack
	// ledger's view of guest IP / tap / ct mark).
	Key FlowKey
	// Denied is true iff this is a denied flow (dropped at L3/4); a denied flow is a
	// legitimately conntrack-only entry (no proxy record), explained by its denial.
	Denied bool
	// EscapeHatch is true iff this is a D45 escape-hatch flow (a deliberate,
	// per-org-cataloged protocol+host+port grant enforced on the session interface);
	// it is legitimately conntrack-only, explained by its explicit allowance.
	EscapeHatch bool
}

// explained reports whether a conntrack flow is legitimately allowed to exist with
// no joining proxy record: a denied flow (dropped at L3/4) or an explicit
// escape-hatch flow (a deliberate allowance). Any other conntrack-only flow is
// UNEXPLAINED — a redirect hole (doc 09 §7 / doc 12 §2.3).
func (c ConntrackFlow) explained() bool {
	return c.Denied || c.EscapeHatch
}

// ── The per-session reconciliation fixture ───────────────────────────────────

// SessionReconciliation is a synthetic fixture: the two streams for ONE session
// over a reconciliation window, plus how a divergence (if any) was disposed. The
// check reconciles ProxyFlows against ConntrackFlows by ID, asserts the D44 three
// keys agree on every joined pair, accounts for legitimately conntrack-only
// (denied / escape-hatch) flows, and asserts an unexplained divergence raises an
// alarm rather than a log line.
type SessionReconciliation struct {
	// Session is the session under reconciliation (the per-session scope D43/D44 fix).
	Session string
	// ProxyFlows is the proxy system-of-record stream for this session.
	ProxyFlows []ProxyFlow
	// ConntrackFlows is the independent conntrack ledger for this session.
	ConntrackFlows []ConntrackFlow
	// DivergenceRaisedAlarm records how an unexplained divergence was surfaced: true
	// = an alarm fired (the required disposition), false = it was only a log line
	// (the regression). Meaningful only when the streams actually diverge; a clean
	// reconciliation needs no alarm. ConntrackDropCounter > 0 also obligates an alarm
	// (doc 12 §2.3 — a conntrack-drop counter is a boundary-hole alarm).
	DivergenceRaisedAlarm bool
	// ConntrackDropCounter is the count of conntrack drops observed in the window. A
	// non-zero counter is itself a boundary-hole alarm obligation (doc 12 §2.3),
	// independent of any per-flow divergence.
	ConntrackDropCounter int
}

// firstDuplicate returns the first duplicated ID in a slice of IDs (a flow that
// appears more than once in a single stream), or "" if all are unique.
func firstDuplicate(ids []string) string {
	seen := map[string]bool{}
	dups := []string{}
	for _, id := range ids {
		if seen[id] {
			dups = append(dups, id)
		}
		seen[id] = true
	}
	if len(dups) == 0 {
		return ""
	}
	sort.Strings(dups)
	return dups[0]
}

// CheckReconciliation asserts the LOG-4 per-session stream-reconciliation claim for
// one synthetic fixture and returns every NAMED violation. An empty result means
// the row holds: every proxy flow joins a conntrack flow, every conntrack flow
// joins a proxy flow or is explicitly explained (denied / escape-hatch), the D44
// three keys agree on every joined pair, no flow is double-counted, every decision
// version is >= its admitting DNS version, and any divergence (or conntrack drop)
// raised an alarm rather than a log line.
func CheckReconciliation(r SessionReconciliation) []Violation {
	var vs []Violation

	// Index both streams by flow ID for the join.
	proxyByID := make(map[string]ProxyFlow, len(r.ProxyFlows))
	proxyIDs := make([]string, 0, len(r.ProxyFlows))
	for _, p := range r.ProxyFlows {
		proxyByID[p.ID] = p
		proxyIDs = append(proxyIDs, p.ID)
	}
	ctByID := make(map[string]ConntrackFlow, len(r.ConntrackFlows))
	ctIDs := make([]string, 0, len(r.ConntrackFlows))
	for _, c := range r.ConntrackFlows {
		ctByID[c.ID] = c
		ctIDs = append(ctIDs, c.ID)
	}

	// (4) flow-double-counted: a flow appears more than once in a single stream.
	if dup := firstDuplicate(proxyIDs); dup != "" {
		vs = append(vs, Violation{
			Class:   ViolationFlowDoubleCounted,
			Subject: r.Session + ":proxy:" + dup,
			Reason: fmt.Sprintf("proxy system-of-record flow %q appears more than once in the "+
				"proxy stream for session %q; reconciliation is a per-session accounting identity, "+
				"so a duplicated flow corrupts the ledger join — every flow joins exactly once "+
				"(doc 06 §3c, doc 09 §7 LOG-4, D43)", dup, r.Session),
		})
	}
	if dup := firstDuplicate(ctIDs); dup != "" {
		vs = append(vs, Violation{
			Class:   ViolationFlowDoubleCounted,
			Subject: r.Session + ":conntrack:" + dup,
			Reason: fmt.Sprintf("conntrack ledger flow %q appears more than once in the conntrack "+
				"stream for session %q; reconciliation is a per-session accounting identity, so a "+
				"duplicated flow corrupts the ledger join — every flow joins exactly once (doc 06 "+
				"§3c, doc 09 §7 LOG-4, D43)", dup, r.Session),
		})
	}

	// (1) proxy-flow-unreconciled-in-conntrack: a proxy SoR flow has no joining
	// conntrack entry. Also assert (3) three-keys agreement and (5) version ordering
	// on each proxy flow.
	for _, p := range r.ProxyFlows {
		c, ok := ctByID[p.ID]
		if !ok {
			vs = append(vs, Violation{
				Class:   ViolationProxyFlowUnreconciled,
				Subject: r.Session + ":" + p.ID,
				Reason: fmt.Sprintf("proxy system-of-record flow %q (domain %q) has no joining "+
					"conntrack ledger entry for session %q; every byte that left a VM interface must "+
					"be explained by the independent conntrack ledger — a proxy flow with no kernel "+
					"join is a reconciliation gap, not a log line (doc 09 §7 LOG-4, D43)",
					p.ID, p.Domain, r.Session),
			})
		} else if !p.Key.agrees(c.Key) {
			// (3) three-keys-disagree-not-dropped: the streams joined on ID but the D44
			// keys disagree. A disagreement is a kernel drop at runtime; a flow that was
			// reconciled (joined, not dropped) under disagreeing keys is the regression.
			vs = append(vs, Violation{
				Class:   ViolationThreeKeysDisagreeNotDropped,
				Subject: r.Session + ":" + p.ID,
				Reason: fmt.Sprintf("flow %q reconciled across the streams under DISAGREEING D44 "+
					"keys — proxy view %s vs conntrack view %s; the three keys (guest IP / tap / "+
					"ct mark) must AGREE, and a disagreement is a kernel drop at runtime, never an "+
					"honored reconciled flow (doc 06 §3c, D44)", p.ID, p.Key, c.Key),
			})
		}

		// (5) decision-version-older-than-admitting-dns: version(decision) must be
		// >= version(admitting DNS event) (D72/LOG-4).
		if p.DecisionVersion < p.AdmittingDNSVersion {
			vs = append(vs, Violation{
				Class:   ViolationDecisionVersionOlderThanDNS,
				Subject: r.Session + ":" + p.ID,
				Reason: fmt.Sprintf("flow %q enforced a TLS/HTTP decision at policy version %d, "+
					"OLDER than the version %d of the DNS event that admitted it; LOG-4 continuously "+
					"asserts version(decision) >= version(admitting DNS event) — a decision can never "+
					"enforce an older policy than the admission it followed (doc 09 §7 LOG-4, D72)",
					p.ID, p.DecisionVersion, p.AdmittingDNSVersion),
			})
		}
	}

	// (2) conntrack-flow-unexplained: a conntrack flow with no joining proxy record
	// and no explicit explanation (denied / escape-hatch) is a redirect hole.
	for _, c := range r.ConntrackFlows {
		if _, ok := proxyByID[c.ID]; ok {
			continue // joined a proxy flow — reconciled (keys checked on the proxy pass)
		}
		if c.explained() {
			continue // legitimately conntrack-only: denied or escape-hatch
		}
		vs = append(vs, Violation{
			Class:   ViolationConntrackFlowUnexplained,
			Subject: r.Session + ":" + c.ID,
			Reason: fmt.Sprintf("conntrack ledger flow %q (key %s) for session %q has no joining "+
				"proxy record and is neither a denied flow nor an explicit escape-hatch allowance; "+
				"an unexplained flow means the redirect has a HOLE — it is an alarm, not a log line "+
				"(doc 09 §7 LOG-4, doc 12 §2.3 boundary-hole alarm, D43)", c.ID, c.Key, r.Session),
		})
	}

	// (6) divergence-not-alarmed: if the streams diverge (any per-flow reconciliation
	// violation above) OR a conntrack-drop counter is non-zero, an ALARM must have
	// fired. A divergence surfaced as a mere log line is the regression doc 09 §7 /
	// doc 12 §2.3 exist to catch.
	diverged := len(vs) > 0 || r.ConntrackDropCounter > 0
	if diverged && !r.DivergenceRaisedAlarm {
		reason := "an unexplained divergence between the proxy and conntrack streams was surfaced " +
			"as a log line, not an ALARM; doc 09 §7 / doc 12 §2.3 make a reconciliation divergence " +
			"an alarm class — \"an unexplained flow is an alarm, not a log line\" (doc 06 §3c, D43)"
		if r.ConntrackDropCounter > 0 {
			reason = fmt.Sprintf("a conntrack-drop counter of %d was not surfaced as an ALARM; "+
				"doc 12 §2.3 makes conntrack-drop counters boundary-hole alarms (recovery shares "+
				"fate with NAT correctness) — a non-zero drop counter is an alarm, never a silently "+
				"swallowed log line (doc 09 §7 LOG-4, doc 12 §2.3)", r.ConntrackDropCounter)
		}
		vs = append(vs, Violation{
			Class:   ViolationDivergenceNotAlarmed,
			Subject: r.Session,
			Reason:  reason,
		})
	}

	sortViolations(vs)
	return vs
}
