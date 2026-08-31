// SPDX-License-Identifier: Apache-2.0

// Package logreconcile holds the executable form of the doc 06 §3c
// per-session stream-reconciliation (c)-tier guardrail-conformance row — suite
// member LOG-4 (doc 09 §7) — as part of the D51 public claims package
// ([../README.md]): every guardrail the docs promise becomes a test that tries to
// make the guardrail FAIL and asserts it doesn't (doc 06 §3c). This row lives in
// its OWN subpackage, distinct from the boundary nftgate/netisolation rows and the
// orchestrator orchctl rows, because the guarantee is the boundary auditing ITSELF
// — the proxy system-of-record stream reconciling against the independent kernel
// conntrack ledger, per session (D43/D44).
//
// THIS IS THE CONFORMANCE ROW, NOT THE PRODUCER. The LOG-4 reconciliation is also a
// runtime control inside ds-flowlog (doc 09 §7: "an unexplained flow is an alarm,
// not a log line"); this package is the (c)-row that asserts the documented
// reconciliation contract over the LOG-1 record shapes (doc 04 §7 FlowRecord +
// DnsEvent + PolicyDecision). It does NOT build, import, or stand in for ds-flowlog
// or any dataplane/ producer — it models the documented record shapes as synthetic
// Go-literal fixtures and checks the reconciliation that a correct producer must
// satisfy.
//
// VOCABULARY (doc 06 §3c, binding). Never attack / redteam / intrusion. These are
// **assurance tests for properties we advertise** — the same way a database ships
// tests that prove it doesn't lose committed writes. Each violation class is named
// for the property it proves and the NAMED way a regression would let it slip (a
// proxy flow with no joining conntrack entry, a three-keys disagreement that was
// not dropped), never for an attacker.
//
// THE CLAIM (doc 06 §3c "Per-session stream reconciliation"; D43/D44; doc 09 §7
// LOG-4; doc 12 §2.3 conntrack-drop/boundary-hole alarm class; doc 72/D72 the
// version-ordering assertion; doc 20 §4 telemetry/attribution row + OQ2):
//
//	The proxy system-of-record stream (per-flow record: DNS name, session,
//	identity, bytes, duration, HTTP metadata — D43) and the independent kernel
//	conntrack ledger (the host daemon's L3/4 ledger from conntrack destroy events,
//	covering DENIED and ESCAPE-HATCH flows — D43) RECONCILE per session. Every flow
//	in one stream joins the other; a flow present in one stream with no joining
//	record in the other — a dropped/unattributed/duplicated flow — is a NAMED
//	violation. Attribution is BY CONSTRUCTION: the three keys guest IP + tap name +
//	`ct mark` must AGREE across both streams (D44); a disagreement is a kernel drop
//	at runtime and a failure in this suite — never an honored, reconciled flow. An
//	unexplained divergence raises an ALARM, not a log line (doc 09 §7 / doc 12
//	§2.3) — and a conntrack-drop counter is a boundary-hole alarm, never silently
//	swallowed. Finally, per D72/LOG-4 the version of the TLS/HTTP decision must be
//	>= the version of the admitting DNS event (a decision can never enforce an
//	OLDER policy than the DNS event that admitted the flow).
//
// THE SIX NAMED VIOLATION CLASSES (logreconcile.go):
//
//	(1) proxy-flow-unreconciled-in-conntrack — a proxy system-of-record flow has no
//	    joining conntrack ledger entry; the kernel accounting lost a flow the proxy
//	    recorded (every byte that left a VM interface must be explained — doc 09 §7).
//	(2) conntrack-flow-unexplained — a conntrack ledger flow (including a DENIED or
//	    ESCAPE-HATCH flow) has no joining proxy record and no explicit escape-hatch
//	    allowance; an unexplained flow means the redirect has a hole (doc 09 §7 /
//	    doc 12 §2.3 boundary-hole alarm).
//	(3) three-keys-disagree-not-dropped — the D44 three keys (guest IP / tap name /
//	    `ct mark`) disagreed across the streams but the flow was reconciled rather
//	    than dropped; a disagreement is a kernel drop at runtime and a suite failure,
//	    never an honored claim (D44).
//	(4) flow-double-counted — the same flow appears more than once in a single
//	    stream (duplicated); reconciliation is a per-session accounting identity, so
//	    a double-counted flow corrupts the ledger join.
//	(5) decision-version-older-than-admitting-dns — the TLS/HTTP decision enforced a
//	    policy version OLDER than the DNS event that admitted the flow; D72/LOG-4
//	    continuously assert version(decision) >= version(admitting DNS event).
//	(6) divergence-not-alarmed — an unexplained divergence (or a conntrack-drop
//	    counter) surfaced as a LOG LINE rather than an ALARM; doc 09 §7 / doc 12
//	    §2.3 make divergence an alarm class, not an audit line.
//
// THE CHECK. The row is a pure CheckReconciliation function over a SYNTHETIC
// fixture (D50): a Go-literal SessionReconciliation the test builds — the two
// streams (proxy SoR flows, conntrack ledger flows) for one session plus the
// divergence-disposition flag — exercised with a CONFORMING control (the streams
// reconcile clean) and one fixture per NAMED violation class. The shape mirrors the
// netisolation/orchctl siblings: a typed fixture, a typed ViolationClass taxonomy,
// and a pure Check returning every NAMED violation in a stable order — so the row
// "fails NAMED" rather than with a bare boolean.
//
// SYNTHETIC ONLY (D50). There is NO live ds-flowlog, no live conntrack, no live
// proxy, no live VM, no host agent, no KVM, no podman, and no live `claude` /
// `cia run` anywhere in this package. The proxy flows, conntrack flows, three-keys
// values, policy versions, and divergence dispositions are all hand-authored DATA
// built in the test; nothing here consumes a conntrack stream, reads ds-flowlog,
// dials a proxy, or imports dataplane/. No DS_*_LIVE token is read or set. The
// module is deliberately OFF the repo go.work `use` list and runs standalone under
// GOWORK=off (../go.mod), so the claim package stays independent of production
// build state.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: a static fixture-vs-reference decision with no data-plane, VM, or
// image dependency, so it executes on any checkout via `go test ./...` from any cwd
// (the fixtures are in-code Go literals, so there is no fixture-path or
// working-directory dependency).
//
// REGISTRATION (claim metadata — pending the guardrail-map's first per-claim
// seeding). This row REGISTERS pending the repo-root guardrail-map.yaml's first
// per-claim seeding (doc 06 TODO "Translate every guardrail claim … (c) assertion"
// / doc SUMMARY next-action 4). The guardrail tag below is single-sourced in
// logreconcile.go (const Tag) so the package's claim metadata and the map row name
// the SAME row when that seeding lands; until then the row is registered via this
// metadata only, and a new unmapped subdir self-gates fail-closed (D47 — the map is
// Boundary-owned and is NOT edited from this package). The tag follows the doc 06
// §3c <domain>-conformance / <property> shape, never attack/redteam naming:
//
//	guardrail tag                        row
//	per-session-stream-reconciliation    LOG-4 per-session stream reconciliation (D43/D44)
//
//	runnability: oss-runnable (see RUNNABILITY above)
//	anchors:     doc 06 §3c "Per-session stream reconciliation"; doc 09 §7 LOG-4;
//	             doc 12 §2.3 conntrack-drop/boundary-hole alarm class; doc 20 §4 + OQ2
//	decisions:   D43 (proxy SoR + independent conntrack ledger, reconciled per session),
//	             D44 (three-keys-must-agree attribution), D72 (version(decision) >=
//	             version(admitting DNS event)), D50 (synthetic fixtures), D51 (public package)
//
// [../README.md]: ../README.md
package logreconcile
