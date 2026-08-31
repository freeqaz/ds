// SPDX-License-Identifier: Apache-2.0

// Package askhold computes the ATTENDED/UNATTENDED HOLD and PARKING decisions
// for ask-a-human, on top of the FROZEN one-way ask transport (doc 16 §8.2,
// D46/D78/TLS-1). It is pure decision logic over an injected D78 attendedness
// signal plus the ask itself: no live IO, no sockets, no clocks of its own —
// the caller hands in `now` and the attendedness verdict, and these functions
// say WHAT the orchestrator should do. The boundary owns the socket-hold
// MECHANICS (doc 16 §1 ownership split); this package owns the policy decision
// that drives them.
//
// What this package is NOT:
//
//   - It opens NO second response contract. Approvals return ONLY as
//     session-scoped, TTL'd allow grants on the already-frozen policy stream
//     (doc 16 §8.2; the boundary AskUserRequest is one-way, POL-5). A "resume
//     on answer" here is a state transition driven by an answer that arrived
//     out-of-band on that stream — never a reply on the ask seam.
//   - It NEVER times out into allow or kill. This is the load-bearing D77/D46
//     invariant: a hold-window timeout closes the connection (block+log) and a
//     parked rung-2 ask stays PARKED — neither a timeout nor a dropped
//     attendedness signal ever yields a grant or a VM kill. Every Decision and
//     ParkState here is checked against this in the tests
//     (never-allow/never-kill-on-timeout).
//   - It does NOT build the orchestrator-doc record seam. The park->resume
//     state machine joins a parked session to its pending question through an
//     INJECTED interface (ParkRecorder), so the durable record is the
//     orchestrator doc's concern (doc 16 §8.2 "the ask-routing record ... is an
//     orchestrator-doc seam") — this package only decides.
//
// The D-number mechanics, exactly:
//
//   - TLS-1 / D77: an ASK on an unknown domain in an ATTENDED session gets a
//     socket-hold window (the strawman 30-60 s, doc 16 §8.2) — the proxy holds
//     the TCP connection and the VM keeps running while the human is notified.
//     The window budget (notify <= 5 s + decision <= 40 s + commit <= 5 s,
//     strawman) is carried as INJECTED POL-1 Window values, never hardcoded
//     constants.
//   - D77 (unattended fork): an ask that is UNATTENDED FROM THE START downgrades
//     to immediate block+log — no hold window is ever opened.
//   - D78 (detach-mid-hold): a hold already IN FLIGHT when attendedness drops
//     RUNS TO ITS TIMEOUT — it is never retroactively killed and never
//     converted to an immediate block. Only NEW asks downgrade. When that
//     in-flight window finally times out it closes block+log (never allow).
//   - D46 (park budget): a genuine rung-2 ask PARKS per the tiered pause budget
//     and RESUMES on answer — never timing out into allow or kill. Resume
//     authority for BIC suspensions is human approval (doc 16 §8.2).
//   - D45: allow-always escalates to org-admin acceptance (posture-delegable).
//     That escalation is an approver-authorization concern owned elsewhere; this
//     package decides only the hold/park/resume shape, so D45 appears here only
//     as the reason a resume's grant SCOPE is carried opaquely (GrantScope) and
//     never decided here.
//   - D77 deny-memo (the session-scoped deny artifact; landing-spot ratified as
//     doc 16 §8.2 option (a) / D118, round-4 packet §6.4 — this package
//     implements the decision SHAPE and ratifies nothing itself): a deny is
//     surfaced as a session-scoped DenyOutcome carrying a machine-readable reason
//     so retries fast-fail. This package produces the decision shape; the
//     policy_log landing (a deny twin on the existing ask-grant write path) is
//     the orchestrator's.
//
// Attendedness coupling, deliberately decoupled. This package consumes the D78
// attendedness verdict by MIRRORING a tiny value type (Attendedness), exactly
// as orchestrator/internal/attendedness mirrors the seat-class value types
// instead of importing internal/store: no store coupling, no import of the
// attendedness package itself — the caller projects the computed
// attendedness.Signal onto askhold.Attendedness at the boundary. The only
// non-stdlib import is the generated proto ask type (boundary/v1.AskUserRequest),
// consumed read-only for the ask payload.
//
// Synthetic inputs only (D50): every test drives these functions with
// hand-built asks and attendedness verdicts and an injected clock — no live
// claude/cia/podman/orchestrator/identity/KVM.
//
// Governing decisions: D46, D77, D78, D45, TLS-1, D50, D80. Primary doc:
// docs/16-identity-and-credentials-design.md §8 (semantics owned by Identity;
// the orchestrator computes the attendedness signal — doc 15 §5.5).
package askhold
