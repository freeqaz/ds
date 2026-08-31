// SPDX-License-Identifier: Apache-2.0

// Package suspendbreach holds the executable form of the **suspend-on-breach
// fires** guardrail-conformance row (doc 06 §3c, the "Suspend-on-breach fires"
// claim; doc 03 §7 BIC; the D77 taxonomy revising D53; the D46 tiered pause
// budget; TLS-6). It is part of the D51 public claims package (README.md): every
// guardrail the docs promise becomes a test that tries to make the guardrail
// FAIL and asserts it doesn't.
//
// THE CLAIM (doc 06 §3c, verbatim in substance; D77/D46). Tripping a cap with
// `action: block` (the D77 default for behavioral caps) serves the IN-BAND error
// (a machine-readable 403/429 the agent self-heals from) and fires an ASYNC
// notification — it does NOT suspend; tripping a **blocklist hit** OR a rule
// explicitly configured `action: suspend` **suspends the VM mid-action**; resume
// is transparent within the D46 pause budget (≤5 min fully transparent — proxy
// holds/buffers both sides, guest wall clock resynced on resume). This row keeps
// the D77 fork honest: suspension is reserved for genuine threats (blocklist hits
// and operator-marked-dangerous suspend rules), and ordinary policy events stay
// in-band.
//
// THE CHECK (mechanical trip-outcome diff over a synthetic trip picture). A
// synthetic fixture records a set of guardrail trips, each tagged with: the trip
// CLASS (blocklist | action_suspend | action_block), the OUTCOME the boundary
// produced (suspended | in_band_error), whether an in-band machine-readable
// reason was served, whether an async notification fired, and — for a suspend
// outcome — the resume latency in seconds against the pause budget. The diff
// FAILS NAMED on:
//
//	(a) SUSPEND-CLASS-NOT-SUSPENDED — a blocklist or action:suspend trip whose
//	    outcome was NOT a suspend: a genuine-threat trip that the VM rode through
//	    without suspending (the core negative control).
//	(b) RESUME-OVER-BUDGET — a suspend whose resume latency exceeds the D46
//	    fully-transparent pause budget (PauseBudgetSeconds, ≤5 min): resume was not
//	    transparent within budget.
//	(c) BLOCK-CLASS-SUSPENDED — an action:block trip that SUSPENDED the VM:
//	    D77 reserves suspension for genuine threats — a behavioral cap must serve
//	    an in-band error + async notify, never a heavyweight suspend.
//	(d) BLOCK-CLASS-NO-INBAND-REASON — an action:block trip that did NOT serve a
//	    machine-readable in-band reason: every denial carries a machine-readable
//	    reason on the densest channel available (D77), so the agent self-heals
//	    instead of looping.
//
// A conforming fixture: every suspend-class trip suspends and resumes within the
// pause budget; every action:block trip stays in-band with a machine-readable
// reason + async notification and never suspends.
//
// THE ANCHOR (one source for the pause budget). The D46 fully-transparent pause
// budget (5 min = 300s) is restated as PauseBudgetSeconds; a guard test pins it
// to the documented tier so a silent drift of the constant fails HERE rather
// than letting the claim assert against a different budget than D46 names.
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored trip
// picture against the DOCUMENTED D77/D46 enforcement contract (doc 04 §6 D77/D46,
// doc 03 §7). The outcomes and latencies are DATA, never produced by a real
// policy engine, a real suspend/resume, a real VM, or a real clock. There is NO
// live claude / qemu(VM-run) / podman / KVM invocation anywhere in this package;
// nothing suspends a real VM, resumes a real snapshot, or measures a real pause.
//
// VOCABULARY (doc 06 §3c, binding). This is an assurance test for a property we
// advertise — suspension reserved for genuine threats, resume transparent within
// the pause budget — framed positively, the way a database ships tests that
// prove it does not lose committed writes. "Breach" here is the doc-06 §3c
// "suspend-on-breach" claim name (a guardrail-trip class), nothing more.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static trip-outcome diff with no data-plane dependency,
// so it executes on any checkout via `go test ./...` from any cwd (fixture paths
// anchor off runtime.Caller, not the process working directory).
//
// REGISTRATION (claim metadata). This row's guardrail tag is single-sourced in
// the package as Tag. The repo-root guardrail-map.yaml is NOT edited here (it is
// Boundary-owned via CODEOWNERS); a new unmapped subdir is fail-closed to the
// full matrix (D47), so the row self-gates without a map edit.
//
//	guardrail tag: suspend-on-breach-fires
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c "Suspend-on-breach fires" (doc 03 §7 BIC; D77
//	               taxonomy; D46 pause budget; TLS-6)
package suspendbreach
