// SPDX-License-Identifier: Apache-2.0

// Package secretegress holds the executable form of the **planted canary
// credential never egresses** guardrail-conformance row (doc 06 §3c, the
// "Secret-scanning gate" claim; D73; doc 12 §5.3 "Canary-secret test"; doc 16 §1
// "A planted canary credential never egresses"; doc 16 §13 "Canary-never-
// egresses"). It is part of the D51 public claims package (README.md): every
// guardrail the docs promise becomes a test that tries to make the guardrail
// FAIL and asserts it doesn't.
//
// THE CLAIM (doc 06 §3c, verbatim in substance). A planted canary credential
// **never egresses on inspected paths** — a forbidden-class canary registered
// through the keyed digest feed, planted in the session, whose exfil attempts
// (raw and in each pushed variant encoding — RAW/BASE64/URLENC/HEX, doc 14 §7)
// over an INSPECTED egress path are caught at the configured rung; the canary
// value appears in zero bytes of any log/event/spool (the fingerprint-only
// invariant, D73).
//
// THE NON-CLAIMS (carried IN-ROW, verbatim in substance — doc 12 §5.3, doc 16
// §1). The row states its own boundaries so the claim is not over-read:
//
//	(1) TLS-4 PASS-THROUGH flows are out of scope. A cert-pinned pass-through
//	    tunnel (D17/D74) gets no inspection, no swap, and no secret scanning — a
//	    canary on a pass-through path is NOT a claim violation here (it is the
//	    passthrough row's concern). The gate is a guardrail against accident and
//	    casual exfiltration, not a cryptographic egress boundary.
//	(2) Adversarial custom encodings (compression, splitting across requests,
//	    bespoke encodings beyond the pushed variant set) are stated, tested
//	    non-claims out of scope (the doc 12 §5.3 / doc 16 §1 wording, carried
//	    in-row verbatim in substance).
//
// THE CHECK (mechanical egress-attempt scan over a synthetic feed picture). A
// synthetic fixture records the keyed digest feed (the forbidden canary plus its
// pushed variant tags) and a set of egress attempts, each tagged with: the path
// class (inspected | pass_through), the variant the canary bytes were observed
// in (or none), and whether the canary value was observed in any log/event/spool
// byte. The check FAILS NAMED on:
//
//	(a) CANARY-EGRESSED-INSPECTED — a canary (raw or any pushed variant) observed
//	    leaving on an INSPECTED path that did NOT block it. This is the core
//	    negative control: the planted canary leaks on an inspected path.
//	(b) CANARY-IN-SPOOL — the canary value observed in a log/event/spool byte
//	    (the fingerprint-only invariant, D73): even a blocked attempt must leave
//	    zero canary bytes in any record.
//	(c) UNKNOWN-VARIANT — a canary observed in a variant tag the feed never
//	    pushed (the feed must enumerate every variant it can match; an
//	    un-enumerated variant is an undecidable verdict, treated as a breach).
//
// A pass-through-path attempt is NEVER flagged for egress (non-claim 1); the
// only thing a pass-through attempt can still trip is CANARY-IN-SPOOL, because
// the fingerprint-only invariant binds the LOGGING plane regardless of path
// class. A conforming fixture: every inspected-path canary attempt blocked with
// the canary value absent from every spool byte, pass-through attempts unflagged.
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored feed +
// egress-attempt picture against the DOCUMENTED SecretMatcher / digest-feed
// contract (doc 12 §5, doc 14 §7, doc 16 §1/§13). The canary "value" is a
// synthetic placeholder string; the egress observations are DATA, never produced
// by a real SecretMatcher, a real digest producer, a real proxy, or a real
// network egress. There is NO live claude / qemu(VM-run) / podman / network
// invocation anywhere in this package; nothing reads a real spool or fires a real
// request.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static feed-vs-attempt diff with no data-plane
// dependency, so it executes on any checkout via `go test ./...` from any cwd
// (fixture paths anchor off runtime.Caller, not the process working directory).
//
// REGISTRATION (claim metadata). This row's guardrail tag is single-sourced in
// the package as Tag. The repo-root guardrail-map.yaml is NOT edited here (it is
// Boundary-owned via CODEOWNERS); a new unmapped subdir is fail-closed to the
// full matrix (D47), so the row self-gates without a map edit.
//
//	guardrail tag: secret-egress-canary-blocked
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c "Secret-scanning gate" (D73; doc 12 §5.3; doc 16 §1)
package secretegress
