// SPDX-License-Identifier: Apache-2.0

// Package passthrough holds the executable form of the **cert-pinned
// pass-through is empty by default** guardrail-conformance row (doc 06 §3c, the
// "Cert-pinned pass-through" claim; D17/TLS-4; the D74 empty-by-default
// invariant, doc 12 §5.3). It is part of the D51 public claims package
// (README.md): every guardrail the docs promise becomes a test that tries to
// make the guardrail FAIL and asserts it doesn't.
//
// THE CLAIM (doc 06 §3c, verbatim in substance; D17/D74). The cert-pinned
// pass-through list is **EMPTY BY DEFAULT** (the D64 baseline pack ships the D17
// pass-through list empty — doc 12 §5.3; adding an entry is a frozen invariant
// requiring attached reproduction evidence, D74). A pass-through-LISTED pinned
// client gets an **opaque tunnel with NO credential swap** (SNI + admission
// enforced and netflow-accounted, but no inspection / swap / scanning, doc 12
// §5.3), while **everything else is TLS-terminated at the per-session CA** (D17)
// and runs through the inspected chain (full-visibility egress by default).
//
// THE CHECK (mechanical pass-through-config diff). A synthetic fixture records
// the pass-through configuration's `is_default` flag (whether this is the
// shipped baseline pack, D64) and a set of endpoints, each tagged with: whether
// it is on the pass-through list, whether its flow was TLS-terminated at the
// per-session CA, and whether a credential swap was performed on it. The diff
// FAILS NAMED on:
//
//	(a) NONEMPTY-DEFAULT — the configuration is the default (is_default=true) yet
//	    its pass-through list is non-empty: the baseline ships an entry, which the
//	    D74 invariant forbids (an entry must be added deliberately with evidence,
//	    never shipped by default).
//	(b) SWAP-ON-PASSTHROUGH — a pass-through-listed endpoint had a credential swap
//	    performed on it: a pass-through tunnel is opaque — no swap (D17/D74). The
//	    swap belongs only on the TLS-terminated inspected path.
//	(c) UNTERMINATED-NONPASSTHROUGH — an endpoint that is NOT on the pass-through
//	    list whose flow was NOT TLS-terminated at the per-session CA: everything
//	    not pass-through-listed must be terminated (D17), so an un-terminated
//	    non-listed endpoint is a silently-opaque flow the claim forbids.
//
// A conforming fixture: the default config carries an EMPTY pass-through list,
// every pass-through-listed endpoint is an opaque tunnel with no swap, and every
// non-listed endpoint is TLS-terminated at the per-session CA. A non-default
// (explicitly-configured, evidence-backed) config MAY carry pass-through entries
// — the empty-by-default invariant binds only the shipped baseline (is_default).
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored
// pass-through-config picture against the DOCUMENTED D17/D74 contract (doc 12
// §5.3). The endpoint observations are DATA, never produced by a real proxy, a
// real per-session CA, or a real TLS handshake. There is NO live claude /
// qemu(VM-run) / podman / TLS / network invocation anywhere in this package;
// nothing performs a real swap, terminates a real connection, or opens a tunnel.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static config-vs-invariant diff with no data-plane
// dependency, so it executes on any checkout via `go test ./...` from any cwd
// (fixture paths anchor off runtime.Caller, not the process working directory).
//
// REGISTRATION (claim metadata). This row's guardrail tag is single-sourced in
// the package as Tag. The repo-root guardrail-map.yaml is NOT edited here (it is
// Boundary-owned via CODEOWNERS); a new unmapped subdir is fail-closed to the
// full matrix (D47), so the row self-gates without a map edit.
//
//	guardrail tag: pass-through-empty-by-default
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c "Cert-pinned pass-through" (D17/TLS-4; D74 empty
//	               default, doc 12 §5.3)
package passthrough
