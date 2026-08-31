// SPDX-License-Identifier: Apache-2.0

// Package credswap holds the executable form of the **credential-swap never
// leaks long-lived secrets** guardrail-conformance row (doc 06 §3c, the
// "Credential swap never leaks long-lived secrets" claim; D8, doc 02 §6;
// D39/D83, doc 16 §13 "Cred-never-in-VM/host"). It is part of the D51 public
// claims package (README.md): every guardrail the docs promise becomes a test
// that tries to make the guardrail FAIL and asserts it doesn't.
//
// THE CLAIM (doc 06 §3c, verbatim in substance). The long-lived credential
// **never appears inside the VM** — not on disk, not in env, not in the CoW
// delta, not in any response the agent can read; only the short-lived cred is
// ever present — and **never on the metal host** (D39; the swap-class half of
// the D8 promise). The swap happens OUTSIDE the VM at the egress gateway
// (ds-tlsproxy's TLS-5 swap executor; doc 16 §5.2): the agent presents its
// short-lived placeholder, the executor fetches the real long-lived credential
// from the off-host key store in the D39 trust zone and substitutes it upstream,
// so a VM (or metal-host) compromise yields nothing worth rotating (D8).
//
// THE INJECT-CLASS TWIN (doc 16 §13; doc 20 §7.3, the deliberately weaker split
// claim). The never-enters-the-VM promise covers **swap-class** in full;
// **inject-class** credentials (STS-style short-lived creds passed into the
// environment by design — doc 02 §6's AWS sketch) are a distinct, weaker claim
// the doc 06 (c) wording must keep split: they are NOT asked to be absent from
// the VM — they are bounded by a **TTL** and the presence of the
// `ISSUED{service_id}` digest in the keyed feed, so a wrong-destination egress
// blocks (doc 16 §5.1/§13). This row encodes BOTH claims and keeps them
// separate: a swap-class secret that appears on ANY in-VM/host surface is a
// breach; an inject-class secret is judged only on its TTL bound and ISSUED
// digest, never on in-VM presence.
//
// THE CHECK (mechanical surface scan over a synthetic credential picture). A
// synthetic fixture records, per credential, its class (swap | inject), and —
// for the surfaces the claim enumerates — whether the LONG-LIVED secret's value
// is observed there. The enumerated surfaces are exactly the doc 06 §3c list:
//
//	disk            — a file inside the VM's filesystem.
//	env             — a process environment variable inside the VM.
//	cow_delta       — the per-session copy-on-write overlay (D82 injection lives
//	                  here, but the long-lived credential must not).
//	agent_response  — any response byte the agent can read (the swapped-upstream
//	                  body/headers must carry the real cred only OUTSIDE the VM).
//	metal_host      — the bare-metal host filesystem/env (the D39 "never on the
//	                  metal host" extension; the executor holds fetched grants in
//	                  memory ≤ session, never written to host-visible state).
//
// For a swap-class credential, the long-lived secret observed on ANY of those
// surfaces FAILS with a surface-named violation class. For an inject-class
// credential, in-VM presence is BY DESIGN and never a violation; instead the
// twin asserts the TTL bound is present and positive AND the
// `ISSUED{service_id}` digest is present — a missing/zero TTL or a missing
// ISSUED digest FAILS NAMED. A conforming fixture: every swap-class secret
// absent from all five surfaces, every inject-class secret carrying a positive
// TTL and an ISSUED digest.
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored
// credential-surface picture against the DOCUMENTED swap/inject contract (doc 16
// §5.2/§13, doc 20 §7.3) and carries a `.provenance` sidecar. Nothing here mints
// a real credential, opens a real key store, runs a real swap, reads a real VM
// disk/env, stats a CoW overlay, or touches the metal host. The credential
// "values" are synthetic placeholder strings; the surface observations are DATA,
// never produced by touching any filesystem, process, or network. There is NO
// live claude / qemu(VM-run) / podman / Vault / OpenBao / KVM invocation anywhere
// in this package, and no DS_KVM_LIVE token is read or set.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static surface-vs-class diff with no data-plane or key
// store dependency (D85 placed the swap mechanics + digest producer in OSS so
// this claim stays OSS-runnable), so it executes on any checkout via
// `go test ./...` from any cwd (fixture paths anchor off runtime.Caller, not the
// process working directory).
//
// REGISTRATION (claim metadata). This row's guardrail tag is single-sourced in
// the package as Tag so the package's claim metadata and any future
// guardrail-map.yaml row name the SAME row. The repo-root guardrail-map.yaml is
// NOT edited here (it is Boundary-owned via CODEOWNERS); a new unmapped subdir is
// fail-closed to the full matrix (D47), so the row self-gates without a map edit
// — a map edit buys only a CI-scope narrowing.
//
//	guardrail tag: cred-swap-never-leaks
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c "Credential swap never leaks long-lived secrets"
//	               (D8/D39/D83; doc 16 §13; the inject-class split per doc 20 §7.3)
package credswap
