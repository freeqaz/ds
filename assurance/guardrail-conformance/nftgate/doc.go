// SPDX-License-Identifier: Apache-2.0

// Package nftgate holds the executable form of the doc 06 §3c M0 guardrail-
// conformance rows for the network boundary: **default-deny outbound (D4)** and
// the **DNS-gated allow-set, no-bypass** family (doc 03 OQ1; D68/D70). It is part
// of the D51 public claims package (README.md): every guardrail the docs promise
// becomes a test that tries to make the guardrail FAIL and asserts it doesn't.
//
// ASSURANCE FRAMING (doc 06 §3c, binding). These are assurance tests for
// properties we advertise — the way a database ships tests proving it does not
// lose committed writes. There is no attack / red-team / intrusion vocabulary
// anywhere in this package. The model phrases each defeat attempt as an "egress
// attempt" the VM (treated as untrusted) makes, and asserts the boundary's
// documented disposition holds.
//
// THE M0 ROWS (the seed set). Each row is one claim → one assertion:
//
//	Default-deny outbound (D4). A VM that aims at a non-allowlisted destination
//	is DENIED — at L3/4 before the proxy (NFT-1's inet default-drop on agent-VM
//	interfaces) AND via the proxy (TLS-1's domain+admitted-IP admission check).
//	The assertion drives both legs: an L3/4 reach to an unadmitted IP is dropped
//	by the NFT-1 base chains, and a proxied connection whose SNI/IP is not an
//	admitted (domain, IP) pair is refused at the egress gateway. An allowlisted
//	destination is the control: it is admitted on BOTH legs (so the suite proves
//	the deny is the default, not a blanket block).
//
//	DNS-gated allow-set, no bypass (doc 03 OQ1). Four defeat attempts, each must
//	fail:
//	  - REBINDING (DNS-4 + NFT-3): an approved name re-resolving to a NEW address
//	    does not silently widen the allow-set — re-resolutions go through full
//	    DNS-2 admission again (insert-then-answer), and a private / link-local /
//	    loopback / host-range answer (incl. an IPv4-mapped/NAT64-embedded v4) is
//	    scrubbed, never inserted. The old address does not stay admitted for the
//	    new flow by accident.
//	  - DoH/DoT BYPASS (NFT-4 + POL-2): all resolution is forced through our
//	    resolver. A DoT attempt (tcp/853) is dropped; a DoH attempt to a known
//	    public DoH resolver domain (D64 baseline blocklist, POL-2) is denied at
//	    DNS-3 and the TLS-1 SNI check; an in-VM `nameserver 8.8.8.8` still lands
//	    on ds-dnsgate (NFT-4 port-53 redirect).
//	  - PORT-53 REDIRECT HOLDS (NFT-4): destination-port-53 traffic from VM
//	    interfaces lands on ds-dnsgate NO MATTER what IP the VM aimed at — there
//	    is no foreign-resolver bypass.
//	  - QUIC REJECT-NOT-DROP (D70, NFT-4): udp/443 from agent-VM interfaces is
//	    REJECTED with ICMP port-unreachable and COUNTED per session — never
//	    silently dropped — to force TCP fallback the proxy can see. The assertion
//	    distinguishes reject-with-icmp+count from a silent drop; a silent drop is
//	    a FAILURE of this row even though "the packet didn't get out" either way.
//
// STEP OWNERSHIP (doc 09 §9, the assurance-hook table). Each row names the
// boundary step that owns it, so a boundary PR's diff-scoped (c) subset (D47
// guardrail-map) can be selected: default-deny → NFT-1; port-53/DoT/QUIC bypass
// → NFT-4; rebinding / no-silent-widen → DNS-4 + NFT-3; known-DoH denial → POL-2
// (+ TLS-6 for the HTTP-level half, deferred). These owners are carried on each
// modeled claim and asserted for coverage.
//
// THE CHECK (offline, synthetic — D50). The boundary's documented disposition is
// modeled as a small, auditable decision function (Disposition) over the frozen
// doc 09 / doc 11 posture; synthetic egress-attempt fixtures under fixtures/ name
// the attempt and the disposition the docs require, and the offline test diffs
// the modeled disposition against the fixture's required disposition. The model
// is the spec read of docs 09 §9 / 11 §6 / D70 — it drives no real services
// (that is conformance-adapter/'s job, README.md) and holds no live state.
//
// THE LIVE HALF (env-gated, fail-loud-but-off — live_test.go). The wire pass
// against a real boundary is DEFERRED MANUAL, gated behind DS_NFTGATE_LIVE=1 and
// SKIPPED BY DEFAULT, so `go test ./...` stays green offline and in CI. No live
// claude / cia / podman, and no CAP_NET_ADMIN / live-nft execution in CI (the
// project constraint): the runners are scaffolded and fail LOUDLY ("not yet
// wired") under the gate so a half-configured live run can never look like a
// pass. Each live runner reuses the SAME modeled disposition the offline half
// asserts, so the two halves can never drift.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). Every row here is
// oss-runnable: the offline check is a static fixture-vs-model diff with no
// data-plane dependency, executing on any checkout via `go test ./...` from any
// cwd (fixture paths are anchored off runtime.Caller, not the process cwd).
package nftgate
