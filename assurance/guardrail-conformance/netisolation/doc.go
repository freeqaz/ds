// SPDX-License-Identifier: Apache-2.0

// Package netisolation holds the executable form of the Stage-2 (doc 09 §8
// "2 — Close the gaps") network-isolation guardrail-conformance rows from the
// doc 06 §3c (c) matrix — the boundary properties that, with NFT-2 / DNS-4 /
// TLS-1 / §2 placement in place, isolate an untrusted agent VM from forging its
// way out, from other sessions, and from the control plane. It is part of the
// D51 public claims package ([../README.md]): every guardrail the docs promise
// becomes a test that tries to make the guardrail FAIL and asserts it doesn't
// (doc 06 §3c).
//
// VOCABULARY (doc 06 §3c, binding). Never attack / redteam / intrusion. These
// are **assurance tests for properties we advertise** — the way a database ships
// tests proving it does not lose committed writes. Each row is named for the
// property it proves and the NAMED way a regression would let it slip; a fixture
// that models a defeat attempt is named for the property it probes (a forged
// source IP, a dormant fe80 reachability), never for an attacker.
//
// THE FIVE STAGE-2 ROWS (doc 06 §3c; doc 09 §8 Stage 2 + §9 assurance-hook
// owners; doc 11 §6; D66/D68/D75; the NFT-2 interface-match row of doc 09 §9):
//
//	(1) in-VM IP-spoofing fails / interface-match (NFT-2; doc 03 §3, doc 09 §9
//	    "In-VM spoofing fails (interface match)") — the prerouting redirect and
//	    the per-session attribution key match on the interface the VM is attached
//	    to (`iifname` / the `dstap-<idx>` tap), NEVER on source IP. A forged
//	    source address inside the VM does not escape the interface-matched
//	    redirect: the disposition turns on the arrival interface, not the claimed
//	    address. D44's three-keys-must-agree rule (iif / assigned guest IP / ct
//	    mark) is the structural backstop — a disagreement is a kernel drop, never
//	    an honored claim.
//
//	(2) ECH / HTTPS-SVCB suppression (D68/D75; doc 06 §3c "ECH / HTTPS-SVCB
//	    suppression"; doc 09 §9 DNS-4 + TLS-1; doc 11 §3.3) — no HTTPS (type 65)
//	    or SVCB (type 64) answer reaches a VM (suppressed entirely; an explicit
//	    type-65 query returns NODATA with an authored SOA), and ECH cannot hide a
//	    non-admitted domain behind an admitted IP: DNS-4 rule 4 removes the records
//	    that advertise real ECH configs, and TLS-1 refuses an ECH ClientHello, so
//	    plaintext-SNI TCP — the path the boundary can see — is forced.
//
//	(3) session A ↛ B isolation / no-L2-path (D66; doc 06 §3c "Session isolation";
//	    doc 09 §9 "§2 placement + NFT-1", doc 09 §2 placement note) — no L2 path
//	    exists between two agent VMs. The proof must be STRUCTURAL or FLAG-AUDITED,
//	    never inherited from the `inet` default-deny ruleset (bridged frames bypass
//	    the `inet` forward chain, so the L3/4 deny does not cover the L2 hole) — a
//	    routed tap / per-session bridge gives the structural no-L2-path proof,
//	    while `BR_ISOLATED` is honored only behind a continuous flag audit.
//
//	(4) IPv6 closure holds while dormant + the fe80 probe (D75; doc 06 §3c "IPv6
//	    closure holds while dormant"; doc 09 §9 / doc 11 §3.3/§3.5/§6 "nightly from
//	    Stage 2") — in the v0/dormant posture the guest is v4-only: AAAA is
//	    answered as a fast NOERROR/NODATA (never dropped/SERVFAIL/REFUSED), and the
//	    nightly v6-closure row — including a sibling fe80 probe — proves the
//	    boundary HOST netns (not the guest sysctl) holds the line: a link-local
//	    fe80::/10 reach between agent taps is closed structurally, so the dormant
//	    posture cannot become a silent v6 escape.
//
//	(5) controls unreachable from the VM (doc 06 §3c "Controls live outside the
//	    agent's reach", doc 04 §5; doc 09 §9 "NFT-1 + §2 placement") — from inside
//	    the VM the proxy / NFTables / policy engine / identity plane are neither
//	    observable nor modifiable: the boundary stack runs in the virtual-metal
//	    host network namespace the VM has no path into (NFT-1 default-drop + §2
//	    placement), so a probe at a control-plane endpoint from a VM interface is
//	    dropped, not answered.
//
// THE CHECK (offline, synthetic — D50). Each row is a pure Decide/Check function
// over a SYNTHETIC fixture: a Go-literal posture + probe the test builds, never a
// live VM / NFTables ruleset / ds-dnsgate / ds-tlsproxy / KVM / podman run. The
// shape mirrors the orchctl sibling — a typed fixture, a typed ViolationClass
// taxonomy, and a Check returning every NAMED violation in a stable order — so a
// row "fails NAMED" rather than with a bare boolean. A CONFORMING control proves
// the green case and one fixture per NAMED violation proves the regression is
// caught (the coverageGate fails closed on either a missing control or an
// un-exercised class).
//
// THE LIVE HALF (env-gated, fail-loud-but-off — live_test.go). The wire pass
// against a real boundary (a real ds-nft ruleset + two agent taps + the boundary
// host netns on a virtual-metal VM) is DEFERRED MANUAL, gated behind
// DS_NETISO_LIVE=1 and SKIPPED BY DEFAULT, so `go test ./...` stays green offline
// and in CI. PROJECT CONSTRAINT (binding): no live claude / cia / podman, and NO
// CAP_NET_ADMIN / live-nft / live-KVM execution in CI. Each runner is SCAFFOLDED
// and fails LOUDLY ("not yet wired") under the gate so a half-configured live run
// can never look like a pass; each reuses the SAME modeled disposition the
// offline half asserts, so the two halves can never drift (the nftgate /
// resolverlock live-runner precedent).
//
// SYNTHETIC ONLY (D50). There is NO live boundary anywhere in this package: the
// arrival interfaces, forged source addresses, record types, tap-pair L2 paths,
// dormant-v6 reach, and control-plane probes are all hand-authored DATA built in
// the test. No DS_*_LIVE token is read or set outside the env-gated live half,
// which is skipped by default. The module is deliberately OFF the repo go.work
// `use` list and runs standalone under GOWORK=off (../go.mod), so the claims
// package stays independent of production build state.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). All five rows are
// oss-runnable: each is a static fixture-vs-reference decision with no data-plane,
// VM, or image dependency, so they execute on any checkout via `go test ./...`
// from any cwd (the fixtures are in-code Go literals — no fixture-path or
// working-directory dependency).
//
// REGISTRATION (claim metadata — pending the guardrail-map's first per-claim
// seeding). These rows REGISTER pending the repo-root guardrail-map.yaml's first
// per-claim seeding (doc 06 TODO "Translate every guardrail claim … (c)
// assertion" / doc SUMMARY next-action 4). guardrail-map.yaml is NOT edited
// from this package — a new unmapped subdir self-gates fail-closed (D47) and the
// map is Boundary-owned (CODEOWNERS); the tags below are single-sourced in
// netisolation.go (Tags) and TestTagsStable pins them so the §3c table, this
// package, and the map name the SAME rows when that seeding lands (the
// orchctl/goldenfreshness honest-map-row discipline). The tags follow the doc 06
// §3c <domain>-conformance / <property> shape, never attack/redteam naming:
//
//	guardrail tag                                row
//	netiso-in-vm-spoofing-fails                  (1) in-VM IP-spoofing fails / interface-match (NFT-2)
//	netiso-ech-https-svcb-suppression            (2) ECH / HTTPS-SVCB suppression (D68/D75)
//	netiso-session-a-not-b-no-l2-path            (3) session A ↛ B isolation / no-L2-path (D66)
//	netiso-ipv6-closure-dormant-fe80-probe       (4) IPv6 closure holds while dormant + fe80 probe (D75)
//	netiso-controls-unreachable-from-vm          (5) controls unreachable from the VM (doc 04 §5)
//
//	runnability: oss-runnable (see RUNNABILITY above)
//	stage:       Stage 2 (doc 09 §8 "2 — Close the gaps"); the IPv6-closure row
//	             runs nightly from Stage 2 (doc 11 §6)
//	owners:      NFT-2 (1); DNS-4 + TLS-1 (2); §2 placement + NFT-1 (3, 5);
//	             DNS-4 / §3.3 + §2 placement + NFT-1 (4) — doc 09 §9, doc 11 §6
//	decisions:   D66 (attachment primitive / no-L2-path), D68 (HTTPS-SVCB / expiry),
//	             D75 (IPv6 hybrid + fe80 probe), D44 (three-keys attribution),
//	             D4 (default-deny), D50 (synthetic fixtures), D51 (public package)
//
// [../README.md]: ../README.md
package netisolation
