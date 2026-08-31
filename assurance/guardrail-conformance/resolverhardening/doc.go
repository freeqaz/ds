// SPDX-License-Identifier: Apache-2.0

// Package resolverhardening holds the executable form of the D42 resolver-
// hardening (c) row — "resolver hardening holds as a unit" — from the doc 20 §4
// guardrail-claims table (claim 1), the doc 06 §3c "DNS-gated allow-sets, no
// bypass" + "ECH / HTTPS-SVCB suppression" rows it maps to, and the doc 11 §3
// frozen wire invariants (W2/W5) it asserts. It is part of the D51 public claims
// package ([../README.md]): every guardrail the docs promise becomes a test that
// tries to make the guardrail FAIL and asserts it doesn't (doc 06 §3c).
//
// VOCABULARY (doc 06 §3c, binding). Never attack / redteam / intrusion. These
// are **assurance tests for properties we advertise** — the way a database ships
// tests proving it does not lose committed writes. Each clause is named for the
// property it proves and the NAMED way a regression would let it slip; a fixture
// that models a defeat attempt is named for the property it probes (a foreign
// resolver aimed at, a private-range answer), never for an attacker.
//
// "AS A UNIT" (D42). The doc 20 §4 claim is that resolver hardening holds AS A
// UNIT — the resolution layer is the policy authority and every bypass is closed
// at the resolver together, not as a scattered set of point fixes. This package
// models the unit as ONE Decide function (DisposeResolution) over a synthetic
// resolution attempt, with a per-clause ViolationClass taxonomy so a single
// regression in any clause "fails NAMED". The nine clauses, each ratified by D42
// as a (c) assertion (amended by D70 reject-not-drop and D68 expiry contract):
//
//	(1) SOLE RESOLUTION PATH — all destination-port-53 traffic from VM interfaces
//	    lands on ds-dnsgate no matter what IP the VM aimed at; an in-VM
//	    `nameserver 8.8.8.8` still resolves through us (doc 09 §3 NFT-4, doc 20 §3.1).
//	(2) DoT DROPPED — DNS-over-TLS (tcp/853) is dropped (NFT-4).
//	(3) DoH BLOCKED AT L3+L7 — known public DoH resolver domains ship in the D64
//	    baseline blocklist (POL-2); enforced by DNS-3 denial (L7) and the L3
//	    closure (the HTTP-level half on otherwise-allowed hosts is TLS-6, deferred).
//	(4) FOREIGN-RESOLVER BYPASS ATTEMPTS COUNTED — a foreign-resolver bypass
//	    *attempt* is counted per session via the frozen NFT-5 counter + nflog rule
//	    (the "canary served" / bypass-attempt visibility clause, D69/D42).
//	(5) ECH PARAMS STRIPPED — HTTPS (type 65) / SVCB (type 64) answers are
//	    suppressed, stripping the ECH configs that would let a client encrypt the
//	    inner server name and defeat the TLS-1 SNI check (DNS-4 rule 4, doc 11 §3.3).
//	(6) PRIVATE-RANGE ANSWERS NEVER ADMITTED — the W5 dual-stack sanity scrub
//	    (private / link-local / loopback / host-and-boundary ranges; v6 ::1,
//	    fe80::/10, fc00::/7; embedded-IPv4 unwrap for ::ffff:0:0/96 and 64:ff9b::/96
//	    checked against the v4 rules) runs ahead of every insert and every answer
//	    (doc 11 W5, DNS-4 rule 2, D42).
//	(7) TTL'd PER-SESSION ALLOW-SETS, 60 s FLOOR / 15 min CAP — the W2 clamp
//	    deadline = clamp(chain_min_ttl, FLOOR=60s, CEIL=900s) + GRACE; re-resolution
//	    refreshes to max(existing, new) (never shortened) and goes through full
//	    admission again rather than silently widening the set (doc 11 W2, DNS-4
//	    rule 3, D42/D68).
//	(8) udp/443 REJECTED + COUNTED — QUIC is REJECTED with ICMP port-unreachable
//	    and counted per session, NEVER silently dropped, to force TCP fallback the
//	    proxy can see (D70 reject-not-drop amendment).
//	(9) SNI ↔ ADMITTED-IP CROSS-CHECK — TLS-1 admits a connection only when the
//	    SNI's domain is policy-allowed AND the original-destination IP is one
//	    ds-dnsgate admitted FOR THAT DOMAIN (closes the shared-CDN-IP hole, doc 03
//	    OQ1; the "cross-check on pass-through" clause, D42).
//
// THE ANCHOR CONSTANTS (the FLOOR/CEIL the docs fix). The 60 s FLOOR / 900 s CEIL
// (15 min) per-session allow-set TTL clamp is restated here as named constants
// with a guard test (TestClampWindowMatchesDocumentedCadence) pinning them to the
// documented D42/D68 values, so a silent constant drift fails HERE, not against a
// different window than the doc promises (the goldenfreshness/orchctl anchor-guard
// discipline). FLOOR/CEIL live in the POL-1 schema (tunable per push); the test
// pins the v0 defaults the docs name (doc 11 §3 W2, §4 frozen-vs-free).
//
// THE CHECK (offline, synthetic — D50). Each clause is a pure Decide/Check over a
// SYNTHETIC resolution attempt (a Go-literal posture + attempt the test builds),
// never a live ds-dnsgate / ds-tlsproxy / NFTables / VM / KVM / podman run. A
// CONFORMING control proves the green case and one fixture per NAMED clause
// proves the regression is caught (the coverageGate fails closed on either a
// missing control or an un-exercised clause).
//
// THE LIVE HALF (env-gated, fail-loud-but-off — live_test.go). The wire pass
// against a real boundary (a real ds-dnsgate + ds-tlsproxy + ds-nft ruleset on a
// virtual-metal VM) is DEFERRED MANUAL, gated behind DS_RESOLVERHARD_LIVE=1 and
// SKIPPED BY DEFAULT, so `go test ./...` stays green offline and in CI. PROJECT
// CONSTRAINT (binding): no live claude / cia / podman, and NO CAP_NET_ADMIN /
// live-nft / live-dataplane / live-identity execution in CI. Each runner is
// SCAFFOLDED and fails LOUDLY ("not yet wired") under the gate so a
// half-configured live run can never look like a pass; each reuses the SAME
// modeled disposition the offline half asserts, so the two halves can never
// drift (the nftgate / resolverlock live-runner precedent).
//
// SYNTHETIC ONLY (D50). There is NO live boundary anywhere in this package: the
// aimed resolvers, transports, record types, answer addresses, clamp inputs, and
// SNI / original-dst pairings are all hand-authored DATA built in the test. No
// DS_*_LIVE token is read or set outside the env-gated live half, which is
// skipped by default. The module is deliberately OFF the repo go.work `use` list
// and runs standalone under GOWORK=off (../go.mod).
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). Every clause is
// oss-runnable: each is a static fixture-vs-reference decision with no data-plane,
// VM, or image dependency, so they execute on any checkout via `go test ./...`
// from any cwd (the fixtures are in-code Go literals — no fixture-path or
// working-directory dependency).
//
// REGISTRATION (claim metadata — pending the guardrail-map's first per-claim
// seeding). This row REGISTERS pending the repo-root guardrail-map.yaml's first
// per-claim seeding (doc 06 TODO "Translate every guardrail claim … (c)
// assertion" / doc SUMMARY next-action 4); doc 06 §3c's TODO names the "D42
// resolver-hardening clauses … new (c) members to seed". guardrail-map.yaml is
// NOT edited from this package — a new unmapped subdir self-gates fail-closed
// (D47) and the map is Boundary-owned (CODEOWNERS); the single guardrail tag below
// is single-sourced in resolverhardening.go (Tag) and TestTagStable pins it so the
// §3c table, this package, and the map name the SAME row when that seeding lands
// (the credswap/suspendbreach const-Tag discipline). The tag follows the doc 06
// §3c <domain>-conformance / <property> shape, never attack/redteam naming:
//
//	guardrail tag                     row
//	resolver-hardening-holds-as-unit  D42 resolver hardening holds as a unit
//
//	runnability: oss-runnable (see RUNNABILITY above)
//	owners:      NFT-4 / DNS-4 + TLS-1 (doc 09 §9, doc 11 §6)
//	decisions:   D42 (resolver hardening as a unit; every clause a (c) assertion),
//	             D70 (udp/443 reject-not-drop amendment), D68 (expiry/clamp contract),
//	             D64 (POL-2 baseline blocklist), D69 (NFT-5 bypass-attempt counter),
//	             D50 (synthetic fixtures), D51 (public package)
//
// [../README.md]: ../README.md
package resolverhardening
