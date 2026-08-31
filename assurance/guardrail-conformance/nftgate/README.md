<!-- SPDX-License-Identifier: Apache-2.0 -->

# nftgate — the network-boundary (c) conformance band

The executable form of the doc 06 §3c / doc 09 §9 **network-boundary** guardrail
claims (D51 public claims package). Every guardrail the docs promise becomes a
test that drives a synthetic egress attempt against the modeled boundary
disposition and asserts the documented outcome holds (vocabulary is binding:
**assurance tests for advertised properties**, never attack / redteam).

All checks are **offline + synthetic (D50)**: a small auditable decision
function (`Posture.Dispose`) over the frozen doc 09 §9 / doc 11 §6 / D70 / D75
posture, diffed against authored fixtures under `fixtures/`. The live half
(`live_test.go`, `DS_NFTGATE_LIVE=1`) drives the SAME model against a real
boundary and is a deferred manual pass, skipped by default (no CAP_NET_ADMIN /
live nft in CI).

## Rows

### M0 seed set — `RowOwners()` (carries a scaffolded live runner)

| Row | doc 09 §9 owner | Claim |
| --- | --- | --- |
| `default-deny-outbound` | NFT-1 + TLS-1 | a non-allowlisted destination is denied at L3/4 and via the proxy (D4) |
| `dns-rebinding-fails` | DNS-4 + NFT-3 | a re-resolving name never silently widens the allow-set; internal ranges are scrubbed |
| `doh-dot-bypass-fails` | NFT-4 + POL-2 | all resolution forced through our resolver (DoT drop, known-DoH deny) |
| `port-53-redirect-holds` | NFT-4 | port-53 lands on ds-dnsgate regardless of aimed-at IP |
| `quic-udp443-reject-not-drop` | NFT-4 (D70) | udp/443 rejected-with-ICMP + counted, never silently dropped |

### Band-c extension — `BandCRowOwners()` (the remaining §9 (c) rows)

| Row | doc 09 §9 owner | Claim |
| --- | --- | --- |
| `interface-match-not-source-ip` | NFT-2 | a forged in-VM source address does not escape the `iifname`-matched redirect |
| `ech-svcb-suppression` | DNS-4 + TLS-1 | no HTTPS/SVCB answer reaches a VM; an ECH ClientHello can't hide a non-admitted domain behind an admitted IP |
| `session-isolation-no-l2-path` | §2 placement + NFT-1 | session A cannot reach session B — no L2 path between agent VMs (D66) |
| `ipv6-closure-dormant-posture-holds` | NFT-1 + DNS-4 (D75) | dormant guest-v6 posture holds: AAAA stripped to NOERROR/NODATA, v6 egress denied at the boundary host netns |

`AllRowOwners()` is the union; fixture-coverage and step-ownership assertions run
over it. The band-c rows are kept in a **separate** owners table from the M0 seed
set because the M0 rows additionally register a scaffolded live runner
(`live_test.go`); the band-c rows are offline spec-vs-model checks whose live
wiring is a later step, so folding them into `RowOwners()` would demand a live
runner each before that wiring exists.

## Host-baseline drift assertion (doc 14 §11)

`hostbaseline.go` / `hostbaseline_test.go` are a **distinct** (c)-suite check from
the egress rows above: they assert the versioned host-baseline artifact
(`dataplane/artifacts/host-baseline/host-baseline.v0.json`) satisfies every doc 14
§11 obligation (kernel ≥6.12 / conntrack sysctls, D68; structural L2 isolation +
`br_netfilter` forbidden, D66; per-session-tap v6/RA posture + `inet` family, D75;
the NFT-1 mark-constant lint pointer, D76). `HostBaseline.Check` returns one
`BaselineViolation` per failed obligation; the suite loads the SHIPPED artifact and
asserts `Check` is empty, so a drifted sysctl/kernel/tap obligation goes RED —
"drift = failure, not log line". Fail-closed: an omitted obligation field is a
violation, never a zero-value pass. The red path is proven non-vacuous by
`fixtures/hostbaseline/violated-baseline.json` (a synthetic, provenance-tagged
baseline drifting six obligations), and an artifact↔ruleset cross-check pins the
baseline's declared `inet` family against the NFT-1 bootstrap's actual `table inet`.
This fixture lives in a `fixtures/` subdirectory and is deliberately skipped by
`LoadFixtures` (which reads only top-level egress-attempt fixtures).

## Fixtures

`fixtures/*.json` are authored egress attempts paired with the disposition the
docs require; each carries a `<name>.provenance` sidecar (`provenance:
synthetic`, D50) and the directory carries `PROVENANCE.md`. Every row is seeded
by a holds/breaks pair (the guardrail-defeated-attempt case and a control that
proves the deny is not a blanket block), enforced by `TestAllRowsSeeded` /
`TestBandCRowsSeeded` and the band-c negative control (`TestBandCNegativeControl`).
