# Boundary — TDD harness & executable specification

This module is the test-driven-development harness for the Dream Serpent **Boundary**
workstream (the boundary build plan, doc 09).
It is the **executable specification** of the boundary's guarantees (doc 04 D26):
a full test suite for every documented outcome, plus the stub seams ("the functions we will
need") those tests drive.

The Boundary is the network guardrail layer that lets coding agents run unattended in
locked-down VMs with a bounded blast radius — default-deny networking, DNS gating, TLS
inspection by the trusted proxy, credential swap that keeps long-lived secrets out of the
agent's reach, and complete per-session attribution. **This suite proves those guardrails
hold.** It is defensive security engineering: every adversarial test asserts that a bypass
*fails*.

## Why Go, when the data plane is Rust

The production data plane is Rust/Pingora + nftables. This harness is Go because it is the
toolchain at hand, and because the guarantees are best expressed as **black-box behavioral
tests**: given this packet / this DNS answer / this TLS ClientHello / this credentialed
request, the boundary must produce this verdict, this admission, this scrubbed log. The Go
interfaces mirror the contracts the real data plane will satisfy (via a conformance adapter,
doc 06 §2). The suite drives development regardless of implementation language.

Each Go island maps to a ratified home in the Rust workspace at
[`dataplane/`](../dataplane/) (doc 14 §6 crate
map):

| Go island | Rust home | Notes |
|---|---|---|
| `policycore/` | [`dataplane/crates/policy-core/`](../dataplane/crates/policy-core/) | the one evaluation engine (POL-3) + SecretMatcher trait; no `ds-` prefix |
| `dnsgate/` | [`dataplane/services/ds-dnsgate/`](../dataplane/services/ds-dnsgate/) | hickory-based per D67 — plain tokio, **not** Pingora |
| `tlsproxy/` | [`dataplane/services/ds-tlsproxy/`](../dataplane/services/ds-tlsproxy/) | pingora-core (D40) |
| `nft/` | [`dataplane/crates/ds-nft/`](../dataplane/crates/ds-nft/) | the one nft/netlink API; `flush_session` impl |
| `flowlog/` | [`dataplane/services/ds-flowlog/`](../dataplane/services/ds-flowlog/) | LOG-1 wire types live in [`dataplane/crates/ds-contracts/`](../dataplane/crates/ds-contracts/), emission in `ds-telemetry` |
| `.` (root, `boundary`) | [`assurance/conformance-adapter/`](../assurance/conformance-adapter/) | the Go module that wires the real data plane behind these seams (doc 06 §2.2); shared contract constants (SessionRef, RejectReason, `flush_session` signature, mark layout) live in `ds-contracts` |

## It is RED by design

Every seam is a stub returning `ErrNotImplemented` (or a zero value). Every test asserts the
**real documented outcome**, so `go test ./...` fails — that is the TDD signal. As the
Rust/nftables data plane is built behind these contracts, the tests go green one guardrail at
a time.

```sh
go vet ./...                 # compiles + vets; should be clean
go test -run '^$' ./...      # compiles all tests, runs none; exit 0 iff everything compiles
go test ./...                # RED: the executable spec of what is not yet built
go test -short ./...         # skips the load/(d)-rig tests
```

A test that *passes* against the stubs is a bug in the test (it is not asserting a real
outcome) — see [`CONVENTIONS.md`](CONVENTIONS.md).

## Layout

Each package is a self-contained island mirroring one part of the plan; it defines its own
types and imports only the standard library (each is developed against fakes of its
neighbors, doc 06 §2).

| Package | Plan section | Proves (headline guardrails) |
|---|---|---|
| [`policycore/`](policycore/) | §6 POL-1..5 | one engine, deny-overrides layering, the D64 baseline (amended by D74) admits exactly the intended endpoints and nothing else, provenance on every decision, fleet push without version skew |
| [`dnsgate/`](dnsgate/) | §4 DNS-1..5 | insert-then-answer, answered ⊆ admitted, dual-stack rebinding scrub (incl. IPv4-mapped IPv6), HTTPS/SVCB suppression, CNAME keyed on the query name, REFUSED-not-NXDOMAIN |
| [`tlsproxy/`](tlsproxy/) | §5 TLS-1..8 | per-domain (not per-IP) admission, ECH refusal, re-admission to *our* resolved address, per-session CA isolation, **the long-lived credential never enters the VM**, pass-through never swaps, suspend-on-breach |
| [`nft/`](nft/) | §3 NFT-1..6 | default-deny, iifname match (source IP never consulted), allow-set expiry gating new flows only, single-writer, resolver-bypass closure, byte-identical teardown, no L2 path A↛B |
| [`flowlog/`](flowlog/) | §7 LOG-1..5 | metadata-only schema, 100% attribution by unforgeable keys, admitting-domain join, self-auditing reconciliation alarm, credential value nowhere / fingerprint-only |
| [`.` (root, `boundary`)](.) | §9 matrix, §8 lifecycle, §1, Stage 0 | the cross-cutting black-box guardrail matrix, the create→…→destroy lifecycle, the developer-value halves, the frozen Stage-0 contracts run against real + fake |

`.specs/` holds the per-component design specs (seams + test enumeration) the suite was
generated from. `CONVENTIONS.md` is the authoring contract.

## What must NOT live here

- **Production implementations behind the seams** — greenness comes only via
  [`assurance/conformance-adapter/`](../assurance/conformance-adapter/) driving the real
  Rust data plane; implementing a seam in this tree would turn the executable spec into
  a second implementation.
- **Adapter shims inside this tree that turn tests green** — a test that passes without
  the real data plane is a bug in the test (see `CONVENTIONS.md`); the only legal path
  to green runs through the conformance adapter.
- **`.proto` files** — `proto/` is the single contract home.
- **A plain `go test ./...` CI gate** — the suite is RED by design (D26); its CI lane is
  vet + build + compile-only (`go test -run '^$'`), never a pass/fail run of the suite.
- **Dependency edges into the go.work modules** — this module imports only the standard
  library; it is deliberately excluded from `go.work` so the harness can never link
  production packages.

## Reading a test

Each test carries a `// planRef:` comment naming the doc 09 step or §9 assurance row it
encodes, so the suite is traceable back to the plan line by line. The adversarial tests (the
majority of the guardrail-assurance set) name the specific bypass they defeat — rebinding,
ECH, source-IP spoofing, credential exfiltration, resolver bypass, cross-session leakage.
