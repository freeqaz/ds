# Boundary TDD harness — conventions (read before writing any file)

This module is the **executable specification** (doc 04 D26) and TDD harness for the
Dream Serpent **Boundary** workstream (`docs/09-boundary-build-plan.md`). It is a Go
module because Go is the available toolchain; the production data plane is Rust/Pingora +
nftables, so these tests are the black-box spec the real data plane must satisfy.

These are **guardrail-assurance tests for a defensive security boundary** (default-deny
networking, credential isolation, DNS-rebinding/ECH defense, full attribution). Every test
proves a guardrail *holds*. We are writing **only tests + the stub seams they drive** — no
real implementation.

## The RED rule (this is TDD)

- Every seam ("the functions we will need") is a Go interface or function with a **stub**
  that returns `ErrNotImplemented` (where there is an `error` result) or a zero value.
- `New…()` constructors return a non-nil stub whose methods return `ErrNotImplemented` —
  tests must never nil-panic.
- Tests assert the **documented outcome** (the "Done when" / §9 row), so they **fail RED**
  until the real data plane satisfies them. **A test that observes `ErrNotImplemented` is
  failing-as-designed.** Never write a test that asserts `ErrNotImplemented` — that would
  pass against the stub and prove nothing.
- Make assertions strict enough that the zero-value stub cannot satisfy them (assert the
  exact expected value/reason/verdict, not just "no error"). A test that passes against the
  trivial stub is a bug in the test.

## Compilation is mandatory; test failure is expected

- The suite **must compile and vet clean**. `go test ./...` will exit non-zero (tests are
  RED) — that is correct.
- Verify your package compiles **without being misled by red tests** using either:
  - `go vet ./<pkg>/...`  (vets/compiles; unaffected by test failures), or
  - `go test -run '^$' ./<pkg>/...`  (compiles tests, runs none → exit 0 iff it compiles).
- Also run `go build ./...` for the non-test code.
- Iterate with the compiler until vet is clean. Do not hand back non-compiling code.

## Package layout (one self-contained island per package — no cross-package imports)

| Dir | Package | Owns |
|---|---|---|
| `policycore/` | `policycore` | policy-core + D64 baseline (POL-1..5) |
| `dnsgate/` | `dnsgate` | DNS gating proxy (DNS-1..5, 2b) |
| `tlsproxy/` | `tlsproxy` | TLS/CONNECT proxy + credential swap (TLS-1..8) |
| `nft/` | `nft` | NFTables L3/4 model (NFT-1..6, 2b) |
| `flowlog/` | `flowlog` | connection & netflow logging (LOG-1..5) |
| `.` (module root) | `boundary` | the cross-cutting §9 / §8 / Stage-0 facade + assurance tests |

Each package defines its **own** types (its own `SessionRef`, `Decision`, etc.) and imports
**only the standard library** (`context`, `time`, `errors`, `net/netip`, `net`, `crypto/tls`,
`io`, `reflect`, `testing`, …). Do not import sibling boundary packages — the duplication is
deliberate: each is a black-box surface developed against fakes of its neighbors (doc 06 §2).

## File naming per package

- `<pkg>.go` — the seams: types, interfaces, `ErrNotImplemented`, and `New…()` stubs.
- `<pkg>_test.go` — the tests. Split into a few files by theme if large
  (e.g. `dnsgate_rebinding_test.go`).
- Fakes / test doubles (recording fakes, fake clock, fake upstream, programmable stores)
  live in `_test.go` files (or an internal `<pkg>test` helper file compiled only for tests),
  so they ship with the tests, not the stubs.

## Test conventions

- **Table-driven** wherever the spec lists a table. Name sub-tests with `t.Run`.
- **Deterministic time**: use an injectable clock / fake `now`; never `time.Sleep` for
  expiry. Advance a fake clock.
- **Adversarial tests** (the spec marks them) prove a *bypass fails*. Make the malicious
  input explicit and assert the boundary denies/scrubs/attributes correctly.
- **Provenance**: where the spec requires it, assert every decision/event carries a non-empty
  rule id + layer + policy version.
- **Credential canaries**: use a high-entropy needle; assert **zero** occurrences across
  every surface (events, logs, downstream bytes, disk/env/CoW). Check raw, base64, hex,
  url-encoded forms where the spec says so.
- **Load tests** (`category: load`): guard with `if testing.Short() { t.Skip("load: scheduled (d) rig") }`.
  They still assert a budget constant and run red against stubs.
- **Tests needing real external infra** (real `curl`/`git`/`npm` binaries, a real kernel, a
  real TLS handshake against a live origin): prefer driving the Go interface seam with fakes
  so the test is RED-against-stub and runnable in CI. Only if a test *genuinely* cannot be
  expressed against the seam, write it and `t.Skip` with a precise reason naming the required
  infra (so it is documented and can be enabled later) — but this should be the rare
  exception, not the default. Most "conformance" tests drive the interface and assert the
  observable outcome.
- Add a one-line `// planRef:` comment on each test naming the doc 09 step / §9 row it encodes.

## What "done" means for your package

`go vet ./<pkg>/...` is clean, `go build ./...` is clean, every test from your component's
spec exists and is RED (fails by asserting the real outcome, not by asserting
`ErrNotImplemented`), and the seams compile as the contract surface the real data plane will
implement.
