# assurance/conformance-adapter/ — the real data plane behind the executable spec

The `boundary/` Go harness is the executable specification of the boundary's guarantees
(D26): every seam is a stub, every test asserts the real documented outcome, and the suite
is RED by design. This module is **how it goes green**: a conformance adapter that
implements the harness's Go interface seams by driving the **real Rust data plane**
(`dataplane/` services — ds-dnsgate, ds-tlsproxy, ds-flowlog — plus the ds-nft ruleset)
over the wire (doc 06 §2.2,
[boundary/README.md](../../boundary/README.md) "Why Go, when the data plane is Rust").
The spec never imports production code and production code never imports the spec; this
adapter is the only place the two meet.

**Owner:** Boundary workstream.

**Licensing:** OSS (Apache-2.0, in `oss-manifest.yaml`) — deliberately. D26's executable
spec ships with the OSS data plane, so **anyone must be able to run the spec against an
OSS deployment** with this adapter; an adapter you can't run would make the spec private
again (Part-4 resolution 11 of the skeleton design; D26/D51).

## Proxy wire-conformance (the non-buf seam)

The proxy data plane speaks real wire protocols, not our RPC, so its contract is enforced
by **conformance tests against real clients** plus golden-trace diffs
(doc 06 §2.2). The client matrix lives here:

| Client | Must observe |
|---|---|
| `curl` | indistinguishable from a vanilla proxy except where policy intervenes |
| `npm` (registry install) | same; cache/pre-bake path exercised |
| `git` over HTTPS | same; cred-swap rewrite on the credentialed path |
| cert-pinned client | hits the **pass-through list** (D17): opaque tunnel, no TLS termination, no cred swap |
| DoH client | **blocked** — all resolution forced through our resolver |

Golden-trace cases record a known request/response exchange (headers, cred-swap rewrite,
allow-set side effect) and diff future runs against the capture.

Note on the `boundary/` conventions: the harness prefers interface-seam fakes and reserves
real-binary tests as documented `t.Skip` exceptions
([boundary/CONVENTIONS.md](../../boundary/CONVENTIONS.md)). Those skipped real-infra tests
are *enabled from here*, where the real services and real client binaries exist.

## Build/workspace posture

This is its own Go module, listed in the root `go.work`; `boundary/` is deliberately
**excluded** from the workspace (the harness is never built with production code). At
skeleton time this module has zero dependencies; when the first adapter lands it gains a
test-scoped dependency on `github.com/dream-serpent/dream-serpent/boundary` (the seam interfaces) — that
wiring choice (require+replace vs. workspace edit) is made in that PR, not now.

## Governing decisions

- **D26** — ship the guardrail suite with the OSS data plane as the executable spec (doc 06 OQ5)
- **D51** — the public subset is the complete claims table; this adapter is what makes it runnable
- **D17** — TLS termination path + cert-pinned pass-through (the two wire behaviors the client matrix proves)
- **D2/D40** — Pingora proxy data plane; pinned `pingora-core 0.8.x` in `dataplane/` (recorded there, not here)

## What must NOT live here

- **Guardrail test bodies** — the assertions live in `boundary/` (the spec) and `guardrail-conformance/` (the published claims package); this module is wiring, not spec.
- **Changes that weaken the spec** — if the real data plane can't satisfy a `boundary/` test, the fix is in `dataplane/` or a spec-owner-approved spec change, never an adapter shim that fakes the outcome.
- **Production code paths** — nothing in `dataplane/` or `orchestrator/` may import this module.
- **Recorded (non-synthetic) traffic fixtures** (D50).

## Neighbors

- `boundary/` — the RED spec; its README carries the Go-island → Rust-crate mapping table this adapter implements seam by seam.
- `dataplane/` — the system under test.
- `guardrail-conformance/` — packages the (c) claims for outsiders; it runs *through* deployments this adapter knows how to drive.
