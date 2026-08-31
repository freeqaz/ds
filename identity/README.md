# identity/ — Identity & credentials

**Owner workstream:** Identity & credentials (doc 05 §3)
**License:** OSS subset per D85 — everything in this tree is OSS; the paid identity layer (brokerage) lives in `paid/brokerage/`, not here
**Language:** **Go for the M0 shim** (`mint/`, a standalone module). The trigger this line reserved — "the workstream's first decision once the Stage-0 seams freeze" — is now **MET**: the Stage-0 `identity.v1` seams froze (`Validate`, `MintInterceptionCA`; the rest reserved per D111), so the M0 shim binds. Go is chosen on three grounds: (a) the now-met Stage-0-freeze trigger this line names; (b) the existing `fakes/digest-publisher` Go precedent already in this tree (same `proto/gen/go` + grpc + protobuf seam, same outside-`go.work` standalone-module pattern); (c) the shim is **throwaway-by-design behind the frozen `Validate` seam** (D22: M0 shim → M1 own CA → M3 SPIFFE), so the language choice binds only the disposable substrate, never the contract — a substrate swap behind a frozen contract, not a rebuild. The other dirs in this tree stay README-only until their own seam binds them.

## Charter

This tree owns rules-and-meaning for identity: per-workload identity minting (X.509 with a SPIFFE-compatible URI SAN + parallel JWT presentation), the interception-CA mint, credential grants and the swap material provisioned to ds-tlsproxy, the keyed secret-digest feed (producer side), credential-class semantics, and ask/attendedness semantics (doc 16 §1). The two headline promises this code exists to keep: **long-lived credentials never enter the VM and never sit on the metal host** (D8/D39), and **a planted canary credential never egresses** on inspected paths (D73, with the TLS-4 pass-through non-claim carried verbatim).

The **mint is a SEPARATE deployable** with its own dedicated instance — not a library inside the orchestrator (D22/D39, doc 02 §7: "key management probably its own dedicated instance, not on the metal box" — smaller attack surface, and security/IT can own it; an orchestrator compromise must never yield keys). The orchestrator's `MintIdentity` RPC fronts this service; it does not absorb it.

## Governing decisions

| D | What it pins here | Doc |
|---|---|---|
| D22 | Identity substrate progression behind one frozen `Validate` seam: M0 shim → M1 own CA → M3 SPIFFE | doc 16 §2 |
| D39 | Long-lived creds only in an off-host key store in a separate trust zone; mint on a dedicated instance | doc 16 §2, doc 02 §7 |
| D73 | Keyed digest feed: Identity owns the producer side; plaintext never crosses | doc 16 §6 |
| D82 | Identity mints the interception CA; two separate root hierarchies | doc 16 §4 |
| D83 | Frozen header-swap seam (user-auth first); SSH = designed-for seam | doc 16 §5 |
| D85 | Generic Vault/OpenBao KV client is OSS; brokerage is paid | doc 16 §2 |

## What must NOT live here

- **No DNS-layer identity.** ds-dnsgate consults no credentials or workload identity — attribution is interface-anchored per D44; this non-edge is recorded so nobody invents a DNS-layer identity check (doc 16 §10).
- **No enforcement plane.** Enforcement executes where D42 put it: the L7 proxy (ds-tlsproxy in `dataplane/`) is *the* policy authority for HTTP(S). The rungs Identity assigns and the swap decisions it grants execute there — never in a parallel identity enforcement plane (doc 16 §1). Identity owns rules-and-meaning; Boundary owns hooks-and-mechanics.
- **No `.proto` files.** All contracts live in `proto/dreamserpent/identity/v1/` (single contract home). The four Stage-0 identity seams (Validate, CA-mint, digest feed, identity-plane LOG-1) freeze there per doc 16 §9.
- **No brokerage.** IdP integration/mapping, fleet identity, hosted SPIFFE, dashboards, onboarding UI are paid → `paid/brokerage/` (D85, D59: no standalone identity SKU before M3).
- **No real credentials anywhere, ever** — tests use synthetic fixtures only (D50).

## Neighbors

- `proto/dreamserpent/identity/v1/` — the contract home for every seam this tree implements.
- `dataplane/` — consumes the Validate verdict, the per-session interception CA, swap material, and digests inside ds-tlsproxy; we never reach into its internals.
- `orchestrator/` — hosts the `MintIdentity` RPC on API surface v1 (D35) and owns the master session-create choreography; this tree owns the mint sub-sequence (doc 16 §6.1).
- `paid/brokerage/` — the paid identity layer (CODEOWNERS sub-glob → this workstream).
- `images/golden/` — executes the D17 per-session CA trust-store injection hook.

## Layout

| Dir | What |
|---|---|
| `mint/` | IdentityMint service — separate deployable, both CA root hierarchies (D82), implements D22 Validate |
| `digest-producer/` | Keyed HMAC digest producer, in the D39 trust zone, off-host |
| `kv-client/` | Generic Vault/OpenBao-compatible KV client (explicitly OSS, D85) |
| `grant-service/` | Stub — freezes with the M1 credential-swap design (D39/D55) |
| `ssh-signer/` | RESERVED seam name only (D83) — no build target |
| `fakes/digest-publisher/` | Stage-0 fake publisher beside the D22 seam fakes (doc 14 §7) |
| `tokens/` | Scoped agent credentials — attenuable session tokens (STS analogy: base token on behalf of the launching user; offline-attenuated children at D18 fan-out). **Design-stage; doc 19 is a proposed seed, rows unratified** |
