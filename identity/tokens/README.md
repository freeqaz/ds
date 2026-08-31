# identity/tokens/ — Scoped agent credentials (attenuable session tokens)

**Owner workstream:** Identity & credentials · **OSS** (issuance/attenuation/verification ride the D85 line — D103, the conformance-forced extension, doc 19 §10)
**Status:** README-only skeleton, **design-stage**. Doc 19 was **ratified 2026-06-12** (round-4 packet): its §12 rows are doc 04 §6 **D97–D105**. Language deliberately unbound, like every sibling in `identity/`.

## Charter

The scoped agent-credential layer — the STS analogy: the mint issues a **per-session base token on behalf of the launching user** (`launching_user` as the root attribution claim; session UUID / role-ref / task-ref as scoping claims), and the orchestrator/wrapper derives **offline-attenuated child tokens** for subagent VMs at D18 fan-out — no mint round-trip (doc 19 §3–§4). The token is what the agent *presents*: it occupies the doc 16 §5.1 placeholder-token slot as a **parallel credential class behind the frozen D22 `Validate` seam** — a substrate, like the X.509/JWT story — never a replacement for the workload identity. The agent never holds long-lived credentials (D8); the boundary maps token → grants → swap (doc 16 §5.2).

Substrate: **Biscuit primary** (public-key verifiable, Datalog blocks, active Rust reference implementation), **macaroons the named alternative** behind the same seam, with recorded flip triggers (doc 19 §6).

## Governing decisions

Ratified context: D8, D18, D22, D39, D53/D77, D72, D85 (see doc 19 Source row). Token-specific decisions are **ratified** — **D97–D105** (doc 19 §12, ratified 2026-06-12; the P-ID → D map lives there). If you change behavior those rows describe, you are reopening a ratified decision (cite the D-number): update doc 19, don't fork it.

## What must NOT live here

- **No `.proto` bodies, and no new proto package.** The token rides `dreamserpent.identity.v1` — `presented_credential` is format-opaque at the D22 `Validate` seam (no second seam, D101); the only contract-side obligation is the reserved LOG-1 lineage field numbers (D104, proto/FREEZE.md identity row).
- **No hand-authored Datalog or free-form caveats.** Attenuation content is generated from typed templates only — the D52 / no-Cedar-in-v0 posture (doc 16 §5.1) carried verbatim (D100).
- **No signing-key custody.** The token signing key is a third D39 trust-zone signing context (never either D82 CA hierarchy, never on a boundary host); custody belongs with `../mint/`.
- **No enforcement.** Verdicts execute in ds-tlsproxy (D42 posture, doc 16 §1); this tree defines token semantics and the attenuation library, nothing more.
- **No workload-identity replacement.** X.509 + parallel JWT (doc 16 §3.1) stands; this is a parallel class.
- **No brokerage.** Role/scope template management, dashboards, fleet token inventory are paid → `paid/brokerage/` (D85/D59).
- **No agent-role semantics.** A role may carry a default attenuation template; the `role_ref` claim and template hook are reserved seams — roles are the sibling design pass's (doc 19 §11; the roles design is doc 18, whose §8 credential-scope template this layer consumes).
- **No real credentials anywhere, ever** — synthetic fixtures only (D50).

## Neighbors

- `../mint/` — issues the base token (`MintSessionToken`, ratified 2026-06-12 — D99; joins the doc 16 §4 mint surface, wave placement per D111) and implements the D22 `Validate` seam the token is verified at.
- `../grant-service/` — grant records are what attenuation templates are generated from; `Validate` returns *grants ∩ token scope*.
- `proto/dreamserpent/identity/v1/` — the contract home; carries the D104 reserved lineage fields on the identity-plane LOG-1 events.
- `orchestrator/` — the attenuator at D18 fan-out (`CreateChildSession`, doc 15 §5.3); derives child tokens offline.
- `dataplane/` — ds-tlsproxy presents tokens to `Validate` on the TLS-5 path; never verifies locally in v0 (D101 leaves the public-key pre-check as a future option).
- `roles/` — the session-role bundles (doc 18) whose credential-scope templates are the designated initial-attenuation source.
- `paid/brokerage/` — the paid template/role management layer.
