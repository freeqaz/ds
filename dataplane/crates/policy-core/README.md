# policy-core

**THE one policy evaluation engine.** Every allow/deny/ask verdict, swap/pass-through
decision, and cap verdict in the data plane comes out of this crate. It is embedded —
not called over a wire — in `ds-dnsgate`, `ds-tlsproxy`, and the NFTables programming
path, so the three enforcement points can never disagree about a rule
(doc 09 §6, POL-3).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25; part of the open data plane, D15)
- **Governing decisions:** D63 (service split, shared engine), D67 (workspace as
  anti-skew mechanism, doc 14 §6),
  D73 (`SecretMatcher` two-plane split, doc 12 §5),
  D52/D53 (guardrail classes + rung ladder, doc 13 §1–2)

Naming note: this is the one crate without the `ds-` prefix — doc 14 §6 names it
`policy-core` and renames are refactors, not contract changes.

## Frozen invariants (implementation may not renegotiate)

| Invariant | Source |
|---|---|
| One evaluator. No consumer reimplements a rule; identical decision semantics in both services and the NFT path | doc 13 §1.1 / POL-3 |
| Every verdict carries POL-3 provenance: matched rule id, policy layer, policy version. A missing-provenance event fails CI | doc 09 POL-3, doc 11 §5.5 |
| Verdict API shape: `evaluate(DnsQueryCtx{session, qname, qtype, source}) -> Verdict ∈ {Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}` | doc 11 §4 (frozen column) |
| Layered composition with deny-overrides (system-baseline → org → repo/session); blocklists always win | doc 13 §1.2 |
| `SecretMatcher` trait + verdict semantics `{Pass, Hold, Block, Flag, Redact-reserved}`; the proxy owns the hold-back invariant; confirm-before-verdict (no Bloom prefilter hit may drive a ≥block verdict) is part of the trait contract | D73; doc 12 §5.1; doc 14 OQ5 |
| Rung caps are structural: schema validation forbids `suspend+ask`/`kill+snapshot` on generic content rules; `fail_open` legal only for flag-only generic configs | D73/D53; doc 13 §2 |

The `SecretMatcher` **trait** is also what the Attach & client workstream links for the
attach-side matcher consumer (doc 14 §6; the consumer itself runs orchestrator-side per
doc 16 §6.5 — there is no `client/secretmatcher/` directory by design).

## Free (firm up during build)

Matcher engines (exact digest set vs Bloom-prefilter-plus-confirm, aho-corasick /
Vectorscan / RegexSet), candidate extraction, evaluator data structures.

## What must NOT live here

- **The POL-1 schema and contract constants** — those are `ds-contracts`' home
  (doc 13 §3 ratifies the placement). This crate evaluates; it does not define wire/schema contracts.
- **Framework types** — no hickory or pingora type may appear in this crate's API (D67/D40).
- **nftables writing** — that is `ds-nft`, single-writer discipline.
- **Any approval surface** — ask-user flows route to the client wrapper over the D18 seam; the boundary never grows its own approval UI (doc 09 POL-5).

## Neighbors

`ds-contracts` (types it stamps provenance into), `ds-policy-snapshot` (delivers the composed
policy document it evaluates), both services (embed it), `boundary/` Go harness
(its executable specification — see the island→crate mapping in `boundary/README.md`).
