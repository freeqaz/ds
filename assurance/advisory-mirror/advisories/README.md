# advisories/ — seed mirrored-advisory test specs

These are the **seed** mirrored-advisory test specs for the two RUSTSEC advisories that
doc 11 §6 obligation 8 names as the corpus seeds:
RUSTSEC-2026-0118 (NSEC3 loop) and RUSTSEC-2026-0119 (compression bomb).

**These are specs/fixtures ONLY.** The `ds-dnsgate` crate they wire into **does not exist yet**, so
nothing here is executable code — each spec is a structured descriptor (input shape, expected
resolver behavior/verdict, suite destination, citation) that is **ready to wire** into the ds-dnsgate
regression corpus the moment that crate lands. The corpus-wiring step is the **proposed follow-up**
this tree files (see `../README.md` § Handover).

## Spec format

Each `RUSTSEC-*.yaml` carries, at minimum:

| Field | Meaning |
|---|---|
| `advisory` | the RUSTSEC id |
| `summary` | one-line description of the vulnerability class |
| `affected` | the pinned crate + the affected version range |
| `class` | the resource-exhaustion / parsing class (drives the (a) reproduction shape) |
| `input_shape` | the structured input the reproduction feeds the resolver (the fixture shape, not bytes) |
| `expected_behavior` | what the **patched** resolver must do — the assertion |
| `expected_verdict` | the wire-observable verdict the conformance suite checks (drives via dig / stub clients, never a hickory API — doc 11 §6 obligation 10) |
| `suite_destination` | `a` and/or `c` (doc 06 tiers) |
| `citation` | the doc 14 §9 / doc 11 §6 rows that mandate this seed |
| `corpus_target` | the named corpus this wires into (ds-dnsgate regression corpus) — pending the crate |

## Why both are mirrored

ds-dnsgate is the fleet's **only resolver** (doc 11 §7), so a
parsing/encoding-DoS that can hang or exhaust it is a **fleet availability incident**. Each seed
therefore lands in **both** tiers: an **(a)** reproduction that the pinned resolver must survive, and
a **(c)** availability assertion of the advertised property "no single malformed query can take the
fleet's resolver down." The fuzz corpus and the DNS-5 hardening pass carry the same weight
(doc 11 §6 obligation 8: "malformed-query fuzz corpus (oversized names, compression loops, truncation
edges) gates DNS-5").
