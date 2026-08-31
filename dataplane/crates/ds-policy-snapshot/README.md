# ds-policy-snapshot

**The host policy snapshot loader.** Both proxies and the NFT programming path consume
exactly one host-local, atomic, versioned snapshot of the composed policy document —
this crate is how they load it, validate it, hot-reload it, and report what they have
applied. It exists so the two services *cannot* run different policy versions
(doc 14 §6;
doc 13 §5).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15)
- **Governing decisions:** D72 (one host subscriber, two-phase admitter-last barrier,
  sweep-in-"applied", doc 13 §5),
  D36 (`policy_log` seq is THE version), D53 (rung-conditional severing in the sweep)

## Frozen invariants

| Invariant | Source |
|---|---|
| Exactly **one** `WatchPolicies(from_seq)` subscriber per host — the D35 host agent. This crate reads the host-local snapshot feed; it never opens a control-plane stream | D72; doc 11 §5.3 |
| Single monotonic version: the D36 `policy_log` bigserial seq, end to end. No per-service or per-resource-type version namespaces. (Digest-set versions are a separate, non-policy namespace — doc 13 §5) | D72/D36 |
| Snapshot identity `(seq, content_hash, full composed document)`; consumers ACK `(seq, content_hash)` and **refuse** any snapshot failing the hash/schema check — NACK aborts the apply host-wide | D72 |
| Two-phase apply, **admitter-LAST commit order**: ds-tlsproxy + the NFT programmer flip before ds-dnsgate, so every transient mixed-version window fails closed | D72 |
| `applied_seq` is reported only after the revocation sweep completes; the (d)-rig push-to-enforced clock stops at sweep-plus-flush | D72 |

## Free (firm up during build)

Local snapshot transport (file+rename+inotify / UDS gRPC / shm), gc interval,
barrier timeout numbers (rig-tuned, doc 13 OQ3), canonical-serialization mechanics
once the cross-language `content_hash` spec lands (doc 13 OQ2 — contract-tested
against the Go side in `orchestrator/internal/nftbridge/`).

## First field on the snapshot — the D71 `boundary_zone` (wave20b)

The loader/hot-reload machinery above is still skeleton; the first policy-pushed field
a boundary service reads off `PolicySnapshot` landed in wave20b
(`01KTZGK0SGFMM765HG1K9EFJNT`): the D71 authored-SOA MNAME suffix `boundary_zone`
(`SOA MNAME = denied.policy.<boundary_zone>.`; doc 11 §3.2). The value is sourced from
the composed POL-1 `dns.boundary_zone` field (`ds-contracts::pol1`) via
`PolicySnapshot::from_dns_config`, defaulting to the working name `boundary.` when a
layer omits it — so `ds-dnsgate` reads the suffix from the snapshot instead of its
handler-local const, and a snapshot without the field reproduces the frozen signature.
The `(seq, content_hash, full composed document)` identity tuple and the rest of the
composed POL-1 document grow this type additively as the loader work lands. A
VALUE-source move only; the D71 SOA shape is unchanged, no new D-number.

### wave20b finalize — composition outcome and deferred follow-ups

The `boundary_zone` field above landed green on `wave20b-integration`
(`01KTZGK0SGFMM765HG1K9EFJNT`, done), composed with the taskdb shared-helper lint unit
(`01KTZGKAW1VB0RGAF8Z2TTXH6F`, done). Two `PolicySnapshot`-adjacent follow-ups were
**deferred for files-overlap** with this unit and re-filed OPEN under wave parent
`01KTYTA82DKD6A28Z42SSA1CF3` for the next loop wave:

- **Wire `boundary_zone` into ds-dnsgate startup** (`01KTZQQT812DMT3B5ATM7G31FK`) — thread
  the composed `DnsConfig.boundary_zone` from the live host `PolicySnapshot` into
  `GateConfig` / `spawn_gate` so the policy-pushed suffix is authored in production, then
  fold into the D72 admitter-LAST hot-reload; collided on `src/lib.rs` (re-scope task
  `01KTZR2P3JY1JS640JBPQ36DJB`).
- **Validate `boundary_zone` at snapshot load** (`01KTZQQCYYJNGA77JXD7W7RHM2`) — NACK a
  malformed DNS name at load (a new additive `ds-contracts` `PolicyError::BadName`) rather
  than panicking the gate's SOA-authoring path at runtime; collided on
  `ds-contracts/src/pol1.rs` (re-scope task `01KTZR2B6Z7ES0D7CSETB98WFX`).

## What must NOT live here

- **A `WatchPolicies` client** — the host agent owns the one subscriber (D72). A
  standalone `ds-policyd` was considered and left free/absent (doc 13 §5, root
  anti-scaffold list).
- **The revocation sweep's conntrack flush** — that is `flush_session`, signature in
  `ds-contracts`, implementation in `ds-nft`.
- **Policy evaluation** — `policy-core` consumes what this crate loads.

## Neighbors

Fed by `orchestrator/cmd/host-agent/`; embedded by both services and the NFT
programming path; types from `ds-contracts`.
