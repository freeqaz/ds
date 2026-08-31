# ds-contracts

**The single home for everything two or more services must agree on**
(doc 14 §6).
If a constant, signature, schema, or generated message is consumed by more than one
data-plane binary (or by the Go host agent over the cgo bridge), it lives here and
nowhere else — that is what makes "the two proxies can never disagree" enforceable
at compile time instead of by review.

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15); all contracts are public (D24/D58/D80)
- **Governing decisions:** D67/D68 (DNS-2b API + deadlines, doc 14 §3),
  D70 (`RejectReason`), D71 (SOA MNAME signature constant), D75 (family-agnostic
  addresses), D76 (mark layout + `flush_session`, doc 14 §5),
  doc 13 §3 (POL-1 schema home)

## Contents when built

| Item | Contract source |
|---|---|
| Generated LOG-1 + digest-feed + control-plane protos (the Rust codegen target of `proto/buf.gen.yaml`; lands in `src/gen/`, marked generated in `.gitattributes`) | doc 14 §2, §7 |
| D76 mark-layout constants (`0xD` magic, leg nibble, 14-bit index field) + `DS_MARK_MASK = 0xFF003FFF` | doc 14 §5 |
| `flush_session(session, dst_filter, legs)` **signature** — defined once, cited by all three callers (D68 revocation, D72 sweep, NFT-6 teardown); **implementation in `ds-nft`** | doc 14 §5 |
| DNS-2b versioned admission-map API: key `(session, original_query_fqdn)`, `admission_type ∈ {NORMAL, SYNTHETIC, SINKHOLE_RESERVED}`, single shared deadline, per-session IP↔domain refcount reverse index **from day one** | doc 14 §3; doc 11 §5.2 |
| `SessionRef` (session_uuid, host_id, host_session_index, tap_name) | doc 14 §2/§4 (D66/D44) |
| `RejectReason` enum distinguishing `QUIC_BLOCKED` from generic default-deny | D70 |
| SOA MNAME signature-name constant (the EDNS-free denial fingerprint, working name `denied.policy.<boundary-zone>.`) | D71; doc 11 §3.2 |
| POL-1 YAML schema v0 + validation (rung caps, fail-open legality, provenance and bare-CIDR rejections are **parse-time structural**, not convention) | doc 13 §3, §7 |

## Frozen invariants

- **No hickory or pingora types cross this crate** — neither in its API nor its
  dependency graph (doc 14 §6; D67/D40: swapping either framework must stay a library
  migration inside one service).
- Any mark-layout change = flow-record migration plan + decision-log entry; the NFT-1
  ruleset artifact is CI-linted against these constants (doc 14 §5).
- DNS-2b invariant changes need a decision-log entry; the API is versioned per doc 06 §2.
- The 14-bit mark field is documented as `host_session_index mod 2^14` — a
  disambiguator, never the primary join key (doc 14 §4).

## What must NOT live here

- **`.proto` source files** — `proto/` is the single contract home; this crate only
  receives generated code via freeze PRs. Zero proto bodies exist at skeleton time
  (the Stage-0 freeze is one-shot and has not happened; the buf gate being RED is the
  documented correct state).
- **The DNS-2b storage mechanism** (mmap / shm / UDS) — free implementation behind the
  frozen API, owned by `ds-dnsgate` (doc 14 OQ6).
- **Evaluation logic** — that is `policy-core`. This crate defines shapes; it decides nothing.
- **`flush_session`'s implementation** — `ds-nft`.

## Neighbors

Everything: both services, `ds-flowlog`, `policy-core`, `ds-policy-snapshot`, `ds-telemetry`,
`ds-nft`, and the Go host agent (via the `ds-nft` C-ABI bridge and the shared
`content_hash` contract tests in `orchestrator/internal/nftbridge/`).
