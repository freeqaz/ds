# ds-flowlog

**The host flow-log collector** — the auditable record of everything every VM did on
the network, per-session, attributed, and shipped off-box
(doc 09 §7).
It consumes conntrack flow events, nflog drop events, and both proxies' event streams,
joins them on session, spools locally, and ships through the log-pipeline contract.
Steps LOG-1 through LOG-5; netflow-style metadata only — full packet capture is
explicitly out (doc 03 §4).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15; LOG-5 credential-use events are data-plane
  and open even though the dashboards over them are paid, D15)
- **Governing decisions:** D66/D44 (tap-name join key,
  doc 14 §4),
  D76 (composite ct-mark decode), D72 (LOG-4 version-chain assertion,
  doc 13 §5),
  D70 (`RejectReason` counting), D73 (fingerprint-only events)

## Frozen contract highlights

| Invariant | Source |
|---|---|
| **LOG-4 reconciliation is an alarm, not a log line:** every byte off a VM interface must be explained by a proxy session or an explicit escape-hatch allowance; an unexplained flow means the redirect has a hole | doc 09 LOG-4 |
| The tap name `dstap-<idx>` / orchestrator session record is the authoritative, never-recycled join key; the FlowRecord's `mark_session_index` is index mod 2^14 — a disambiguator, never the primary key | doc 14 §4 (D66/D76) |
| Version-chain assertion, continuous: `version(TLS/HTTP decision) ≥ version(admitting DNS event)` per flow; a decreasing pair proves a commit-order violation. Digest-set versions are a separate, non-policy namespace and are never compared against `policy_log` seqs | D72; doc 13 §5 |
| udp/443 rejects land with the `QUIC_BLOCKED` reason code, counted per session — what makes the D70 flip-to-inspect trigger queryable off-box | D70 |
| Credential values appear in zero events — fingerprint only (`CredentialUseEvent` convention, enforced in `ds-telemetry`) | D73 |
| Conntrack-drop counters are treated as boundary-hole alarms (recovery shares fate with NAT correctness) | doc 12 §2.3 |

## What must NOT live here

- **The off-box log sink** — v0 sink is files + Postgres inside the orchestrator
  (doc 15 §5.6); only the reserved `proto/dreamserpent/logsink/v1/` seam exists. This
  service ships events; it does not store them durably off-box.
- **Policy evaluation or any nftables write** — it observes and reconciles; it never
  decides or enforces.
- **Packet capture** — metadata only (doc 03 §4).

## Anti-drift

The session-index field width quoted above (`index mod 2^14`) is the one
load-bearing numeric literal this README shares with crate source, so it is
reconciled at lint time rather than trusted to stay in sync by hand:
`scripts/check-service-readme.sh` (wired into `make repo-lints`) reads the
canonical `pub const INDEX_BITS` in `dataplane/crates/ds-contracts/src/mark.rs`
— the same width `SESSION_INDEX_MODULUS = 1 << INDEX_BITS` derives from — and
fails the gate if this README's exponent and that constant ever disagree. The
check is read-only (it greps; it edits nothing) and follows the same
unique-anchor contract the ds-dnsgate and ds-tlsproxy README guards use.

## Neighbors

Both proxies (event sources), `ds-telemetry` (emission/spool conventions),
`ds-contracts` (LOG-1 types + mark decode), the orchestrator log sink (destination),
`assurance/e2e/` and the (c) suite (the deliberately mis-ruled-host LOG-4 test).
