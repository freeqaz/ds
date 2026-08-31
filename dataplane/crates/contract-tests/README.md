# contract-tests

A **test-only** workspace member (no production code; `src/lib.rs` is an empty
crate, every assertion lives under `tests/`). It is the single place in the
`dataplane` workspace that may path-depend on **both** `flush_session`
consumers at once — `ds-nft` and `ds-tlsproxy` — so it can exercise the frozen
`ds_contracts::flush::DstKey` contract *across* them.

This is a **contract test, proposed** — it ratifies nothing and mints **no
D-number**. It pins an existing convention; it does not decide one.

## What it guards

`ds_contracts::flush::DstKey` is an opaque `String` placeholder; the concrete
address representation is owned by `ds-nft` / the §3 admission map
(`ds-contracts/src/flush.rs:47`). Two consumers narrow a revocation by that key
and both compare it by **string equality**:

- `ds-nft`'s `NftWriter` — `DstFilter::Only([key])` → `conntrack -D --dst <key>`;
- `ds-tlsproxy`'s `SeveringRegistry` — stores the key at register time, severs a
  live tunnel / pooled upstream socket only on an exactly-equal key at sweep time.

If the representation used at register time differs from the one the revocation
sweep passes in `DstFilter::Only` (e.g. `203.0.113.10:443` vs `203.0.113.10`),
the sweep silently severs **nothing** on **both** sides — a guardrail no-op with
no error. This is the documented failure mode the tests exist to catch (the
wave-4 planner note on task `01KTXJG7R3T6EN5D3K03D0NQGC`).

`tests/dstkey_cross_consumer.rs`:

- **positive round-trip** — register + revoke under the one canonical key; both
  consumers report a non-empty severing outcome;
- **negative (mismatch no-op)** — a mismatched representation of the same logical
  destination severs nothing on both consumers (the silent no-op);
- **parity** — pins the canonical key shape (below) and asserts both consumers
  mint an equal `DstKey` from it and round-trip on it.

## Pinned canonical key shape

The canonical `DstKey` string is the **bare dotted-quad destination address** —
the exact form the `ds-nft` `flush` test vectors and the §3 admission-map reverse
index use:

```
203.0.113.10
```

No port (`:443`), no CIDR (`/32`) — a single address. Register-time and
revoke-time keys must be this same shape on both consumers, or the sweep is a
silent no-op. If a future change adopts a different canonical shape, update this
README and the `CANONICAL_KEY` constant together; the `parity_*` test fails here,
with the pin in view, if the two diverge.

## Frozen non-edge (D76, doc 12 §4.2, doc 14 §5)

`ds-nft` and `ds-tlsproxy` must never depend on each other — the egress-gateway
proxy runs `CAP_NET_RAW` only and must not link the netlink writer that contains
it. That rule forbids either consumer from importing the other to host this test.
This downstream test-only member is the exception the rule leaves open: it links
both as **dev-dependencies** and adds **no** edge between them. The ds-nft side is
driven through its public `NftBackend` trait, implemented by a local fake (no
ds-nft test helper is exported); the ds-tlsproxy side through its public
`Severable` seam.
