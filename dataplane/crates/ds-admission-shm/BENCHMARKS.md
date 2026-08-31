# DNS-2b admission map → shared memory (`ds-admission-shm`)

**What it is.** The little in-memory table that answers one question on **every outbound
TLS connection** an agent VM makes: *"is this IP allowed for this domain, for this session?"*
`ds-dnsgate` (our DNS gate) writes it when it admits a DNS answer; `ds-tlsproxy` (our egress
gateway) reads it to decide whether to let the connection out. It's the guard that closes the
**CDN shared-IP hole** — an IP admitted for `github.com` must not silently vouch for
`evil.com` just because they share a CDN address.

We moved it from a `HashMap`-behind-a-lock into a **shared-memory segment with a per-entry
seqlock** (decision **D131**, now ratified). Two wins: reads stop contending, and the table
**outlives the writer process** so restarting `ds-dnsgate` no longer drops the allow-state.

```
  ds-dnsgate                       ds-tlsproxy   (many concurrent readers)
 (single WRITER)                  ┌─────────────────────────────────────┐
      │ admit / revoke            │ every TLS connection asks the map:   │
      │ on each DNS answer        │ "IP allowed for this domain+session?"│
      ▼                           └──────────────────┬──────────────────┘
 ┌──────────────────────────────┐   lock-free        │ lookup()
 │ SHARED MEMORY (mmap)          │   seqlock reads    │
 │ [header][entry table][revidx] │◀───────────────────┘  readers never
 │  slot = seq·state·hash·entry  │◀──────────────────────  block each other
 └──────────────────────────────┘◀──────────────────────  or the writer
      ▲ segment outlives ds-dnsgate  →  writer can restart, allow-state survives
```

**How the seqlock works (the "odd/even" bits).** Each slot has a sequence counter:
**even = stable, odd = a write is in progress.**
- **Writer** (only ds-dnsgate): bump `seq` to odd → write the entry bytes → bump `seq` to the
  next even. No lock taken.
- **Reader** (ds-tlsproxy): read `seq`; if odd, a write is mid-flight (spin briefly, then give
  up *safely*); copy the entry; **re-read `seq`** — if it changed, a write landed during the
  copy, so discard and retry. Only an unchanged-even snapshot is trusted.
- **Net:** readers take no lock and never block the writer or each other. A half-written entry
  is produced but **never observed**. Worst case a reader fails safe to *"not admitted"* (which
  just re-asks DNS) — it can never vouch on torn bytes.

---

## The benchmark — `services/ds-dnsgate/src/bin/admission_bench.rs`

It measures how fast that one lookup is **under realistic load**: 1 writer, N reader threads,
a field-shaped map (many sessions × a handful of FQDNs each). Five sections, but two carry the
decision: **(2)** the old lock-based map vs **(5)** the new shared-memory map, same workload.

> **Mlk/s = millions of lookups per second** — total admission-map reads all reader threads
> complete per second, combined. Higher = more TLS connections/sec the platform can clear.
> **p99 = the 99th-percentile latency of a single lookup** (the slow tail every TLS handshake
> can hit). Lower = smoother. `µs` = microsecond = 1000 ns.

**Headline: 32 reader threads + a live writer** (the production shape — 32-core box, lightly loaded):

| Map implementation              | Throughput | p99 latency | What it is |
|---------------------------------|-----------:|------------:|------------|
| `Mutex<HashMap>` (the original) |  **1.3** Mlk/s | **196 µs** | one lock, every reader serialized |
| `RwLock<HashMap>` (interim fix, shipped) | **8.1** Mlk/s | **13 µs** | readers share, writer still excludes |
| **`ds-admission-shm`** (seqlock, shipped) | **78** Mlk/s | **0.7 µs** | lock-free reads |

**≈ 60× the throughput and ≈ 280× lower tail latency than the Mutex.**

**Why the gap — it's about scaling, not a faster data structure.** At *one* thread the shm map
is actually a hair slower (it copies a full record out of shared memory; the HashMap just hands
back a pointer). It wins because lock-free reads **scale with cores** while a lock **anti-scales**:

```
 readers:     1     2     4     8    16    32      (Mlk/s, with writer)
 Mutex      5.5   2.8   2.5   1.7   1.6   1.3   ← more readers → SLOWER (lock fight)
 shm        3.0   7.2  16.3  33.5  57.9  78.2   ← near-linear with cores
```

The Mutex doesn't just fail to speed up — it goes *backwards*: at 32 readers its p99 is **196 µs**
(and p999 spikes into the hundreds-of-µs/ms range). Lock contention, not lookup cost, was the
problem. (The other sections: **(1)** single-thread baseline ~100 ns; **(3)** the write/admit
transaction ~0.7 µs steady-state; **(4)** a throwaway seqlock prototype that predicted (5).)

## Why this piece's performance matters

- It's on the **critical path of every HTTPS connection out of every agent VM.** Latency here is
  latency the agent feels on *every* network call, and throughput here caps how many concurrent
  connections the whole platform can serve.
- The workload is **read-dominated, many-reader, one-writer** — the exact shape a single lock
  handles worst. Under real fan-out the Mutex's tail (196 µs) is felt on every handshake; the
  shm map holds **sub-microsecond** and scales with the machine.
- Bonus (the original D131 driver): the segment **survives a `ds-dnsgate` restart**, so a writer
  crash/redeploy degrades to a fast re-attach + reconcile instead of dropping every session's
  allow-state and forcing a cold re-admit.

---

*Reproduce:* `cargo run --release --bin admission_bench -p ds-dnsgate -- --quick`
(drop `--quick` for the full sweep). Numbers above were measured on a 32-thread AMD Ryzen 9
7950X under light parallel load; absolute Mlk/s will vary by hardware, but the **shape** —
Mutex anti-scales, shm scales near-linearly — is the load-bearing result.

*Code:* `dataplane/crates/ds-admission-shm/` · *Design:* `docs/11-ds-dnsgate-design.md` §8.4 / §8.4.1 · *Decision:* D131
