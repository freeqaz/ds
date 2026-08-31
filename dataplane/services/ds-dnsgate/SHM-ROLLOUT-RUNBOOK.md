# SHM admission-map production rollout runbook (D131 / T1)

Operator runbook for turning the **D131 Candidate-A live shm admission map** on in
production. It is the companion to the D131 shm admission-map live-rollout
design doc and codifies the §Rollout-ordering rules: **writer before reader**, **explicit
production profile with a startup assertion**, and **fatal fail-closed posture**.

## What this turns on

In production the DNS-2b admission map is backed by a **single-writer / many-reader
POSIX-shm segment** (seqlock reads), not the in-process map:

- **ds-dnsgate** is the **sole WRITER** — its W1/W2 insert-then-answer admission
  transaction writes each `(session, fqdn) → entry` into the named segment.
- **ds-tlsproxy** is a **read-only CONSUMER** — its FORWARD admission gate
  (`acquire_admission_map`) attaches a `ShmAdmissionReader` to the **same name** and
  does a lock-free seqlock lookup on every TLS-1/TLS-4 connection.

Both sides single-source the segment name through
`ds_contracts::dns_admission::admission_shm_name()` (default `/ds-admission`, override
`DS_ADMISSION_SHM_NAME`).

## The forget-the-gate footgun (and the guard)

The shm path is **opt-in, presence-only** by env gate (`DS_ADMISSION_SHM_LIVE` writer,
`DS_TLS1_LIVE` reader). Left as-is, a production deploy that **forgets** a gate would
silently run the **in-process map** (writer) / **empty fake** (reader) — exactly the
M1 `WithCAStore` / D56 footgun (a default that forgets the gate degrades to a non-live
backing with no operator signal).

The guard (T1, doc 13 §Rollout item 4) is an **explicit production profile** that
**asserts the gates at startup**:

> Setting **`DS_PRODUCTION`** makes the relevant shm gate **MANDATORY** and the process
> **REFUSES TO BOOT** (fatal banner + non-zero exit) if it is missing.

- `ds-dnsgate` under `DS_PRODUCTION` **requires** `DS_ADMISSION_SHM_LIVE`; missing →
  fatal exit. It also **warns** (non-fatal) if `DS_DNSGATE_RERESOLVE_LISTEN` is unset
  (a map miss would refuse instead of D68 re-admit).
- `ds-tlsproxy` under `DS_PRODUCTION` **requires** `DS_TLS1_LIVE`; missing → fatal exit.

This is **NOT a bare default-flip** of the gate semantics: with `DS_PRODUCTION` UNSET
the gates stay opt-in/presence-only and the bare-default path is **byte-identical** to
today (every offline/CI test stays green, and a reader without a co-host writer is not
forced refuse-closed). Production gets "on by default" by **selecting the profile**,
which turns the gates on and refuses to boot without them.

## Prerequisites (must land first)

The shm reader can only be turned on once the read path admits correctly:

- **T2** — live host policy-snapshot → `PolicyCoreOracle` (else `DenyAllOracle` refuses
  everything).
- **T3** — the cross-service re-resolve transport → live `ReResolve` (else a map miss
  refuses instead of D68 re-admitting). Armed by `DS_DNSGATE_RERESOLVE_LISTEN`.
- **T5** — the shm reverse index bound into the §5.4 revocation sweep (else a revoked
  domain stays vouched on the live read path).

`DS_PRODUCTION` is the *operator switch*; do not set it on a fleet until T2/T3/T5 are
deployed (the assertion guards the gate, not the prerequisites).

## Rollout ordering — WRITER BEFORE READER

Bring up the writer (and its segment) **before** the reader attaches:

1. **Writer (ds-dnsgate)** — set, in order:
   - `DS_ADMISSION_SHM_LIVE=1` — back the map with the live shm writer (create-or-
     reattach the named segment).
   - `DS_DNSGATE_RERESOLVE_LISTEN=1` (or a path) — serve the D68 re-resolve seam so a
     reader's map miss **re-admits** instead of refusing.
   - `DS_ADMISSION_SHM_NAME=/ds-admission-<instance>` — **pin a unique name per
     co-located instance** (the default `/ds-admission` collides if two stacks share a
     host).
   - `DS_PRODUCTION=1` — assert the writer gate at startup (refuse to boot if forgotten).
   - (live kernel write also needs `DS_NFTGATE_LIVE`, orthogonal — see doc 14 §11.)
2. **Confirm the segment exists** before starting the reader:
   - `ls -l /dev/shm/` shows the segment (e.g. `ds-admission-<instance>`).
3. **Reader (ds-tlsproxy)** — set the SAME `DS_ADMISSION_SHM_NAME`, then:
   - `DS_TLS1_LIVE=1` — arm the FORWARD admission gate + attach the live reader.
   - `DS_PRODUCTION=1` — assert the reader gate at startup (refuse to boot if forgotten).

Why this order: the reader's attach is **fail-closed-to-fake** — if the segment is not
yet present it degrades to the empty in-process fake (refuse), it does **not** weaken
the boundary. Starting the writer first means the reader attaches a live segment on its
first boot rather than starting in the degraded fallback.

## Failure posture — FATAL = fail-closed

- A shm **attach/create failure** in the writer is **FATAL** (`ds-dnsgate` returns an
  error and exits) — it never silently falls back to an in-process map a reader cannot
  see.
- A **missing mandatory gate under `DS_PRODUCTION`** is **FATAL** (fatal banner + exit 1)
  on both binaries.
- A reader **attach failure** (segment absent / header-version mismatch) degrades to the
  **empty fake → refuse** (fail-closed); it never admits. A policy-allowed SNI with no
  live admission becomes a D68 re-admit, which the not-wired/unreachable re-resolve seam
  refuses — the boundary only ever tightens.

## Verification

- **Cargo live-path smoke** (portable, runs in-sandbox on `/dev/shm`):

  ```sh
  cd dataplane
  cargo test -p ds-tlsproxy --test shm_live_path_smoke   # writer→reader→FORWARD Proceed
  cargo test -p ds-dnsgate  --test admission_shm_e2e      # writer→independent reader read-back
  ```

  `shm_live_path_smoke` drives the full reader gate selection over a **unique** segment
  name and asserts a real FORWARD **Proceed** (`Tls1Decision::Tunnel`), plus the
  fail-closed edges (SNI-dst mismatch refuse, no-admission re-admit).

- **Production-profile assertion** (the boot guard, unit-tested pure):

  ```sh
  cargo test -p ds-tlsproxy requires_gates production_profile
  cargo test -p ds-dnsgate  production_profile
  ```

- **Operator-gated two-binary boot smoke** (the real two-process boot; opt-in so CI
  never runs it):

  ```sh
  DS_SHM_SMOKE=1 dataplane/scripts/shm-rollout-smoke.sh
  ```

  It boots ds-dnsgate (writer) then ds-tlsproxy (reader) under the production profile
  over a unique `DS_ADMISSION_SHM_NAME`, confirms the segment in `/dev/shm`, and asserts
  the forget-the-gate guard (each binary exits non-zero with `DS_PRODUCTION` set but its
  gate missing).

- **Quick checks:**
  - `ls -l /dev/shm/` — the named segment is present while the writer runs (it
    **persists** across a writer restart — warm re-attach, POSIX-shm survivability).
  - A boot with `DS_PRODUCTION` set but the gate missing prints the fatal banner and
    exits non-zero (it must NOT serve).

## T4 follow-up (host-agent segment ownership)

The v1 segment is **ds-dnsgate-created**, so it survives a ds-dnsgate restart but not a
host-orchestrated teardown. **T4** (`01KVBXDVZ8`) moves segment create/teardown to the
**host agent** (D131 host-agent-owned segment) for full warm-restart survivability
across orchestrated teardown + NFT-6 alignment. Until T4 lands, do not rely on the
segment outliving the host-agent's session lifecycle.
