<!-- SPDX-License-Identifier: Apache-2.0 -->

# Truncation-length + oracle analysis (doc 16 §6.3 / OQ8)

**Status:** in-tree rationale for the adopted defaults. It MIRRORS the proposed
update to `docs/16-identity-and-credentials-design.md`
§6.3 (OQ8, doc 16 §14 item 8). Docs are hands-off in this wave; the coordinator
should land the §6.3 record from the **Proposed docs/16 §6.3 record** block below.
If the chosen truncation length ever moves, this file, `DefaultTruncationLenBytes`
(`producer.go`), and `TestChosenTruncationLength` (`keys_test.go`) move together,
and the docs/16 §6.3 record is reopened (it cites a number).

## What OQ8 asks

doc 16 §14.8 — *"Per-epoch HMAC parameters — §6.3 defaults pending the oracle
analysis; truncation length chosen against fleet digest counts."* §6.3 adopts the
target **FP ≈ 0 at fleet digest counts** and names the honest residual: *"a
compromised boundary host yields key + digests — an offline oracle that matters
for low-entropy user secrets, far less for high-entropy machine creds."*

## The oracle (why truncation alone cannot fix it, and what bounds it)

The producer pushes `trunc( HMAC-SHA-256(key, ENCODE_variant(plaintext)) )` to the
boundary host; the host holds the **per-host per-epoch HMAC key + the digests**
(plaintext never crosses — `producer.go`). A **fully compromised boundary host**
therefore holds both halves of the predicate and can run it **offline** against
candidate plaintexts:

> for each guess `g`: does `trunc(HMAC(key, ENCODE_v(g)))` hit a loaded digest?

This is an **offline guessing oracle**, and the entropy of the *secret*, not the
digest length, sets its cost:

- **High-entropy machine credentials** (random PATs, AWS keys, 256-bit tokens):
  the guess space is astronomically large; the oracle confers no practical
  advantage. This is the common case and the design's comfortable zone.
- **Low-entropy user secrets** (a human-chosen password reused as a credential):
  the oracle reduces to the cost of the secret's own entropy — the host can
  enumerate a wordlist offline. **No digest length changes this**; the only
  mitigations are out of this module's scope and are recorded as such below.

Truncation length is therefore **NOT** an oracle-strength knob. Its only job is
to keep the **false-positive (collision) rate ≈ 0 at fleet digest counts** so the
matcher never blocks a benign egress span that happens to share a truncated
digest. We choose it for FP, and bound the oracle by other means (key lifecycle +
scope), which is exactly why the two analyses are reported together.

### Oracle-window bounding (key lifecycle, this module's lever)

What this module *does* contribute to the oracle residual is **bounding the
window**, via the §6.3 key lifecycle implemented in `keys.go` / `rotation.go`:

- **Per-host per-epoch keys** (`KeyEpoch` + `DeriveKey`): a compromised host yields
  *its* current (and briefly retiring) epoch key, never the fleet root and never
  another host's key. Derivation is HKDF-Expand-style from a root held only in the
  D39 trust zone; the host gets derived material, never the root.
- **Rotation at the golden-image cadence** (`KeyManager.Rotate`) and **re-key on
  host redeploy** (`KeyManager.Rekey`, generation-bumped so a redeploy never
  reuses a key id/material): every roll *invalidates the offline corpus* a prior
  host capture produced — old digests no longer match candidates under the new
  key. The oracle's value decays to the rotation period.
- **Live re-key without a gap** (`KeyManager.LiveRekey`): the new-key digests are
  published + **acked before** the old key is retired (mint-before-attach applied
  to a re-key, doc 16 §6.1), and the optional `RetireOldKeyViaRevoke` *flushes*
  the old digests **after** the new are live — shrinking the host's retained
  corpus without ever leaving a session unshadowed.

## Fleet-scope re-key over the policy stream (the second cadence, D72)

`LiveRekey` (above) bounds the oracle window for **SESSION-scope** digests over
the `DigestFeedService` seam. But **FLEET-scope** forbidden-class digests (the
org-wide canaries — "canary never egresses", D73) are **NOT** session-lifecycle
data: per **D72** / doc 16 §6.2 *"two cadences, no third channel"* they are
**policy artifacts** carried under the `policy_log` seq, delivered through the
one-per-host WatchPolicies subscriber (covered by the prepare/commit barrier +
revocation sweep, inheriting the POL-4 seconds-scale bar). They ride a
**different cadence** from the session feed, and the design opens **no third
channel** for them.

A key rotation/re-key therefore has **two legs**, one per cadence:

- **Session leg** — `KeyManager.LiveRekey`: re-pushes every live session's
  digests under the new key over `DigestFeedService`, new acked before old
  retired (unchanged).
- **Fleet leg** — `KeyManager.LiveRekeyFleet`: re-derives the fleet-scope digest
  set under the new key and **re-registers it as a policy artifact over the
  policy stream**, the new-key artifact **applied before** the old fleet key's
  artifact is retired (the policy revocation-sweep model). It rides the **same
  policy-log path the fleet digests always rode** (modeled here behind the
  `PolicySink` seam — a Go interface onto `orchestrator.v1.PolicyService`'s
  append path, **not** a new RPC, so it is not a "third channel"), and it
  **never** touches `DigestFeedService`. `PublishFleetPolicy`/`RevokeFleetPolicy`
  are the identity-side append verbs; `FleetBatchEntries` asserts every entry is
  `DIGEST_SCOPE_FLEET` so a session-scope entry can never cross onto the policy
  stream.

**Why the fleet leg is load-bearing for the oracle bound (and correctness):**
without it a rotation re-keys only the session digests and **strands the fleet
canaries under the retired key** — once that key id is dropped at the boundary,
the fleet digests are **matchable nowhere**, silently disabling the
canary-never-egresses guarantee for the whole fleet. The fleet leg closes that
gap **gap-free** (new fleet artifact applied before the old fleet key is retired,
fail-closed: a failed new-key registration leaves the old fleet key live, so the
fleet is shadowed at every instant), exactly mirroring `LiveRekey`'s
mint-before-attach ordering on the session cadence.

The shared lifecycle `retiring` set (the boundary still needs a key id loaded
*at all*) is dropped at most once per old key across both legs: in a full
rotation the session leg may drop it first, so the fleet leg tolerates a
"already retired by the session leg" at its lifecycle `RetireKey` step — its own
policy-stream retire artifact is what carries the no-gap guarantee for the fleet
cadence.

### Proposed docs/16 §6.2 record (for the coordinator to land)

> **§6.2, fleet-scope re-key clause — proposed addition.** A key
> rotation/re-key re-registers the **fleet-scope** digest set under the new key
> **as a policy artifact over the policy stream** (the `policy_log` cadence),
> the new-key artifact applied **before** the old fleet key's artifact is retired
> (the revocation-sweep model) — gap-free and fail-closed (a failed new-key
> registration leaves the old fleet key live). This is the **second of the two
> cadences (D72)**: the session leg re-keys session digests over
> `DigestFeedService`; the fleet leg re-keys fleet digests over the **same**
> policy-log path the fleet digests always rode — **no third channel**. Without
> the fleet leg a rotation strands the fleet canaries under the retired key
> (matchable nowhere once it is dropped), silently disabling the
> canary-never-egresses guarantee fleet-wide. Cross-cite `identity/digest`
> `rotation.go` (`LiveRekeyFleet`) + `publish.go` (`PolicySink` /
> `PublishFleetPolicy` / `RevokeFleetPolicy`).

Out of scope (recorded honestly, not solved here): low-entropy *user* secrets are
better served upstream — the §6.4 designation gate should steer humans toward
high-entropy machine credentials, and the §6.3 residual stands as the documented
honest limit. This module cannot raise a weak secret's entropy.

## Truncation-length choice: **16 bytes / 128 bits**

We keep the landed `DefaultTruncationLenBytes = 16` (also the
`identity/fakes/digest-publisher` value, so the production producer and the fake
stay byte-compatible against one boundary key). The FP analysis below shows 16
bytes clears the FP ≈ 0 bar with an enormous margin; it is **not** chosen for
oracle strength (see above).

### FP model

Model the truncated keyed digest as a uniform `b = 8·L`-bit value (HMAC-SHA-256 is
a PRF under its key; truncation of a PRF output is uniform). For a matcher holding
**N** distinct digests, a single scanned candidate span that is *not* a registered
secret collides with the set with probability bounded (union bound) by

> P(FP per candidate) ≤ N / 2^b.

Over **Q** candidate spans scanned across the fleet's lifetime, the expected
number of false positives is `E[FP] ≤ Q · N / 2^b`.

Fleet digest count `N = sessions × creds/session × 4 variants` (`AllVariants`).
Worked at `Q = 1e9 spans/day × 365 days ≈ 4·10¹¹` candidate spans/yr:

| trunc L | bits | N (fleet) | P(FP/candidate) | E[FP] over 4·10¹¹ spans/yr |
|--------:|-----:|----------:|----------------:|---------------------------:|
| 8  | 64  |     200,000 | 1.1·10⁻¹⁴ | 4.0·10⁻³ |
| 8  | 64  |  80,000,000 | 4.3·10⁻¹² | **1.6** (NOT FP≈0) |
| 12 | 96  |  80,000,000 | 1.0·10⁻²¹ | 3.7·10⁻¹⁰ |
| **16** | **128** | **200,000** | **5.9·10⁻³⁴** | **2.1·10⁻²²** |
| **16** | **128** | **80,000,000** | **2.4·10⁻³¹** | **8.6·10⁻²⁰** |
| 20 | 160 |  80,000,000 | 5.5·10⁻⁴¹ | 2.0·10⁻²⁹ |

(N rows: 10k sessions × 5 creds, …, 1M sessions × 20 creds, each × 4 variants —
the 200k and 80M endpoints bracket plausible fleet sizes.)

### Why 16 and not 8 or 12

- **8 bytes / 64 bits is rejected.** At an 80M-digest fleet it yields ≈ **1.6
  expected false positives per year** — a blocked benign egress is a real
  operational event, not FP ≈ 0. 64 bits fails the bar at fleet scale.
- **12 bytes / 96 bits clears the bar** (E[FP] ≈ 3.7·10⁻¹⁰/yr) and is a defensible
  alternative. We do **not** pick it: it buys ~4 bytes/digest of wire/index
  savings that are immaterial at these N, while breaking byte-compatibility with
  the landed fake and the matcher fixtures. The savings do not justify the churn.
- **16 bytes / 128 bits is chosen.** E[FP] ≤ ~9·10⁻²⁰/yr even at the 80M-digest
  fleet — FP ≈ 0 by any operational measure, with margin for fleet growth well
  beyond the modeled endpoints. It matches the landed default and the fake, so the
  production producer/matcher and the Stage-0 fixtures interoperate unchanged.
- **20 bytes** over-provisions for no FP benefit and is not adopted as the default
  (the producer still *permits* up to 32, the full HMAC-SHA-256 width — the
  `truncLen ≤ 32` guard in `producer.go` — for a future high-N regime).

The truncation guard already landed (`minTruncationLenBytes = 8` floor,
`hmacSHA256LenBytes = 32` ceiling) is unchanged; this analysis ratifies **16** as
the adopted default within it.

## Proposed docs/16 §6.3 record (for the coordinator to land)

> **§6.3, truncation clause — proposed amendment.** Adopt **truncation length =
> 16 bytes / 128 bits** as the digest-feed default (OQ8 resolved). Rationale: the
> false-positive rate is bounded by `N / 2^128` per scanned candidate; at fleet
> digest counts up to ~8·10⁷ and ~4·10¹¹ candidate spans/yr the expected
> false-positive count is ≤ ~9·10⁻²⁰/yr — FP ≈ 0 with margin. 64-bit truncation is
> rejected (≈ 1.6 expected FP/yr at an 80M-digest fleet); 96-bit clears the bar
> but is not adopted (no operational benefit over 128-bit, breaks fixture
> byte-compatibility). Truncation length is **not** an oracle-strength knob — the
> §6.3 offline-oracle residual for low-entropy user secrets is bounded by the key
> lifecycle (per-host per-epoch keys + golden-image rotation + redeploy re-key,
> each invalidating a captured host's offline corpus; live re-key + post-re-push
> flush shrink the retained corpus without a mint-before-attach gap), not by
> digest length. **Mark doc 16 §14 OQ8 resolved**, cross-citing this rationale.
