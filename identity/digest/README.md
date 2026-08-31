# identity/digest/ — Production secret-digest producer + matchability proof

**Owner workstream:** Identity & credentials · **OSS** (the session digest producer ships with the OSS data plane per D85)
**Status:** Real producer — replaces the Stage-0 fake (`../fakes/digest-publisher/`). Go module, outside `go.work` (`GOWORK=off`).
**D-numbers:** D39 (trust-zone placement), D73 (the keyed feed + canary-never-egresses), D84 (mount/path-prefix scoping), D109 (host-agent ack-er), D50 (synthetic fixtures only). HMAC key lifecycle (per-host per-epoch keys, golden-image rotation, redeploy re-key, gap-free live re-key, truncation choice) is Identity's per doc 16 §6.3 / OQ8 (the doc 14 OQ7 erratum).

## What this is

The production **secret-digest producer** of doc 16 §6. Given a credential's plaintext — touched **only here, inside the D39 secret-store trust zone** — it computes the keyed **HMAC-SHA-256** digest of every encoding variant (**RAW / BASE64 / URLENC / HEX**) and emits the frozen doc 14 §7 `DigestEntry` set. It drives the **existing** `dreamserpent.identity.v1.DigestFeedService` seam the fake drove — no new cross-service contract; proto bodies are hands-off.

The charter, trust-zone placement, and frozen invariants live in [`../digest-producer/README.md`](../digest-producer/README.md) (the original skeleton); this module is its implementation.

## Files

| File | Role |
|---|---|
| `variant.go` | The four encodings. `encodeVariant` returns the exact on-the-wire bytes per variant; the producer HMACs them, the matcher hashes raw wire bytes, and they line up decode-free. |
| `producer.go` | `Producer` — holds the per-host per-epoch HMAC key + id + truncation length (doc 16 §6.3); `Entries`/`BatchEntries` compute the `DigestEntry` set. Plaintext is digested and dropped, never retained. `NewProducerForEpoch` threads a `KeyEpoch` coordinate's derived key + id through production (the lifecycle-aware constructor). |
| `keys.go` | `KeyEpoch` + `DeriveKey` (per-host per-epoch key derivation, HKDF-Expand-style from a trust-zone root) and `KeyManager` — the rotation/re-key state machine: `Rotate` (golden-image cadence), `Rekey` (host redeploy, generation-bumped), retiring-set tracking, and active-key `Producer`/`Matchers`. |
| `rotation.go` | `KeyManager.LiveRekey` — re-pushes every live SESSION digest under the new key over `DigestFeedService`, new published + **acked before** the old key is retired (mint-before-attach across a flip, no gap; fail-closed leaves the old key live). `RetireOldKeyViaRevoke` flushes the old digests **after** the re-push (oracle-window bounding). `KeyManager.LiveRekeyFleet` — the **second cadence** (D72, doc 16 §6.2): re-registers the FLEET-scope digest set under the new key as a **policy artifact over the policy stream**, new artifact applied **before** the old fleet key's artifact is retired (gap-free, fail-closed) — without it a rotation strands the fleet canaries under the retired key. |
| `matcher.go` | `Matcher` — the producer-side reference of the boundary SecretMatcher predicate: load the pushed entries, hash a candidate wire span, set-membership test. Carries match provenance (class/scope/variant). |
| `publish.go` | `PublishSession` / `RevokeSession` — the identity-side SESSION verbs over the frozen `DigestFeedService` seam, **fail-closed** (uncommitted ack ⇒ session not routable). `PublishSessionWithManager` threads the lifecycle's active key. `PublishFleetPolicy` / `RevokeFleetPolicy` — the FLEET-scope verbs over the `PolicySink` seam (the policy-stream path, doc 16 §6.2 / D72 — a Go interface onto `orchestrator.v1.PolicyService`'s append path, **not** a new RPC), fail-closed on an uncommitted policy-apply. |
| `RATIONALE.md` | The OQ8 oracle analysis + the chosen truncation length (16 bytes / 128 bits) with the FP ≈ 0-at-fleet-counts justification; mirrors the proposed doc 16 §6.3 record. |
| `*_test.go` | Producer correctness vs an independent recomputation; the **matchability proof** (every variant matchable pre-egress, round2/08 test 6); the end-to-end publish→ack→matchable path over an in-process consumer; the key lifecycle — rotation, re-key, and the **live re-key end-to-end** (no mint-before-attach gap, no digest dropped); the truncation choice; fail-closed legs. |

## The producer/matcher symmetry

```
producer digest(variant) = trunc( HMAC-SHA-256(key, ENCODE_variant(plaintext)) )
matcher  candidate-hash  = trunc( HMAC-SHA-256(key, RAW_WIRE_BYTES) )
```

A base64'd secret on the wire **is** `ENCODE_BASE64(plaintext)` as bytes, so the matcher's hash of those raw bytes equals the producer's BASE64 digest. The matcher never decodes — it only hashes what it sees. (A secret of only RFC-3986-unreserved bytes has `RAW == URLENC` by construction; that aliasing is correct url-encoding, not a bug — see `TestUnreservedSecretRawEqualsUrlenc`.)

## What does NOT live here (scope fence)

- **The boundary SecretMatcher enforcement plane** (trait, hold-back, verdict execution) — Boundary's (`dataplane/`, docs 11–14). `matcher.go` is the producer's *matchability proof*, not a second enforcement plane.
- **The feed proto** — frozen in `proto/dreamserpent/identity/v1/digest_feed.proto`; not edited here.
- **The orchestrator create-choreography** (mint→CA→grants→cred→digest→write→ack→routable ordering, and round2/08 test-6 end-to-end) — owned by the session-create task. This module supplies the identity-side publish/revoke verbs the choreography calls; it does not order the larger sequence (see the deferred-integration follow-up).
- **Real credentials in tests** — synthetic `ds-synth-*` only (D50).
