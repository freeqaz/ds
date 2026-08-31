# identity/digest-producer/ — Secret-digest feed, producer side

**Owner workstream:** Identity & credentials · **OSS** (the session digest producer ships with the OSS data plane per D85)
**Status:** README-only skeleton. Language unbound.

## Charter

Computes **keyed HMAC digests** (plus encoded variants: RAW / BASE64 / URLENC / HEX) of every credential Identity mints (tagged `ISSUED{service_id}` + TTL) or guards (tagged `FORBIDDEN`), and pushes them to the boundary host where ds-tlsproxy's SecretMatcher consumes them (D73, doc 16 §6). The entry shape and invariants are frozen law in doc 14 §7: `{key_id, algo, digest, cred_class, scope: SESSION|FLEET, expiry, variant_tag}`.

## Trust zone — D39, off-host by deployment

The producer runs **in the D39 secret-store trust zone, never on the virtual-metal host** — it is the only component besides the store that touches credential plaintext, and only for D84-designated Vault mounts/path prefixes. At bring-compute/on-prem tiers it deploys adjacent to the customer's Vault inside *their* trust zone (doc 16 §2, §11.3).

## Frozen invariants (don't relitigate in code review)

- **Plaintext never crosses** the feed; the producer pushes encoded variants so the consumer never re-derives them.
- **Never log the secret** (D73): digests are the only representation that leaves this process; identity-plane events are fingerprint-only, and the canary-never-egresses (c) row asserts zero canary bytes in any log/spool (doc 16 §13).
- **Mint-before-attach, ack-gated, fail-closed**: digest write → host-agent ack → session marked routable; write failure fails/stalls create, never degrades open (doc 16 §6.1; ack-er = host agent is a proposed default pending doc 15 OQ1).
- **Two cadences, no third channel** (D72): fleet-scope registration/revocation rides the `policy_log`; session-scope digests are session-lifecycle data. This component opens no per-service policy stream (doc 16 §6.2).
- **HMAC key lifecycle is owned HERE** (Identity — doc 14 OQ7 erratum): per-host per-epoch keys, rotation at golden-image cadence, live re-key re-pushes every live digest (doc 16 §6.3).
- **Multi-consumer by design** (doc 16 §6.5): consumer registration, per-consumer ack, distribution policy. Attach-side matching runs orchestrator-side — digests never leave trusted territory.

Honest residual (doc 16 §6.3): a compromised boundary host yields key + digests — an offline oracle for low-entropy secrets.

## What must NOT live here

- **The consumer.** SecretMatcher invocation, hold-back, verdict execution are Boundary's (`dataplane/`, docs 11–14).
- **The feed proto** — it freezes in `proto/dreamserpent/identity/v1/` beside the D22 seam. The Stage-0 fake lives in `../fakes/digest-publisher/`.
- **Real credentials in tests** — synthetic only (D50).

## Create-choreography wiring (publishsession-wire, orchfu2b)

The **publishsession-wire** unit landed both halves of the doc 16 §6.1
create-choreography closure:

1. **Orchestrator create-spine wiring** (`orchestrator/internal/sessions/`).
   The create spine (`createspine.go`) now drives a **fail-closed
   digest-publish step BETWEEN cred-mint and mark-routable** (D73
   mint-before-attach). A new orchestrator-local seam (`digestPublisher`) and
   its production adapter `DigestFeedPublisher` (`digestpublish.go`) speak the
   **frozen `identityv1.DigestFeedServiceClient` directly via `proto/gen/go`** —
   never importing `identity/*` (**D80**), reimplementing the same fail-closed
   ack gate this component's `PublishSession` applies. A publish/transport error,
   an uncommitted ack, or an unwired publisher all **stall create — the session
   is never marked routable**. The step is **flag-gated** behind
   `DS_ORCH_DIGEST_PUBLISH_WIRE` (default OFF, byte-identical when off — D50); the
   live push to a real boundary is the deferred, env-gated manual step.

2. **HMAC key-lifecycle reconciliation** (pinned in prose, not rebuilt — the
   machinery was already landed). The composition point is
   **`PublishSessionWithManager` over a `KeyManager`** (`publish.go` /
   `keys.go`): per-host per-epoch key custody stays **identity-side, in the D39
   trust zone, never on the virtual-metal host**. The epoch-roll re-push rides
   **`KeyManager.LiveRekey`** (`rotation.go`): re-publish every live session under
   the new active key, ack-gate each, then retire the old
   (**RevokeSession-then-republish**, no-gap). The `DefaultTruncationLenBytes=16`
   false-positive-vs-fleet-digest-count analysis remains **open under taskdb
   `01KTWJ4NR0A76YW7SY2CV528AH`** (linked from `producer.go`, not duplicated).

The producer-side verbs (`PublishSession`/`RevokeSession` in `publish.go`,
fail-closed by return value) and the full re-key path (`rotation.go`) were
already implemented; this unit added the orchestrator caller and the
reconciliation notes, leaving no LiveRekey→RevokeSession leg missing.

## Wave findings breadcrumb (orchfu2b)

Six units landed this wave on `orchfu2b-integration-28fce343abfc`, all
`orchestrator/`-tree work wiring landed-but-uncalled bridges onto the
production spine, plus one doc-tightening fixup:

- **publishsession-wire** (above) — the digest-publish create-choreography
  closure itself.
- **metering-wire** — arms the previously-landed `sessions.MeteringWire` /
  `MeteringWire` / `CreateTimingWire` bridges onto `createspine.go`,
  `heartbeatingest.go`, and `reconcileloop.go`; all three stay gated behind
  their existing `DS_ORCH_*_WIRE` flags, default OFF, byte-identical when off
  (D50).
- **snapshotref-producer** — closes the durability *producer* arc for
  `SnapshotRefs` (the wave-1 consumer/recovery half already existed): new
  `CapturedRefStore` seam + `capturedRefRecoverer` decorator, fail-closed,
  nil-store default keeps historical in-memory-only behavior byte-identical.
- **hookfault-reap** — mirrors the create-path `HookFaultObserver` onto the
  §4.2 post-destroy reap path (new `HookPostDestroy` kind); the `Destroy`
  verdict itself stays byte-identical, only the out-of-band observation is
  new.
- **migration-regexp** — single-sources the `^([0-9]{4})_[a-z0-9_]+\.sql$`
  migration-name pattern into `storetest.MigrationNamePattern`, collapsing
  three mirrored literals across the migrations/store/policylog suites.
- **trustpath-sessionmode** — adds the `SessionMode*` helper family to
  `internal/trustpath` (mirroring the sibling AttachToken/SessionRecord/
  EntrypointRef/ConfigDriveImage triples) and repoints
  `libvirt/sessionmodestore.go` through it; on-disk path stays byte-identical.
  A follow-up doc-only commit tightened the `SessionModePath` comment to match
  the sibling-helper convention (no path/behavior change).

**Deferred to the next loop wave** (files-overlap with the units above, or
not dispatched this wave — see the wave's `next_wave_plan` / re-scope notes
on each task): wiring `CapturedRefStore` into the live host-agent daemon
(`capturedref-host-wire`), wiring `DigestFeedPublisher` into the orchestrator
create coordinator behind gate-on-`Routable` (`digestpublish-coordinator-wire`),
routing the EntrypointProducer serving-leg path through
`trustpath.SessionModePath` (`trustpath-entrypoint-swap`), a createtiming feed
follow-up, and a shellcheck SC1007 fixup.
