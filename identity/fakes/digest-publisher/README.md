# identity/fakes/digest-publisher/ — Stage-0 fake digest publisher

**Owner workstream:** Identity & credentials · **OSS**
**Status:** LANDED with the Stage-0 freeze PR (2026-06-12) — `main.go` +
`publisher_test.go` in this directory implement this spec against the frozen
`dreamserpent.identity.v1.DigestFeedService` (FREEZE.md identity.v1 row: "fake
publisher in the same PR"). LANGUAGE NOTE: Go here binds the **fake's**
implementation language only — the `identity/` tree's product-language decision
stays the workstream's own (`identity/README.md`); this module sits outside
`go.work`, and its CI lane rides the fakes-first follow-up task together with
the generated programmable fakes. Verified: `go build/vet/test` green standalone
(`GOWORK=off`), live fail-closed smoke (publisher against no consumer exits
non-zero — the session is never marked routable).

## Charter

The hand-rolled **behavioral** fake for the D73 Identity→Boundary secret-digest
feed. It drives the wire surface authored in
[`proto/dreamserpent/identity/v1/digest_feed.proto`](../../../proto/dreamserpent/identity/v1/digest_feed.proto)
(package `dreamserpent.identity.v1`, service **`DigestFeedService`**) so Boundary
can build ds-tlsproxy's `SecretMatcher` consumer against a runnable producer
instead of against `../../digest-producer/` source — fakes-first is the
cross-workstream contract discipline (doc 05 OQ3; the repo rule: neighbors build
against the fake). The fake runs as a **local process** speaking the frozen
protos over the wire; it is never Go-imported from its home tree.

It is the producer half of the seam only. It does **not** implement the boundary
consumer, the real producer, the HMAC keystore, or any conntrack/`flush_session`
behavior (that is boundary-side, doc 14 §5) — it emits the publish/revoke/ack
traffic a real Identity producer would, and asserts the consumer honors the
frozen invariants.

## The wire surface it drives (every message + RPC, by name)

Service **`DigestFeedService`** (`digest_feed.proto`):

- **`rpc DigestPublish(DigestPublishRequest) returns (DigestPublishResponse)`** —
  registers a batch of session-scoped digests; `DigestPublishResponse` is the
  **ack** (doc 16 §6.6), carrying `batch_id` (echo), `session`, `consumer_id`,
  and `committed`.
- **`rpc DigestRevoke(DigestRevokeRequest) returns (DigestRevokeResponse)`** —
  revokes published digests by `key_ids`; `DigestRevokeResponse` is the revoke
  ack (`session`, `consumer_id`, `committed`).

Messages and enums the fake constructs and inspects:

- **`DigestEntry`** — the frozen doc 14 §7 entry: `key_id`, `algo`
  (**`DigestAlgo`** = `Family` ∈ {`FAMILY_UNSPECIFIED`, `FAMILY_HMAC_SHA256`} +
  `truncation_len_bytes`), `digest` (bytes), `cred_class`, `scope`, `expiry`
  (`google.protobuf.Timestamp`), `variant_tag`.
- **`DigestCredClass`** — the `oneof class` of `Issued{ service_id }` |
  `Forbidden{}`. The fake registers both classes.
- **`DigestScope`** — `DIGEST_SCOPE_SESSION` | `DIGEST_SCOPE_FLEET` |
  `DIGEST_SCOPE_UNSPECIFIED`.
- **`DigestVariantTag`** — `DIGEST_VARIANT_TAG_RAW` | `_BASE64` | `_URLENC` |
  `_HEX` (+ `_UNSPECIFIED`). The fake emits one `DigestEntry` per variant of a
  given synthetic credential.
- **`DigestSessionRef`** — `session_uuid`, scoping the mint-before-attach
  ordering (never used to attribute traffic — doc 14 §4).
- **`DigestPublishRequest`** / **`DigestRevokeRequest`** — the batch carriers
  (`session`, `entries`/`key_ids`, `batch_id`/`scope`).

## Startup & config

The fake is a small gRPC **server** for `DigestFeedService` (the producer is the
calling side on the real seam, but the fake is *run as a local process the
consumer dials* — doc 05 fakes-as-servers pattern; the consumer test harness
drives it). Config surface (env or a flags file; no secrets, ever):

- **`listen`** — UDS path or `host:port` the boundary consumer dials.
- **`key_id` / `epoch`** — the synthetic HMAC `key_id` stamped on every
  `DigestEntry` (per-host per-epoch shape, D73; rotation is simulated by handing
  a new `key_id` and re-publishing live entries — doc 16 §6.3).
- **`truncation_len_bytes`** — the `DigestAlgo.truncation_len_bytes` the fake and
  the consumer matcher must agree on.
- **`fail_closed`** (default **true**) — when the keyed plane is loaded, an ack
  with `committed=false` (or a withheld ack) must stall the consumer's
  session-create; the scenario toggles this to exercise the fail-closed path.
- **`scripted fixtures`** — a synthetic-only catalog of credentials → variants →
  expected `DigestEntry` rows, so a run is deterministic and replayable.

## The publish → ack → revoke happy path it drives

1. **Mint-before-attach publish.** For a fresh `DigestSessionRef{session_uuid}`,
   the fake sends one `DigestPublishRequest` with `scope=DIGEST_SCOPE_SESSION`, a
   `batch_id`, and a batch of `DigestEntry` rows covering both `DigestCredClass`
   cases (an `Issued{service_id}` cred and a `Forbidden` canary) and **all four**
   `DigestVariantTag` encodings (`RAW`/`BASE64`/`URLENC`/`HEX`) of each — exactly
   what makes a base64'd or url-encoded secret matchable, doc 14 §7.
2. **Ack.** The consumer (standing in for the D35 host agent — the ack-er,
   **ratified D109** / doc 16 §6.1: a host-side actor proving host-wide
   visibility) returns `DigestPublishResponse{ batch_id, session, consumer_id,
   committed=true }`. The fake asserts `batch_id` echoes, `committed=true`, and —
   the **mint-before-attach invariant** — that the consumer reports the session
   matchable **before** it would route first egress (round2/08 test 6: digests
   matchable before the first egress byte).
3. **Match probes.** With the entries acked, the fake feeds the consumer
   synthetic candidate bytes in each variant and asserts the `Forbidden` canary
   is caught in every encoding and the `Issued` cred matches its intended
   `service_id` (wrong-destination is the consumer's block+log, D73 — asserted,
   not implemented here).
4. **Revoke + teardown flush.** The fake sends `DigestRevokeRequest{ session,
   key_ids, scope=DIGEST_SCOPE_SESSION }`, gets `DigestRevokeResponse{ committed
   =true }`, and asserts the revoked `key_ids` no longer match — the **teardown-
   flush** hygiene (doc 14 §7; entry `expiry` also ages entries out in lockstep
   with cred TTL).

## Scenarios it must exercise (the frozen invariants)

- **Plaintext never crosses the seam.** A structural assertion over every
  `DigestPublishRequest` the fake emits: only `key_id`, `DigestAlgo`, the
  `digest` bytes, `cred_class`, `scope`, `expiry`, and `variant_tag` cross —
  **no field carries a credential plaintext**, and the fake's catalog proves
  every `digest` is a keyed hash of a *synthetic* value, never the value itself
  (doc 14 §7; the producer computes digests in the D39 trust zone).
- **Mint-before-attach ordering.** The happy-path step 2 assertion, run as a
  named scenario: a session is **not routable until its digests are acked**
  (`DigestPublishResponse.committed=true`) — the fake withholds nothing and
  proves matchability precedes first egress.
- **Teardown flush.** Step 4 as a named scenario: after `DigestRevoke` (and on
  session end) the entries are gone; a stale `DigestEntry` never lingers past the
  cred it shadows (the `expiry`-tracks-TTL clause).
- **Fail-closed while the keyed plane is loaded.** With `fail_closed=true`, the
  fake drives a publish whose ack returns `committed=false` (or is withheld) and
  asserts the consumer **stalls/fails session-create rather than routing open**
  (doc 16 §6.1/§7). Fail-open is asserted to be reachable **only** under an
  explicit generic flag-only config, never with the keyed plane loaded.
- **Scope split (D72/D73), faithful to doc 14 §7.** The fake exercises the
  **session-scope** path on this seam (publish/revoke ride `DigestFeedService`,
  acked per `DigestPublishResponse`) and asserts that **fleet-scope**
  registration/revocation is **not** delivered here: a `DIGEST_SCOPE_FLEET` entry
  states class only — fleet registration/revocation is a **policy artifact under
  the `policy_log` seq via the one-per-host `WatchPolicies` subscriber (D72)**,
  out of this fake's transport. The fake never invents a second policy stream or
  a second policy-version namespace; the **digest-set version** lives in boundary
  verdict provenance, a separate non-policy namespace (doc 14 §2 `PolicyDecision`
  row), and is not minted here.

## Discipline

- **Synthetic digests only** (D50): every value in this fake is derived from a
  synthetic credential; nothing here may originate from a real secret, ever, and
  no HMAC key material lives in this tree.
- **No code lands here pre-freeze.** The `identity/` tree is language-unbound;
  this spec ships with the freeze, the implementation lands after in the
  workstream's chosen language. The generated **programmable** fakes (stub
  servers/clients) come from the `proto/gen/go` codegen pipeline; this directory
  holds the **behavioral** fake (ordering, ack, fail-closed, scope-split
  semantics) the generated stubs cannot express.
- Register it in the `proto/README.md` fakes index when it lands.

## What must NOT live here

The real producer (`../../digest-producer/`), the boundary consumer, the feed
proto itself ([`proto/dreamserpent/identity/v1/`](../../../proto/dreamserpent/identity/v1/)),
any HMAC key material, and any `go.mod`/`Cargo.toml` or compiled code (the tree
is language-unbound until the workstream binds it post-freeze).
