# ISSUED{service_id} wrong-destination egress-block fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** ISSUED{service_id}-digest egress picture
exercising one disposition of the
doc 06 §3c inject-class twin's
**digest half** — "Inject-class (STS-style short-lived) creds assert … the
presence of the `ISSUED{service_id}` digest" so **wrong-destination egress
blocks** (doc 16 §5.1/§6/§10, the keyed-issued-to-wrong-destination block+log
rung default): conforming (wrong-destination blocked + intended-destination
passes), wrong-destination-egressed, intended-destination-blocked, undecidable.
Each fixture records one or more presentations as DATA —
`{issued_service_id, egress_destination, blocked}`.

The conformance test mechanically diffs each presentation against the
destination fence its own issued service names, but the presentations themselves
are invented — no real credential is minted, no HMAC digest is computed, no
digest feed or SecretMatcher is dialed, and no grant record is opened. The
runtime intended-vs-wrong destination match of the production swap path (doc 16
§5.5 step 7 / §10, the swap/scan filter-ordering interlock) is modeled as fixed
rows.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only legal
`provenance` value in this directory is `synthetic`. Real service ids, digests,
or credential material never enter this repository — re-author them as synthetic
presentations first, per the canonical contract.
