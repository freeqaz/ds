# Credential-TTL conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** inject-class credential presentation
exercising one disposition of the
doc 06 §3c inject-class **TTL
bound** — "Inject-class (STS-style short-lived) creds assert the TTL bound"
(doc 16 §5.1 / §5.4, the token-TTL + grant-TTL freshness legs, TTL-as-revocation):
conforming (grant-wins-the-min), token-expired, grant-expired, undecidable. Each
fixture records the validation policy in force (`{now_unix}`) and one presentation
as DATA — `{token_ttl_unix, grant_ttl_unix}`.

The conformance test mechanically diffs each presentation against its policy, but
the presentations themselves are invented — no real credential is minted, no
keystore is opened, no `Validate` seam is dialed, and no wall clock is read. The
runtime ttl-vs-now comparison of the production reference validator
(`assurance/contract-harness/seams/identity-validate/refimpl.go` HonestDecision
steps 3 and 4) is modeled as fixed rows.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only legal
`provenance` value in this directory is `synthetic`. Recorded credential TTLs
never enter this repository — re-author them as synthetic presentations first,
per the canonical contract.
