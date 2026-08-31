# Policy-pack fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is `synthetic` — authored for the baseline-pack tooling
tests, never recorded from a live source:

- `baseline-pack.synthetic.json` — an authored baseline-endpoint pack
  exercising the pack schema (the name says what it is).
- `github-meta.json` — a hand-reduced, value-neutralized copy of the
  *public* GitHub `/meta` endpoint **shape** (public CIDR metadata, no user
  or partner data, no credential of any kind) used to test the meta-poller
  parsing path.

Non-NDJSON fixtures carry their D50 tag in a `<name>.provenance` sidecar
(one per fixture, committed beside it), per the sidecar convention in the
canonical contract. The only legal `provenance` value in this directory is
`synthetic`.

Recorded packs (dogfood / partner-consented) never enter this repository —
they live in the segregated internal store described in the canonical
contract.
