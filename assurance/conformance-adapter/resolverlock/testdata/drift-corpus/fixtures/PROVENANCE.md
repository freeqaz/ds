# Resolver-lock drift corpus — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** POL-1 policy document — one good
baseline plus adversarial drift cases (missing/empty blocklists, wildcard
FQDNs, agreement/both-accept compounds, and siblings added at the corpus
tail) — written to drive the resolver-lock conformance checks, never
captured from a live host or partner policy. Hostnames, org names, and rule
ids are invented values.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`.

Corpus additions are **append-only at the tail index** (waves extend it
concurrently); a new fixture lands with its sidecar in the same commit, and
recorded policy material never enters this repository — re-author it as a
synthetic equivalent first, per the canonical contract.
