# App-install conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** app-install manifest exercising one
disposition of the doc 16 §5.2 D83 read-level check (conforming,
above-read-level, write-on-read-path, absent-from-inventory, and siblings):
the manifests are mechanically diffed against the **live** doc 16 §5.2
inventory table by the conformance test, but the manifests themselves are
invented — no real app credential, grant, token, or partner integration is
recorded in them.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded
manifests never enter this repository — re-author them as synthetic
equivalents first, per the canonical contract.
