# Golden-freshness conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** golden manifest exercising one
disposition of the doc 03 §6 "Package & build caching"
rotation / freshness check — the "Nightly golden images" bullet's CVE-roll SLA
(conforming, stale, missing, unrotatable): each manifest records the rotation
policy in force and
a set of opted-in `(repo, branch)` goldens as DATA — `{present, age_hours}`.
The conformance test mechanically diffs each manifest against its policy, but
the manifests themselves are invented — no real on-disk image is stat'd, no
`output_dir` is read, no qcow2 is opened, no bake fires. The runtime
mtime-vs-now arithmetic of `images/golden/nightly-rebuild.sh` is modeled as
fixed manifest rows.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded image
inventories never enter this repository — re-author them as synthetic
manifests first, per the canonical contract.
