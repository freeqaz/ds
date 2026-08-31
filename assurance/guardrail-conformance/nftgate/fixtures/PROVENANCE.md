# nftgate conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** egress-attempt — the VM, treated as
untrusted (doc 06 §3c), trying to defeat one M0 network guardrail — paired with
the disposition the docs require for it. The attempts are mechanically diffed
against the modeled doc 09 §9 / doc 11 §6 / D70 boundary posture by the offline
conformance test (`nftgate_test.go`); the attempts and their required
dispositions are invented against the DOCUMENTED wire/posture shape, never
captured from a live boundary, a live NFTables ruleset, or any real session.

Addresses use the documentation ranges (RFC 5737 `203.0.113.0/24`,
`198.51.100.0/24`; RFC 3849 for v6) and the well-known public resolver IPs that
appear verbatim in the docs (the POL-2 baseline names them); none is a real
session destination.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded attempts
never enter this repository — re-author them as synthetic equivalents first,
per the canonical contract.
