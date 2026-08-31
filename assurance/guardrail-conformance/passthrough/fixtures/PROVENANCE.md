# Pass-through-empty-by-default conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** pass-through configuration exercising one
disposition of the doc 06 §3c
"Cert-pinned pass-through" claim (D17/TLS-4; the D74 empty-by-default invariant,
doc 12 §5.3): the shipped baseline
pass-through list is **empty by default**, a pass-through-listed pinned client
gets an opaque tunnel with **no credential swap**, and everything else is
TLS-terminated at the per-session CA. The dispositions covered are
empty-default (conforming), nonempty-default, and swap-on-pass-through.

Each fixture records the configuration's `is_default` flag and a set of
endpoints as DATA; the conformance test mechanically diffs them against the
D17/D74 invariant, but no real proxy, no real per-session CA, no real TLS
handshake, and no real swap is involved. No `DS_KVM_LIVE` token is read or set;
no live qemu / KVM / network is invoked (D50).

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded proxy
configurations never enter this repository — re-author them as synthetic
equivalents first, per the canonical contract.
