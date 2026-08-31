# Canary-never-egresses conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** feed + egress picture exercising one
disposition of the doc 06 §3c
"Secret-scanning gate" claim (D73; doc 12 §5.3;
doc 16 §1/§13): a
planted forbidden canary credential that must never egress on **inspected**
paths — raw and in each pushed variant (RAW/BASE64/URLENC/HEX, doc 14 §7) — with
the canary value in zero log/event/spool bytes. The stated **non-claims** are
carried in-row: TLS-4 pass-through tunnels get no inspection / swap / scanning,
and adversarial custom encodings are out of scope. The dispositions covered are
conforming and canary-egressed-on-inspected-path.

Each fixture records the keyed digest feed and a set of egress attempts as DATA;
the conformance test mechanically scans them, but no real `SecretMatcher`, no
real digest producer, no real proxy, and no real network egress is involved. The
canary "value" is a synthetic placeholder string — no real secret enters this
repository. No `DS_KVM_LIVE` token is read or set; no live qemu / KVM / network
is invoked (D50).

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded egress
captures never enter this repository — re-author them as synthetic equivalents
first, per the canonical contract.
